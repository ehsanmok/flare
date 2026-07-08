"""Happy-eyeballs HTTP/3-vs-HTTP/2 *connection* race.

When an ``https://`` request is eligible for HTTP/3 (``prefer_h3`` or a
fresh Alt-Svc advert) AND is idempotent, flare races the h3 (QUIC)
*connection establishment* against the proven h2/h1 (TLS) connect
*concurrently* on two OS threads instead of trying h3 first and falling
back sequentially. UDP is far more likely than TCP to be blocked by a
middlebox, so a dead h3 path must not add its dial timeout on top of the
h2 dial -- overlapping the two means the wall-clock cost is
``max(h3, h2)`` rather than ``h3_timeout + h2``. h3 is preferred
whenever it connects.

Design (mirrors :func:`flare.runtime.scheduler._worker_entry`):

* Each leg establishes *only the connection* for one protocol on its own
  thread via :func:`_race_worker`, which calls a caller-supplied
  connect function (``_ConnectFn``) and records success / failure into a
  heap-allocated :class:`_RaceResult` cell. The connect function is
  passed in (rather than this module importing ``HttpClient``) to avoid
  an import cycle. The h3 leg leaves its established connection in the
  client's QUIC pool so the subsequent request reuses it.
* :func:`race_h3_h2_connect` spawns both
  :class:`flare.runtime._thread.ThreadHandle` workers and ``join()``s
  both before reading any result. ``pthread_join`` is a happens-before
  barrier, so the result cells are read race-free with no atomics, and
  joining guarantees no worker outlives its handle (which the thread
  module documents as UB).
* Returns the winning protocol (:data:`RACE_H3` when the h3 connect
  succeeded, else :data:`RACE_H2` when the h2 connect succeeded, else
  :data:`RACE_NONE`). The caller then runs the request *once* on the
  winner -- the request itself is never duplicated.

This replaces the earlier whole-*request* race, which sent an idempotent
request on both wires (the server saw it twice). Racing only the connect
keeps the latency win while sending the request exactly once.

The h2/h1 leg probes reachability by establishing a TLS
connection; unless the HTTPS keep-alive pool is enabled (``with_pool``)
that probed connection is closed, so on the (rarer) h2-wins path the
real request re-dials TLS -- one redundant handshake. The h3 leg always
pools its connection, so the common h3-wins path does not re-dial.
Upgrade path: pool the probed h2/h1 connection unconditionally once the
TLS pool accepts h2 connections.
The join is bounded (not detached) -- each leg's own dial timeout caps
how long the slower leg holds up the return; the upgrade path is
``pthread_detach`` + an atomic refcount on the cell once the stdlib
ships an ``Atomic`` type.
"""

from std.memory import UnsafePointer, alloc

from flare.runtime._thread import ThreadHandle, _OpaquePtr, _null_ptr


comptime RACE_NONE: Int = -1
"""Neither leg established a connection."""
comptime RACE_H2: Int = 0
"""The h2/h1 TLS leg connected (h3 did not, or lost)."""
comptime RACE_H3: Int = 1
"""The h3/QUIC leg connected (preferred winner)."""


# A connect leg establishes (and, for h3, pools) the connection for one
# protocol. Args: ``(client_addr, is_h3, url) -> Bool`` (True on a
# successful establish). The URL is passed as a String (re-parsed in the
# leg) because Url is move-only and each leg needs its own copy. ``thin``
# (non-capturing) so it can be stored in a struct field and passed as a
# value; supplied by the client module so this file needs no HttpClient
# import (avoids an import cycle).
comptime _ConnectFn = def(Int, Bool, String) raises thin -> Bool


struct _RaceResult(Movable):
    """One leg's outcome: whether the connection established, plus an
    error message on failure. Heap-allocated; written by the worker
    thread, read by :func:`race_h3_h2_connect` after the join barrier."""

    var ok: Bool
    var err: String

    def __init__(out self):
        self.ok = False
        self.err = String("")


struct _RaceArg(Movable):
    """Inputs handed to one race worker. Addresses are carried as
    ``Int`` so no typed pointer crosses the FFI boundary; the worker
    re-materialises the result cell."""

    var leg: _ConnectFn
    var client_addr: Int
    var result_addr: Int
    var is_h3: Bool
    var url: String

    def __init__(
        out self,
        leg: _ConnectFn,
        client_addr: Int,
        result_addr: Int,
        is_h3: Bool,
        url: String,
    ):
        self.leg = leg
        self.client_addr = client_addr
        self.result_addr = result_addr
        self.is_h3 = is_h3
        self.url = url


def _race_worker(arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine: establish one leg's connection via the
    stored ``leg`` function and stash the outcome. Never raises across
    the FFI boundary -- every error is captured into the cell."""
    var a = arg.bitcast[_RaceArg]()
    var result = UnsafePointer[_RaceResult, MutUntrackedOrigin](
        unsafe_from_address=a[].result_addr
    )
    try:
        result[].ok = a[].leg(a[].client_addr, a[].is_h3, a[].url)
    except e:
        result[].err = String(e)
    return _null_ptr()


def race_h3_h2_connect(
    leg: _ConnectFn,
    client_addr: Int,
    url: String,
) raises -> Int:
    """Race the h3 and h2/h1 connection legs concurrently and return the
    winning protocol (:data:`RACE_H3` preferred, then :data:`RACE_H2`,
    else :data:`RACE_NONE`). ``leg`` is the per-protocol connect worker
    supplied by the caller (so this module needs no ``HttpClient``
    import). Never raises for a failed connect -- the caller decides how
    to handle :data:`RACE_NONE`."""
    var h3_res = alloc[_RaceResult](1)
    h3_res.init_pointee_move(_RaceResult())
    var h2_res = alloc[_RaceResult](1)
    h2_res.init_pointee_move(_RaceResult())

    var h3_arg = alloc[_RaceArg](1)
    h3_arg.init_pointee_move(_RaceArg(leg, client_addr, Int(h3_res), True, url))
    var h2_arg = alloc[_RaceArg](1)
    h2_arg.init_pointee_move(
        _RaceArg(leg, client_addr, Int(h2_res), False, url)
    )

    var h3_ptr = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=Int(h3_arg)
    )
    var h2_ptr = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=Int(h2_arg)
    )

    var h3_thread = ThreadHandle.spawn[_race_worker](h3_ptr)
    var h2_thread = ThreadHandle.spawn[_race_worker](h2_ptr)

    # Join is a happens-before barrier: after both return, the result
    # cells are safe to read without atomics, and no worker outlives
    # its handle.
    h3_thread.join()
    h2_thread.join()

    var winner = RACE_NONE
    if h3_res[].ok:
        winner = RACE_H3
    elif h2_res[].ok:
        winner = RACE_H2

    h3_arg.destroy_pointee()
    h3_arg.free()
    h2_arg.destroy_pointee()
    h2_arg.free()
    h3_res.destroy_pointee()
    h3_res.free()
    h2_res.destroy_pointee()
    h2_res.free()

    return winner
