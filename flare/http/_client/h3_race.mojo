"""Happy-eyeballs HTTP/3-vs-HTTP/2 connection race.

When an ``https://`` request is eligible for HTTP/3 (``prefer_h3`` or a
fresh Alt-Svc advert) AND is idempotent, flare races the h3 (QUIC) path
against the proven h2/h1 (TLS) path *concurrently* on two OS threads
instead of trying h3 first and falling back sequentially. UDP is far
more likely than TCP to be blocked by a middlebox, so a dead h3 path
must not add its dial timeout on top of the h2 dial -- overlapping the
two means the wall-clock cost is ``max(h3, h2)`` rather than
``h3_timeout + h2``. h3 is preferred whenever it succeeds.

Design (mirrors :func:`flare.runtime.scheduler._worker_entry`):

* Each leg runs the *full* request on its own thread via
  :func:`_race_worker`, which calls a caller-supplied leg function
  (``_LegFn``) and writes the outcome into a heap-allocated
  :class:`_RaceResult` cell. The leg function is passed in (rather than
  this module importing ``HttpClient``) to avoid an import cycle.
* :func:`race_h3_h2` spawns both
  :class:`flare.runtime._thread.ThreadHandle` workers and then
  ``join()``s both before reading any result. ``pthread_join`` is a
  happens-before barrier, so the result cells are read race-free with
  no atomics, and joining guarantees no worker outlives its handle
  (which the thread module documents as UB).
* h3 wins when its leg produced a response; otherwise h2's response is
  used; if both failed the combined error is raised.

ponytail: this races whole *requests*, not just connection
establishment, so an idempotent request is sent on both wires (the
server sees it twice). Sound for idempotent methods (the only ones
routed here) but it doubles their load; the upgrade path is to split
the h2/h1 connect from the request so only the connection is raced.
Bounded join (not detach): each leg's own dial timeout caps how long
the slower leg can hold up the return; the upgrade path is
``pthread_detach`` + an atomic refcount on the cell once the stdlib
ships an ``Atomic`` type.
"""

from std.collections import List, Optional
from std.memory import UnsafePointer, alloc

from flare.runtime._thread import ThreadHandle, _OpaquePtr, _null_ptr

from ..headers import HeaderMap
from ..response import Response


# A leg runs the full request for one protocol. Args:
# ``(client_addr, is_h3, url, method, headers, body, wire) -> Response``.
# The URL is passed as a String (re-parsed in the leg) because Url is
# move-only and each of the two legs needs its own copy. ``thin``
# (non-capturing) so it can be stored in a struct field and passed as a
# value; supplied by the client module so this file needs no HttpClient
# import (avoids an import cycle).
comptime _LegFn = def(
    Int, Bool, String, String, HeaderMap, List[UInt8], String
) raises thin -> Response


struct _RaceResult(Movable):
    """One leg's outcome: a response on success, else an error
    message. Heap-allocated; written by the worker thread, read by
    :func:`race_h3_h2` after the join barrier."""

    var resp: Optional[Response]
    var err: String

    def __init__(out self):
        self.resp = None
        self.err = String("")


struct _RaceArg(Movable):
    """Inputs handed to one race worker. Addresses are carried as
    ``Int`` so no typed pointer crosses the FFI boundary; the worker
    re-materialises the result cell."""

    var leg: _LegFn
    var client_addr: Int
    var result_addr: Int
    var is_h3: Bool
    var url: String
    var method: String
    var headers: HeaderMap
    var body: List[UInt8]
    var wire: String

    def __init__(
        out self,
        leg: _LegFn,
        client_addr: Int,
        result_addr: Int,
        is_h3: Bool,
        url: String,
        method: String,
        headers: HeaderMap,
        body: List[UInt8],
        wire: String,
    ):
        self.leg = leg
        self.client_addr = client_addr
        self.result_addr = result_addr
        self.is_h3 = is_h3
        self.url = url
        self.method = method
        self.headers = headers.copy()
        self.body = body.copy()
        self.wire = wire


def _race_worker(arg: _OpaquePtr) -> _OpaquePtr:
    """Pthread start routine: run one leg's full request via the stored
    ``leg`` function and stash the outcome. Never raises across the FFI
    boundary -- every error is captured into the cell."""
    var a = arg.bitcast[_RaceArg]()
    var result = UnsafePointer[_RaceResult, MutUntrackedOrigin](
        unsafe_from_address=a[].result_addr
    )
    try:
        var resp = a[].leg(
            a[].client_addr,
            a[].is_h3,
            a[].url,
            a[].method,
            a[].headers,
            a[].body,
            a[].wire,
        )
        result[].resp = Optional(resp^)
    except e:
        result[].err = String(e)
    return _null_ptr()


def race_h3_h2(
    leg: _LegFn,
    client_addr: Int,
    url: String,
    method: String,
    headers: HeaderMap,
    body: List[UInt8],
    wire: String,
) raises -> Response:
    """Race the h3 and h2/h1 legs concurrently and return the winning
    :class:`Response` (h3 preferred). Raises if both legs fail. ``leg``
    is the per-protocol worker body supplied by the caller (so this
    module needs no ``HttpClient`` import)."""
    var h3_res = alloc[_RaceResult](1)
    h3_res.init_pointee_move(_RaceResult())
    var h2_res = alloc[_RaceResult](1)
    h2_res.init_pointee_move(_RaceResult())

    var h3_arg = alloc[_RaceArg](1)
    h3_arg.init_pointee_move(
        _RaceArg(
            leg,
            client_addr,
            Int(h3_res),
            True,
            url,
            method,
            headers,
            body,
            wire,
        )
    )
    var h2_arg = alloc[_RaceArg](1)
    h2_arg.init_pointee_move(
        _RaceArg(
            leg,
            client_addr,
            Int(h2_res),
            False,
            url,
            method,
            headers,
            body,
            wire,
        )
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

    var winner = Optional[Response](None)
    var err_msg = String("")
    if h3_res[].resp:
        winner = Optional(h3_res[].resp.take())
    elif h2_res[].resp:
        winner = Optional(h2_res[].resp.take())
    else:
        err_msg = (
            String("h3+h2 race: both legs failed: h3=")
            + h3_res[].err
            + String(" h2=")
            + h2_res[].err
        )

    h3_arg.destroy_pointee()
    h3_arg.free()
    h2_arg.destroy_pointee()
    h2_arg.free()
    h3_res.destroy_pointee()
    h3_res.free()
    h2_res.destroy_pointee()
    h2_res.free()

    if winner:
        return winner.take()
    raise Error(err_msg)
