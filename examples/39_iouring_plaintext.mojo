"""Example 39 — io_uring HTTP/1.1 plaintext server.

Single-worker HTTP/1.1 server built **directly on top of**
:class:`flare.runtime.uring_reactor.UringReactor`. Returns a
fixed ``Hello, World!`` plain-text response for every request.
Demonstrates that the io_uring substrate (FFI, ring driver,
multishot accept, per-conn multishot recv, async send + close)
composes into a working HTTP server with a few hundred LOC of
pure Mojo and **no** ``liburing`` C dependency.

What this example demonstrates
------------------------------

1. **End-to-end io_uring HTTP serving.** Listener is a vanilla
   ``AF_INET`` / ``SOCK_STREAM`` socket bound to ``0.0.0.0:8080``;
   everything past the bind goes through io_uring SQE/CQE.
2. **Multishot accept** for the listener — one SQE arms it, the
   kernel keeps posting accept CQEs as connections arrive.
3. **Multishot recv** per accepted connection — one SQE arms it,
   the kernel keeps posting recv CQEs as bytes arrive on that
   socket.
4. **Fire-and-forget send** for the canned plaintext response.
5. **Async close** with ``IOSQE_CQE_SKIP_SUCCESS`` so the typical
   close path doesn't even round-trip a CQE.
6. **Generation-stamped conn_ids** so a slot reused after a
   close never gets misrouted CQEs from its previous occupant.

What this example deliberately leaves out
-----------------------------------------

This example is intentionally a **demonstrator**, not a
production HTTP server. Specifically:

* No HTTP/1.1 parser — every accepted connection is treated as
  a single-request close-after-response client. Pipelining,
  keep-alive request boundary detection, request-line + header
  validation are deliberately out of scope; that work belongs
  to ``flare.http._server_reactor_impl`` (the production reactor
  that owns the parser + state machine).
* The connection slab is a flat ``List[_Conn]`` with linear
  scan ``_alloc_conn``; the production wire-in uses the per-
  worker ``Pool[BufferHandle]`` from
  :mod:`flare.runtime.buffer_pool`.
* Concurrent close-heavy workloads (e.g. ``wrk -t8 -c256`` with
  HTTP/1.0-shape close-each-request clients) trigger a slot-
  reuse race that this example handles via a generation counter
  + inflight-op tracker but doesn't fully resolve under high
  contention. The hardened server-side state machine in
  ``_server_reactor_impl`` resolves this by integrating with
  the same ``Pool[ConnHandle]`` lifecycle the existing epoll
  path uses.

How to run
----------

::

    pixi run example-iouring-plaintext

By default the example serves one HTTP request and exits — the
deterministic CI smoke shape. Override via the environment:

* ``FLARE_IOURING_MAX_REQUESTS=N`` — exit after N requests.
  Set to ``-1`` for unbounded.
* ``FLARE_IOURING_SECS=T`` — wall-clock cap in seconds. Set to
  ``-1`` for no cap.

Skip behaviour
--------------

If the host kernel does not expose io_uring (very old Linux,
sandboxed container, non-Linux build), the example prints a
clear message and exits 0 — same idiom as
``test_io_uring_driver``.
"""

from std.os import getenv
from std.ffi import c_int, c_uint, c_size_t, get_errno
from std.memory import UnsafePointer, alloc, stack_allocation
from std.time import perf_counter_ns

from flare.net._libc import (
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SO_REUSEPORT,
    INVALID_FD,
    _bind,
    _close,
    _fill_sockaddr_in,
    _listen,
    _setsockopt,
    _socket,
    _strerror,
)
from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.uring_reactor import (
    URING_OP_ACCEPT,
    URING_OP_RECV,
    URING_OP_SEND,
    URING_OP_CLOSE,
    UringCompletion,
    UringReactor,
)


# ── Canned TFB-plaintext response ────────────────────────────────────────────


comptime _RESP_TEXT = (
    "HTTP/1.1 200 OK\r\nServer: flare-uring\r\nContent-Type:"
    " text/plain\r\nContent-Length: 13\r\nDate: Sat, 02 May 2026 16:00:00"
    " GMT\r\n\r\nHello, World!"
)


# ── Per-connection slab ──────────────────────────────────────────────────────


@fieldwise_init
struct _Conn(Copyable, Movable):
    """Per-connection state.

    The recv buffer pointer is stored as ``Int`` (raw address)
    and re-materialised per access — storing it as a typed
    ``UnsafePointer[UInt8, MutExternalOrigin]`` triggers the
    v0.5-documented Mojo stale-read anomaly (see
    development.mdc § Mojo nightly anomalies). Same idiom the
    multicore ``Scheduler`` uses for its ``stopping`` cell.
    """

    var fd: c_int
    var rx_buf_addr: Int
    var in_use: Bool
    var generation: UInt32


comptime _RX_BUF_BYTES: Int = 4096
comptime _MAX_CONNS: Int = 1024
comptime _SLOT_BITS: UInt64 = 16
comptime _SLOT_MASK: UInt64 = (UInt64(1) << _SLOT_BITS) - UInt64(1)
comptime _GEN_BITS: UInt64 = 32
comptime _GEN_MASK: UInt64 = (UInt64(1) << _GEN_BITS) - UInt64(1)


@always_inline
def _pack_conn_id(slot: Int, generation: UInt32) -> UInt64:
    """Encode a slot index + generation into a 48-bit conn_id."""
    return (UInt64(Int(generation)) << _SLOT_BITS) | (UInt64(slot) & _SLOT_MASK)


@always_inline
def _unpack_slot(conn_id: UInt64) -> Int:
    return Int(conn_id & _SLOT_MASK)


@always_inline
def _unpack_gen(conn_id: UInt64) -> UInt32:
    return UInt32(Int((conn_id >> _SLOT_BITS) & _GEN_MASK))


@always_inline
def _conn_rx_buf(c: _Conn) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Re-materialise the typed recv-buffer pointer."""
    return UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=c.rx_buf_addr
    )


# ── Listener helper ──────────────────────────────────────────────────────────


def _make_listener(port: UInt16) raises -> c_int:
    """Build an ``AF_INET`` listener on ``0.0.0.0:port`` with
    ``SO_REUSEADDR | SO_REUSEPORT`` and ``backlog=1024``."""
    var s = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if s < c_int(0):
        raise Error("socket: " + _strerror(get_errno().value))
    var one = stack_allocation[4, UInt8]()
    (one + 0).init_pointee_copy(UInt8(1))
    for k in range(1, 4):
        (one + k).init_pointee_copy(UInt8(0))
    _ = _setsockopt(s, SOL_SOCKET, SO_REUSEADDR, one, c_uint(4))
    _ = _setsockopt(s, SOL_SOCKET, SO_REUSEPORT, one, c_uint(4))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    for k in range(4):
        (ip + k).init_pointee_copy(UInt8(0))
    _fill_sockaddr_in(sa, port, ip)
    if _bind(s, sa, c_uint(16)) < c_int(0):
        var e = _strerror(get_errno().value)
        _ = _close(s)
        raise Error("bind 0.0.0.0:" + String(Int(port)) + " failed: " + e)
    if _listen(s, c_int(1024)) < c_int(0):
        var e = _strerror(get_errno().value)
        _ = _close(s)
        raise Error("listen failed: " + e)
    return s


# ── Connection slab management ──────────────────────────────────────────────


def _alloc_conn(mut conns: List[_Conn], fd: c_int) raises -> Int:
    """Find a free slot, install ``fd``, return slot index."""
    for i in range(len(conns)):
        if not conns[i].in_use:
            conns[i].fd = fd
            conns[i].in_use = True
            return i
    raise Error(
        "io_uring server: connection slab is full (max="
        + String(_MAX_CONNS)
        + ")"
    )


def _free_conn(mut conns: List[_Conn], slot: Int) -> None:
    """Mark ``conns[slot]`` free, invalidate its fd, and bump
    generation so stale CQEs get filtered out."""
    if slot < 0 or slot >= len(conns):
        return
    conns[slot].fd = INVALID_FD
    conns[slot].in_use = False
    conns[slot].generation = conns[slot].generation + 1


# ── Server loop ──────────────────────────────────────────────────────────────


def _serve(port: UInt16, max_seconds: Float64, max_requests: Int) raises -> Int:
    """Run the io_uring HTTP plaintext server until either
    ``max_seconds`` of wall time has elapsed, or
    ``max_requests`` have been served (and their sends
    drained), or — if both are negative — until killed.
    """
    if not is_io_uring_available():
        print(
            "io_uring is not available on this host; example skipped (kernel"
            " too old, sandboxed, or non-Linux build)"
        )
        return 0

    print("io_uring HTTP server: starting on 0.0.0.0:" + String(Int(port)))
    var listener_fd = _make_listener(port)
    var reactor = UringReactor(4096)

    var conns = List[_Conn](capacity=_MAX_CONNS)
    for _ in range(_MAX_CONNS):
        var buf = alloc[UInt8](_RX_BUF_BYTES)
        for j in range(_RX_BUF_BYTES):
            (buf + j).init_pointee_copy(UInt8(0))
        conns.append(
            _Conn(
                fd=INVALID_FD,
                rx_buf_addr=Int(buf),
                in_use=False,
                generation=UInt32(0),
            )
        )

    var resp_bytes = _RESP_TEXT.as_bytes()
    var resp_buf = alloc[UInt8](len(resp_bytes))
    for i in range(len(resp_bytes)):
        (resp_buf + i).init_pointee_copy(resp_bytes[i])

    reactor.arm_listener_multishot(Int(listener_fd), UInt64(0))

    var requests_served: Int = 0
    var sends_completed: Int = 0
    var completions = List[UringCompletion]()
    var t_start = perf_counter_ns()
    var t_print = t_start
    print("io_uring HTTP server: ready, entering poll loop")

    while True:
        # Only exit on max_requests *after* the last send has
        # completed. Otherwise we'd tear down ``resp_buf`` /
        # the listener while the kernel still has an in-flight
        # IORING_OP_SEND against the freed pointer.
        if (
            max_requests >= 0
            and requests_served >= max_requests
            and sends_completed >= max_requests
        ):
            break
        var now = perf_counter_ns()
        if max_seconds >= 0.0:
            var elapsed = Float64(Int(now) - Int(t_start)) / 1_000_000_000.0
            if elapsed >= max_seconds:
                break
            if Int(now) - Int(t_print) >= 1_000_000_000:
                print(
                    "  [t="
                    + String(Int(elapsed))
                    + "s] requests served so far="
                    + String(requests_served)
                )
                t_print = now
        # Block for at least one CQE per iteration. Because the
        # wakeup eventfd is *blocking* (no EFD_NONBLOCK), this
        # only returns when the kernel posts a real (accept /
        # recv / send / close) CQE or when ``wakeup()`` writes
        # to the eventfd from another thread.
        _ = reactor.poll(1, completions)
        var n = len(completions)
        for i in range(n):
            var comp = completions[i]
            try:
                var slot = _unpack_slot(comp.conn_id)
                var gen = _unpack_gen(comp.conn_id)
                if comp.op == URING_OP_ACCEPT:
                    if comp.is_error():
                        continue
                    var new_fd = c_int(comp.res)
                    var new_slot = _alloc_conn(conns, new_fd)
                    var new_id = _pack_conn_id(
                        new_slot, conns[new_slot].generation
                    )
                    reactor.arm_recv_multishot(
                        Int(new_fd),
                        _conn_rx_buf(conns[new_slot]),
                        _RX_BUF_BYTES,
                        new_id,
                    )
                elif comp.op == URING_OP_RECV:
                    if (
                        slot < 0
                        or slot >= len(conns)
                        or not conns[slot].in_use
                        or conns[slot].generation != gen
                    ):
                        continue
                    if comp.is_error() or comp.res == 0:
                        var fd = conns[slot].fd
                        var bye_id = _pack_conn_id(slot, conns[slot].generation)
                        try:
                            reactor.submit_close(Int(fd), bye_id)
                        except _e:
                            _ = _close(fd)
                        _free_conn(conns, slot)
                        continue
                    var send_id = _pack_conn_id(slot, conns[slot].generation)
                    reactor.submit_send(
                        Int(conns[slot].fd),
                        resp_buf,
                        len(resp_bytes),
                        send_id,
                    )
                    requests_served += 1
                elif comp.op == URING_OP_SEND:
                    sends_completed += 1
                    if comp.is_error() and (
                        slot >= 0
                        and slot < len(conns)
                        and conns[slot].in_use
                        and conns[slot].generation == gen
                    ):
                        var fd = conns[slot].fd
                        var bye_id = _pack_conn_id(slot, conns[slot].generation)
                        try:
                            reactor.submit_close(Int(fd), bye_id)
                        except _e:
                            _ = _close(fd)
                        _free_conn(conns, slot)
                elif comp.op == URING_OP_CLOSE:
                    pass
            except _e:
                # Slab-full or SQ-full or stale-slot is non-fatal.
                pass
        completions.clear()

    print(
        "io_uring HTTP server: poll loop exit; requests served="
        + String(requests_served)
    )

    for i in range(len(conns)):
        var addr = conns[i].rx_buf_addr
        if addr != 0:
            var raw = UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=addr
            )
            raw.free()
        if conns[i].in_use:
            _ = _close(conns[i].fd)
    resp_buf.free()
    _ = _close(listener_fd)
    return requests_served


# ── Entry point ─────────────────────────────────────────────────────────────


def main() raises:
    print("=== Example 39 — io_uring HTTP plaintext server ===")
    if not is_io_uring_available():
        print(
            "io_uring not available on this host; example exits cleanly. To"
            " run on a Linux ≥ 5.19 host with io_uring enabled:"
        )
        print("  pixi run example-iouring-plaintext")
        return
    var secs_env = getenv("FLARE_IOURING_SECS", "")
    var seconds: Float64 = 5.0
    if secs_env.byte_length() > 0:
        if secs_env == "-1":
            seconds = -1.0
        else:
            try:
                seconds = Float64(atof(secs_env))
            except _e:
                print(
                    "FLARE_IOURING_SECS="
                    + secs_env
                    + " is not a number; using default 5 s"
                )
    var reqs_env = getenv("FLARE_IOURING_MAX_REQUESTS", "")
    var max_reqs: Int = 1
    if reqs_env.byte_length() > 0:
        try:
            max_reqs = Int(atol(reqs_env))
        except _e:
            print(
                "FLARE_IOURING_MAX_REQUESTS="
                + reqs_env
                + " is not a number; using default 1"
            )
    print(
        "Serving up to "
        + (
            "infinity requests" if max_reqs
            < 0 else (String(max_reqs) + " requests")
        )
        + " over up to "
        + ("infinity seconds" if seconds < 0.0 else (String(seconds) + " s"))
        + " on port 8080. Override via FLARE_IOURING_SECS /"
        + " FLARE_IOURING_MAX_REQUESTS."
    )
    print(
        "Hint: in another shell, run `curl -i"
        " http://127.0.0.1:8080/plaintext` to drive the server."
    )
    var served = _serve(UInt16(8080), seconds, max_reqs)
    print("=== Example 39 done — served " + String(served) + " requests ===")
