"""The HTTP/3 serving loop, on one thread or across workers.

:func:`serve_h3` runs the QUIC reactor loop for an HTTP/3 listener. When
the listener was configured with ``num_workers > 1``
(:attr:`flare.quic.QuicServerConfig.num_workers`), it binds one more
``SO_REUSEPORT`` listener per extra worker on the same port, runs each on
its own OS thread with its own copy of the handler, and runs worker 0 on
the calling thread. The kernel spreads client flows across the sockets by
4-tuple; a packet that lands on the wrong worker after a migration is
forwarded to its owner (see :mod:`flare.quic._worker_route`).

The workers share nothing but a control cell (stop flag + drain window,
written by :class:`flare.http.HttpServer`) and the forwarded-datagram
inboxes.
"""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc

from ..errors import log_handler_error, map_handler_error
from ..quic.server import QuicListener
from ..quic._server_support import _monotonic_ms
from ..quic._worker_route import free_inbox_table, new_inbox_table
from ..runtime._thread import ThreadHandle, _OpaquePtr
from ..ws.server_h3 import (
    WsH3Hooks,
    WsOverH3ServerStream,
    ws_h3_accept,
    ws_h3_dispatch,
)
from .cancel import Cancel
from .handler import Handler
from .response import Response


# ── Control cell: [0] stop flag, [1] drain window in ms (-1: none) ──────


def new_h3_control() -> Int:
    var p = alloc(Layout[Int64](count=2)).unsafe_leak()
    p[unsafe_offset=0] = 0
    p[unsafe_offset=1] = -1
    return Int(p)


def free_h3_control(addr: Int):
    if addr != 0:
        Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=addr
        ).unsafe_free()


def _cell(addr: Int, i: Int) -> Pointer[Int64, MutUntrackedOrigin]:
    return (
        Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr)
        .unsafe_bitcast[Int64]()
        .unsafe_offset(i)
    )


def h3_control_set(addr: Int, i: Int, value: Int):
    """Release-store slot ``i`` of the control cell (no-op at 0)."""
    if addr != 0:
        Atomic[Int64].store[ordering=Ordering.RELEASE](
            _cell(addr, i), Int64(value)
        )


def h3_control_get(addr: Int, i: Int) -> Int:
    """Acquire-load slot ``i`` of the control cell."""
    return Int(Atomic[Int64].load[ordering=Ordering.ACQUIRE](_cell(addr, i)))


# ── One request ─────────────────────────────────────────────────────────


def _serve_h3_stream[
    H: Handler & Copyable
](mut listener: QuicListener, slot: Int, stream_id: Int, mut handler: H):
    """Answer one completed HTTP/3 request stream, whatever happens.

    Both h3 dispatch loops used to call take / serve / emit bare, so a
    request the h3 layer could not build or a handler that raised
    propagated out of ``serve_http3`` and stopped the server for every
    connection. Now a request that cannot be built gets a 400, a handler
    error is mapped the way the h1 and h2 paths map it (``500``, the
    text only with ``expose_errors``), and a response that cannot be
    framed ends just that stream.
    """
    var resp: Response
    try:
        var req = listener.take_http3_request(slot, stream_id)
        var expose = req.expose_errors
        var request_id = req.headers.get("x-request-id")
        try:
            resp = handler.serve(req).lower()
        except e:
            log_handler_error(request_id, String(e))
            var mapped = map_handler_error(String(e), expose)
            resp = Response(status=mapped.status, reason=mapped.reason)
    except e:
        if "too large" in String(e):
            resp = Response(status=413, reason="Content Too Large")
        else:
            resp = Response(status=400, reason="Bad Request")
    try:
        listener.emit_http3_response(slot, stream_id, resp^)
    except:
        pass


def pump_h3_requests[
    H: Handler & Copyable
](mut listener: QuicListener, mut handler: H) raises -> Int:
    """Run ``handler`` over every completed request on every connection
    of ``listener``; returns how many were answered."""
    var dispatched = 0
    for slot in listener.take_ready_slots():
        var ready = listener.take_http3_completed_streams(slot)
        for j in range(len(ready)):
            _serve_h3_stream[H](listener, slot, ready[j], handler)
            dispatched += 1
    return dispatched


# ── The loop ────────────────────────────────────────────────────────────


def _serve_loop[
    H: Handler & Copyable
](
    mut listener: QuicListener,
    mut handler: H,
    ctl: Int,
    ws: Optional[WsH3Hooks] = None,
) raises:
    """One worker's reactor loop, until the control cell says stop or a
    requested drain has closed every connection. ``ws`` takes the
    WebSocket extended CONNECT streams (RFC 9220) before ``handler``
    sees the rest."""
    var tunnels = List[WsOverH3ServerStream]()
    while not listener._stopping and h3_control_get(ctl, 0) == 0:
        # Graceful drain: GOAWAY to every connection, then each closes
        # once its requests are answered (RFC 9114 sec 5.2); the loop
        # ends when none is left.
        var drain_ms = h3_control_get(ctl, 1)
        if drain_ms >= 0:
            if listener._drain_deadline_ms == 0:
                listener.begin_drain(drain_ms)
            if listener.drain_step():
                break
        _ = listener.tick(timeout_ms=listener.poll_timeout_ms())
        if ws:
            ws_h3_accept(ws.value(), listener, tunnels)
        _ = pump_h3_requests[H](listener, handler)
        if ws:
            ws_h3_dispatch(ws.value(), listener, tunnels)
        # Advance in-flight streaming responses by one chunk each so
        # their DATA rides this turn's drain.
        _ = listener.pump_http3_streams(Cancel.never())
        # Flush what the handler just queued on this turn.
        _ = listener.drain_all_egress()
        _ = listener.advance_timers(_monotonic_ms())


struct _WorkerCtx[H: Handler & Copyable](Movable):
    var listener: QuicListener
    var handler: Self.H
    var ctl: Int
    var ws: Optional[WsH3Hooks]
    """This worker's own copy of the WebSocket sidecar, if any."""

    def __init__(
        out self,
        var listener: QuicListener,
        var handler: Self.H,
        ctl: Int,
        ws: Optional[WsH3Hooks],
    ):
        self.listener = listener^
        self.handler = handler^
        self.ctl = ctl
        self.ws = ws.copy()


def _worker_entry[H: Handler & Copyable](arg: _OpaquePtr) -> _OpaquePtr:
    var ctx = arg.unsafe_bitcast[_WorkerCtx[H]]()
    try:
        _serve_loop[H](ctx[].listener, ctx[].handler, ctx[].ctl, ctx[].ws)
    except:
        pass  # this worker's connections end; the others keep serving
    return arg


def serve_h3[
    H: Handler & Copyable
](
    mut first: QuicListener,
    mut handler: H,
    ctl: Int,
    ws: Optional[WsH3Hooks] = None,
) raises:
    """Serve HTTP/3 on ``first`` and, for ``num_workers > 1``, on one
    more ``SO_REUSEPORT`` listener per extra worker, each on its own OS
    thread. Returns when every worker has stopped; the extra listeners
    are closed and freed here. Each extra worker serves its own copy of
    the WebSocket sidecar (``ws``)."""
    var n = first.config.num_workers
    if n <= 1:
        _serve_loop[H](first, handler, ctl, ws)
        return
    first.config.inbox_table = new_inbox_table(n)
    var threads = alloc(Layout[ThreadHandle](count=n)).unsafe_leak()
    var ctxs = List[Int]()
    var started = 0
    var err = String("")
    try:
        for w in range(1, n):
            var cfg = first.config.copy()
            cfg.worker_id = w
            cfg.port = first.local_addr().port
            var ctx = alloc(Layout[_WorkerCtx[H]](count=1)).unsafe_leak()
            var mine = Optional[WsH3Hooks](None)
            if ws:
                mine = ws.value().clone()
            ctx.unsafe_write(
                _WorkerCtx[H](QuicListener.bind(cfg), handler.copy(), ctl, mine)
            )
            ctxs.append(Int(ctx))
            threads.unsafe_offset(started).unsafe_write(
                ThreadHandle.spawn_os[_worker_entry[H]](
                    ctx.unsafe_bitcast[UInt8]()
                )
            )
            started += 1
        _serve_loop[H](first, handler, ctl, ws)
    except e:
        err = String(e)
    h3_control_set(ctl, 0, 1)
    for i in range(started):
        try:
            threads.unsafe_offset(i)[].join()
        except:
            pass
        threads.unsafe_offset(i).unsafe_deinit_pointee()
    threads.unsafe_bitcast[UInt8]().unsafe_free()
    for i in range(len(ctxs)):
        var ctx = Pointer[UInt8, MutUntrackedOrigin](
            unsafe_from_address=ctxs[i]
        ).unsafe_bitcast[_WorkerCtx[H]]()
        ctx[].listener.close()
        if ctx[].ws:
            ctx[].ws.value().destroy(ctx[].ws.value().addr)
        ctx.unsafe_deinit_pointee()
        ctx.unsafe_bitcast[UInt8]().unsafe_free()
    free_inbox_table(first.config.inbox_table, n)
    first.config.inbox_table = 0
    if err.byte_length() > 0:
        raise Error(err)
