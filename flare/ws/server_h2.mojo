"""Server-side WebSocket-over-HTTP/2 carrier (RFC 8441).

The inverse of :class:`flare.ws.client_h2.WsOverH2Stream`: it bridges the
WebSocket framing layer onto one server-side HTTP/2 stream driven by
:class:`flare.http2.server.Http2Connection`. After the server accepts an
Extended CONNECT tunnel (``Http2Connection.accept_ws_over_h2``), this
carrier sends server->client frames UNMASKED (RFC 6455 5.3) as DATA via
``queue_stream_data`` and reads client->server frames (masked) out of the
stream's inbound DATA buffer via ``drain_stream_data``.

Symmetric with the client carrier's sans-I/O contract: it does not drive
the connection; the caller feeds/drains the underlying
:class:`Http2Connection` (reactor or paired-driver test).
"""

from .frame import WsCloseCode, WsFrame, WsOpcode
from .protocol import WS_EVENT_MESSAGE, WsProtocol
from ..http2.server import Http2Connection
from ..runtime.pool import Pool


struct WsOverH2ServerStream(Copyable):
    """Stream-keyed server adapter turning one h2 stream into a WS tunnel.

    The RFC 6455 rules live in :class:`flare.ws.protocol.WsProtocol`; this
    carrier moves its bytes. Outbound frames are unmasked (RFC 6455 5.3)
    and go out through :meth:`Http2Connection.queue_stream_data` as far
    as the stream's send window allows; the rest waits in the protocol's
    bounded outbox.
    """

    var stream_id: Int
    var proto: WsProtocol
    var closed: Bool

    def __init__(out self, stream_id: Int):
        self.stream_id = stream_id
        self.proto = WsProtocol()
        self.closed = False

    def flush(mut self, mut conn: Http2Connection) raises -> Int:
        """Push queued outbound bytes as far as the window allows; return
        how many are still waiting."""
        if len(self.proto.outbox) == 0:
            return 0
        var n = conn.queue_stream_data(
            self.stream_id, Span[UInt8, _](self.proto.outbox)
        )
        self.proto.consumed(n)
        return len(self.proto.outbox)

    def send_frame(
        mut self, mut conn: Http2Connection, frame: WsFrame
    ) raises -> None:
        """Queue ``frame`` UNMASKED as DATA on this stream. A CLOSE ends
        the tunnel (later sends raise), and so does a send that would
        take the outbox past its bound (closed with 1008)."""
        if self.closed:
            raise Error("WsOverH2ServerStream: send on closed stream")
        try:
            self.proto.send_frame(frame)
        except e:
            self.closed = True
            _ = self.flush(conn)
            raise e^
        _ = self.flush(conn)
        if self.proto.close_sent:
            self.closed = True

    def try_pull_frame(
        mut self, mut conn: Http2Connection
    ) raises -> Optional[WsFrame]:
        """Drain inbound DATA and return the next complete message as one
        TEXT or BINARY frame, a CLOSE frame once the session has ended
        (by the peer, or by a protocol violation answered with its CLOSE
        code), or ``None`` until more data arrives. PING, PONG and the
        CLOSE reply are handled here."""
        # Readable edges (a WINDOW_UPDATE among them) come through here,
        # so this is where queued outbound bytes get their next chance.
        _ = self.flush(conn)
        self.proto.inbox.extend(
            Span[UInt8, _](conn.drain_stream_data(self.stream_id))
        )
        var ev = self.proto.next_event()
        _ = self.flush(conn)
        if not ev:
            return None
        if ev.value().kind != WS_EVENT_MESSAGE:
            self.closed = True
        return self.proto.event_frame(ev.value())

    def is_closed(imm self) -> Bool:
        return self.closed

    def close(
        mut self,
        mut conn: Http2Connection,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises -> None:
        """Send a server CLOSE frame (unmasked) to complete the handshake."""
        if self.closed:
            return
        self.send_frame(conn, WsFrame.close(code, reason))


# ── Edge-driven WS-over-h2 sidecar handler ─────────────────────────────────
#
# The h1 ``WsHandler.on_connection`` is a blocking run-to-completion loop;
# on the non-blocking multiplexed h2 reactor that would head-of-line block
# the whole worker. So the sidecar handler is edge-driven: the reactor calls
# ``on_open`` once when an Extended CONNECT tunnel (RFC 8441) is accepted,
# ``on_message`` per decoded client frame, and ``on_close`` on teardown. The
# handler never blocks -- it reacts to one edge and returns.


trait WsH2Handler(Copyable, Deinitable):
    """Edge-driven handler for WebSocket-over-HTTP/2 tunnels (RFC 8441).

    One handler instance is shared across every tunnel on the worker (like
    the HTTP :trait:`flare.http.Handler`); per-tunnel state belongs on the
    ``carrier`` or in handler-owned maps keyed by ``carrier.stream_id``.
    """

    def on_open(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
    ) raises -> None:
        """Called once when a tunnel is accepted; may send opening frames."""
        ...

    def on_message(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
        frame: WsFrame,
    ) raises -> None:
        """Called per decoded client->server frame."""
        ...

    def on_close(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
    ) raises -> None:
        """Called once on teardown (peer CLOSE / RST / END_STREAM)."""
        ...


# Type-erasure: the reactor's non-generic ``Http2ConnHandle`` cannot carry
# the user's ``W`` as a type parameter, so we box ``W`` behind an opaque
# address + monomorphised ``thin`` thunks (the same idiom the Router uses
# for struct handlers). ``Http2ConnHandle`` owns the per-connection carrier
# map and passes each carrier by ref into these thunks.

comptime _WsOpenThunk = def(
    Int, mut WsOverH2ServerStream, mut Http2Connection
) raises thin -> None
comptime _WsMsgThunk = def(
    Int, mut WsOverH2ServerStream, mut Http2Connection, WsFrame
) raises thin -> None
comptime _WsCloseThunk = def(
    Int, mut WsOverH2ServerStream, mut Http2Connection
) raises thin -> None
comptime _WsDestroyThunk = def(Int) thin -> None
comptime _WsCloneThunk = def(Int) raises thin -> Int


def _ws_h2_open_thunk[
    W: WsH2Handler
](
    addr: Int, mut carrier: WsOverH2ServerStream, mut conn: Http2Connection
) raises -> None:
    Pool[W].get_ptr(addr)[].on_open(carrier, conn)


def _ws_h2_msg_thunk[
    W: WsH2Handler
](
    addr: Int,
    mut carrier: WsOverH2ServerStream,
    mut conn: Http2Connection,
    frame: WsFrame,
) raises -> None:
    Pool[W].get_ptr(addr)[].on_message(carrier, conn, frame)


def _ws_h2_close_thunk[
    W: WsH2Handler
](
    addr: Int, mut carrier: WsOverH2ServerStream, mut conn: Http2Connection
) raises -> None:
    Pool[W].get_ptr(addr)[].on_close(carrier, conn)


def _ws_h2_destroy_thunk[W: WsH2Handler](addr: Int) -> None:
    Pool[W].free(addr)


def _ws_h2_clone_thunk[W: WsH2Handler](addr: Int) raises -> Int:
    return Pool[W].alloc_move(Pool[W].get_ptr(addr)[].copy())


struct WsH2Hooks(Copyable):
    """Opaque, non-owning boxed WS-over-h2 handler + its thunks.

    Carries the heap address of the boxed ``W`` and its monomorphised
    thunks so the non-generic reactor handle can invoke ``W``'s methods
    without knowing its type. The address is owned by the ``serve`` call
    that created it (:func:`make_ws_h2_hooks`); copies threaded to
    connection handles are non-owning -- only the owner runs
    ``destroy_thunk``.
    """

    var addr: Int
    var open_thunk: _WsOpenThunk
    var msg_thunk: _WsMsgThunk
    var close_thunk: _WsCloseThunk
    var destroy_thunk: _WsDestroyThunk
    var clone_thunk: _WsCloneThunk

    def __init__(
        out self,
        addr: Int,
        open_thunk: _WsOpenThunk,
        msg_thunk: _WsMsgThunk,
        close_thunk: _WsCloseThunk,
        destroy_thunk: _WsDestroyThunk,
        clone_thunk: _WsCloneThunk,
    ):
        self.addr = addr
        self.open_thunk = open_thunk
        self.msg_thunk = msg_thunk
        self.close_thunk = close_thunk
        self.destroy_thunk = destroy_thunk
        self.clone_thunk = clone_thunk

    def clone(self) raises -> Self:
        """Hooks over a fresh boxed copy of the handler (one per worker);
        the caller destroys it."""
        var out = self.copy()
        out.addr = self.clone_thunk(self.addr)
        return out^


def make_ws_h2_hooks[W: WsH2Handler](var handler: W) raises -> WsH2Hooks:
    """Box ``handler`` on the heap and return its :class:`WsH2Hooks`.

    The caller owns the returned hooks' allocation and MUST run
    ``hooks.destroy_thunk(hooks.addr)`` exactly once after the serving
    loop exits.
    """
    var addr = Pool[W].alloc_move(handler^)
    return WsH2Hooks(
        addr=addr,
        open_thunk=_ws_h2_open_thunk[W],
        msg_thunk=_ws_h2_msg_thunk[W],
        close_thunk=_ws_h2_close_thunk[W],
        destroy_thunk=_ws_h2_destroy_thunk[W],
        clone_thunk=_ws_h2_clone_thunk[W],
    )
