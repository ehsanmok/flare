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

from .frame import WsCloseCode, WsFrame, WsOpcode, _DecodeResult
from ..http2.server import Http2Connection
from ..runtime.pool import Pool


struct WsOverH2ServerStream(Copyable, Movable):
    """Stream-keyed server adapter turning one h2 stream into a WS tunnel.

    Owns the per-stream receive buffer. Unlike the client carrier it does
    NOT mask outbound frames (a server MUST NOT mask, RFC 6455 5.3) and it
    writes through :meth:`Http2Connection.queue_stream_data` /
    :meth:`Http2Connection.drain_stream_data`.
    """

    var stream_id: Int
    var read_buffer: List[UInt8]
    var closed: Bool

    def __init__(out self, stream_id: Int):
        self.stream_id = stream_id
        self.read_buffer = List[UInt8]()
        self.closed = False

    def send_frame(
        mut self, mut conn: Http2Connection, frame: WsFrame
    ) raises -> None:
        """Encode ``frame`` UNMASKED and queue it as DATA on this stream.
        A CLOSE frame ends the tunnel (subsequent sends raise)."""
        if self.closed:
            raise Error("WsOverH2ServerStream: send on closed stream")
        var zero = SIMD[DType.uint8, 4](0, 0, 0, 0)
        var wire = frame.encode_with_key(False, zero)
        _ = conn.queue_stream_data(self.stream_id, Span[UInt8, _](wire))
        if frame.opcode == WsOpcode.CLOSE:
            self.closed = True

    def try_pull_frame(
        mut self, mut conn: Http2Connection
    ) raises -> Optional[WsFrame]:
        """Drain inbound DATA and decode at most one WS frame; ``None``
        when the buffer doesn't yet hold a complete frame. Client frames
        are masked; :meth:`WsFrame.decode_one` unmasks them."""
        var data = conn.drain_stream_data(self.stream_id)
        for i in range(len(data)):
            self.read_buffer.append(data[i])
        if len(self.read_buffer) == 0:
            return None
        var dr: _DecodeResult
        try:
            dr = WsFrame.decode_one(Span[UInt8, _](self.read_buffer))
        except e:
            var msg = String(e)
            if msg.find("decode_one: need") >= 0 or msg.find("truncated") >= 0:
                return None
            raise e^
        var consumed = dr.consumed
        var got = dr^.take_frame()
        if got.opcode == WsOpcode.CLOSE:
            self.closed = True
        var rest = List[UInt8]()
        for i in range(consumed, len(self.read_buffer)):
            rest.append(self.read_buffer[i])
        self.read_buffer = rest^
        return got^

    def is_closed(read self) -> Bool:
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


trait WsH2Handler(Copyable, ImplicitlyDestructible, Movable):
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


struct WsH2Hooks(Copyable, Movable):
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

    def __init__(
        out self,
        addr: Int,
        open_thunk: _WsOpenThunk,
        msg_thunk: _WsMsgThunk,
        close_thunk: _WsCloseThunk,
        destroy_thunk: _WsDestroyThunk,
    ):
        self.addr = addr
        self.open_thunk = open_thunk
        self.msg_thunk = msg_thunk
        self.close_thunk = close_thunk
        self.destroy_thunk = destroy_thunk


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
    )
