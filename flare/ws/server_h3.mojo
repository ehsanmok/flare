"""Server-side WebSocket over HTTP/3 (RFC 9220).

The HTTP/3 counterpart of :mod:`flare.ws.server_h2`: a client opens a
WebSocket with an extended CONNECT (``:protocol: websocket``) request
stream, the server answers 200 without ending the stream, and the
WebSocket frames ride DATA frames on it both ways. The handler shape is
the h2 sidecar's: edge-driven ``on_open`` / ``on_message`` /
``on_close`` over a per-tunnel :class:`WsOverH3ServerStream`, attached
with :meth:`flare.http.HttpServer.attach_ws_h3`.
"""

from .frame import (
    DEFAULT_MAX_FRAME_BYTES,
    WS_TOO_BIG_MARKER,
    WsCloseCode,
    WsFrame,
    WsOpcode,
)
from .server_h2 import pull_client_frame
from ..http.response import Response
from ..quic.server import Http3Tunnel, QuicListener
from ..runtime.pool import Pool


struct WsOverH3ServerStream(Copyable):
    """One WebSocket tunnel on an HTTP/3 stream. Outbound frames are
    unmasked (RFC 6455 sec 5.3) and queued on the stream; inbound ones
    must be masked."""

    var tunnel: Http3Tunnel
    var read_buffer: List[UInt8]
    var closed: Bool
    var max_frame_size: Int
    """Largest frame payload accepted; a larger one is answered with
    CLOSE 1009 and ends the tunnel."""

    def __init__(out self, tunnel: Http3Tunnel, var initial: List[UInt8]):
        self.tunnel = tunnel
        self.read_buffer = initial^
        self.closed = False
        self.max_frame_size = DEFAULT_MAX_FRAME_BYTES

    def send_frame(
        mut self, mut listener: QuicListener, frame: WsFrame
    ) raises -> None:
        """Queue ``frame`` on the tunnel; a CLOSE frame ends it."""
        if self.closed:
            raise Error("WsOverH3ServerStream: send on closed stream")
        var zero = SIMD[DType.uint8, 4](0, 0, 0, 0)
        var wire = frame.encode_with_key(False, zero)
        if not listener.send_http3_tunnel(self.tunnel, Span[UInt8, _](wire)):
            self.closed = True
            raise Error("WsOverH3ServerStream: tunnel closed")
        if frame.opcode == WsOpcode.CLOSE:
            self.closed = True

    def try_pull_frame(
        mut self, mut listener: QuicListener
    ) raises -> Optional[WsFrame]:
        """Decode at most one client frame from what has arrived;
        ``None`` until a whole frame is buffered. A CLOSE is answered
        with a CLOSE (RFC 6455 sec 5.5.1) before it is returned."""
        self.read_buffer.extend(
            Span[UInt8, _](listener.take_http3_tunnel(self.tunnel))
        )
        try:
            var got = pull_client_frame(self.read_buffer, self.max_frame_size)
            if got and got.value().opcode == WsOpcode.CLOSE:
                self.close(listener)
            return got^
        except e:
            if WS_TOO_BIG_MARKER in String(e):
                try:
                    self.close(listener, WsCloseCode.MESSAGE_TOO_BIG)
                except:
                    pass
            self.closed = True
            raise e^

    def is_closed(imm self) -> Bool:
        return self.closed

    def close(
        mut self,
        mut listener: QuicListener,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises -> None:
        """Send a CLOSE frame; the tunnel ends once it is sent."""
        if self.closed:
            return
        self.send_frame(listener, WsFrame.close(code, reason))


trait WsH3Handler(Copyable, Deinitable):
    """Edge-driven handler for WebSocket-over-HTTP/3 tunnels, shared by
    every tunnel on the server like :trait:`flare.ws.WsH2Handler`."""

    def on_open(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises -> None:
        """Called once when a tunnel is accepted."""
        ...

    def on_message(
        mut self,
        mut carrier: WsOverH3ServerStream,
        mut listener: QuicListener,
        frame: WsFrame,
    ) raises -> None:
        """Called per decoded client frame."""
        ...

    def on_close(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises -> None:
        """Called once when the tunnel ends, whichever side ended it."""
        ...


# Type erasure, as in server_h2: the HTTP/3 serve loop is generic over
# the HTTP handler only, so the sidecar travels as a boxed address and
# monomorphised thunks.

comptime _OpenThunk = def(
    Int, mut WsOverH3ServerStream, mut QuicListener
) raises thin -> None
comptime _MsgThunk = def(
    Int, mut WsOverH3ServerStream, mut QuicListener, WsFrame
) raises thin -> None
comptime _DestroyThunk = def(Int) thin -> None


def _open_thunk[
    W: WsH3Handler
](addr: Int, mut c: WsOverH3ServerStream, mut l: QuicListener) raises:
    Pool[W].get_ptr(addr)[].on_open(c, l)


def _msg_thunk[
    W: WsH3Handler
](
    addr: Int, mut c: WsOverH3ServerStream, mut l: QuicListener, f: WsFrame
) raises:
    Pool[W].get_ptr(addr)[].on_message(c, l, f)


def _close_thunk[
    W: WsH3Handler
](addr: Int, mut c: WsOverH3ServerStream, mut l: QuicListener) raises:
    Pool[W].get_ptr(addr)[].on_close(c, l)


def _destroy_thunk[W: WsH3Handler](addr: Int):
    Pool[W].free(addr)


struct WsH3Hooks(Copyable):
    """A boxed :trait:`WsH3Handler` and its thunks. Copies are
    non-owning; the owner runs ``destroy`` once."""

    var addr: Int
    var open: _OpenThunk
    var msg: _MsgThunk
    var close: _OpenThunk
    var destroy: _DestroyThunk

    def __init__(
        out self,
        addr: Int,
        open: _OpenThunk,
        msg: _MsgThunk,
        close: _OpenThunk,
        destroy: _DestroyThunk,
    ):
        self.addr = addr
        self.open = open
        self.msg = msg
        self.close = close
        self.destroy = destroy


def make_ws_h3_hooks[W: WsH3Handler](var handler: W) raises -> WsH3Hooks:
    """Box ``handler``; the caller runs ``hooks.destroy(hooks.addr)``
    once after the serve loop exits."""
    return WsH3Hooks(
        Pool[W].alloc_move(handler^),
        _open_thunk[W],
        _msg_thunk[W],
        _close_thunk[W],
        _destroy_thunk[W],
    )


def ws_h3_accept(
    hooks: WsH3Hooks,
    mut listener: QuicListener,
    mut tunnels: List[WsOverH3ServerStream],
) raises:
    """Take every extended CONNECT stream that has arrived: a WebSocket
    one (``:protocol: websocket``, ``sec-websocket-version: 13``, RFC
    9220 sec 3 and RFC 8441 sec 5) becomes a tunnel and gets
    ``on_open``; any other is refused (400 malformed, 501 another
    protocol) and its stream ends. Other requests are left for the
    HTTP handler."""
    for slot in listener.ready_slots():
        var ready = listener.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var sid = ready[i]
            if not listener.is_http3_tunnel_request(slot, sid):
                continue
            var status = 400
            try:
                var req = listener.take_http3_request(slot, sid)
                if req.headers.get(":protocol") != "websocket":
                    status = 501
                elif req.headers.get("sec-websocket-version") == "13":
                    var early = List[UInt8]()
                    swap(early, req.body)
                    var c = WsOverH3ServerStream(
                        listener.open_http3_tunnel(slot, sid), early^
                    )
                    hooks.open(hooks.addr, c, listener)
                    tunnels.append(c^)
                    continue
            except:
                pass
            listener.emit_http3_response(slot, sid, Response(status=status))


def ws_h3_dispatch(
    hooks: WsH3Hooks,
    mut listener: QuicListener,
    mut tunnels: List[WsOverH3ServerStream],
) raises:
    """Hand each tunnel's arrived frames to ``on_message``; a tunnel
    whose CLOSE went out, whose peer ended or reset it, or that sent a
    bad frame gets ``on_close`` and is ended and dropped."""
    var i = 0
    while i < len(tunnels):
        ref c = tunnels[i]
        while not c.closed:
            var f: Optional[WsFrame]
            try:
                f = c.try_pull_frame(listener)
            except:
                break  # the carrier queued its CLOSE, if one applies
            if not f:
                break
            hooks.msg(hooks.addr, c, listener, f.take())
        if c.closed or not listener.http3_tunnel_open(c.tunnel):
            try:
                hooks.close(hooks.addr, c, listener)
            except:
                pass
            listener.close_http3_tunnel(c.tunnel)
            _ = tunnels.pop(i)
        else:
            i += 1
