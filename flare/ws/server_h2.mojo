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


struct WsOverH2ServerStream(Movable):
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
