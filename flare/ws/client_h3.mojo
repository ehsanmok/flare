"""Client side of WebSocket over HTTP/3 (RFC 9220).

:class:`WsOverH3Stream` opens an extended CONNECT (``:protocol:
websocket``) request stream on an :class:`flare.http3.Http3ClientConnection`
and carries WebSocket frames in its DATA frames: masked from the client
(RFC 6455 sec 5.3), and refused if the server masks.
"""

from .frame import DEFAULT_MAX_FRAME_BYTES, WsFrame, WsOpcode, _DecodeResult
from ..http3.client import Http3ClientConnection
from ..qpack import QpackHeader
from ..quic.client import _monotonic_ms


struct WsOverH3Stream(Movable):
    var stream_id: UInt64
    var read_buffer: List[UInt8]
    var closed: Bool
    var max_frame_size: Int

    def __init__(out self, stream_id: UInt64):
        self.stream_id = stream_id
        self.read_buffer = List[UInt8]()
        self.closed = False
        self.max_frame_size = DEFAULT_MAX_FRAME_BYTES

    @staticmethod
    def open(
        mut h3: Http3ClientConnection,
        authority: String,
        path: String,
        timeout_ms: Int = 5000,
    ) raises -> WsOverH3Stream:
        """Open the tunnel: wait for the server's SETTINGS, which must
        enable extended CONNECT (RFC 9220 sec 3), send the CONNECT and
        require a 200."""
        h3.open_streams()
        var deadline = _monotonic_ms() + UInt64(timeout_ms)
        while not h3.peer_settings and _monotonic_ms() < deadline:
            _ = h3.poll_responses(10)
        if not h3.peer_connect_protocol:
            raise Error(
                "ws over h3: the server does not enable extended CONNECT"
            )
        var headers = List[QpackHeader]()
        headers.append(QpackHeader("sec-websocket-version", "13"))
        var sid = h3.send_request_open(
            "CONNECT", "https", authority, path, headers, protocol="websocket"
        )
        while not h3.head_ready(sid):
            if _monotonic_ms() >= deadline:
                raise Error("ws over h3: no response to the CONNECT")
            _ = h3.poll_responses(10)
        var status = h3.stream_status(sid)
        if status != 200:
            raise Error("ws over h3: CONNECT answered " + String(status))
        return WsOverH3Stream(sid)

    def send_frame(
        mut self, mut h3: Http3ClientConnection, frame: WsFrame
    ) raises:
        """Send ``frame`` masked; a CLOSE frame ends our sending."""
        if self.closed:
            raise Error("ws over h3: send on a closed tunnel")
        h3.send_request_body(self.stream_id, frame.encode(mask=True), False)
        if frame.opcode == WsOpcode.CLOSE:
            self.closed = True

    def try_pull_frame(
        mut self, mut h3: Http3ClientConnection, timeout_ms: Int = 100
    ) raises -> Optional[WsFrame]:
        """The next server frame, or ``None`` until one has arrived."""
        if not self._has_frame():
            var chunk = h3.poll_body(self.stream_id, timeout_ms)
            self.read_buffer.extend(Span[UInt8, _](chunk.data))
        if len(self.read_buffer) == 0:
            return None
        var dr: _DecodeResult
        try:
            dr = WsFrame.decode_one(
                Span[UInt8, _](self.read_buffer),
                max_payload=self.max_frame_size,
            )
        except e:
            var msg = String(e)
            if msg.find("decode_one: need") >= 0 or msg.find("truncated") >= 0:
                return None
            raise e^
        var consumed = dr.consumed
        var got = dr^.take_frame()
        if got.masked:
            raise Error("ws over h3: the server masked a frame")
        self.read_buffer = List[UInt8](
            Span[UInt8, _](self.read_buffer)[consumed:]
        )
        return got^

    def _has_frame(self) -> Bool:
        try:
            _ = WsFrame.decode_one(
                Span[UInt8, _](self.read_buffer),
                max_payload=self.max_frame_size,
            )
            return True
        except:
            return False

    def close(
        mut self, mut h3: Http3ClientConnection, code: UInt16 = 1000
    ) raises:
        """Send CLOSE and end the stream."""
        if not self.closed:
            self.send_frame(h3, WsFrame.close(code, ""))
        h3.send_request_body(self.stream_id, List[UInt8](), True)
