"""Exclusive-connection HTTP/2 response body reader."""

from ...http2.client import Http2ClientConnection
from ...net import NetworkError
from ..headers import HeaderMap
from .h2_transport import _H2Transport


struct Http2Download(Movable):
    var transport: _H2Transport
    var conn: Http2ClientConnection
    var sid: Int
    var status: Int
    var headers: HeaderMap
    var trailers: HeaderMap
    var _pending: List[UInt8]
    var _pos: Int
    var _done: Bool

    def __init__(
        out self,
        var transport: _H2Transport,
        var conn: Http2ClientConnection,
        sid: Int,
    ) raises:
        self.transport = transport^
        self.conn = conn^
        self.sid = sid
        self.status = 0
        self.headers = HeaderMap()
        self.trailers = HeaderMap()
        self._pending = List[UInt8]()
        self._pos = 0
        self._done = False
        self.conn.enable_response_streaming(sid)
        self.flush()
        while not self.conn.headers_received(sid):
            self._check_error()
            self.pump()
        self._check_error()
        var fields = self.conn.initial_response_headers(sid)
        for field in fields:
            if field.name == ":status":
                self.status = Int(field.value)
            else:
                self.headers.append(field.name, field.value)
        if self.status < 200:
            raise NetworkError("HTTP/2 stream: missing final response head")

    def flush(mut self) raises:
        var wire = self.conn.drain()
        if len(wire) > 0:
            self.transport.write_all(Span(wire))

    def pump(mut self) raises:
        # A previous body drain may have queued receive credit.
        self.flush()
        var scratch = List[UInt8]()
        scratch.resize(16384, 0)
        var n = self.transport.read(scratch.unsafe_ptr(), len(scratch))
        if n == 0:
            raise NetworkError(
                "HTTP/2 stream: connection closed before END_STREAM"
            )
        self.conn.feed(Span(scratch)[:n])
        self.flush()

    def _check_error(self) raises:
        if self.conn.conn.goaway_sent:
            raise NetworkError("HTTP/2 stream: connection protocol error")
        var error = self.conn.stream_error(self.sid)
        if error:
            raise NetworkError("HTTP/2 stream reset: " + String(error.value()))

    def read_chunk(mut self, max_bytes: Int) raises -> List[UInt8]:
        while self._pos == len(self._pending):
            if self._done:
                return List[UInt8]()
            self._check_error()
            self._pending = self.conn.drain_body(self.sid)
            self._pos = 0
            if self.conn.stream_ended(self.sid):
                var fields = self.conn.response_trailers(self.sid)
                for field in fields:
                    self.trailers.append(field.name, field.value)
                self._done = True
                self.conn.discard_stream(self.sid)
            if len(self._pending) > 0:
                break
            if not self._done:
                self.pump()
        var count = min(max_bytes, len(self._pending) - self._pos)
        var out = List[UInt8](
            Span(self._pending)[self._pos : self._pos + count]
        )
        self._pos += count
        return out^

    def done(self) -> Bool:
        return self._done and self._pos == len(self._pending)

    def close(mut self):
        if not self._done:
            self.conn.cancel_stream(self.sid)
            try:
                self.flush()
            except:
                pass
        self._done = True
        self.transport.close()
