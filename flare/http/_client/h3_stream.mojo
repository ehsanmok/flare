"""Exclusive-connection HTTP/3 response body reader."""

from ...http3.client import Http3ClientConnection
from ...net import NetworkError
from ...quic.client import _monotonic_ms
from ..headers import HeaderMap


struct Http3Download(Movable):
    var conn: Http3ClientConnection
    var sid: UInt64
    var status: Int
    var headers: HeaderMap
    var trailers: HeaderMap
    var _pending: List[UInt8]
    var _pos: Int
    var _done: Bool
    var _timeout_ms: Int

    def __init__(
        out self, var conn: Http3ClientConnection, sid: UInt64, timeout_ms: Int
    ) raises:
        self.conn = conn^
        self.sid = sid
        self.status = 0
        self.headers = HeaderMap()
        self.trailers = HeaderMap()
        self._pending = List[UInt8]()
        self._pos = 0
        self._done = False
        self._timeout_ms = timeout_ms
        var start = _monotonic_ms()
        while not self.conn.head_ready(sid):
            self._check_timeout(start)
            _ = self.conn.poll_responses(self._poll_timeout())
        self.status = self.conn.stream_status(sid)
        var fields = self.conn.stream_headers(sid)
        for field in fields:
            self.headers.append(field.name, field.value)

    def _poll_timeout(self) -> Int:
        return min(100, self._timeout_ms) if self._timeout_ms > 0 else 100

    def _check_timeout(self, start: UInt64) raises:
        if self._timeout_ms > 0 and _monotonic_ms() - start >= UInt64(
            self._timeout_ms
        ):
            raise NetworkError("HTTP/3 stream: read timed out")

    def read_chunk(mut self, max_bytes: Int) raises -> List[UInt8]:
        var start = _monotonic_ms()
        while self._pos == len(self._pending):
            if self._done:
                return List[UInt8]()
            self._check_timeout(start)
            var chunk = self.conn.poll_body(self.sid, self._poll_timeout())
            var finished = chunk.done
            self._pending = chunk.data^
            chunk.data = List[UInt8]()
            self._pos = 0
            if finished:
                var final = self.conn.take_if_complete(self.sid)
                if not final:
                    raise NetworkError("HTTP/3 stream: missing final response")
                var response = final.take()
                for field in response.trailers:
                    self.trailers.append(field.name, field.value)
                self._done = True
            if len(self._pending) > 0:
                break
        var count = min(max_bytes, len(self._pending) - self._pos)
        var out = List[UInt8](
            Span(self._pending)[self._pos : self._pos + count]
        )
        self._pos += count
        return out^

    def done(self) -> Bool:
        return self._done and self._pos == len(self._pending)

    def close(mut self):
        try:
            if not self._done:
                self.conn.quic.cancel_stream(self.sid)
            self.conn.quic.shutdown()
        except:
            self.conn.quic.close()
        self._done = True
