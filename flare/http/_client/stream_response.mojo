"""Protocol-erased, pull-based HTTP response with exclusive connection ownership."""

from ...runtime.pool import Pool
from ..headers import HeaderMap
from ..error import HttpError
from .download import HttpDownload
from .h2_transport import _H2Transport
from .h2_stream import Http2Download
from .h3_stream import Http3Download


struct HttpStreamResponse(Movable):
    """Final response head plus a bounded, blocking body reader.

    Empty ``read_chunk`` means clean EOS. HTTP transfer framing is removed;
    content encodings remain untouched. Trailers become available at EOS.
    Each response owns one connection; close/drop never returns it to a pool.
    """

    var status: Int
    var reason: String
    var headers: HeaderMap
    var trailers: HeaderMap
    var _kind: Int
    var _addr: Int

    def __init__(out self, var body: HttpDownload[_H2Transport]) raises:
        self.status = body.status
        self.reason = body.reason
        self.headers = body.headers.copy()
        self.trailers = HeaderMap()
        self._kind = 1
        self._addr = Pool[HttpDownload[_H2Transport]].alloc_move(body^)
        if Pool[HttpDownload[_H2Transport]].get_ptr(self._addr)[]._done:
            self.close()

    def __init__(out self, var body: Http2Download) raises:
        self.status = body.status
        self.reason = ""
        self.headers = body.headers.copy()
        self.trailers = HeaderMap()
        self._kind = 2
        self._addr = Pool[Http2Download].alloc_move(body^)

    def __init__(out self, var body: Http3Download) raises:
        self.status = body.status
        self.reason = ""
        self.headers = body.headers.copy()
        self.trailers = HeaderMap()
        self._kind = 3
        self._addr = Pool[Http3Download].alloc_move(body^)

    def __deinit__(deinit self):
        self.close()

    def protocol(self) -> String:
        if self._kind == 2:
            return "h2"
        if self._kind == 3:
            return "h3"
        return "http/1.1"

    def header(self, name: String) -> String:
        return self.headers.get(name)

    def ok(self) -> Bool:
        return 200 <= self.status < 300

    def raise_for_status(self) raises:
        if not self.ok():
            raise HttpError(self.status, self.reason)

    def done(self) -> Bool:
        return self._addr == 0

    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        if max_bytes <= 0:
            raise Error("HTTP stream: max_bytes must be positive")
        if self._addr == 0:
            return List[UInt8]()
        try:
            var out: List[UInt8]
            var ended: Bool
            if self._kind == 1:
                var p = Pool[HttpDownload[_H2Transport]].get_ptr(self._addr)
                out = p[].read_chunk(max_bytes)
                ended = p[]._done
                if ended:
                    self.trailers = p[].trailers.copy()
            elif self._kind == 2:
                var p = Pool[Http2Download].get_ptr(self._addr)
                out = p[].read_chunk(max_bytes)
                ended = p[].done()
                if ended:
                    self.trailers = p[].trailers.copy()
            else:
                var p = Pool[Http3Download].get_ptr(self._addr)
                out = p[].read_chunk(max_bytes)
                ended = p[].done()
                if ended:
                    self.trailers = p[].trailers.copy()
            if ended:
                self.close()
            return out^
        except e:
            self.close()
            raise e^

    def read_all(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Buffer the remaining body. ``max_bytes`` is the pull size, NOT a limit.
        """
        return self._collect(-1, max_bytes)

    def read_all_limited(
        mut self, max_body_bytes: Int, chunk_size: Int = 65536
    ) raises -> List[UInt8]:
        """Buffer at most the limit; exceeding it closes the stream and raises.
        """
        if max_body_bytes < 0:
            raise Error("HTTP stream: body limit must be nonnegative")
        return self._collect(max_body_bytes, chunk_size)

    def _collect(mut self, limit: Int, chunk_size: Int) raises -> List[UInt8]:
        if chunk_size <= 0:
            raise Error("HTTP stream: chunk_size must be positive")
        var out = List[UInt8]()
        while True:
            var cap = chunk_size
            if limit >= 0 and limit - len(out) < cap:
                cap = min(cap, limit - len(out) + 1)
            var chunk = self.read_chunk(cap)
            if len(chunk) == 0:
                return out^
            if limit >= 0 and len(chunk) > limit - len(out):
                self.close()
                raise Error("HTTP stream: body limit exceeded")
            out.extend(chunk^)

    def close(mut self):
        """Release the connection. Safe after EOS, an error, or another close.
        """
        if self._addr == 0:
            return
        if self._kind == 1:
            Pool[HttpDownload[_H2Transport]].free(self._addr)
        elif self._kind == 2:
            Pool[Http2Download].get_ptr(self._addr)[].close()
            Pool[Http2Download].free(self._addr)
        else:
            Pool[Http3Download].get_ptr(self._addr)[].close()
            Pool[Http3Download].free(self._addr)
        self._addr = 0
