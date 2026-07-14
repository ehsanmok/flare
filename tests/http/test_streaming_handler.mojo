"""K1 end-to-end: stream a Response through the normal Handler path.

A forked HttpServer serves a Handler that returns ``stream_response`` (a
Response carrying a ChunkSource). The reactor emits
``Transfer-Encoding: chunked`` headers and pulls the source chunk by
chunk on writable edges. The parent client reads the response and
de-chunks it, asserting the reassembled body and the chunked framing --
proving streaming works through ``HttpServer.serve(handler)`` (not just
the raw StreamHandler path).
"""

from std.collections import Optional
from std.testing import assert_true, assert_equal

from flare.http import HttpServer, Handler, Request, Response
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response import stream_response
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


struct _CountSource(ChunkSource, Movable):
    """Yields ``count`` chunks ("chunk0".."chunkN-1"), then None."""

    var count: Int
    var i: Int

    def __init__(out self, count: Int):
        self.count = count
        self.i = 0

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.i >= self.count:
            return Optional[List[UInt8]]()
        var s = String("chunk") + String(self.i)
        self.i += 1
        var out = List[UInt8]()
        for b in s.as_bytes():
            out.append(b)
        return Optional[List[UInt8]](out^)


@fieldwise_init
struct _StreamGreeter(Copyable, Handler, Movable):
    def serve(self, req: Request) raises -> Response:
        var resp = stream_response[_CountSource](_CountSource(3))
        resp.headers.set("Content-Type", "text/plain")
        return resp^


def _read_until_terminator(mut s: TcpStream, max_ms: Int) raises -> String:
    """Read the whole chunked response (until the ``0\\r\\n\\r\\n``
    terminator appears) or the ms budget expires."""
    var acc = String("")
    var waited = 0
    var buf = List[UInt8](capacity=2048)
    buf.resize(2048, 0)
    while waited < max_ms:
        var n = s.read(buf.unsafe_ptr(), 2048)
        if n > 0:
            acc += String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])
            if acc.find("0\r\n\r\n") != -1:
                return acc^
        else:
            break
    return acc^


def _hex_to_int(s: String) -> Int:
    var acc = 0
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[i])
        var d = -1
        if c >= 48 and c <= 57:
            d = c - 48
        elif c >= 97 and c <= 102:
            d = c - 97 + 10
        elif c >= 65 and c <= 70:
            d = c - 65 + 10
        if d < 0:
            break
        acc = acc * 16 + d
    return acc


def _dechunk(body: String) -> String:
    """De-chunk an RFC 9112 sec 7.1 chunked body (ASCII payloads)."""
    var acc = String("")
    var i = 0
    var n = body.byte_length()
    var bytes = body.as_bytes()
    while i < n:
        # size line up to CRLF
        var j = i
        while j + 1 < n and not (bytes[j] == 13 and bytes[j + 1] == 10):
            j += 1
        var size = _hex_to_int(String(unsafe_from_utf8=bytes[i:j]))
        i = j + 2
        if size == 0:
            break
        acc += String(unsafe_from_utf8=bytes[i : i + size])
        i += size + 2  # skip chunk + CRLF
    return acc^


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_StreamGreeter())
        except:
            pass
        exit()

    usleep(250_000)

    var c = TcpStream.connect(SocketAddr.localhost(port))
    var req = String("GET /stream HTTP/1.1\r\nHost: t\r\n\r\n")
    _ = c.write(req.as_bytes())
    var resp = _read_until_terminator(c, 3000)
    c.close()

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    # Chunked framing present, no Content-Length.
    assert_true(
        resp.find("Transfer-Encoding: chunked") != -1,
        "expected chunked framing, got: " + resp,
    )
    assert_true(
        resp.find("Content-Length") == -1,
        "streamed response must not carry Content-Length",
    )
    # Split headers from body and de-chunk.
    var sep = resp.find("\r\n\r\n")
    assert_true(sep != -1, "no header terminator in response")
    var body = String(
        unsafe_from_utf8=resp.as_bytes()[sep + 4 : resp.byte_length()]
    )
    var decoded = _dechunk(body)
    assert_equal(decoded, "chunk0chunk1chunk2")
    print("test_streaming_handler: passed (chunked stream via Handler)")
