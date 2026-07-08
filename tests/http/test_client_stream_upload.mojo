"""Streaming request-body upload over HTTP/1.1.

:meth:`flare.http.HttpClient.send_chunked` streams a request body from
a ``ChunkSource`` using ``Transfer-Encoding: chunked`` without ever
materializing the whole body in memory. This test drives a multi-MB
upload (32 x 64 KiB = 2 MiB) from a generator ``ChunkSource`` against a
forked raw-TCP server that reads the chunked request, decodes it (via
the same ``_decode_chunked`` the client parser uses), and replies with
the total number of decoded body bytes. The assertion that the server
received exactly the bytes the source produced proves the chunked
framing is correct and complete; the source itself only ever holds one
64 KiB chunk at a time, so client memory stays bounded.

(flare's own ``HttpServer`` does not decode chunked *request* bodies --
see ``flare/http/_server/parse.mojo`` -- so this test uses a minimal
raw-TCP decoder server instead.)
"""

from std.collections import Optional
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import HttpClient
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http._client.parse import _decode_chunked
from flare.http.headers import HeaderMap
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _CHUNK_SIZE: Int = 65536
comptime _CHUNK_COUNT: Int = 32


@fieldwise_init
struct _FixedChunks(ChunkSource, Movable):
    """A ``ChunkSource`` yielding ``count`` chunks of ``size`` 'x'
    bytes, then end-of-stream. Holds only one chunk at a time."""

    var remaining: Int
    var size: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.remaining <= 0:
            return Optional[List[UInt8]]()
        var chunk = List[UInt8]()
        chunk.resize(self.size, UInt8(ord("x")))
        self.remaining -= 1
        return Optional[List[UInt8]](chunk^)


def _find_crlf2(raw: List[UInt8]) -> Int:
    """Return the index of the first ``\\r\\n\\r\\n`` in ``raw``, or
    ``-1``."""
    for i in range(len(raw) - 3):
        if (
            raw[i] == 13
            and raw[i + 1] == 10
            and raw[i + 2] == 13
            and raw[i + 3] == 10
        ):
            return i
    return -1


def _ends_with_last_chunk(raw: List[UInt8]) -> Bool:
    """Return True once ``raw`` ends with the chunked terminator
    ``0\\r\\n\\r\\n`` (all upload bytes here are 'x', so this marker is
    unambiguous)."""
    var n = len(raw)
    if n < 5:
        return False
    return (
        raw[n - 5] == UInt8(ord("0"))
        and raw[n - 4] == 13
        and raw[n - 3] == 10
        and raw[n - 2] == 13
        and raw[n - 1] == 10
    )


def _decode_server(var conn: TcpStream) raises:
    """Read one chunked request to completion, decode the body, and
    reply with the decoded byte count as the response body."""
    var raw = List[UInt8]()
    var buf = List[UInt8]()
    buf.resize(16384, UInt8(0))
    while not _ends_with_last_chunk(raw):
        var n = conn.read(buf.unsafe_ptr(), len(buf))
        if n == 0:
            break
        for i in range(n):
            raw.append(buf[i])
    var hdr_end = _find_crlf2(raw)
    var total = 0
    if hdr_end >= 0:
        var trailers = HeaderMap()
        var body = _decode_chunked(raw, hdr_end + 4, trailers)
        total = len(body)
    var payload = String(total)
    var resp = (
        String("HTTP/1.1 200 OK\r\nContent-Length: ")
        + String(payload.byte_length())
        + "\r\nConnection: close\r\n\r\n"
        + payload
    )
    var rb = resp.as_bytes()
    conn.write_all(Span[UInt8, _](rb))
    conn.close()


def test_streamed_upload_round_trips_full_body() raises:
    """A 2 MiB chunked upload arrives byte-complete at the server."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            var conn = listener.accept()
            _decode_server(conn^)
        except:
            pass
        exit()
    usleep(120_000)

    var raised = False
    var status = -1
    var text = String("")
    try:
        var url = String("http://127.0.0.1:") + String(Int(port)) + "/upload"
        var src = _FixedChunks(_CHUNK_COUNT, _CHUNK_SIZE)
        with HttpClient() as c:
            var r = c.send_chunked("POST", url, src)
            status = r.status
            text = r.text()
    except e:
        print("test_streamed_upload raised:", e)
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_true(not raised, "streamed upload raised")
    assert_equal(status, 200)
    assert_equal(text, String(_CHUNK_COUNT * _CHUNK_SIZE))


def main() raises:
    print("=" * 60)
    print("test_client_stream_upload.mojo -- chunked request body")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
