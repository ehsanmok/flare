"""Streaming response-body download over HTTP/1.1 with TLS.

The generic get_streaming entry point accepts HTTPS; get_streaming_tls
remains an HTTPS-only compatibility wrapper. H2 negotiation is exercised
separately in test_client_stream_response.

Asserts the property that matters for a streaming reader: the bytes
arrive intact *and* no single pull exceeds the caller's bound, which is
what distinguishes streaming from buffering-then-slicing.

Both response framings a server actually produces are covered:
Content-Length (buffered handler) and chunked (``stream_response``).
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import HttpClient, HttpServer, Request, Response, ok
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response import Status, stream_response
from flare.net import IpAddr, SocketAddr
from flare.tls import TlsConfig
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"

comptime _BODY_BYTES: Int = 256 * 1024
comptime _PULL_CAP: Int = 4096
comptime _STREAM_CHUNKS: Int = 64
comptime _STREAM_CHUNK_BYTES: Int = 1024


def _pattern(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(97 + (i % 26)))
    return out^


@fieldwise_init
struct _Chunks(ChunkSource, Copyable, Movable):
    var remaining: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.remaining <= 0:
            return None
        self.remaining -= 1
        return _pattern(_STREAM_CHUNK_BYTES)


def _handler(req: Request) raises -> Response:
    if req.url == "/stream":
        return stream_response(_Chunks(_STREAM_CHUNKS))
    return Response(Status.OK, body=_pattern(_BODY_BYTES))


def _alpn_h1() -> List[String]:
    var a = List[String]()
    a.append("http/1.1")
    return a^


def _drain(port: UInt16, path: String) raises -> Tuple[Int, Int]:
    """Pull the whole body in bounded chunks.

    Returns ``(total_bytes, largest_single_pull)``.
    """
    var url = String("https://localhost:") + String(Int(port)) + path
    with HttpClient(TlsConfig(ca_bundle=_CA_CRT)) as c:
        var dl = c.get_streaming(url)
        var total = 0
        var largest = 0
        while True:
            var chunk = dl.read_chunk(_PULL_CAP)
            if len(chunk) == 0:
                break
            total += len(chunk)
            if len(chunk) > largest:
                largest = len(chunk)
        return (total, largest)


def test_https_streaming_download_content_length() raises:
    """A buffered HTTPS response is pulled in bounded chunks."""
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_handler)
        except:
            pass
        exit()
    usleep(300000)

    var total = 0
    var largest = 0
    try:
        total, largest = _drain(port, "/big")
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(total, _BODY_BYTES)
    assert_true(
        largest <= _PULL_CAP,
        "a pull returned more than the cap, so this is not streaming: "
        + String(largest),
    )


def test_https_streaming_download_chunked() raises:
    """A chunked HTTPS response is pulled in bounded chunks."""
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=_alpn_h1(),
    )
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_handler)
        except:
            pass
        exit()
    usleep(300000)

    var total = 0
    var largest = 0
    try:
        total, largest = _drain(port, "/stream")
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(total, _STREAM_CHUNKS * _STREAM_CHUNK_BYTES)
    assert_true(largest <= _PULL_CAP, "pull exceeded the cap")


def test_get_streaming_tls_rejects_cleartext() raises:
    """The compatibility entry point remains HTTPS-only."""
    var raised = False
    var msg = String("")
    try:
        with HttpClient() as c:
            _ = c.get_streaming_tls("http://example.invalid/x")
    except e:
        raised = True
        msg = String(e)
    assert_true(raised, "get_streaming_tls must reject cleartext")
    assert_true(
        "https:// only" in msg,
        "the error should name the right entry point; got: " + msg,
    )


def main() raises:
    print("=" * 60)
    print("test_client_stream_download_tls.mojo — HTTPS streaming download")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
