"""End-to-end HTTPS/1.1 tests for the Phase-4 ``serve_tls`` path.

Drives a real TLS handshake + HTTP/1.1 exchange between two flare
components via ``fork(2)``:

  - Child: the server side -- accepts one connection and runs
    :func:`flare.http.tls_server.handle_tls_h1_connection` (the exact
    driver :meth:`HttpServer.serve_tls` loops over), built on the
    non-blocking :class:`flare.http._reactor.tls_conn_handle.TlsConnHandle`.
  - Parent: the blocking :class:`flare.tls.TlsStream` client, which
    connects with the self-signed test CA trusted, issues an HTTP/1.1
    request, reads the full response, and asserts on it.

Covers both response shapes:

  - Buffered (``Content-Length``) round-trip through ``SSL_write``.
  - Streaming (``Transfer-Encoding: chunked``) round-trip: a
    ``stream_response`` handler emitted chunk-by-chunk as ciphertext.

Plus a construction smoke test for :meth:`HttpServer.bind_tls`.
"""

from std.testing import assert_true, TestSuite
from std.memory import stack_allocation

from flare.utils import exit, fork, usleep, waitpid
from flare.net import SocketAddr, IpAddr
from flare.tcp import TcpListener
from flare.tls import TlsConfig, TlsStream
from flare.tls._server_ffi import ServerCtx
from flare.http._reactor.tls_conn_handle import TlsConnHandle
from flare.http.tls_server import handle_tls_h1_connection
from flare.http.server import HttpServer, ServerConfig
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response, Status, stream_response
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel


comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


@fieldwise_init
struct _ListSource(ChunkSource, Copyable, Movable):
    """Yields a fixed list of chunks, then end-of-stream."""

    var chunks: List[List[UInt8]]
    var idx: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.idx >= len(self.chunks):
            return None
        var out = self.chunks[self.idx].copy()
        self.idx += 1
        return out^


@fieldwise_init
struct _HelloHandler(Handler, Movable):
    """Buffered handler: returns a fixed body."""

    def serve(self, req: Request) raises -> Response:
        return Response(Status.OK, body=_bytes("hello over tls"))


@fieldwise_init
struct _StreamHandler(Handler, Movable):
    """Streaming handler: returns a chunked body via ``stream_response``."""

    def serve(self, req: Request) raises -> Response:
        var chunks = List[List[UInt8]]()
        chunks.append(_bytes("Hello, "))
        chunks.append(_bytes("streamed "))
        chunks.append(_bytes("world!"))
        var src = _ListSource(chunks^, 0)
        return stream_response(src^)


def _read_all(mut stream: TlsStream) -> String:
    """Read the whole response until the server closes the connection."""
    var acc = List[UInt8]()
    var tmp = stack_allocation[2048, UInt8]()
    while True:
        var n: Int
        try:
            n = stream.read(tmp, 2048)
        except:
            break
        if n <= 0:
            break
        for i in range(n):
            acc.append(tmp[i])
    return String(unsafe_from_utf8=Span[UInt8, _](acc))


def _serve_one[
    H: Handler
](listener: TcpListener, ctx: ServerCtx, var handler: H) -> None:
    """Child: accept one connection, drive it, exit. Never returns."""
    try:
        var stream = listener.accept()
        var conn = TlsConnHandle(stream^, ctx)
        handle_tls_h1_connection(conn, ServerConfig(), handler)
        _ = conn^
    except:
        pass
    exit()


def test_https_h1_buffered_roundtrip() raises:
    """A TLS-terminated HTTP/1.1 GET returns the handler's buffered body."""
    var ctx = ServerCtx.new(_SERVER_CRT, _SERVER_KEY)
    var listener = TcpListener.bind(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0))
    )
    var port = Int(listener.local_addr().port)

    var pid = fork()
    if pid == 0:
        _serve_one(listener, ctx, _HelloHandler())
        return

    usleep(60000)
    var cfg = TlsConfig(ca_bundle=_CA_CRT)
    var stream = TlsStream.connect("localhost", UInt16(port), cfg)
    var req = _bytes(
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    stream.write_all(Span[UInt8, _](req))
    var resp = _read_all(stream)
    stream.close()

    assert_true("200" in resp, "expected 200 status, got: " + resp)
    assert_true("hello over tls" in resp, "expected handler body, got: " + resp)
    assert_true(
        "Content-Length:" in resp, "buffered response must set Content-Length"
    )
    waitpid(pid)


def test_https_h1_streaming_roundtrip() raises:
    """A streaming handler is delivered chunked over TLS."""
    var ctx = ServerCtx.new(_SERVER_CRT, _SERVER_KEY)
    var listener = TcpListener.bind(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0))
    )
    var port = Int(listener.local_addr().port)

    var pid = fork()
    if pid == 0:
        _serve_one(listener, ctx, _StreamHandler())
        return

    usleep(60000)
    var cfg = TlsConfig(ca_bundle=_CA_CRT)
    var stream = TlsStream.connect("localhost", UInt16(port), cfg)
    var req = _bytes(
        "GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    stream.write_all(Span[UInt8, _](req))
    var resp = _read_all(stream)
    stream.close()

    assert_true(
        "Transfer-Encoding: chunked" in resp,
        "streaming response must be chunked, got: " + resp,
    )
    assert_true("Hello, " in resp, "missing first chunk, got: " + resp)
    assert_true("streamed " in resp, "missing second chunk, got: " + resp)
    assert_true("world!" in resp, "missing last chunk, got: " + resp)
    # The last-chunk terminator must be present.
    assert_true("0\r\n\r\n" in resp, "missing chunked terminator")
    waitpid(pid)


def test_bind_tls_constructs() raises:
    """``HttpServer.bind_tls`` loads the cert/key and stashes a context
    without serving; drop must free it cleanly."""
    var alpn = List[String]()
    alpn.append("http/1.1")
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=alpn^,
    )
    var addr = srv.local_addrs()
    assert_true(len(addr) == 1, "one bound address expected")
    assert_true(addr[0].port > 0, "ephemeral port must be assigned")


def main() raises:
    print("=" * 60)
    print("test_https_server.mojo — HTTPS/1.1 over the TLS reactor primitive")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
