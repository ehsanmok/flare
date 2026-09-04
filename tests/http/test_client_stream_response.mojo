"""Generic streamed-response API across HTTP/1.1 and HTTP/2 wires."""

from std.testing import assert_equal, assert_true, assert_raises, TestSuite
from flare.http import (
    HttpClient,
    HttpServer,
    Request,
    Response,
    BearerAuth,
    ok,
    redirect,
)
from flare.http.response import stream_response
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.reliability import RetryPolicy
from flare.http.redirect_policy import RedirectPolicy
from flare.http.encoding import compress_gzip, decompress_gzip
from flare.net import SocketAddr
from flare.tls import TlsConfig
from flare.testing import fork_server, kill_forked_server
from flare.tcp import TcpListener
from flare.utils import exit, fork


@fieldwise_init
struct Chunks(ChunkSource, Copyable, Movable):
    var left: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.left == 0 or cancel.cancelled():
            return None
        self.left -= 1
        var bytes = List[UInt8]()
        bytes.resize(8192, 97)
        return bytes^


def handler(req: Request) raises -> Response:
    if req.url == "/retry":
        if req.headers.get("Cookie") == "attempt=one":
            return ok("retried")
        var response = Response(503)
        response.headers.set("Set-Cookie", "attempt=one")
        return response^
    if req.url == "/cross":
        return redirect(req.headers.get("X-Destination"))
    if req.url == "/redirect":
        var response = redirect("/echo")
        response.headers.append("Set-Cookie", "session=present")
        return response^
    if req.url == "/echo":
        return ok(
            req.method
            + ":"
            + String(len(req.body))
            + ":"
            + req.headers.get("Authorization")
            + ":"
            + req.headers.get("Accept-Encoding")
            + ":"
            + req.headers.get("Cookie")
        )
    if req.url == "/encoded":
        var original = String("raw-compressed-payload")
        var response = Response(
            200, body=compress_gzip(Span(original.as_bytes()))
        )
        response.headers.set("Content-Encoding", "gzip")
        response.headers.set("Content-Length", String(len(response.body)))
        return response^
    var response = stream_response(Chunks(32))
    response.headers.append("X-Value", "first")
    response.headers.append("X-Value", "second")
    response.trailers.set("x-complete", "yes")
    return response^


def exercise(
    client: HttpClient, protocol: String, stored_auth: Bool = True
) raises:
    var auth = String("Bearer stored") if stored_auth else String(
        "Bearer caller"
    )
    var req = Request(
        method="POST", url="/echo", body=List[UInt8](String("body").as_bytes())
    )
    req.headers.set("Authorization", "Bearer caller")
    req.headers.append("Content-Length", "900")
    req.headers.append("Content-Length", "901")
    var response = client.send_streaming(req)
    assert_equal(response.protocol(), protocol)
    response.raise_for_status()
    var body = response.read_all_limited(1024, 3)
    assert_true(
        String(unsafe_from_utf8=Span(body)).startswith(
            "POST:4:" + auth + ":identity:"
        )
    )
    assert_true(response.done())
    response.close()
    response.close()

    var large = client.get_streaming("/large")
    assert_equal(len(large.headers.get_all("X-Value")), 2)
    var total = 0
    while True:
        var chunk = large.read_chunk(997)
        assert_true(len(chunk) <= 997)
        if len(chunk) == 0:
            break
        for b in chunk:
            assert_equal(b, UInt8(97))
        total += len(chunk)
    assert_equal(total, 32 * 8192)
    # The unified H1 server does not yet emit Response.trailers. H1 trailer
    # reception is exercised with an explicit wire fixture below.
    if protocol != "http/1.1":
        assert_equal(large.trailers.get("x-complete"), "yes")

    var limited = client.get_streaming("/large")
    with assert_raises():
        _ = limited.read_all_limited(12)
    assert_true(limited.done())

    var encoding_request = Request(method="GET", url="/encoded")
    encoding_request.headers.set("Accept-Encoding", "gzip")
    var encoded = client.send_streaming(encoding_request)
    assert_equal(encoded.header("Content-Encoding"), "gzip")
    var raw = encoded.read_all()
    assert_equal(raw[0], UInt8(0x1F))
    assert_equal(raw[1], UInt8(0x8B))
    assert_equal(Int(encoded.header("Content-Length")), len(raw))
    var decoded = decompress_gzip(Span(raw))
    assert_equal(
        String(unsafe_from_utf8=Span(decoded)), "raw-compressed-payload"
    )

    var redirected = client.get_streaming("/redirect")
    body = redirected.read_all()
    assert_true(String(unsafe_from_utf8=Span(body)).endswith("session=present"))


def run_cleartext(prior: Bool, upgrade: Bool) raises:
    var server = HttpServer.bind(SocketAddr.localhost(0))
    var base = "http://127.0.0.1:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, handler)
    try:
        var client = HttpClient(
            BearerAuth("stored"),
            base_url=base,
            timeout_ms=3000,
            prefer_h2c=prior,
            h2c_upgrade=upgrade,
        ).with_cookies()
        exercise(client, "h2" if prior or upgrade else "http/1.1")
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_h1_request_streaming() raises:
    run_cleartext(False, False)


def test_h2_prior_knowledge_request_streaming() raises:
    run_cleartext(True, False)


def test_h2_upgrade_request_streaming() raises:
    run_cleartext(False, True)


def test_h2_tls_request_streaming() raises:
    var server = HttpServer.bind_tls(
        SocketAddr.localhost(0),
        "tests/certs/server.crt",
        "tests/certs/server.key",
        alpn=[String("h2"), String("http/1.1")],
    )
    var base = "https://localhost:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, handler)
    try:
        var client = HttpClient(
            TlsConfig(ca_bundle="tests/certs/ca.crt"),
            base_url=base,
            timeout_ms=3000,
        ).with_cookies()
        exercise(client, "h2", False)
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_returns_before_eof_and_closes_early() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var url = "http://127.0.0.1:" + String(Int(listener.local_addr().port))
    var pid = fork()
    if pid == 0:
        try:
            var socket = listener.accept()
            var buf = List[UInt8]()
            buf.resize(4096, 0)
            _ = socket.read(buf.unsafe_ptr(), len(buf))
            var wire = String(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc"
            )
            socket.write_all(Span(wire.as_bytes()))
            # Withhold framing/EOS until the client closes; read_chunk must
            # still return the three available bytes without timing out.
            _ = socket.read(buf.unsafe_ptr(), len(buf))
        except:
            pass
        exit()
    try:
        var client = HttpClient(timeout_ms=500)
        var response = client.get_streaming(url)
        assert_equal(response.status, 200)
        assert_equal(len(response.read_chunk(3)), 3)
        response.close()
        assert_true(response.done())
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def raw_case(wire: String, broken: Bool) raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var url = "http://127.0.0.1:" + String(Int(listener.local_addr().port))
    var pid = fork()
    if pid == 0:
        try:
            var socket = listener.accept()
            var buf = List[UInt8]()
            buf.resize(4096, 0)
            _ = socket.read(buf.unsafe_ptr(), len(buf))
            socket.write_all(Span(wire.as_bytes()))
            socket.close()
        except:
            pass
        exit()
    try:
        var client = HttpClient(timeout_ms=500)
        var response = client.get_streaming(url)
        if broken:
            with assert_raises():
                _ = response.read_all()
        else:
            assert_equal(response.status, 400)
            with assert_raises():
                response.raise_for_status()
            var body = response.read_all()
            assert_equal(String(unsafe_from_utf8=Span(body)), "abc")
            assert_equal(len(response.trailers.get_all("x-end")), 2)
        assert_true(response.done())
        response.close()
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_h1_public_trailers_and_error_body() raises:
    raw_case(
        (
            "HTTP/1.1 400 Bad Request\r\nTransfer-Encoding:"
            " chunked\r\n\r\n3\r\nabc\r\n0\r\nx-end: one\r\nx-end: two\r\n\r\n"
        ),
        False,
    )


def test_read_error_releases_connection() raises:
    raw_case("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", True)


def test_retry_and_redirect_policy() raises:
    var server = HttpServer.bind(SocketAddr.localhost(0))
    var base = "http://127.0.0.1:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, handler)
    try:
        var retry = RetryPolicy()
        retry.max_attempts = 2
        var client = HttpClient(base_url=base).with_retry(retry).with_cookies()
        var response = client.get_streaming("/retry")
        assert_equal(response.status, 200)
        var bytes = response.read_all()
        assert_equal(String(unsafe_from_utf8=Span(bytes)), "retried")
        var post_client = (
            HttpClient(base_url=base).with_retry(retry).with_cookies()
        )
        var post = post_client.send_streaming(
            Request(method="POST", url="/retry")
        )
        assert_equal(post.status, 503)
        post.close()
        var denied_client = HttpClient(base_url=base).with_redirect_policy(
            RedirectPolicy.deny()
        )
        var denied = denied_client.get_streaming("/redirect")
        assert_equal(denied.status, 302)
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_cross_origin_redirect_strips_auth() raises:
    var first = HttpServer.bind(SocketAddr.localhost(0))
    var second = HttpServer.bind(SocketAddr.localhost(0))
    var base = "http://127.0.0.1:" + String(Int(first.local_addr().port))
    var target = (
        "http://127.0.0.1:" + String(Int(second.local_addr().port)) + "/echo"
    )
    var first_pid = fork_server(first^, handler)
    var second_pid = fork_server(second^, handler)
    try:
        var client = HttpClient(BearerAuth("stored"), base_url=base)
        var req = Request(method="GET", url="/cross")
        req.headers.set("X-Destination", target)
        req.headers.set("Authorization", "Bearer caller")
        var response = client.send_streaming(req)
        var bytes = response.read_all()
        assert_equal(String(unsafe_from_utf8=Span(bytes)), "GET:0::identity:")
    except e:
        kill_forked_server(first_pid)
        kill_forked_server(second_pid)
        raise e^
    kill_forked_server(first_pid)
    kill_forked_server(second_pid)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
