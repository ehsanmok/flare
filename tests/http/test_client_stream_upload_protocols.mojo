"""Unknown-length streamed uploads across HTTP/1.1, HTTP/2, and TLS."""

from std.testing import assert_equal, assert_true, TestSuite
from flare.http import HttpClient, HttpServer, Request, Response, BearerAuth, ok
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.reliability import RetryPolicy
from flare.http2 import (
    Frame,
    FrameType,
    FrameFlags,
    HpackEncoder,
    HpackHeader,
    encode_frame,
)
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


def upload_handler(req: Request) raises -> Response:
    if req.url == "/retry":
        if req.headers.get("Cookie") == "attempt=one":
            return ok("retried")
        var response = Response(503)
        response.headers.set("Set-Cookie", "attempt=one")
        return response^
    return ok(
        req.method
        + ":"
        + String(len(req.body))
        + ":"
        + req.headers.get("Authorization")
        + ":"
        + req.headers.get("Accept-Encoding")
    )


def exercise_upload(client: HttpClient, expected_auth: String) raises:
    var req = Request(method="PUT", url="/echo")
    req.headers.set("Authorization", "Bearer caller")
    var source = Chunks(12)
    var response = client.send_chunked(req, source)
    assert_true(
        response.text().startswith("PUT:98304:" + expected_auth + ":identity")
    )


def test_h1_streamed_upload() raises:
    run_cleartext(False)


def test_h2_prior_knowledge_streamed_upload() raises:
    run_cleartext(True)


def run_cleartext(prior: Bool) raises:
    var server = HttpServer.bind(SocketAddr.localhost(0))
    var base = "http://127.0.0.1:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, upload_handler)
    try:
        var client = HttpClient(
            BearerAuth("stored"),
            base_url=base,
            timeout_ms=3000,
            prefer_h2c=prior,
        )
        exercise_upload(client, "Bearer stored")
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_h2_tls_streamed_upload() raises:
    var server = HttpServer.bind_tls(
        SocketAddr.localhost(0),
        "tests/certs/server.crt",
        "tests/certs/server.key",
        alpn=[String("h2"), String("http/1.1")],
    )
    var base = "https://localhost:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, upload_handler)
    try:
        var client = HttpClient(
            TlsConfig(ca_bundle="tests/certs/ca.crt"),
            base_url=base,
            timeout_ms=3000,
        )
        exercise_upload(client, "Bearer caller")
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def test_h2_upload_returns_early_response() raises:
    for reset in [False, True]:
        var listener = TcpListener.bind(SocketAddr.localhost(0))
        var url = "http://127.0.0.1:" + String(Int(listener.local_addr().port))
        var pid = fork()
        if pid == 0:
            try:
                var socket = listener.accept()
                socket.set_recv_timeout(3000)
                var buf = List[UInt8]()
                buf.resize(16384, 0)
                _ = socket.read(buf.unsafe_ptr(), len(buf))
                var settings = Frame()
                settings.header.type = FrameType.SETTINGS()
                var wire = encode_frame(settings^)
                var encoder = HpackEncoder()
                var fields: List[HpackHeader] = [
                    HpackHeader(":status", "413"),
                    HpackHeader("content-length", "0"),
                ]
                var head = Frame()
                head.header.type = FrameType.HEADERS()
                head.header.stream_id = 1
                head.header.flags = FrameFlags(
                    FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
                )
                head.payload = encoder.encode(Span(fields))
                head.header.length = len(head.payload)
                wire.extend(encode_frame(head^))
                if reset:
                    var rst = Frame()
                    rst.header.type = FrameType.RST_STREAM()
                    rst.header.stream_id = 1
                    rst.payload.resize(4, 0)  # NO_ERROR ends only the upload.
                    rst.header.length = 4
                    wire.extend(encode_frame(rst^))
                socket.write_all(Span(wire))
                # Withhold all WINDOW_UPDATEs. Waiting for upload credit
                # instead of returning the response would time out.
                while socket.read(buf.unsafe_ptr(), len(buf)) > 0:
                    pass
            except:
                pass
            exit()
        try:
            var client = HttpClient(timeout_ms=1000, prefer_h2c=True)
            var source = Chunks(32)
            var response = client.send_chunked("POST", url, source)
            assert_equal(response.status, 413)
            assert_equal(len(response.body), 0)
            assert_true(source.left > 0, "stop consuming the rejected upload")
        except e:
            kill_forked_server(pid)
            raise e^
        kill_forked_server(pid)


def test_streamed_upload_is_not_retried() raises:
    var server = HttpServer.bind(SocketAddr.localhost(0))
    var base = "http://127.0.0.1:" + String(Int(server.local_addr().port))
    var pid = fork_server(server^, upload_handler)
    try:
        var retry = RetryPolicy()
        retry.max_attempts = 2
        var client = HttpClient(base_url=base).with_retry(retry).with_cookies()
        var source = Chunks(1)
        var response = client.send_chunked("PUT", "/retry", source)
        assert_equal(response.status, 503)
    except e:
        kill_forked_server(pid)
        raise e^
    kill_forked_server(pid)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
