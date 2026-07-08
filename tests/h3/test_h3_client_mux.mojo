"""Many concurrent requests over one QUIC connection.

Drives the multiplexed :class:`flare.http3.client.Http3ClientConnection`
API (:meth:`request` / :meth:`poll_responses` / :meth:`take_if_complete`)
against the real :class:`flare.quic.server.QuicListener` over loopback
UDP, pumped in lockstep on one thread (same harness as
``test_h3_client_e2e.mojo``).

Two requests are opened back-to-back on the one connection (two
distinct bidi streams) before any response is pumped, then a single
poll loop fans server bursts out across both in-flight streams. Each
response body must match its own request body, proving the demux keys
chunks to the right reader.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.http3 import Http3ClientConnection
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _bind_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    return QuicListener.bind(cfg^)


@fieldwise_init
struct _EchoBody(Copyable, Handler, Movable):
    """200 handler that echoes the request body verbatim."""

    def serve(self, req: Request) raises -> Response:
        var resp = ok(String(""))
        resp.body = req.body.copy()
        return resp^


def _server_dispatch(mut server: QuicListener) raises:
    var handler = _EchoBody()
    for slot in range(server.connection_count()):
        var ready = server.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var sid = ready[i]
            var req = server.take_http3_request(slot, sid)
            var resp = handler.serve(req^)
            server.emit_http3_response(slot, sid, resp^)


def _drive_handshake(mut server: QuicListener) raises -> QuicClientConnection:
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")
    return client^


def _body(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def test_two_concurrent_requests() raises:
    """Two POSTs in flight on one connection get independent bodies."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var body_a = _body(String("alpha-request-body"))
    var body_b = _body(String("bravo-request-body"))

    # Open both requests before pumping any response so they are
    # genuinely concurrent on the wire.
    var sid_a = h3.request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/a"),
        List[QpackHeader](),
        body_a,
    )
    var sid_b = h3.request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/b"),
        List[QpackHeader](),
        body_b,
    )
    assert_true(sid_a != sid_b, "each request gets its own stream")

    var got_a = False
    var got_b = False
    var status_a = 0
    var status_b = 0
    var body_out_a = List[UInt8]()
    var body_out_b = List[UInt8]()
    for _ in range(60):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        _ = h3.poll_responses(timeout_ms=50)
        if not got_a:
            var ra = h3.take_if_complete(sid_a)
            if ra:
                status_a = ra.value().status
                body_out_a = ra.value().body.copy()
                got_a = True
        if not got_b:
            var rb = h3.take_if_complete(sid_b)
            if rb:
                status_b = rb.value().status
                body_out_b = rb.value().body.copy()
                got_b = True
        if got_a and got_b:
            break

    assert_true(got_a, "request A must complete")
    assert_true(got_b, "request B must complete")
    assert_equal(status_a, 200)
    assert_equal(status_b, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](body_out_a)),
        String("alpha-request-body"),
    )
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](body_out_b)),
        String("bravo-request-body"),
    )
    server.close()
    h3.close()


def main() raises:
    test_two_concurrent_requests()
    print("test_h3_client_mux: 1 passed")
