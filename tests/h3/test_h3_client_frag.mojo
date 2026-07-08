"""Multi-packet request-body send + idle keepalive reuse.

Drives the real H3 client over the loopback QUIC server (same lockstep
harness as ``test_h3_client_e2e.mojo``) to exercise two reuse
prerequisites:

1. A request body larger than the path MTU is fragmented across several
   1-RTT STREAM frames by ``QuicClientConnection.send_stream`` and
   reassembled by the server. The handler replies with a tiny
   ``len:checksum`` digest (the response itself stays single-packet) so
   the test isolates *client* fragmentation + *server* reassembly.
2. After a request completes, a ``keepalive()`` PING plus an idle poll
   keep the connection established, and a second request reuses it.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.http3 import Http3ClientConnection, Http3ResponseReader
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
struct _Digest(Copyable, Handler, Movable):
    """200 handler returning ``<len>:<bytesum>`` for the request body
    so a large upload is verified by a tiny response."""

    def serve(self, req: Request) raises -> Response:
        var s = 0
        for i in range(len(req.body)):
            s += Int(req.body[i])
        return ok(String(len(req.body)) + ":" + String(s))


def _server_dispatch(mut server: QuicListener) raises:
    var handler = _Digest()
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


def _pattern(n: Int) -> List[UInt8]:
    var b = List[UInt8](capacity=n)
    for i in range(n):
        b.append(UInt8((i * 31 + 7) % 256))
    return b^


def _digest_of(body: List[UInt8]) -> String:
    var s = 0
    for i in range(len(body)):
        s += Int(body[i])
    return String(len(body)) + ":" + String(s)


def test_large_body_fragments() raises:
    """A 6000-byte POST body spans multiple packets and the server
    reassembles it intact."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var body = _pattern(6000)  # > default 1452 MTU -> several frames
    var want = _digest_of(body)
    var sid = h3.send_request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/upload"),
        List[QpackHeader](),
        body,
    )
    var reader = Http3ResponseReader.new()
    var done = False
    for _ in range(80):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        if h3.read_response(sid, reader, timeout_ms=50):
            done = True
            break
    assert_true(done, "large POST must complete over loopback h3")
    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](resp.body)), want)
    server.close()
    h3.close()


def test_idle_then_reuse() raises:
    """After one request, keepalive + idle poll keep the connection
    established and a second request reuses it."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var body1 = _pattern(64)
    var want1 = _digest_of(body1)
    var sid1 = h3.send_request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/first"),
        List[QpackHeader](),
        body1,
    )
    var reader1 = Http3ResponseReader.new()
    var done1 = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        if h3.read_response(sid1, reader1, timeout_ms=50):
            done1 = True
            break
    assert_true(done1, "first request must complete")
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](reader1.take_response().body)),
        want1,
    )

    # Idle: PING + a few poll/tick rounds, connection stays up.
    h3.quic.keepalive()
    for _ in range(5):
        _ = server.tick(timeout_ms=20)
        _ = h3.quic.poll(timeout_ms=20)
    assert_true(h3.is_established(), "connection stays established while idle")

    # Reuse: a second request on the same connection.
    var body2 = _pattern(128)
    var want2 = _digest_of(body2)
    var sid2 = h3.send_request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/second"),
        List[QpackHeader](),
        body2,
    )
    assert_true(sid2 != sid1, "reuse opens a fresh stream")
    var reader2 = Http3ResponseReader.new()
    var done2 = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        if h3.read_response(sid2, reader2, timeout_ms=50):
            done2 = True
            break
    assert_true(done2, "reused request must complete")
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](reader2.take_response().body)),
        want2,
    )
    server.close()
    h3.close()


def main() raises:
    test_large_body_fragments()
    test_idle_then_reuse()
    print("test_h3_client_frag: 2 passed")
