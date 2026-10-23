"""1-RTT key updates over a live h3 connection (RFC 9001 sec 6).

Before, the key phase bit was always 0 and the next-generation secrets
were dropped, so the first packet a peer sent after its own key update
failed to decrypt and the connection died.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.http.server import ok
from flare.http3 import Http3ClientConnection
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"
comptime _BIG: Int = 1024 * 1024


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _server(interval: UInt64) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.key_update_interval = interval
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg)


def _connect(mut server: QuicListener) raises -> QuicClientConnection:
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=20)
        _ = quic.poll(timeout_ms=20)
        if quic.is_established():
            break
    assert_true(quic.is_established(), "handshake")
    return quic^


def _get(
    mut server: QuicListener, mut h3: Http3ClientConnection, size: Int
) raises -> Int:
    """GET a ``size``-byte body; return the received body length."""
    var sid = h3.request(
        "GET", "https", "localhost", "/", List[QpackHeader](), List[UInt8]()
    )
    var deadline = _monotonic_ms() + 20_000
    while _monotonic_ms() < deadline:
        _ = server.tick(timeout_ms=1)
        for slot in range(server.connection_count()):
            var ready = server.take_http3_completed_streams(slot)
            for i in range(len(ready)):
                _ = server.take_http3_request(slot, ready[i])
                var resp = ok("")
                resp.body = List[UInt8](length=size, fill=UInt8(0x61))
                server.emit_http3_response(slot, ready[i], resp^)
        _ = server.drain_all_egress()
        _ = server.advance_timers(_monotonic_ms())
        _ = h3.poll_responses(1)
        var r = h3.take_if_complete(sid)
        if r:
            return len(r.value().body)
    raise Error("response did not complete")


def test_server_initiated_updates_during_a_download() raises:
    var server = _server(UInt64(64))
    var h3 = Http3ClientConnection(_connect(server))
    assert_equal(_get(server, h3, _BIG), _BIG)
    assert_true(
        server.connections[0].phase_first_pn > 0, "the server updated keys"
    )
    server.close()


def test_client_initiated_update_is_followed() raises:
    var server = _server(UInt64(1) << 23)
    var quic = _connect(server)
    quic.initiate_key_update()
    var h3 = Http3ClientConnection(quic^)
    assert_equal(_get(server, h3, 1000), 1000)
    assert_true(server.connections[0].key_phase, "server followed the peer")
    assert_equal(_get(server, h3, 1000), 1000)
    server.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
