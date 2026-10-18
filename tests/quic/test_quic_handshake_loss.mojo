"""Server handshake flight loss (RFC 9002 sec 6) and Initial padding
(RFC 9000 sec 14.1).

The client's first poll is skipped and the server's first flight is
read off the client socket and dropped, as a lossy path would. The
server must re-send its CRYPTO on its own PTO; before, a lost server
flight was only recovered by the idle timeout.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _client(server: QuicListener) raises -> QuicClientConnection:
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    return QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )


def _drop_inbound(mut client: QuicClientConnection) raises -> List[Int]:
    """Read and discard every datagram queued for the client; return
    their sizes."""
    var sizes = List[Int]()
    var buf = List[UInt8](length=2048, fill=0)
    for _ in range(64):
        try:
            var got = client.sock.try_recv_from(Span[UInt8, _](buf))
            if got[0] <= 0:
                break
            sizes.append(got[0])
        except:
            break
    return sizes^


def test_lost_server_flight_is_resent() raises:
    var server = _server()
    var client = _client(server)
    _ = server.tick(timeout_ms=50)
    var dropped = _drop_inbound(client)
    assert_true(len(dropped) > 0, "the server answered the ClientHello")
    var deadline = _monotonic_ms() + 5_000
    while _monotonic_ms() < deadline and not client.is_established():
        _ = server.tick(timeout_ms=5)
        _ = server.advance_timers(_monotonic_ms())
        _ = client.poll(timeout_ms=5)
    assert_true(client.is_established(), "handshake recovered from the loss")
    server.close()


def test_ack_eliciting_initial_datagram_is_padded() raises:
    var server = _server()
    var client = _client(server)
    _ = server.tick(timeout_ms=50)
    var dropped = _drop_inbound(client)
    assert_true(len(dropped) > 0)
    # The first datagram carries the ServerHello Initial.
    assert_true(dropped[0] >= 1200, "Initial datagram under 1200 bytes")
    server.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
