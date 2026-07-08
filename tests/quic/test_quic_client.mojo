"""The QUIC client connection driver end to end.

Drives :class:`flare.quic.client.QuicClientConnection` against the
real :class:`flare.quic.server.QuicListener` over loopback UDP. The
two sides run in lockstep on one thread -- each ``server.tick`` /
``client.poll`` does a short blocking recv then processes + flushes
egress, so a queued datagram is consumed on the next step without
threads. This proves the full client handshake: client-chosen
Initial DCID, padded ClientHello, server Initial/Handshake decrypt
through rustls, the client Finished flight, 1-RTT promotion, and
``h3`` ALPN negotiation.

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/`` (CA trust anchor +
``localhost`` leaf) so certificate validation passes exactly as in
``test_rustls_quic_client.mojo``.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConfig, RustlsQuicConnector


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


def test_client_handshake_completes() raises:
    """Full loopback QUIC handshake: client driver vs QuicListener,
    h3 negotiated, server tracks exactly one connection."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )

    var done = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            done = True
            break

    assert_true(done, "client handshake should complete over loopback UDP")
    assert_true(client.is_established(), "client must report established")
    assert_equal(client.alpn(), String("h3"))
    assert_equal(server.connection_count(), 1)

    server.close()
    client.close()


def test_client_send_stream_after_handshake() raises:
    """Once established the client can open a bidi stream and ship a
    1-RTT STREAM frame; the server tick consumes it without error.

    The payload here is opaque bytes (real H3/QPACK framing is tested
    separately); this asserts the 1-RTT egress + server ingress path is
    wired, not the H3 semantics."""
    var server = _bind_server()
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

    var sid = client.open_bidi_stream()
    assert_equal(sid, UInt64(0))
    var body = List[UInt8]()
    for b in String("hello-h3c1").as_bytes():
        body.append(b)
    client.send_stream(sid, body, fin=True)

    # Pump a few rounds so the server ingests the STREAM datagram and
    # the client drains the resulting ACK; neither side should raise.
    for _ in range(4):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)

    assert_equal(server.connection_count(), 1)
    server.close()
    client.close()


def main() raises:
    test_client_handshake_completes()
    test_client_send_stream_after_handshake()
    print("test_quic_client: 2 passed")
