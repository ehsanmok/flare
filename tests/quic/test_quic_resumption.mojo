"""Client-side TLS session resumption / 0-RTT readiness over loopback
QUIC (RFC 9001 §4.6).

Drives two QUIC client connections through one reused
:class:`RustlsQuicConnector` against a :class:`QuicListener` whose
rustls config advertises a non-zero ``max_early_data_size`` (so the
issued session tickets allow 0-RTT):

1. Connection 1 completes the handshake; the server then sends a
   ``NewSessionTicket`` (1-RTT CRYPTO) which the client feeds to
   rustls, caching it in the connector's in-memory session store.
2. Connection 2 is opened with ``enable_0rtt=True`` on the same
   connector. rustls resumes the cached session and installs 0-RTT
   (EarlyData) keys, so :meth:`early_data_ready` is True.

This verifies the client resumption foundation. Actually transmitting
application data at 0-RTT additionally needs the server QUIC driver to
pump EarlyData packets, which is the tracked v0.9 0-RTT server
follow-up; this test asserts only the client-side readiness that lands
now (off by default -- a fresh connection reports not-ready).

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/``.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_false, assert_true

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
    # Advertise 0-RTT in issued tickets so the resumed client gets
    # EarlyData keys (the readiness this test asserts).
    cfg.rustls_config.max_early_data_size = UInt32(0xFFFF)
    return QuicListener.bind(cfg^)


def _drive(
    mut server: QuicListener,
    mut client: QuicClientConnection,
    rounds: Int,
):
    """Pump server + client in lockstep for ``rounds`` iterations
    (tolerant of transient poll errors so the harness stays simple)."""
    for _ in range(rounds):
        try:
            _ = server.tick(timeout_ms=50)
        except:
            pass
        try:
            _ = client.poll(timeout_ms=50)
        except:
            pass


def test_resumption_installs_early_keys() raises:
    var server = _bind_server()
    var connector = _make_connector()

    # Connection 1: full handshake, then pump extra rounds so the
    # server's NewSessionTicket reaches + is cached by the client.
    var c1 = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = c1.poll(timeout_ms=50)
        if c1.is_established():
            break
    assert_true(c1.is_established(), "first connection must establish")
    # A fresh connection has no early keys.
    assert_false(c1.early_data_ready(), "fresh connection has no early keys")
    # Elicit + absorb the post-handshake NewSessionTicket. The server
    # only drains 1-RTT CRYPTO (the ticket) on a client packet that
    # does not itself feed crypto, so ping then pump a few times.
    for _ in range(6):
        c1.keepalive()
        _drive(server, c1, 6)
    c1.close()

    # Connection 2: same connector, opt into 0-RTT. rustls should
    # resume the cached session and install EarlyData keys.
    var c2 = QuicClientConnection.start(
        server.local_addr(),
        connector,
        String("localhost"),
        enable_0rtt=True,
    )
    assert_true(
        c2.early_data_ready(),
        "resumed connection must install 0-RTT early keys",
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = c2.poll(timeout_ms=50)
        if c2.is_established():
            break
    assert_true(c2.is_established(), "resumed connection must establish")
    server.close()
    c2.close()


def main() raises:
    test_resumption_installs_early_keys()
    print("test_quic_resumption: 1 passed")
