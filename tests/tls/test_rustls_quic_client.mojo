"""H3C-0 smoke: the rustls QUIC client-role binding.

Companion to ``test_rustls_quic_handshake.mojo`` (the server side).
This drives the client surface added for the HTTP/3 client:

- ``RustlsQuicConnector`` construction from a CA PEM bundle + ALPN list
  (handle != 0), and the NULL-handle raise path on a bad CA bundle.
- ``connect(server_name)`` produces a real client session (handle != 0)
  that is not yet handshake-complete and has no negotiated ALPN.
- The first ``take_crypto(INITIAL)`` drains a non-empty ClientHello --
  proof the client role drives the handshake (the server side is empty
  here until it receives that ClientHello).
- A full loopback handshake: client connector + server acceptor, CRYPTO
  pumped both ways until both report complete, with ALPN negotiated to
  ``"h3"`` on both ends. This exercises the role-agnostic feed/take
  CRYPTO + KeyChange capture for the client direction end to end.

The fixtures under ``tests/tls/fixtures/rustls-quic-client/`` are a real
2-cert chain: ``ca.pem`` is the trust anchor the client loads, and
``cert.pem`` is a ``localhost`` leaf (``subjectAltName = DNS:localhost``)
signed by that CA, presented by the server. A self-signed cert cannot be
both the root and the leaf -- webpki rejects that as ``CaUsedAsEndEntity``
-- so the chain mirrors a real deployment.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.tls import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicConnector,
    RustlsQuicSession,
)


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    """Client connector trusting the fixture CA (``ca.pem``)."""
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _make_acceptor() raises -> RustlsQuicAcceptor:
    """Server acceptor presenting the CA-signed ``localhost`` leaf."""
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert^
    cfg.private_key_pem = key^
    cfg.alpn_protocols = _h3_alpn()
    return RustlsQuicAcceptor(cfg^)


def _pump(mut src: RustlsQuicSession, mut dst: RustlsQuicSession) raises -> Int:
    """Drain every non-empty CRYPTO level from ``src`` and feed it
    into ``dst`` at the matching level. Returns the byte count moved
    (0 means the source had nothing pending this round)."""
    var moved = 0
    var levels = [
        QuicEncryptionLevel.INITIAL,
        QuicEncryptionLevel.HANDSHAKE,
        QuicEncryptionLevel.APPLICATION,
    ]
    for level in levels:
        var bytes = src.take_crypto(level)
        if len(bytes) > 0:
            dst.feed_crypto(level, bytes)
            moved += len(bytes)
    return moved


def test_connector_construct() raises:
    """Real CA PEM + ALPN -> connector handle != 0."""
    var connector = _make_connector()
    assert_true(
        connector._opaque_handle != 0,
        "real CA PEM should produce a non-zero connector handle",
    )
    assert_equal(len(connector.alpn_protocols), 1)
    assert_equal(connector.alpn_protocols[0], String("h3"))


def test_connector_bad_ca_is_null() raises:
    """A garbage CA bundle yields a 0 handle and connect() raises."""
    var bad = String("not actually pem")
    var connector = RustlsQuicConnector(bad, _h3_alpn())
    assert_equal(connector._opaque_handle, 0)
    var raised = False
    try:
        var _s = connector.connect(String("localhost"))
    except:
        raised = True
    assert_true(raised, "connect on a NULL connector must raise")


def test_connector_system_roots() raises:
    """``with_system_roots`` builds a usable connector off the OS CA
    bundle (rustls-native-certs): a non-zero handle and a fresh
    client session that drives a ClientHello -- no PEM supplied.
    Skips the non-zero assertion only if the host has no trust store
    (a bare container), in which case the handle is 0 and connect
    raises, which is the documented behavior."""
    var connector = RustlsQuicConnector.with_system_roots(_h3_alpn())
    if connector._opaque_handle == 0:
        # No native roots on this host: connect must surface it.
        var raised = False
        try:
            var _s = connector.connect(String("example.com"))
        except:
            raised = True
        assert_true(raised, "NULL native-roots connector must raise")
        return
    var session = connector.connect(String("example.com"))
    assert_true(
        session._opaque_session_handle != 0,
        "system-roots connect should produce a non-zero session",
    )
    var hello = session.take_crypto(QuicEncryptionLevel.INITIAL)
    assert_true(len(hello) > 0, "client should emit a ClientHello")


def test_connect_fresh_session() raises:
    """A fresh client session (connect) is non-zero, not yet complete,
    and has no negotiated ALPN before the handshake runs."""
    var connector = _make_connector()
    var session = connector.connect(String("localhost"))
    assert_true(
        session._opaque_session_handle != 0,
        "connect should produce a non-zero session handle",
    )
    assert_false(session.is_handshake_complete())
    assert_equal(session.selected_alpn(), String(""))


def test_client_emits_clienthello() raises:
    """The client drives the first flight: take_crypto(INITIAL) on a
    fresh client session returns a non-empty ClientHello (unlike a
    fresh server session, which is empty until it is fed one)."""
    var connector = _make_connector()
    var session = connector.connect(String("localhost"))
    var hello = session.take_crypto(QuicEncryptionLevel.INITIAL)
    assert_true(
        len(hello) > 0,
        "client should emit a non-empty Initial ClientHello",
    )


def test_loopback_handshake_completes() raises:
    """Client connector + server acceptor, CRYPTO pumped both ways
    until both complete, ALPN negotiated to h3 on both ends."""
    var connector = _make_connector()
    var acceptor = _make_acceptor()
    var client = connector.connect(String("localhost"))
    var server = acceptor.accept(List[UInt8]())

    var done = False
    for _ in range(12):
        var moved = _pump(client, server)
        moved += _pump(server, client)
        if client.is_handshake_complete() and server.is_handshake_complete():
            done = True
            break
        if moved == 0:
            break

    assert_true(done, "client + server handshake should complete")
    assert_equal(client.selected_alpn(), String("h3"))
    assert_equal(server.selected_alpn(), String("h3"))


def main() raises:
    test_connector_construct()
    test_connector_bad_ca_is_null()
    test_connector_system_roots()
    test_connect_fresh_session()
    test_client_emits_clienthello()
    test_loopback_handshake_completes()
    print("test_rustls_quic_client: 6 passed")
