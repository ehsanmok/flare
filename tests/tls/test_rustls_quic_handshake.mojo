"""Handshake fixtures for the rustls QUIC FFI.

This is the live-fire test for the full FFI surface. Unlike the
scaffold suite in ``test_rustls_quic.mojo`` -- which exercises the
NULL-handle raise paths with fake PEM -- this suite uses a real
self-signed Ed25519 certificate under
``tests/tls/fixtures/rustls-quic-cert/`` so the rustls side actually
constructs the ``Arc<ServerConfig>`` and accepts per-connection
sessions.

What the suite covers:

1. Acceptor construction from real PEM succeeds (handle != 0).
2. Per-connection session construction (``acceptor.accept(dcid)``)
   succeeds and returns a handle != 0.
3. The fresh session is *not* handshake-complete (1-RTT keys
   not derived without inbound CRYPTO bytes).
4. The fresh session has no negotiated ALPN yet (empty string).
5. ``take_crypto`` on a fresh session returns an empty list at
   the Initial level (rustls hasn't generated outbound bytes
   without a ClientHello).
6. Feeding an empty CRYPTO buffer is a no-op (return 0, no
   raise).
7. Acceptor reconstruction with the same config produces another
   independent acceptor (no global state).
8. Sessions across different DCIDs are independent (no cross-talk
   in the test).

Out of scope here:

- Driving an actual ClientHello packet from a vendored aioquic
  fixture -- requires loading the encrypted Initial packet and
  feeding the decrypted CRYPTO frame bytes via
  :func:`OpenSslQuicCrypto.decrypt`. The handshake-to-completion
  test lands under ``tests/quic/test_server.mojo`` once the
  reactor wiring is in place.
"""

from std.collections import List
from std.testing import assert_equal, assert_false, assert_true

from flare.tls import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicSession,
)


def _read_file(path: String) raises -> String:
    """Read a UTF-8 file's contents into a Mojo String. Used for
    loading the PEM fixtures from disk at test time -- the
    bytes never leave the test process."""
    from std.pathlib import Path

    var content = Path(path).read_text()
    return content^


def _load_fixture_pem() raises -> Tuple[String, String]:
    """Load the self-signed cert + private key from
    ``tests/tls/fixtures/rustls-quic-cert/``. Generated once with
    ``openssl req -x509 -nodes -newkey ed25519 -days 36500
    -subj /CN=flare-quic-test -keyout key.pem -out cert.pem`` so
    every run reads the same bytes -- handshake input determinism
    is required for byte-exact conformance later.
    """
    var cert_pem = _read_file(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    )
    var key_pem = _read_file(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    )
    return (cert_pem^, key_pem^)


def _make_h3_config() raises -> RustlsQuicConfig:
    """Build a :class:`RustlsQuicConfig` with the fixture cert
    and the standard H3 ALPN list."""
    var cert_pem: String
    var key_pem: String
    cert_pem, key_pem = _load_fixture_pem()
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert_pem^
    cfg.private_key_pem = key_pem^
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    return cfg^


def _dcid_4() -> List[UInt8]:
    """A short 4-byte DCID. Real client DCIDs are 8 bytes by
    convention but 4 is enough for the tests here."""
    var dcid = List[UInt8]()
    dcid.append(UInt8(0xDE))
    dcid.append(UInt8(0xAD))
    dcid.append(UInt8(0xBE))
    dcid.append(UInt8(0xEF))
    return dcid^


def _dcid_8() -> List[UInt8]:
    """An 8-byte DCID matching the RFC 9001 §7.2 example shape."""
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x83))
    dcid.append(UInt8(0x94))
    dcid.append(UInt8(0xC8))
    dcid.append(UInt8(0xF0))
    dcid.append(UInt8(0x3E))
    dcid.append(UInt8(0x51))
    dcid.append(UInt8(0x57))
    dcid.append(UInt8(0x08))
    return dcid^


def test_real_pem_acceptor_construct() raises:
    """Real Ed25519 PEM -> acceptor handle != 0. The Rust crate
    parses the cert + key, builds the rustls ServerConfig, and
    Box-leaks an Acceptor; we read back the raw pointer through
    the Mojo carrier."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    assert_true(
        acceptor._opaque_handle != 0,
        "real PEM should produce a non-zero acceptor handle",
    )
    assert_equal(len(acceptor.config.alpn_protocols), 1)
    assert_equal(acceptor.config.alpn_protocols[0], String("h3"))


def test_accept_real_session() raises:
    """A real acceptor + real DCID produces a non-zero session
    handle. rustls's ``rustls::quic::ServerConnection::new``
    constructs the per-connection state; flare's carrier wraps
    the Box-leaked pointer."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var dcid = _dcid_4()
    var session = acceptor.accept(dcid)
    assert_true(
        session._opaque_session_handle != 0,
        "real acceptor should produce a non-zero session handle",
    )
    assert_equal(len(session.dst_cid), 4)
    assert_equal(Int(session.dst_cid[0]), 0xDE)


def test_fresh_session_not_complete() raises:
    """A session that hasn't received any CRYPTO bytes is still
    handshaking -- ``is_handshake_complete`` returns False."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    assert_false(session.is_handshake_complete())


def test_fresh_session_no_alpn() raises:
    """ALPN negotiation happens during the handshake; before
    receiving the ClientHello the session has no negotiated
    ALPN identifier."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var alpn = session.selected_alpn()
    assert_equal(alpn, String(""))


def test_fresh_session_take_crypto_empty() raises:
    """No outbound bytes until rustls processes a ClientHello;
    ``take_crypto`` on a fresh session at any level returns an
    empty list."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var out = session.take_crypto(QuicEncryptionLevel.INITIAL)
    assert_equal(len(out), 0)


def test_feed_empty_crypto_is_noop() raises:
    """An empty inbound CRYPTO buffer is a no-op (rustls's
    ``read_hs`` accepts an empty slice without protocol error)."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var empty = List[UInt8]()
    session.feed_crypto(QuicEncryptionLevel.INITIAL, empty)
    assert_false(session.is_handshake_complete())


def test_two_acceptors_are_independent() raises:
    """Two acceptors built from the same config produce different
    handles -- there's no global state in the rustls crate that
    would alias the two."""
    var cfg1 = _make_h3_config()
    var cfg2 = _make_h3_config()
    var a1 = RustlsQuicAcceptor(cfg1^)
    var a2 = RustlsQuicAcceptor(cfg2^)
    assert_true(a1._opaque_handle != 0)
    assert_true(a2._opaque_handle != 0)
    assert_true(
        a1._opaque_handle != a2._opaque_handle,
        "independent acceptors must have distinct handles",
    )


def test_two_sessions_are_independent() raises:
    """Two sessions from the same acceptor on distinct DCIDs
    must have distinct handles -- no cross-talk between
    connections."""
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var s1 = acceptor.accept(_dcid_4())
    var s2 = acceptor.accept(_dcid_8())
    assert_true(s1._opaque_session_handle != 0)
    assert_true(s2._opaque_session_handle != 0)
    assert_true(
        s1._opaque_session_handle != s2._opaque_session_handle,
        "independent sessions must have distinct handles",
    )
    assert_equal(len(s1.dst_cid), 4)
    assert_equal(len(s2.dst_cid), 8)


def main() raises:
    test_real_pem_acceptor_construct()
    test_accept_real_session()
    test_fresh_session_not_complete()
    test_fresh_session_no_alpn()
    test_fresh_session_take_crypto_empty()
    test_feed_empty_crypto_is_noop()
    test_two_acceptors_are_independent()
    test_two_sessions_are_independent()
    print("test_rustls_quic_handshake: 8 passed")
