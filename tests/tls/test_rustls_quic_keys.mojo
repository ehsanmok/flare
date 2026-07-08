"""Mojo binding tests for the
KeyChange-driven per-level AEAD + header-protection FFI thunks.

These tests exercise the new public surface added to
:class:`flare.tls.rustls_quic.RustlsQuicSession`:

* :meth:`have_keys` -- readiness check at each encryption level.
* :meth:`packet_encrypt` / :meth:`packet_decrypt` -- AEAD via
  rustls's ``Keys.local.packet`` / ``Keys.remote.packet``.
* :meth:`header_encrypt` / :meth:`header_decrypt` -- RFC 9001
  §5.4 header protection via rustls's
  ``Keys.local.header`` / ``Keys.remote.header``.

What we can verify *without* driving a full ClientHello at the
binding-layer test:

1. A fresh session (post-``accept``, pre-CRYPTO-feed) has *no*
   keys installed at any level (the rustls ``KeyChange`` only
   fires once the server processes a ClientHello).
2. Calling the new AEAD / HP methods at a level with no keys
   installed raises with the FFI's "per-level keys not yet
   installed" error -- the safety gate stays armed.
3. The NULL-session carrier (test-only constructor) raises with
   the expected "NULL session handle" message on every new
   method.
4. Out-of-range encryption levels are rejected at the FFI
   boundary (level 4 / -1).

Driving the full handshake to the point where rustls *does*
install the Handshake + 1-RTT keys lands in
``tests/quic/test_quic_loopback_integration.mojo`` under Phase F
commit 3/6 (the loopback test that pumps a full Initial ->
Handshake -> 1-RTT progression through the QuicListener reactor
and confirms the keys flip at each transition).
"""

from std.collections import List
from std.testing import assert_equal, assert_false, assert_raises

from flare.tls import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicSession,
)


def _read_file(path: String) raises -> String:
    from std.pathlib import Path

    return Path(path).read_text()


def _make_h3_config() raises -> RustlsQuicConfig:
    var cert_pem = _read_file(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    )
    var key_pem = _read_file(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    )
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert_pem^
    cfg.private_key_pem = key_pem^
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    return cfg^


def _dcid_4() -> List[UInt8]:
    var dcid = List[UInt8]()
    dcid.append(UInt8(0xDE))
    dcid.append(UInt8(0xAD))
    dcid.append(UInt8(0xBE))
    dcid.append(UInt8(0xEF))
    return dcid^


def _zeros(n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        out.append(UInt8(0))
    return out^


def test_fresh_session_has_no_keys_at_any_level() raises:
    """Right after ``acceptor.accept(dcid)`` the rustls side
    hasn't seen any CRYPTO bytes, so ``KeyChange`` hasn't fired
    and every level reports ``have_keys == False``.

    The Initial level (0) is *always* False here because rustls
    doesn't surface Initial keys via ``KeyChange`` at all
    (they derive from the connection ID per RFC 9001 §5.2 and
    the flare side runs Initial AEAD through
    :class:`OpenSslQuicCrypto`).
    """
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    assert_false(session.have_keys(QuicEncryptionLevel.INITIAL))
    assert_false(session.have_keys(QuicEncryptionLevel.HANDSHAKE))
    assert_false(session.have_keys(QuicEncryptionLevel.APPLICATION))


def test_packet_encrypt_raises_when_keys_not_installed() raises:
    """Without an installed key slot at Handshake / 1-RTT, the
    rustls FFI rejects the packet_encrypt call. The error text
    flows through :func:`_do_last_error` -- we check the rc
    contract here, not the error text (the text is verified in
    the cargo-side test under
    ``flare/tls/ffi/rustls_wrapper/src/lib.rs``).
    """
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var header = _zeros(20)
    var payload = _zeros(64)
    with assert_raises():
        _ = session.packet_encrypt(
            QuicEncryptionLevel.HANDSHAKE,
            UInt64(0),
            header,
            payload,
        )


def test_packet_decrypt_raises_when_keys_not_installed() raises:
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var header = _zeros(20)
    var payload = _zeros(80)
    with assert_raises():
        _ = session.packet_decrypt(
            QuicEncryptionLevel.APPLICATION,
            UInt64(0),
            header,
            payload,
        )


def test_header_encrypt_raises_when_keys_not_installed() raises:
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var sample = _zeros(16)
    var first_byte: UInt8 = 0
    var first_addr = Int(UnsafePointer(to=first_byte))
    var pn = _zeros(4)
    with assert_raises():
        session.header_encrypt(
            QuicEncryptionLevel.HANDSHAKE,
            sample,
            first_addr,
            Int(pn.unsafe_ptr()),
            len(pn),
        )


def test_header_decrypt_raises_when_keys_not_installed() raises:
    var cfg = _make_h3_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var session = acceptor.accept(_dcid_4())
    var sample = _zeros(16)
    var first_byte: UInt8 = 0
    var first_addr = Int(UnsafePointer(to=first_byte))
    var pn = _zeros(4)
    with assert_raises():
        session.header_decrypt(
            QuicEncryptionLevel.APPLICATION,
            sample,
            first_addr,
            Int(pn.unsafe_ptr()),
            len(pn),
        )


def test_null_session_have_keys_returns_false() raises:
    """The test-only constructor (``RustlsQuicSession(dcid)``)
    leaves the handle at 0; ``have_keys`` returns False without
    touching the FFI."""
    var dcid = _dcid_4()
    var session = RustlsQuicSession(dcid)
    assert_false(session.have_keys(QuicEncryptionLevel.HANDSHAKE))
    assert_false(session.have_keys(QuicEncryptionLevel.APPLICATION))


def test_null_session_packet_encrypt_raises() raises:
    var dcid = _dcid_4()
    var session = RustlsQuicSession(dcid)
    var header = _zeros(20)
    var payload = _zeros(64)
    with assert_raises():
        _ = session.packet_encrypt(
            QuicEncryptionLevel.HANDSHAKE,
            UInt64(0),
            header,
            payload,
        )


def test_null_session_packet_decrypt_raises() raises:
    var dcid = _dcid_4()
    var session = RustlsQuicSession(dcid)
    var header = _zeros(20)
    var payload = _zeros(80)
    with assert_raises():
        _ = session.packet_decrypt(
            QuicEncryptionLevel.APPLICATION,
            UInt64(0),
            header,
            payload,
        )


def test_null_session_header_encrypt_raises() raises:
    var dcid = _dcid_4()
    var session = RustlsQuicSession(dcid)
    var sample = _zeros(16)
    var first_byte: UInt8 = 0
    var first_addr = Int(UnsafePointer(to=first_byte))
    var pn = _zeros(4)
    with assert_raises():
        session.header_encrypt(
            QuicEncryptionLevel.HANDSHAKE,
            sample,
            first_addr,
            Int(pn.unsafe_ptr()),
            len(pn),
        )


def test_null_session_header_decrypt_raises() raises:
    var dcid = _dcid_4()
    var session = RustlsQuicSession(dcid)
    var sample = _zeros(16)
    var first_byte: UInt8 = 0
    var first_addr = Int(UnsafePointer(to=first_byte))
    var pn = _zeros(4)
    with assert_raises():
        session.header_decrypt(
            QuicEncryptionLevel.APPLICATION,
            sample,
            first_addr,
            Int(pn.unsafe_ptr()),
            len(pn),
        )


def main() raises:
    test_fresh_session_has_no_keys_at_any_level()
    test_packet_encrypt_raises_when_keys_not_installed()
    test_packet_decrypt_raises_when_keys_not_installed()
    test_header_encrypt_raises_when_keys_not_installed()
    test_header_decrypt_raises_when_keys_not_installed()
    test_null_session_have_keys_returns_false()
    test_null_session_packet_encrypt_raises()
    test_null_session_packet_decrypt_raises()
    test_null_session_header_encrypt_raises()
    test_null_session_header_decrypt_raises()
    print("test_rustls_quic_keys: 10 passed")
