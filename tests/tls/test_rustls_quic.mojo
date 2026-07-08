"""Unit tests for the `flare.tls.rustls_quic` scaffold.

The actual rustls Rust crate (`flare/tls/ffi/rustls_wrapper.rs`)
plus the `build_rustls.sh` activation script land in a focused
follow-up commit. This test suite pins the Mojo-side API surface
so the QUIC server reactor + the H3 server can build against the
typed boundary today.

Every test exercises one of two properties:

1. The carrier struct compiles, allocates, and exposes the fields
   the reactor will read.
2. Every method that would touch the Rust crate raises a clear
   :class:`Error` whose message points at the follow-up commit
   (so a missing Rust crate is a loud, immediate failure rather
   than a silent zero-byte handshake output).
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.tls import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
    RustlsQuicError,
    RustlsQuicErrorKind,
    RustlsQuicSession,
)


def _make_config() -> RustlsQuicConfig:
    """Build a minimal :class:`RustlsQuicConfig` for tests."""
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = String("-----BEGIN CERTIFICATE-----\n...")
    cfg.private_key_pem = String("-----BEGIN PRIVATE KEY-----\n...")
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    cfg.alpn_protocols.append(String("hq-interop"))
    return cfg^


def test_config_defaults() raises:
    """A default-constructed :class:`RustlsQuicConfig` matches the
    scaffold's documented production defaults."""
    var cfg = RustlsQuicConfig()
    assert_equal(cfg.cert_chain_pem, String(""))
    assert_equal(cfg.private_key_pem, String(""))
    assert_equal(len(cfg.alpn_protocols), 0)
    assert_equal(cfg.max_early_data_size, UInt32(0))
    assert_true(cfg.session_resumption_enabled)


def test_config_holds_alpn_list() raises:
    """ALPN protocols round-trip through the config carrier
    without re-ordering or de-duplication. Tests both the
    iteration order RFC 7301 §3.2 documents and the carrier's
    own movability."""
    var cfg = _make_config()
    assert_equal(len(cfg.alpn_protocols), 2)
    assert_equal(cfg.alpn_protocols[0], String("h3"))
    assert_equal(cfg.alpn_protocols[1], String("hq-interop"))


def test_encryption_level_codepoints() raises:
    """RFC 9001 §4.1 packet protection levels carry stable
    integer codepoints. The scaffold uses these for the
    reactor's per-level dispatch table."""
    assert_equal(QuicEncryptionLevel.INITIAL, 0)
    assert_equal(QuicEncryptionLevel.EARLY_DATA, 1)
    assert_equal(QuicEncryptionLevel.HANDSHAKE, 2)
    assert_equal(QuicEncryptionLevel.APPLICATION, 3)


def test_error_kind_codepoints() raises:
    """The error kind enum exposes stable codepoints so the
    reactor's CONNECTION_CLOSE mapping table (RFC 9000 §20)
    can switch on them."""
    assert_equal(RustlsQuicErrorKind.NOT_BUILT, 0)
    assert_equal(RustlsQuicErrorKind.HANDSHAKE_INCOMPLETE, 1)
    assert_equal(RustlsQuicErrorKind.PROTOCOL_VIOLATION, 2)
    assert_equal(RustlsQuicErrorKind.CERTIFICATE_INVALID, 3)
    assert_equal(RustlsQuicErrorKind.INTERNAL_ERROR, 4)


def test_not_built_error_carries_reason() raises:
    """:meth:`RustlsQuicError.not_built` returns a carrier with
    the ``NOT_BUILT`` kind and a reason string that points the
    caller at the build script. The reactor uses this to
    distinguish a configuration error from a per-packet
    handshake failure."""
    var err = RustlsQuicError.not_built()
    assert_equal(err.kind, RustlsQuicErrorKind.NOT_BUILT)
    assert_true(
        err.reason.startswith(String("rustls QUIC binding")),
        "expected reason to identify the rustls QUIC binding",
    )


def test_acceptor_constructs() raises:
    """The acceptor constructs cleanly from a config carrier;
    the opaque handle is zero in the scaffold (no Rust crate
    yet), which the follow-up commit will overwrite with the
    real handle."""
    var cfg = _make_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    assert_equal(acceptor._opaque_handle, 0)
    assert_equal(len(acceptor.config.alpn_protocols), 2)


def test_acceptor_accept_raises() raises:
    """:meth:`RustlsQuicAcceptor.accept` raises a clear error
    pointing at the follow-up work needed. The reactor treats
    this as a hard configuration failure (every connection
    bounces immediately) rather than a silent handshake hang."""
    var cfg = _make_config()
    var acceptor = RustlsQuicAcceptor(cfg^)
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x83))
    dcid.append(UInt8(0x94))
    dcid.append(UInt8(0xC8))
    dcid.append(UInt8(0xF0))
    var raised = False
    try:
        var _ = acceptor.accept(dcid)
    except:
        raised = True
    assert_true(raised, "expected RustlsQuicAcceptor.accept to raise")


def test_session_holds_dcid() raises:
    """A constructed session remembers the client's DCID so the
    reactor can sanity-check key derivation against the value
    used to initialize the rustls binding."""
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x83))
    dcid.append(UInt8(0x94))
    dcid.append(UInt8(0xC8))
    dcid.append(UInt8(0xF0))
    dcid.append(UInt8(0x3E))
    dcid.append(UInt8(0x51))
    dcid.append(UInt8(0x57))
    dcid.append(UInt8(0x08))
    var session = RustlsQuicSession(dcid)
    assert_equal(len(session.dst_cid), 8)
    assert_equal(Int(session.dst_cid[0]), 0x83)
    assert_equal(Int(session.dst_cid[7]), 0x08)


def test_session_starts_at_initial_level() raises:
    """A fresh session sits at the Initial encryption level. The
    level-machine wiring needs to be verifiable before the Rust
    crate lands so the reactor's level-dispatch table can be
    unit-tested in isolation."""
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x01))
    var session = RustlsQuicSession(dcid)
    assert_equal(session.current_level(), QuicEncryptionLevel.INITIAL)
    assert_false(session.is_handshake_complete())


def test_session_feed_crypto_raises() raises:
    """Feeding CRYPTO frame bytes raises because the Rust crate
    is absent. The error message identifies the follow-up
    commit + carries the level + length context so logs are
    useful even before the crate ships."""
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x01))
    var session = RustlsQuicSession(dcid)
    var data = List[UInt8]()
    data.append(UInt8(0x01))
    data.append(UInt8(0x02))
    data.append(UInt8(0x03))
    var raised = False
    try:
        session.feed_crypto(QuicEncryptionLevel.INITIAL, data)
    except:
        raised = True
    assert_true(raised, "expected feed_crypto to raise")


def test_session_take_crypto_raises() raises:
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x01))
    var session = RustlsQuicSession(dcid)
    var raised = False
    try:
        var _ = session.take_crypto(QuicEncryptionLevel.INITIAL)
    except:
        raised = True
    assert_true(raised, "expected take_crypto to raise")


def test_session_selected_alpn_raises() raises:
    var dcid = List[UInt8]()
    dcid.append(UInt8(0x01))
    var session = RustlsQuicSession(dcid)
    var raised = False
    try:
        var _ = session.selected_alpn()
    except:
        raised = True
    assert_true(raised, "expected selected_alpn to raise")


def main() raises:
    test_config_defaults()
    test_config_holds_alpn_list()
    test_encryption_level_codepoints()
    test_error_kind_codepoints()
    test_not_built_error_carries_reason()
    test_acceptor_constructs()
    test_acceptor_accept_raises()
    test_session_holds_dcid()
    test_session_starts_at_initial_level()
    test_session_feed_crypto_raises()
    test_session_take_crypto_raises()
    test_session_selected_alpn_raises()
    print("test_rustls_quic: 12 passed")
