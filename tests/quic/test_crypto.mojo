"""Unit tests for ``flare.quic.crypto`` -- RFC 9001 §5.2
initial-secret derivation + RFC 5869 HKDF + RFC 8446 §7.1
HKDF-Expand-Label.

The AEAD encrypt / decrypt / header-protection-mask surface is
deliberately stubbed here; the OpenSSL FFI wiring lands in a
focused follow-up. These tests cover the *math-only* slabs
that ship today:

1. HKDF-Extract over the QUIC v1 initial salt against the test
   vector in RFC 9001 Appendix A.1.
2. HKDF-Expand-Label producing the canonical
   ``client_initial_secret`` / ``server_initial_secret`` shown in
   RFC 9001 Appendix A.1.
3. The :func:`derive_initial_secrets` convenience that bundles
   the above two steps into the single call the QUIC server
   reactor will use.
4. The :trait:`QuicCrypto` stub backend raises a clear error on
   every operation (so the reactor wiring tests can confirm the
   trait boundary is in place even before the AEAD lands).
"""

from std.testing import assert_equal, assert_true
from std.memory import Span

from flare.quic.crypto import (
    QUIC_V1_INITIAL_SALT,
    QuicAead,
    SHA256_OUTPUT_BYTES,
    StubQuicCrypto,
    derive_initial_secrets,
    hkdf_expand,
    hkdf_expand_label_empty_context,
    hkdf_extract,
)


def _hex_to_bytes(hex_str: String) raises -> List[UInt8]:
    """Decode a lower-case ASCII hex string (no spaces or 0x prefix)
    into a byte list. Tiny helper used to encode the RFC 9001
    Appendix A.1 test vectors inline.
    """
    var bytes = hex_str.as_bytes()
    if len(bytes) % 2 != 0:
        raise Error("hex string has odd length")
    var out = List[UInt8]()
    var i = 0
    while i < len(bytes):
        var hi = _hex_nibble(bytes[i])
        var lo = _hex_nibble(bytes[i + 1])
        out.append((hi << 4) | lo)
        i = i + 2
    return out^


def _hex_nibble(c: UInt8) raises -> UInt8:
    if c >= UInt8(0x30) and c <= UInt8(0x39):  # '0'..'9'
        return c - UInt8(0x30)
    if c >= UInt8(0x61) and c <= UInt8(0x66):  # 'a'..'f'
        return c - UInt8(0x61) + UInt8(10)
    if c >= UInt8(0x41) and c <= UInt8(0x46):  # 'A'..'F'
        return c - UInt8(0x41) + UInt8(10)
    raise Error("not a hex digit")


def _assert_bytes_equal(
    got: List[UInt8], want: List[UInt8], context: String
) raises:
    assert_equal(len(got), len(want), context + ": length mismatch")
    for i in range(len(got)):
        assert_equal(
            Int(got[i]),
            Int(want[i]),
            context + ": byte " + String(i) + " mismatch",
        )


# ── RFC 9001 Appendix A.1 vectors ───────────────────────────────────────


def test_initial_salt_matches_rfc9001() raises:
    """The QUIC v1 initial salt is fixed at
    ``0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`` per RFC 9001 §5.2."""
    var expected = _hex_to_bytes(
        String("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
    )
    var salt = materialize[QUIC_V1_INITIAL_SALT]()
    _assert_bytes_equal(salt, expected, "QUIC_V1_INITIAL_SALT")


def test_hkdf_extract_matches_rfc9001_a1() raises:
    """RFC 9001 Appendix A.1 -- ``HKDF-Extract(initial_salt, DCID)``
    where ``DCID = 0x8394c8f03e515708`` produces the canonical
    ``initial_secret``."""
    var salt = materialize[QUIC_V1_INITIAL_SALT]()
    var dcid = _hex_to_bytes(String("8394c8f03e515708"))
    var prk = hkdf_extract(Span[UInt8, _](salt), Span[UInt8, _](dcid))
    var expected = _hex_to_bytes(
        String(
            "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
        )
    )
    # The hex string above is the 32-byte initial_secret printed
    # in RFC 9001 §A.1 with whitespace removed.
    _assert_bytes_equal(prk, expected, "initial_secret")


def test_client_initial_secret_matches_rfc9001_a1() raises:
    """RFC 9001 Appendix A.1 -- ``HKDF-Expand-Label(initial_secret,
    "client in", "", 32)``."""
    var salt = materialize[QUIC_V1_INITIAL_SALT]()
    var dcid = _hex_to_bytes(String("8394c8f03e515708"))
    var prk = hkdf_extract(Span[UInt8, _](salt), Span[UInt8, _](dcid))
    var client = hkdf_expand_label_empty_context(
        Span[UInt8, _](prk), "client in", SHA256_OUTPUT_BYTES
    )
    var expected = _hex_to_bytes(
        String(
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        )
    )
    _assert_bytes_equal(client, expected, "client_initial_secret")


def test_server_initial_secret_matches_rfc9001_a1() raises:
    """RFC 9001 Appendix A.1 -- ``HKDF-Expand-Label(initial_secret,
    "server in", "", 32)``."""
    var salt = materialize[QUIC_V1_INITIAL_SALT]()
    var dcid = _hex_to_bytes(String("8394c8f03e515708"))
    var prk = hkdf_extract(Span[UInt8, _](salt), Span[UInt8, _](dcid))
    var server = hkdf_expand_label_empty_context(
        Span[UInt8, _](prk), "server in", SHA256_OUTPUT_BYTES
    )
    var expected = _hex_to_bytes(
        String(
            "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"
        )
    )
    _assert_bytes_equal(server, expected, "server_initial_secret")


def test_derive_initial_secrets_bundles_both_directions() raises:
    """:func:`derive_initial_secrets` returns the same bytes as
    deriving each secret separately."""
    var dcid = _hex_to_bytes(String("8394c8f03e515708"))
    var secrets = derive_initial_secrets(Span[UInt8, _](dcid))
    assert_equal(len(secrets.initial_secret), SHA256_OUTPUT_BYTES)
    assert_equal(len(secrets.client_initial_secret), SHA256_OUTPUT_BYTES)
    assert_equal(len(secrets.server_initial_secret), SHA256_OUTPUT_BYTES)
    # Spot-check the first byte against the RFC 9001 §A.1 vector --
    # the full byte-by-byte check is in the dedicated client /
    # server tests above.
    assert_equal(Int(secrets.client_initial_secret[0]), 0xC0)
    assert_equal(Int(secrets.server_initial_secret[0]), 0x3C)


# ── HKDF-Expand fundamentals ────────────────────────────────────────────


def test_hkdf_expand_length_zero() raises:
    """HKDF-Expand with length 0 returns an empty list."""
    var prk = _hex_to_bytes(String("deadbeef"))
    var info = _hex_to_bytes(String("aabb"))
    var out = hkdf_expand(Span[UInt8, _](prk), Span[UInt8, _](info), 0)
    assert_equal(len(out), 0)


def test_hkdf_expand_truncates_to_length() raises:
    """HKDF-Expand returns exactly ``length`` bytes even when the
    final HMAC block produces more."""
    var prk = _hex_to_bytes(String("deadbeefcafebabe"))
    var info = _hex_to_bytes(String("aa"))
    # Ask for a length that is not a multiple of 32 so the last
    # HMAC block contributes a partial chunk.
    var out = hkdf_expand(Span[UInt8, _](prk), Span[UInt8, _](info), 35)
    assert_equal(len(out), 35)


# ── Trait surface scaffold ──────────────────────────────────────────────


def test_stub_backend_reports_aead_choice() raises:
    """The stub backend remembers the AEAD it was initialized with;
    real backends will plumb this through to the OpenSSL EVP_AEAD
    selection."""
    var stub = StubQuicCrypto(QuicAead.CHACHA20_POLY1305)
    assert_equal(stub.aead(), QuicAead.CHACHA20_POLY1305)


def test_stub_backend_raises_on_encrypt() raises:
    """The stub explicitly raises so the QUIC reactor + H3 server
    can build against the trait boundary without silently producing
    junk ciphertext before the OpenSSL AEAD lands."""
    var stub = StubQuicCrypto()
    var pt = _hex_to_bytes(String("aabb"))
    var ad = _hex_to_bytes(String("cc"))
    var raised = False
    try:
        var _ = stub.encrypt(Span[UInt8, _](pt), Span[UInt8, _](ad), UInt64(0))
    except:
        raised = True
    assert_true(raised, "expected StubQuicCrypto.encrypt to raise")


def test_stub_backend_raises_on_decrypt() raises:
    var stub = StubQuicCrypto()
    var ct = _hex_to_bytes(String("aabbccddee"))
    var ad = _hex_to_bytes(String("dd"))
    var raised = False
    try:
        var _ = stub.decrypt(Span[UInt8, _](ct), Span[UInt8, _](ad), UInt64(0))
    except:
        raised = True
    assert_true(raised, "expected StubQuicCrypto.decrypt to raise")


def test_stub_backend_raises_on_header_protection() raises:
    var stub = StubQuicCrypto()
    var sample = _hex_to_bytes(String("00112233445566778899aabbccddeeff"))
    var raised = False
    try:
        var _ = stub.header_protection_mask(Span[UInt8, _](sample))
    except:
        raised = True
    assert_true(
        raised, "expected StubQuicCrypto.header_protection_mask to raise"
    )


def main() raises:
    test_initial_salt_matches_rfc9001()
    test_hkdf_extract_matches_rfc9001_a1()
    test_client_initial_secret_matches_rfc9001_a1()
    test_server_initial_secret_matches_rfc9001_a1()
    test_derive_initial_secrets_bundles_both_directions()
    test_hkdf_expand_length_zero()
    test_hkdf_expand_truncates_to_length()
    test_stub_backend_reports_aead_choice()
    test_stub_backend_raises_on_encrypt()
    test_stub_backend_raises_on_decrypt()
    test_stub_backend_raises_on_header_protection()
    print("test_quic_crypto: 11 passed")
