"""Tests for the QUIC AEAD FFI thunks (RFC 9001 §5.3).

The Mojo-side ``QuicCrypto`` trait + ``OpenSslQuicCrypto`` impl
ships the FFI thunks ``flare_quic_aead_seal`` / ``flare_quic_aead_open``
/ ``flare_quic_aead_build_nonce``; the tests here exercise
the FFI directly through ``OwnedDLHandle`` to pin:

- Nonce construction matches RFC 9001 §5.3 byte-for-byte.
- Seal -> open round-trips for all three ciphers.
- A tampered tag is rejected with status -2 (the RFC 9001
  invalid-packet path, distinct from misconfiguration -1).
- A tampered AAD is rejected with -2.
- A wrong packet number is rejected with -2.
- Empty plaintext / empty AAD are valid (tag-only AEAD,
  RFC 5116 §3.1).

The RFC 9001 Appendix A vectors that exercise the full
initial-secret -> AEAD-key -> seal round-trip live in a
separate conformance suite; this suite covers the
primitive layer first.
"""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_true

from flare.net.socket import _find_flare_lib


comptime AEAD_AES_128_GCM: Int = 1
comptime AEAD_AES_256_GCM: Int = 2
comptime AEAD_CHACHA20_POLY1305: Int = 3
comptime AEAD_TAG_LEN: Int = 16
comptime AEAD_NONCE_LEN: Int = 12


def _do_build_nonce(
    read lib: OwnedDLHandle,
    iv: List[UInt8],
    pn: UInt64,
    mut out: List[UInt8],
) raises:
    var nonce_fn = lib.get_function[
        def(Int, UInt64, Int) thin abi("C") -> c_int
    ]("flare_quic_aead_build_nonce")
    var rc = nonce_fn(Int(iv.unsafe_ptr()), pn, Int(out.unsafe_ptr()))
    if Int(rc) != 0:
        raise Error("flare_quic_aead_build_nonce: FFI failed")


def _do_seal(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    key: List[UInt8],
    iv: List[UInt8],
    pn: UInt64,
    aad: List[UInt8],
    plaintext: List[UInt8],
    mut out: List[UInt8],
) raises -> Int:
    var seal_fn = lib.get_function[
        def(
            c_int,
            Int,
            Int,
            Int,
            UInt64,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
        ) thin abi("C") -> c_int
    ]("flare_quic_aead_seal")
    var written = List[Int](length=1, fill=0)
    var rc = seal_fn(
        c_int(cipher_id),
        Int(key.unsafe_ptr()),
        len(key),
        Int(iv.unsafe_ptr()),
        pn,
        Int(aad.unsafe_ptr()),
        len(aad),
        Int(plaintext.unsafe_ptr()),
        len(plaintext),
        Int(out.unsafe_ptr()),
        len(out),
        Int(written.unsafe_ptr()),
    )
    if Int(rc) != 0:
        raise Error("flare_quic_aead_seal: rc=" + String(Int(rc)))
    return written[0]


def _do_open(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    key: List[UInt8],
    iv: List[UInt8],
    pn: UInt64,
    aad: List[UInt8],
    ct: List[UInt8],
    ct_len: Int,
    mut out: List[UInt8],
) raises -> Int:
    """Returns: written count on success, -2 on AEAD tag failure."""
    var open_fn = lib.get_function[
        def(
            c_int,
            Int,
            Int,
            Int,
            UInt64,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
            Int,
        ) thin abi("C") -> c_int
    ]("flare_quic_aead_open")
    var written = List[Int](length=1, fill=0)
    var rc = open_fn(
        c_int(cipher_id),
        Int(key.unsafe_ptr()),
        len(key),
        Int(iv.unsafe_ptr()),
        pn,
        Int(aad.unsafe_ptr()),
        len(aad),
        Int(ct.unsafe_ptr()),
        ct_len,
        Int(out.unsafe_ptr()),
        len(out),
        Int(written.unsafe_ptr()),
    )
    var rc_i = Int(rc)
    if rc_i == 0:
        return written[0]
    if rc_i == -2:
        return -2
    raise Error("flare_quic_aead_open: misconfiguration rc=" + String(rc_i))


def _bytes_n(n: Int, fill: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        out.append(UInt8(fill))
    return out^


def test_build_nonce_zero_pn() raises:
    """RFC 9001 §5.3: nonce = iv XOR (pn padded BE to 12).
    For pn = 0, the XOR is the identity (zero buffer)."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var iv = List[UInt8]()
    for i in range(12):
        iv.append(UInt8(i))
    var out = _bytes_n(12, 0)
    _do_build_nonce(lib, iv, UInt64(0), out)
    for i in range(12):
        assert_equal(Int(out[i]), i)


def test_build_nonce_xor_low_bytes() raises:
    """For pn = 0x01_02_03_04_05_06_07_08, the low 8 bytes of the
    nonce XOR with the iv's tail and the upper 4 bytes stay as
    the iv prefix (RFC 9001 §5.3, big-endian pn padding)."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var iv = _bytes_n(12, 0)
    var out = _bytes_n(12, 0)
    _do_build_nonce(lib, iv, UInt64(0x0102030405060708), out)
    assert_equal(Int(out[0]), 0)
    assert_equal(Int(out[1]), 0)
    assert_equal(Int(out[2]), 0)
    assert_equal(Int(out[3]), 0)
    assert_equal(Int(out[4]), 0x01)
    assert_equal(Int(out[5]), 0x02)
    assert_equal(Int(out[6]), 0x03)
    assert_equal(Int(out[7]), 0x04)
    assert_equal(Int(out[8]), 0x05)
    assert_equal(Int(out[9]), 0x06)
    assert_equal(Int(out[10]), 0x07)
    assert_equal(Int(out[11]), 0x08)


def _round_trip(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    key_len: Int,
) raises:
    var key = _bytes_n(key_len, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(8, 0xAA)
    var pt = _bytes_n(32, 0x11)
    var ct = _bytes_n(32 + AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(lib, cipher_id, key, iv, UInt64(7), aad, pt, ct)
    assert_equal(ct_len, 32 + AEAD_TAG_LEN)
    var recovered = _bytes_n(32, 0)
    var pt_len = _do_open(
        lib, cipher_id, key, iv, UInt64(7), aad, ct, ct_len, recovered
    )
    assert_equal(pt_len, 32)
    for i in range(32):
        assert_equal(Int(recovered[i]), 0x11)


def test_aes_128_gcm_round_trip() raises:
    var lib = OwnedDLHandle(_find_flare_lib())
    _round_trip(lib, AEAD_AES_128_GCM, 16)


def test_aes_256_gcm_round_trip() raises:
    var lib = OwnedDLHandle(_find_flare_lib())
    _round_trip(lib, AEAD_AES_256_GCM, 32)


def test_chacha20_poly1305_round_trip() raises:
    var lib = OwnedDLHandle(_find_flare_lib())
    _round_trip(lib, AEAD_CHACHA20_POLY1305, 32)


def test_open_rejects_tampered_tag() raises:
    """Flip a tag byte; open returns -2 (RFC 9001 invalid packet)."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var key = _bytes_n(16, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(8, 0xAA)
    var pt = _bytes_n(16, 0x11)
    var ct = _bytes_n(16 + AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(
        lib, AEAD_AES_128_GCM, key, iv, UInt64(1), aad, pt, ct
    )
    ct[ct_len - 1] = ct[ct_len - 1] ^ UInt8(0x01)
    var recovered = _bytes_n(16, 0)
    var rc = _do_open(
        lib, AEAD_AES_128_GCM, key, iv, UInt64(1), aad, ct, ct_len, recovered
    )
    assert_equal(rc, -2)


def test_open_rejects_tampered_aad() raises:
    """The AAD is part of the AEAD; tampering it flips the tag and
    open rejects with -2."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var key = _bytes_n(32, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(8, 0xAA)
    var pt = _bytes_n(16, 0x11)
    var ct = _bytes_n(16 + AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(
        lib, AEAD_AES_256_GCM, key, iv, UInt64(1), aad, pt, ct
    )
    var bad_aad = _bytes_n(8, 0xAB)
    var recovered = _bytes_n(16, 0)
    var rc = _do_open(
        lib,
        AEAD_AES_256_GCM,
        key,
        iv,
        UInt64(1),
        bad_aad,
        ct,
        ct_len,
        recovered,
    )
    assert_equal(rc, -2)


def test_open_rejects_wrong_packet_number() raises:
    """Different pn -> different nonce -> tag verification fails."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var key = _bytes_n(32, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(0, 0)
    var pt = _bytes_n(16, 0x11)
    var ct = _bytes_n(16 + AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(
        lib, AEAD_CHACHA20_POLY1305, key, iv, UInt64(1), aad, pt, ct
    )
    var recovered = _bytes_n(16, 0)
    var rc = _do_open(
        lib,
        AEAD_CHACHA20_POLY1305,
        key,
        iv,
        UInt64(2),  # wrong pn
        aad,
        ct,
        ct_len,
        recovered,
    )
    assert_equal(rc, -2)


def test_empty_plaintext_round_trip() raises:
    """RFC 5116 §3.1: zero-length plaintext is valid; output is
    just the 16-byte tag."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var key = _bytes_n(16, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(4, 0xAA)
    var pt = _bytes_n(0, 0)
    var ct = _bytes_n(AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(
        lib, AEAD_AES_128_GCM, key, iv, UInt64(0), aad, pt, ct
    )
    assert_equal(ct_len, AEAD_TAG_LEN)
    var recovered = _bytes_n(1, 0)  # 1 byte buffer for 0-byte output
    var pt_len = _do_open(
        lib,
        AEAD_AES_128_GCM,
        key,
        iv,
        UInt64(0),
        aad,
        ct,
        ct_len,
        recovered,
    )
    assert_equal(pt_len, 0)


def test_empty_aad_round_trip() raises:
    """No AAD is also a valid AEAD shape."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var key = _bytes_n(32, 0x42)
    var iv = _bytes_n(12, 0x55)
    var aad = _bytes_n(0, 0)
    var pt = _bytes_n(8, 0x33)
    var ct = _bytes_n(8 + AEAD_TAG_LEN, 0)
    var ct_len = _do_seal(
        lib, AEAD_AES_256_GCM, key, iv, UInt64(99), aad, pt, ct
    )
    assert_equal(ct_len, 8 + AEAD_TAG_LEN)
    var recovered = _bytes_n(8, 0)
    var pt_len = _do_open(
        lib,
        AEAD_AES_256_GCM,
        key,
        iv,
        UInt64(99),
        aad,
        ct,
        ct_len,
        recovered,
    )
    assert_equal(pt_len, 8)
    for i in range(8):
        assert_equal(Int(recovered[i]), 0x33)


def main() raises:
    test_build_nonce_zero_pn()
    test_build_nonce_xor_low_bytes()
    test_aes_128_gcm_round_trip()
    test_aes_256_gcm_round_trip()
    test_chacha20_poly1305_round_trip()
    test_open_rejects_tampered_tag()
    test_open_rejects_tampered_aad()
    test_open_rejects_wrong_packet_number()
    test_empty_plaintext_round_trip()
    test_empty_aad_round_trip()
    print("test_aead_ffi: 10 passed")
