"""Tests for the QUIC header-protection mask FFI (RFC 9001 §5.4).

This commit pins ``flare_quic_hp_mask`` against the canonical
RFC 9001 Appendix A vectors:

- A.2 client-initial AES-128:
    hp     = 9f50449e04a0e810283a1e9933adedd2
    sample = d1b1c98dd7689fb8ec11d242b123dc9b
    mask   = 437b9aec36

- A.5 ChaCha20-Poly1305 short header:
    hp     = 25a282b9e82f06f21f488917a4fc8f1b
             73573685608597d0efcb076b0ab7a7a4
    sample = 5e5cd55c41f69080575d7999c25a5bfb
    mask   = aefefe7d03

RFC 9001 Appendix A doesn't ship an AES-256 vector, so the AES-256
case pins determinism (same input -> same output, different sample
-> different output) and the OpenSSL contract directly. The Mojo
``OpenSslQuicCrypto`` impl is the layer that uses these masks;
its tests pin the impl against full packet-protect round-trips.
"""

from std.ffi import OwnedDLHandle, c_int
from std.testing import assert_equal, assert_not_equal

from flare.net.socket import _find_flare_lib


comptime HP_AES_128: Int = 1
comptime HP_AES_256: Int = 2
comptime HP_CHACHA20: Int = 3


def _hex(s: String) -> List[UInt8]:
    var bytes = s.as_bytes()
    var out = List[UInt8]()
    var i = 0
    while i < len(bytes):
        var hi = _hex_nibble(bytes[i])
        var lo = _hex_nibble(bytes[i + 1])
        out.append((hi << 4) | lo)
        i += 2
    return out^


@always_inline
def _hex_nibble(c: UInt8) -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48  # 0-9
    if c >= 97 and c <= 102:
        return c - 87  # a-f
    return c - 55  # A-F


def _do_mask(
    read lib: OwnedDLHandle,
    cipher_id: Int,
    hp_key: List[UInt8],
    sample: List[UInt8],
    mut out: List[UInt8],
) raises:
    var mask_fn = lib.get_function[
        def(c_int, Int, Int, Int, Int) thin abi("C") -> c_int
    ]("flare_quic_hp_mask")
    var rc = mask_fn(
        c_int(cipher_id),
        Int(hp_key.unsafe_ptr()),
        len(hp_key),
        Int(sample.unsafe_ptr()),
        Int(out.unsafe_ptr()),
    )
    if Int(rc) != 0:
        raise Error("flare_quic_hp_mask: rc=" + String(Int(rc)))


def _assert_bytes_eq(actual: List[UInt8], expected: List[UInt8]) raises:
    assert_equal(len(actual), len(expected))
    for i in range(len(expected)):
        assert_equal(Int(actual[i]), Int(expected[i]))


def test_rfc9001_a2_aes128_client_initial() raises:
    """RFC 9001 Appendix A.2 client initial: hp_key + sample -> mask."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var hp_key = _hex("9f50449e04a0e810283a1e9933adedd2")
    var sample = _hex("d1b1c98dd7689fb8ec11d242b123dc9b")
    var expected = _hex("437b9aec36")
    var out = List[UInt8](length=5, fill=UInt8(0))
    _do_mask(lib, HP_AES_128, hp_key, sample, out)
    _assert_bytes_eq(out, expected)


def test_rfc9001_a5_chacha20_short_header() raises:
    """RFC 9001 Appendix A.5 ChaCha20 short header: sample -> mask."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var hp_key = _hex(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
    )
    var sample = _hex("5e5cd55c41f69080575d7999c25a5bfb")
    var expected = _hex("aefefe7d03")
    var out = List[UInt8](length=5, fill=UInt8(0))
    _do_mask(lib, HP_CHACHA20, hp_key, sample, out)
    _assert_bytes_eq(out, expected)


def test_aes256_deterministic() raises:
    """AES-256: same key+sample -> same mask, twice in a row."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var hp_key = _hex(
        "0011223344556677889900112233445566778899001122334455667788990011"
    )
    var sample = _hex("00112233445566778899aabbccddeeff")
    var out1 = List[UInt8](length=5, fill=UInt8(0))
    var out2 = List[UInt8](length=5, fill=UInt8(0))
    _do_mask(lib, HP_AES_256, hp_key, sample, out1)
    _do_mask(lib, HP_AES_256, hp_key, sample, out2)
    _assert_bytes_eq(out1, out2)


def test_aes256_sample_change_flips_mask() raises:
    """AES-256: changing the sample changes the mask (ECB is a PRP
    so almost-equal samples produce unrelated masks)."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var hp_key = _hex(
        "0011223344556677889900112233445566778899001122334455667788990011"
    )
    var sample_a = _hex("00112233445566778899aabbccddeeff")
    var sample_b = _hex("00112233445566778899aabbccddeefe")  # last byte ^1
    var out_a = List[UInt8](length=5, fill=UInt8(0))
    var out_b = List[UInt8](length=5, fill=UInt8(0))
    _do_mask(lib, HP_AES_256, hp_key, sample_a, out_a)
    _do_mask(lib, HP_AES_256, hp_key, sample_b, out_b)
    # Mask bytes should differ -- ECB is a permutation so any input
    # flip yields a completely different output block.
    var diffs = 0
    for i in range(5):
        if Int(out_a[i]) != Int(out_b[i]):
            diffs += 1
    assert_not_equal(diffs, 0)


def test_chacha20_sample_change_flips_mask() raises:
    """ChaCha20: changing the sample changes the mask (the counter
    or nonce derivation reads from sample)."""
    var lib = OwnedDLHandle(_find_flare_lib())
    var hp_key = _hex(
        "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"
    )
    var sample_a = _hex("5e5cd55c41f69080575d7999c25a5bfb")
    var sample_b = _hex("5e5cd55c41f69080575d7999c25a5bfa")  # last byte ^1
    var out_a = List[UInt8](length=5, fill=UInt8(0))
    var out_b = List[UInt8](length=5, fill=UInt8(0))
    _do_mask(lib, HP_CHACHA20, hp_key, sample_a, out_a)
    _do_mask(lib, HP_CHACHA20, hp_key, sample_b, out_b)
    var diffs = 0
    for i in range(5):
        if Int(out_a[i]) != Int(out_b[i]):
            diffs += 1
    assert_not_equal(diffs, 0)


def main() raises:
    test_rfc9001_a2_aes128_client_initial()
    test_rfc9001_a5_chacha20_short_header()
    test_aes256_deterministic()
    test_aes256_sample_change_flips_mask()
    test_chacha20_sample_change_flips_mask()
    print("test_hp_mask_ffi: 5 passed")
