"""Tests for ``flare.crypto.hmac`` (— track D).

Covers RFC 4231 vectors 1-4, constant-time verify, length mismatch,
empty key/msg, and base64url round-trip.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.crypto import (
    base64url_decode,
    base64url_encode,
    hmac_sha256,
    hmac_sha256_verify,
)


@always_inline
def _hex_byte(c: UInt8) -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    return c - 55  # uppercase


def _hex(s: String) -> List[UInt8]:
    """Decode a hex string into bytes (no padding, lowercase or
    uppercase)."""
    var n = s.byte_length()
    var src = s.unsafe_ptr()
    var out = List[UInt8](capacity=n // 2)
    var i = 0
    while i + 2 <= n:
        var hi = _hex_byte(src[i])
        var lo = _hex_byte(src[i + 1])
        out.append(UInt8((Int(hi) << 4) | Int(lo)))
        i += 2
    return out^


def _bytes(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


# ── RFC 4231 vectors ────────────────────────────────────────────────────────


def test_rfc4231_test_case_1() raises:
    # Key = 0x0b * 20, Data = "Hi There"
    var key = _hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    var msg = _bytes("Hi There")
    var got = hmac_sha256(key, msg)
    var want = _hex(
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    )
    assert_equal(len(got), 32)
    for i in range(32):
        assert_equal(Int(got[i]), Int(want[i]))


def test_rfc4231_test_case_2() raises:
    # Key = "Jefe", Data = "what do ya want for nothing?"
    var key = _bytes("Jefe")
    var msg = _bytes("what do ya want for nothing?")
    var got = hmac_sha256(key, msg)
    var want = _hex(
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    )
    for i in range(32):
        assert_equal(Int(got[i]), Int(want[i]))


def test_rfc4231_test_case_3() raises:
    # Key = 0xaa * 20, Data = 0xdd * 50
    var key = _hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    var msg = List[UInt8](length=50, fill=UInt8(0xDD))
    var got = hmac_sha256(key, msg)
    var want = _hex(
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    )
    for i in range(32):
        assert_equal(Int(got[i]), Int(want[i]))


def test_rfc4231_test_case_4() raises:
    # Key = 0x0102...19, Data = 0xcd * 50
    var key = _hex("0102030405060708090a0b0c0d0e0f10111213141516171819")
    var msg = List[UInt8](length=50, fill=UInt8(0xCD))
    var got = hmac_sha256(key, msg)
    var want = _hex(
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    )
    for i in range(32):
        assert_equal(Int(got[i]), Int(want[i]))


# ── Verify path ─────────────────────────────────────────────────────────────


def test_verify_happy_path() raises:
    var key = _bytes("super-secret")
    var msg = _bytes("payload")
    var mac = hmac_sha256(key, msg)
    assert_true(hmac_sha256_verify(key, msg, mac))


def test_verify_tampered_payload_rejects() raises:
    var key = _bytes("super-secret")
    var mac = hmac_sha256(key, _bytes("payload"))
    assert_false(hmac_sha256_verify(key, _bytes("payload!"), mac))


def test_verify_wrong_key_rejects() raises:
    var msg = _bytes("payload")
    var mac = hmac_sha256(_bytes("k1"), msg)
    assert_false(hmac_sha256_verify(_bytes("k2"), msg, mac))


def test_verify_short_mac_rejects() raises:
    var key = _bytes("k")
    var msg = _bytes("m")
    var bad = List[UInt8](length=16, fill=UInt8(0))
    assert_false(hmac_sha256_verify(key, msg, bad))


def test_empty_key_and_msg() raises:
    var got = hmac_sha256(List[UInt8](), List[UInt8]())
    assert_equal(len(got), 32)
    assert_true(hmac_sha256_verify(List[UInt8](), List[UInt8](), got))


# ── base64url ──────────────────────────────────────────────────────────────


def test_b64url_empty() raises:
    assert_equal(base64url_encode(List[UInt8]()), "")
    assert_equal(len(base64url_decode("")), 0)


def test_b64url_simple_roundtrip() raises:
    var data = _bytes("hello")
    var enc = base64url_encode(data)
    assert_equal(enc, "aGVsbG8")  # no padding
    var dec = base64url_decode(enc)
    assert_equal(len(dec), 5)
    for i in range(5):
        assert_equal(Int(dec[i]), Int(data[i]))


def test_b64url_padding_tolerated() raises:
    # Add padding manually; decoder must strip it.
    var dec = base64url_decode("aGVsbG8=")
    assert_equal(len(dec), 5)


def test_b64url_url_safe_chars() raises:
    # 0xff 0xff 0xff under standard base64 produces '////'; URL-safe
    # must produce '___'.
    var enc = base64url_encode(_hex("ffffff"))
    assert_equal(enc, "____")
    var dec = base64url_decode("____")
    assert_equal(len(dec), 3)
    assert_equal(Int(dec[0]), 0xFF)


def test_b64url_invalid_character_raises() raises:
    var raised = False
    try:
        _ = base64url_decode("invalid@char")
    except:
        raised = True
    assert_true(raised)


def main() raises:
    test_rfc4231_test_case_1()
    test_rfc4231_test_case_2()
    test_rfc4231_test_case_3()
    test_rfc4231_test_case_4()
    test_verify_happy_path()
    test_verify_tampered_payload_rejects()
    test_verify_wrong_key_rejects()
    test_verify_short_mac_rejects()
    test_empty_key_and_msg()
    test_b64url_empty()
    test_b64url_simple_roundtrip()
    test_b64url_padding_tolerated()
    test_b64url_url_safe_chars()
    test_b64url_invalid_character_raises()
    print("test_hmac: 14 passed")
