"""Tests for ``flare.http.hpack_huffman`` (Track B9).

Validates the RFC 7541 Appendix B canonical Huffman codec
against the Appendix C.4 fixtures (the request examples that
every conformant HPACK implementation must reproduce
byte-for-byte) plus round-trip + boundary tests on the encoder
and decoder.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.http import (
    HuffmanError,
    huffman_encode,
    huffman_decode,
    huffman_encoded_length,
    huffman_decoded_length,
)


def _bytes_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def _hex_to_bytes(hex_str: String) -> List[UInt8]:
    """Convert a hex string ("ab12cd") to a List[UInt8]."""
    var out = List[UInt8]()
    var i = 0
    while i + 1 < hex_str.byte_length():
        var hi = _hex_nibble(hex_str.as_bytes()[i])
        var lo = _hex_nibble(hex_str.as_bytes()[i + 1])
        out.append(UInt8(hi * 16 + lo))
        i += 2
    return out^


@always_inline
def _hex_nibble(b: UInt8) -> Int:
    if b >= UInt8(48) and b <= UInt8(57):
        return Int(b) - 48
    if b >= UInt8(97) and b <= UInt8(102):
        return Int(b) - 97 + 10
    if b >= UInt8(65) and b <= UInt8(70):
        return Int(b) - 65 + 10
    return 0


def _str_to_bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var b = s.as_bytes()
    for i in range(s.byte_length()):
        out.append(b[i])
    return out^


# ── RFC 7541 Appendix C.4 fixtures ──────────────────────────────────────────


def test_rfc7541_c41_first_request() raises:
    """RFC 7541 §C.4.1 — Huffman-encoded ``www.example.com`` is
    the byte sequence ``f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff``
    (12 bytes, vs. 15 bytes raw — 80 % of original).
    """
    var input = _str_to_bytes(String("www.example.com"))
    var expected = _hex_to_bytes(String("f1e3c2e5f23a6ba0ab90f4ff"))
    var got = List[UInt8]()
    huffman_encode(input, got)
    assert_true(_bytes_eq(got, expected))


def test_rfc7541_c42_no_cache() raises:
    """RFC 7541 §C.4.2 — Huffman-encoded ``no-cache`` is
    ``a8 eb 10 64 9c bf`` (6 bytes, vs. 8 bytes raw — 75 %).
    """
    var input = _str_to_bytes(String("no-cache"))
    var expected = _hex_to_bytes(String("a8eb10649cbf"))
    var got = List[UInt8]()
    huffman_encode(input, got)
    assert_true(_bytes_eq(got, expected))


def test_rfc7541_c43_custom_key() raises:
    """RFC 7541 §C.4.3 — Huffman-encoded ``custom-key`` is
    ``25 a8 49 e9 5b a9 7d 7f`` (8 bytes, vs. 10 bytes raw).
    """
    var input = _str_to_bytes(String("custom-key"))
    var expected = _hex_to_bytes(String("25a849e95ba97d7f"))
    var got = List[UInt8]()
    huffman_encode(input, got)
    assert_true(_bytes_eq(got, expected))


def test_rfc7541_c43_custom_value() raises:
    """RFC 7541 §C.4.3 — Huffman-encoded ``custom-value`` is
    ``25 a8 49 e9 5b b8 e8 b4 bf`` (9 bytes vs. 12).
    """
    var input = _str_to_bytes(String("custom-value"))
    var expected = _hex_to_bytes(String("25a849e95bb8e8b4bf"))
    var got = List[UInt8]()
    huffman_encode(input, got)
    assert_true(_bytes_eq(got, expected))


# ── Decoder round-trip against the Appendix C.4 fixtures ───────────────────


def test_decode_rfc7541_c41() raises:
    var encoded = _hex_to_bytes(String("f1e3c2e5f23a6ba0ab90f4ff"))
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    var expected = _str_to_bytes(String("www.example.com"))
    assert_true(_bytes_eq(decoded, expected))


def test_decode_rfc7541_c42() raises:
    var encoded = _hex_to_bytes(String("a8eb10649cbf"))
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    var expected = _str_to_bytes(String("no-cache"))
    assert_true(_bytes_eq(decoded, expected))


def test_decode_rfc7541_c43_key() raises:
    var encoded = _hex_to_bytes(String("25a849e95ba97d7f"))
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    var expected = _str_to_bytes(String("custom-key"))
    assert_true(_bytes_eq(decoded, expected))


def test_decode_rfc7541_c43_value() raises:
    var encoded = _hex_to_bytes(String("25a849e95bb8e8b4bf"))
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    var expected = _str_to_bytes(String("custom-value"))
    assert_true(_bytes_eq(decoded, expected))


# ── Round-trip on a variety of payloads ────────────────────────────────────


def test_round_trip_empty() raises:
    var input = List[UInt8]()
    var encoded = List[UInt8]()
    huffman_encode(input, encoded)
    assert_equal(len(encoded), 0)
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    assert_equal(len(decoded), 0)


def test_round_trip_single_byte() raises:
    """Single-byte round-trip exercises the partial-final-byte
    padding path on every length class.
    """
    for sym in range(256):
        var input = List[UInt8]()
        input.append(UInt8(sym))
        var encoded = List[UInt8]()
        huffman_encode(input, encoded)
        var decoded = List[UInt8]()
        huffman_decode(encoded, decoded)
        assert_true(_bytes_eq(decoded, input))


def test_round_trip_ascii_text() raises:
    var input = _str_to_bytes(
        String("Hello, World! The quick brown fox jumps over the lazy dog.")
    )
    var encoded = List[UInt8]()
    huffman_encode(input, encoded)
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    assert_true(_bytes_eq(decoded, input))


def test_round_trip_all_byte_values_ascending() raises:
    var input = List[UInt8]()
    for i in range(256):
        input.append(UInt8(i))
    var encoded = List[UInt8]()
    huffman_encode(input, encoded)
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    assert_true(_bytes_eq(decoded, input))


# ── Size-estimator tests ────────────────────────────────────────────────────


def test_encoded_length_matches_actual_output() raises:
    var inputs = List[String]()
    inputs.append(String("www.example.com"))
    inputs.append(String("no-cache"))
    inputs.append(String("custom-key"))
    inputs.append(String("custom-value"))
    inputs.append(String(""))
    inputs.append(String("a"))
    for j in range(len(inputs)):
        var bytes = _str_to_bytes(inputs[j])
        var predicted = huffman_encoded_length(bytes)
        var got = List[UInt8]()
        huffman_encode(bytes, got)
        assert_equal(len(got), predicted)


def test_decoded_length_is_upper_bound() raises:
    """``huffman_decoded_length`` is an over-estimate; the
    actual decoded length must be ≤ the prediction.
    """
    var encoded = _hex_to_bytes(String("f1e3c2e5f23a6ba0ab90f4ff"))
    var predicted = huffman_decoded_length(encoded)
    var decoded = List[UInt8]()
    huffman_decode(encoded, decoded)
    assert_true(len(decoded) <= predicted)


# ── Conformance: invalid inputs raise HuffmanError ──────────────────────────


def test_invalid_padding_raises() raises:
    """Decoding ``80`` (binary 10000000) should fail — the
    7 trailing padding bits are 0, not 1, so RFC 7541 §5.2
    INVALID_PADDING applies.
    """
    var encoded = _hex_to_bytes(String("80"))
    var decoded = List[UInt8]()
    var raised = False
    try:
        huffman_decode(encoded, decoded)
    except e:
        raised = True
    assert_true(raised)


def test_padding_too_long_raises() raises:
    """Eight pad bits is too many — the input should have ended
    before this byte.
    """
    var encoded = _hex_to_bytes(String("ff"))
    var decoded = List[UInt8]()
    # 0xff = 11111111 — could legally be the first 8 bits of a
    # >= 9-bit code but no symbol matches so the bit-walker
    # leaves all 8 bits unconsumed and PADDING_TOO_LONG fires.
    var raised = False
    try:
        huffman_decode(encoded, decoded)
    except e:
        raised = True
    assert_true(raised)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
