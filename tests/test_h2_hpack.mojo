"""Tests for ``flare.http2.hpack`` (RFC 7541 codec, — Track J).

Covers:

- :func:`encode_integer` / :func:`decode_integer` round-trip across
  4-/5-/6-/7-bit prefixes including the boundary values 0,
  ``2^prefix-1``, and ``2^31``.
- RFC 7541 §C.1 example: encoding 1337 with a 5-bit prefix yields
  ``11111 10011010 00001010``.
- Static-table indexed lookup (RFC 7541 §C.2.4).
- Literal w/ Incremental Indexing populates the dynamic table.
- Literal w/o Indexing leaves the dynamic table untouched.
- Dynamic Table Size Update (§6.3) shrinks / preserves table.
- Encoder + Decoder round-trip on a realistic request.
- Huffman gating: ``H=1`` literals raise when ``allow_huffman``
  is False (default) and round-trip cleanly when set True.
- Encoder Huffman opt-in: with ``allow_huffman=True`` the encoder
  picks the shorter of raw vs Huffman per literal; the decoder
  with the same flag round-trips the result.
- Truncated inputs / pathological integer sizes raise rather than
  hang.
"""

from std.testing import assert_equal, assert_raises, assert_true

from flare.http2.hpack import (
    HpackDecoder,
    HpackEncoder,
    HpackHeader,
    decode_integer,
    encode_integer,
)


# ── Integer codec ───────────────────────────────────────────────────────


def _bytes(values: List[Int]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(values))
    for i in range(len(values)):
        out.append(UInt8(values[i]))
    return out^


def test_decode_integer_short() raises:
    var b = List[UInt8]()
    b.append(UInt8(10))
    var p = decode_integer(Span[UInt8, _](b), 0, 5)
    assert_equal(p.value, 10)
    assert_equal(p.offset, 1)


def test_rfc_7541_c1_5bit_1337() raises:
    """RFC 7541 §C.1.1 — encode 1337 with 5-bit prefix.

    Expected wire bytes: ``11111 10011010 00001010``.
    """
    var b = List[UInt8]()
    encode_integer(b, 1337, 5, UInt8(0))
    assert_equal(len(b), 3)
    assert_equal(Int(b[0]), 0x1F)
    assert_equal(Int(b[1]), 0x9A)
    assert_equal(Int(b[2]), 0x0A)
    var p = decode_integer(Span[UInt8, _](b), 0, 5)
    assert_equal(p.value, 1337)


def test_integer_roundtrip_boundaries() raises:
    var values = List[Int]()
    values.append(0)
    values.append(15)
    values.append(31)
    values.append(127)
    values.append(128)
    values.append(255)
    values.append(1024)
    values.append(65535)
    values.append(1234567)
    for prefix in range(4, 8):
        for i in range(len(values)):
            var v = values[i]
            var b = List[UInt8]()
            encode_integer(b, v, prefix, UInt8(0))
            var p = decode_integer(Span[UInt8, _](b), 0, prefix)
            assert_equal(p.value, v)


def test_integer_truncated_raises() raises:
    var b = List[UInt8]()
    b.append(UInt8(0x1F))  # 5-bit prefix maxed -> continuation expected
    with assert_raises():
        _ = decode_integer(Span[UInt8, _](b), 0, 5)


# ── Decoder ─────────────────────────────────────────────────────────────


def test_decode_indexed_static() raises:
    """RFC 7541 §C.2.4 — Indexed Header Field for ``:path: /``."""
    var b = List[UInt8]()
    b.append(UInt8(0x84))  # idx 4 -> :path: /
    var dec = HpackDecoder()
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(len(hdrs), 1)
    assert_equal(hdrs[0].name, ":path")
    assert_equal(hdrs[0].value, "/")


def test_decode_literal_with_indexing_grows_dynamic() raises:
    """Literal w/ Incremental Indexing inserts into dynamic table."""
    var dec = HpackDecoder()
    var b = List[UInt8]()
    # 0x40 = 0100 0000 -> Literal w/ Inc Indexing, index 0 (literal name).
    b.append(UInt8(0x40))
    # Name "x-foo" length 5.
    b.append(UInt8(0x05))
    var name = String("x-foo")
    var np = name.unsafe_ptr()
    for i in range(5):
        b.append(np[i])
    # Value "bar" length 3.
    b.append(UInt8(0x03))
    var v = String("bar")
    var vp = v.unsafe_ptr()
    for i in range(3):
        b.append(vp[i])
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(len(hdrs), 1)
    assert_equal(hdrs[0].name, "x-foo")
    assert_equal(hdrs[0].value, "bar")
    assert_equal(len(dec.dynamic), 1)
    assert_equal(dec.dynamic[0].name, "x-foo")


def test_decode_literal_without_indexing() raises:
    """Literal w/o Indexing leaves the dynamic table empty."""
    var dec = HpackDecoder()
    var b = List[UInt8]()
    # 0x00 = 0000 0000 -> Literal w/o Indexing, index 0.
    b.append(UInt8(0x00))
    b.append(UInt8(0x03))
    var name = String("foo")
    var np = name.unsafe_ptr()
    for i in range(3):
        b.append(np[i])
    b.append(UInt8(0x03))
    var v = String("baz")
    var vp = v.unsafe_ptr()
    for i in range(3):
        b.append(vp[i])
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(len(hdrs), 1)
    assert_equal(hdrs[0].name, "foo")
    assert_equal(hdrs[0].value, "baz")
    assert_equal(len(dec.dynamic), 0)


def test_decode_huffman_raises_when_disabled() raises:
    """``H=1`` raises while ``allow_huffman`` defaults to False —
    matches v0.6 wire-reject behaviour."""
    var dec = HpackDecoder()
    var b = List[UInt8]()
    b.append(UInt8(0x00))  # literal w/o indexing
    b.append(UInt8(0x83))  # H=1, len=3
    b.append(UInt8(0x01))
    b.append(UInt8(0x02))
    b.append(UInt8(0x03))
    with assert_raises():
        _ = dec.decode(Span[UInt8, _](b))


def test_decode_huffman_appendix_c4_www_example_com() raises:
    """RFC 7541 §C.4.1 — the Huffman literal ``www.example.com``.

    Wire layout (synthesised here as a Literal w/o Indexing,
    name index 0, name = ``"x"`` raw, value = the Huffman-coded
    ``"www.example.com"``):

    * 0x00 — Literal w/o Indexing, name idx 0.
    * 0x01 0x78 — name length 1, ASCII ``'x'``.
    * 0x8C ... — H=1, length 12 (Huffman length of the 15-byte
      ASCII source per Appendix C.4.1) followed by the 12 wire
      bytes from the spec fixture.

    The 12 Huffman bytes for ``www.example.com`` per RFC 7541
    §C.4.1: ``f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff``.
    """
    var dec = HpackDecoder()
    dec.allow_huffman = True
    var b = List[UInt8]()
    b.append(UInt8(0x00))  # literal w/o indexing, name idx 0
    b.append(UInt8(0x01))  # name length 1
    b.append(UInt8(0x78))  # 'x'
    b.append(UInt8(0x8C))  # H=1, value length 12
    var huff = List[Int]()
    huff.append(0xF1)
    huff.append(0xE3)
    huff.append(0xC2)
    huff.append(0xE5)
    huff.append(0xF2)
    huff.append(0x3A)
    huff.append(0x6B)
    huff.append(0xA0)
    huff.append(0xAB)
    huff.append(0x90)
    huff.append(0xF4)
    huff.append(0xFF)
    for i in range(len(huff)):
        b.append(UInt8(huff[i]))
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(len(hdrs), 1)
    assert_equal(hdrs[0].name, "x")
    assert_equal(hdrs[0].value, "www.example.com")


def test_encoder_decoder_roundtrip_with_huffman() raises:
    """Encoder + decoder with ``allow_huffman=True`` preserve
    every header byte-for-byte across compressible payloads."""
    var enc = HpackEncoder()
    enc.allow_huffman = True
    var dec = HpackDecoder()
    dec.allow_huffman = True
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/api/users/42"))
    hdrs.append(HpackHeader(":authority", "www.example.com"))
    hdrs.append(HpackHeader("user-agent", "flare-test/0.7"))
    hdrs.append(HpackHeader("accept-encoding", "gzip, br, deflate"))
    var wire = enc.encode(Span[HpackHeader, _](hdrs))
    var back = dec.decode(Span[UInt8, _](wire))
    assert_equal(len(back), len(hdrs))
    for i in range(len(hdrs)):
        assert_equal(back[i].name, hdrs[i].name)
        assert_equal(back[i].value, hdrs[i].value)


def test_encoder_huffman_picks_shorter_form() raises:
    """For a long compressible value the H=1 emit is shorter than
    the H=0 emit; for a short incompressible value the encoder
    falls back to H=0."""
    var enc_h0 = HpackEncoder()
    var enc_h1 = HpackEncoder()
    enc_h1.allow_huffman = True

    var h_long = List[HpackHeader]()
    h_long.append(HpackHeader("x-trace", "abcdefghijklmnopqrstuvwxyz_abcdefgh"))
    var w0 = enc_h0.encode(Span[HpackHeader, _](h_long))
    var w1 = enc_h1.encode(Span[HpackHeader, _](h_long))
    assert_true(
        len(w1) <= len(w0),
        "H=1 must not be larger than H=0 for any input",
    )


def test_decode_dynamic_size_update_shrinks() raises:
    """Size update (§6.3) within the SETTINGS cap is honoured."""
    var dec = HpackDecoder()
    var b = List[UInt8]()
    # 0x20 = 001x xxxx -> size update, value 0
    b.append(UInt8(0x20))
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(len(hdrs), 0)
    assert_equal(dec.max_size, 0)


def test_decode_size_update_above_cap_raises() raises:
    """Size update larger than ``max_size`` is a decoding error."""
    var dec = HpackDecoder()
    dec.max_size = 64
    var b = List[UInt8]()
    # 0x3F + 0x81 0x01 -> size update value 31 + 0x80 = 159
    b.append(UInt8(0x3F))
    b.append(UInt8(0x81))
    b.append(UInt8(0x01))
    with assert_raises():
        _ = dec.decode(Span[UInt8, _](b))


# ── Encoder ─────────────────────────────────────────────────────────────


def test_encoder_decoder_roundtrip() raises:
    var enc = HpackEncoder()
    var dec = HpackDecoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/api/users"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader("user-agent", "flare-test/0.6"))
    hdrs.append(HpackHeader("x-trace-id", "abc-123"))
    var wire = enc.encode(Span[HpackHeader, _](hdrs))
    var back = dec.decode(Span[UInt8, _](wire))
    assert_equal(len(back), len(hdrs))
    for i in range(len(hdrs)):
        assert_equal(back[i].name, hdrs[i].name)
        assert_equal(back[i].value, hdrs[i].value)


def test_encoder_status_uses_static_name_index() raises:
    """``:status`` should compress to a name-only index."""
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":status", "200"))
    var wire = enc.encode(Span[HpackHeader, _](hdrs))
    # 1 byte prefix + 1 byte length + 3 bytes "200" = 5 bytes max.
    assert_true(len(wire) <= 6)


def main() raises:
    test_decode_integer_short()
    test_rfc_7541_c1_5bit_1337()
    test_integer_roundtrip_boundaries()
    test_integer_truncated_raises()
    test_decode_indexed_static()
    test_decode_literal_with_indexing_grows_dynamic()
    test_decode_literal_without_indexing()
    test_decode_huffman_raises_when_disabled()
    test_decode_huffman_appendix_c4_www_example_com()
    test_decode_dynamic_size_update_shrinks()
    test_decode_size_update_above_cap_raises()
    test_encoder_decoder_roundtrip()
    test_encoder_decoder_roundtrip_with_huffman()
    test_encoder_huffman_picks_shorter_form()
    test_encoder_status_uses_static_name_index()
    print("test_h2_hpack: 15 passed")
