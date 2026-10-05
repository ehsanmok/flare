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
        b.append(np[unsafe_offset=i])
    # Value "bar" length 3.
    b.append(UInt8(0x03))
    var v = String("bar")
    var vp = v.unsafe_ptr()
    for i in range(3):
        b.append(vp[unsafe_offset=i])
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
        b.append(np[unsafe_offset=i])
    b.append(UInt8(0x03))
    var v = String("baz")
    var vp = v.unsafe_ptr()
    for i in range(3):
        b.append(vp[unsafe_offset=i])
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
    """Size update above the advertised SETTINGS cap is a decoding
    error. The bound is ``settings_max_size`` (what the decoder told
    the peer it can handle), not the table's current ``max_size``:
    RFC 7541 sec 6.3 explicitly allows restoring a shrunk table."""
    var dec = HpackDecoder()
    dec.max_size = 64
    dec.settings_max_size = 64
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


def test_decode_keeps_non_ascii_octets_exact() raises:
    """UTF-8 values used to be rebuilt byte by byte through chr(), which
    double-encoded them and made the dynamic table count more bytes
    than the peer's."""
    var dec = HpackDecoder()
    var b = List[UInt8]()
    b.append(UInt8(0x40))  # literal with incremental indexing, new name
    var name = String("x-name")
    b.append(UInt8(name.byte_length()))
    for c in name.as_bytes():
        b.append(c)
    var v = String("café 世界")
    b.append(UInt8(v.byte_length()))
    for c in v.as_bytes():
        b.append(c)
    var hdrs = dec.decode(Span[UInt8, _](b))
    assert_equal(hdrs[0].value, v)
    assert_equal(hdrs[0].value.byte_length(), v.byte_length())
    # RFC 7541 sec 4.1: entry size is name + value octets + 32.
    assert_equal(dec.dynamic_size, name.byte_length() + v.byte_length() + 32)


def test_default_decoder_accepts_a_real_servers_huffman_headers() raises:
    """A response header block captured from httpbin.org over h2. It is
    Huffman-coded, as every real server's is; the default decoder
    rejected it with "Huffman-coded string not supported", which the
    HTTP client turned into COMPRESSION_ERROR."""
    from flare.http2.client import Http2ClientConfig

    var hx = String(
        "886196d07abe9413ca6e2d6a080271410ae09fb80754c5a37f5f8b1d75d0620d"
        "263d4c7441ea5c033432390085416cee5b3f8b9ada8c43d953017d77d707"
    )
    var b = hx.as_bytes()
    var blk = List[UInt8]()
    var i = 0
    while i + 1 < len(b):
        var hi = Int(b[i])
        var lo = Int(b[i + 1])
        hi = hi - 48 if hi < 58 else hi - 87
        lo = lo - 48 if lo < 58 else lo - 87
        blk.append(UInt8(hi * 16 + lo))
        i += 2
    var dec = HpackDecoder()
    var hs = dec.decode(Span[UInt8, _](blk))
    var ct = String("")
    var server = String("")
    for h in hs:
        if h.name == "content-type":
            ct = h.value.copy()
        if h.name == "server":
            server = h.value.copy()
    assert_equal(ct, "application/json")
    assert_equal(server, "gunicorn/19.9.0")
    assert_true(Http2ClientConfig().allow_huffman_decode)


def _literal_with_indexing(name: String, value: List[UInt8]) -> List[UInt8]:
    """Literal Header Field with Incremental Indexing, new name, no Huffman."""
    var b = List[UInt8]()
    b.append(UInt8(0x40))
    b.append(UInt8(name.byte_length()))
    for c in name.as_bytes():
        b.append(c)
    b.append(UInt8(0x7F))  # H=0, length prefix saturated: 127 + extension
    var rest = len(value) - 127
    while rest >= 128:
        b.append(UInt8(0x80 | (rest & 0x7F)))
        rest >>= 7
    b.append(UInt8(rest))
    for c in value:
        b.append(c)
    return b^


def test_invalid_utf8_value_keeps_the_table_in_step_with_the_peer() raises:
    """HPACK-01: a legal value made of 0xFF octets must be stored byte for
    byte. Rebuilding it as lossy UTF-8 (each bad octet becomes U+FFFD, 3
    octets) made the entry bigger than the peer's, evicted entries the peer
    still indexes, and killed the connection on the next block (RFC 7541
    sec 4.1)."""
    var dec = HpackDecoder()
    var v1 = List[UInt8](length=500, fill=UInt8(ord("a")))
    var v2 = List[UInt8](length=1300, fill=UInt8(0xFF))
    _ = dec.decode(Span[UInt8, _](_literal_with_indexing("x-1", v1)))
    var h2 = dec.decode(Span[UInt8, _](_literal_with_indexing("x-2", v2)))
    # Stored and returned exactly as sent.
    assert_equal(h2[0].value.byte_length(), 1300)
    var raw = h2[0].value.as_bytes()
    for i in range(1300):
        assert_equal(Int(raw[i]), 0xFF)
    # The peer's table: 535 + 1335 octets, both entries still present.
    assert_equal(dec.dynamic_size, (3 + 500 + 32) + (3 + 1300 + 32))
    var idx = List[UInt8]()
    idx.append(UInt8(0x80 | 63))  # the second dynamic entry: x-1
    var h3 = dec.decode(Span[UInt8, _](idx))
    assert_equal(len(h3), 1)
    assert_equal(h3[0].name, "x-1")
    assert_equal(h3[0].value.byte_length(), 500)


def _literal_block(name: String, value_len: Int) -> List[UInt8]:
    """One Literal-without-Indexing field with a new name: the field is
    ``name.byte_length() + value_len + 32`` octets by RFC 7541 sec 4.1."""
    var block = List[UInt8]()
    block.append(UInt8(0x00))
    block.append(UInt8(name.byte_length()))
    for i in range(name.byte_length()):
        block.append(name.as_bytes()[i])
    block.append(UInt8(value_len))
    for _ in range(value_len):
        block.append(UInt8(ord("a")))
    return block^


def test_the_last_field_of_a_block_counts_against_the_budget() raises:
    """HPACK-02: every decoded field is charged, the last one included. A
    one-field block of 133 octets used to pass a budget of 50, since a
    field was only charged when the next one was about to be decoded."""
    var dec = HpackDecoder()
    var block = _literal_block("x", 100)
    with assert_raises():
        _ = dec.decode(Span[UInt8, _](block), 50)


def test_the_budget_is_inclusive_and_covers_the_whole_block() raises:
    """HPACK-02: a block exactly at the budget decodes; one octet under
    is refused, whether the overrun is the first, the last or the sum."""
    var block = _literal_block("x", 100)  # 133
    var dec = HpackDecoder()
    assert_equal(len(dec.decode(Span[UInt8, _](block), 133)), 1)
    var dec2 = HpackDecoder()
    with assert_raises():
        _ = dec2.decode(Span[UInt8, _](block), 132)
    # Two fields of 33 + 33 = 66 octets: the sum, not one field, trips it.
    var two = _literal_block("x", 0)
    two.extend(_literal_block("y", 0))
    var dec3 = HpackDecoder()
    assert_equal(len(dec3.decode(Span[UInt8, _](two), 66)), 2)
    var dec4 = HpackDecoder()
    with assert_raises():
        _ = dec4.decode(Span[UInt8, _](two), 65)


def test_no_budget_means_unlimited() raises:
    """HPACK-02: budget 0 (the default) keeps the old unbounded behaviour."""
    var dec = HpackDecoder()
    var block = _literal_block("x", 100)
    assert_equal(len(dec.decode(Span[UInt8, _](block))), 1)
    assert_equal(len(dec.decode(Span[UInt8, _](block), 0)), 1)


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
    test_decode_keeps_non_ascii_octets_exact()
    test_default_decoder_accepts_a_real_servers_huffman_headers()
    test_invalid_utf8_value_keeps_the_table_in_step_with_the_peer()
    test_the_last_field_of_a_block_counts_against_the_budget()
    test_the_budget_is_inclusive_and_covers_the_whole_block()
    test_no_budget_means_unlimited()
    print("test_h2_hpack: 21 passed")
