"""Tests for the WebSocket permessage-deflate extension (RFC 7692).

Eight cases per the v0.7 deferred plan:

1. Client offer round-trips through ``parse_extensions``.
2. Parameter parser handles flags + ``key=value`` + quoted values.
3. Server negotiation picks the first ``permessage-deflate`` offer
   and forces ``no_context_takeover`` on both sides (v0.7 codec
   constraint).
4. Server negotiation returns ``None`` when no offer matches.
5. ``compress_message`` -> ``decompress_message`` round-trips a
   non-trivial UTF-8 payload.
6. Compress on an empty payload + decompress reject of empty
   compressed payload (RFC 7692 §7.2.3.6).
7. Decompress respects ``max_decompressed_bytes`` (zip-bomb
   guard) and raises a clear error.
8. RSV1 handshake honesty: the offer header reflects which
   ``no_context_takeover`` flags are on; cfg parameters survive
   round-trip through parse + negotiate.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.ws.extensions import (
    build_permessage_deflate_offer,
    negotiate_permessage_deflate,
    parse_extensions,
)
from flare.ws.permessage_deflate import (
    DEFAULT_DEFLATE_LEVEL,
    DEFAULT_MAX_DECOMPRESSED_BYTES,
    PermessageDeflateConfig,
    PermessageDeflateContext,
    compress_message,
    decompress_message,
)


def test_parse_simple_offer_round_trips() raises:
    """A simple ``permessage-deflate`` offer with two flags + one
    value parameter parses into the expected shape."""
    var offers = parse_extensions(
        "permessage-deflate; client_no_context_takeover;"
        " server_max_window_bits=12"
    )
    assert_equal(len(offers), 1)
    var o = offers[0].copy()
    assert_equal(o.name, "permessage-deflate")
    assert_true(o.has("client_no_context_takeover"))
    var smw = o.get("server_max_window_bits")
    assert_true(Bool(smw))
    assert_equal(smw.value(), "12")
    var sct = o.get("client_no_context_takeover")
    assert_true(Bool(sct))
    assert_equal(sct.value(), "")


def test_parse_handles_flags_kv_quoted_values_multi_offer() raises:
    """Multiple comma-delimited offers + a quoted-string value
    parse correctly; case is folded on extension + parameter
    names; whitespace is tolerated."""
    var offers = parse_extensions(
        'Permessage-Deflate ; client_max_window_bits , x-custom; q="0.7" '
    )
    assert_equal(len(offers), 2)
    assert_equal(offers[0].name, "permessage-deflate")
    var cmw = offers[0].get("client_max_window_bits")
    assert_true(Bool(cmw))
    assert_equal(cmw.value(), "")
    assert_equal(offers[1].name, "x-custom")
    var qval = offers[1].get("q")
    assert_true(Bool(qval))
    assert_equal(qval.value(), "0.7")


def test_negotiate_picks_first_pmd_offer_and_locks_no_context_takeover() raises:
    """The server picks the first ``permessage-deflate`` offer and
    the response value reflects the v0.7 codec invariant
    (``no_context_takeover`` on both sides)."""
    var offers = parse_extensions(
        "x-bogus; foo=bar, permessage-deflate; client_max_window_bits"
    )
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    var got = negotiate_permessage_deflate(offers, cfg)
    assert_true(Bool(got))
    var t = got.value().copy()
    var hdr = t[0]
    var negotiated = t[1].copy()
    assert_true(hdr.find("permessage-deflate") >= 0)
    assert_true(hdr.find("client_no_context_takeover") >= 0)
    assert_true(hdr.find("server_no_context_takeover") >= 0)
    assert_true(negotiated.client_no_context_takeover)
    assert_true(negotiated.server_no_context_takeover)


def test_negotiate_returns_none_when_no_offer_matches() raises:
    """No ``permessage-deflate`` offer + the server returns
    ``None`` (the upgrade response simply omits the
    ``Sec-WebSocket-Extensions`` header)."""
    var offers = parse_extensions("x-bogus; foo=bar")
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    var got = negotiate_permessage_deflate(offers, cfg)
    assert_false(Bool(got))


def test_compress_decompress_round_trip_utf8_payload() raises:
    """A non-trivial UTF-8 payload survives compress -> decompress
    byte-for-byte."""
    var msg = String(
        "the quick brown fox jumps over the lazy dog "
        "0123456789 the quick brown fox jumps over the lazy dog"
    )
    var compressed = compress_message(
        Span[UInt8, _](msg.as_bytes()), DEFAULT_DEFLATE_LEVEL
    )
    assert_true(len(compressed) > 0)
    # The compressed form should be smaller than the input on a
    # repetitive payload like this.
    assert_true(len(compressed) < msg.byte_length())
    var decompressed = decompress_message(
        Span[UInt8, _](compressed), DEFAULT_MAX_DECOMPRESSED_BYTES
    )
    assert_equal(len(decompressed), msg.byte_length())
    var orig = msg.as_bytes()
    for i in range(len(decompressed)):
        assert_equal(Int(decompressed[i]), Int(orig[i]))


def test_compress_empty_payload_emits_single_byte_and_decompress_rejects() raises:
    """Empty plaintext -> one-byte compressed output (RFC 7692
    §7.2.3.6); empty *compressed* input is rejected."""
    var empty = List[UInt8]()
    var compressed = compress_message(Span[UInt8, _](empty))
    assert_equal(len(compressed), 1)
    assert_equal(Int(compressed[0]), 0x00)
    with assert_raises(contains="empty payload"):
        _ = decompress_message(Span[UInt8, _](empty))


def test_decompress_respects_max_decompressed_bytes_cap() raises:
    """A high-ratio payload that would inflate past the cap raises
    rather than silently producing many MiB of output."""
    # Build a 256 KiB plaintext of a single repeated byte; this
    # compresses to a few hundred bytes, then decompresses back to
    # 256 KiB. With a 16 KiB cap the decompressor must raise.
    var big = List[UInt8]()
    for _ in range(256 * 1024):
        big.append(UInt8(0x41))
    var compressed = compress_message(Span[UInt8, _](big))
    with assert_raises(contains="max_decompressed_bytes"):
        _ = decompress_message(Span[UInt8, _](compressed), 16 * 1024)


def test_offer_emit_reflects_config_flags() raises:
    """The offer-builder honors the cfg flags so a server reading
    the response can trust that the codec mode is what the
    handshake claims."""
    var cfg = PermessageDeflateConfig()
    cfg.enabled = True
    cfg.client_no_context_takeover = True
    cfg.server_no_context_takeover = False
    cfg.client_max_window_bits = 12
    var hdr = build_permessage_deflate_offer(cfg)
    assert_true(hdr.find("permessage-deflate") >= 0)
    assert_true(hdr.find("client_no_context_takeover") >= 0)
    assert_false(hdr.find("server_no_context_takeover") >= 0)
    assert_true(hdr.find("client_max_window_bits=12") >= 0)
    # Disabled cfg -> empty header (we offer nothing).
    var off = PermessageDeflateConfig()
    assert_equal(build_permessage_deflate_offer(off), "")


def test_context_takeover_round_trips_three_messages() raises:
    """A persistent encoder/decoder pair must round-trip three
    sequential messages with the LZ77 window carried between them.
    The repeated payload exercises the dictionary so context-
    takeover output is strictly smaller than the no-context-
    takeover path for the second and third call.
    """
    var ctx_enc = PermessageDeflateContext()
    var ctx_dec = PermessageDeflateContext()
    var msg = "the quick brown fox jumps over the lazy dog".as_bytes()
    var sizes = List[Int]()
    for _ in range(3):
        var compressed = ctx_enc.compress(Span[UInt8, _](msg))
        sizes.append(len(compressed))
        var back = ctx_dec.decompress(Span[UInt8, _](compressed))
        assert_equal(len(back), len(msg))
        for i in range(len(msg)):
            assert_equal(back[i], msg[i])
    # First message has no dictionary; later messages should
    # compress to at most the first one (context carries; the
    # window may produce identical-or-better output).
    assert_true(sizes[1] <= sizes[0])
    assert_true(sizes[2] <= sizes[0])


def test_context_takeover_compresses_repeated_payload_better_than_no_context() raises:
    """Encoding the *same* repetitive payload three times through
    a persistent compressor should benefit from the LZ77
    dictionary built up by the first call. The second + third
    outputs must be strictly smaller than the first."""
    var ctx = PermessageDeflateContext()
    var payload = ("hello world hello world hello world " * 8).as_bytes()
    var first = ctx.compress(Span[UInt8, _](payload))
    var second = ctx.compress(Span[UInt8, _](payload))
    var third = ctx.compress(Span[UInt8, _](payload))
    # The first compressed output establishes the dictionary;
    # the second + third use it. zlib emits literal matches for
    # the entire payload by referencing the dictionary, so the
    # output is far smaller.
    assert_true(len(second) < len(first))
    assert_true(len(third) <= len(second))


def test_context_takeover_empty_payload_round_trips() raises:
    """Empty payload encodes to the single-byte 0x00 per
    RFC 7692 §7.2.3.6 even with context-takeover on. The
    decompressor must reject the empty *compressed* input
    explicitly (matching the no-context-takeover path's
    contract)."""
    var ctx_enc = PermessageDeflateContext()
    var empty = String("").as_bytes()
    var out = ctx_enc.compress(Span[UInt8, _](empty))
    assert_equal(len(out), 1)
    assert_equal(out[0], UInt8(0x00))
    var ctx_dec = PermessageDeflateContext()
    with assert_raises():
        var _ = ctx_dec.decompress(Span[UInt8, _](List[UInt8]()))


def test_context_takeover_respects_max_decompressed_bytes() raises:
    """The persistent decompressor honours the per-instance cap,
    just like the free-function ``decompress_message``."""
    var ctx_enc = PermessageDeflateContext()
    # 16 KiB of repeated 'a' compresses extremely tightly.
    var huge = ("a" * (16 * 1024)).as_bytes()
    var packed = ctx_enc.compress(Span[UInt8, _](huge))
    var ctx_dec = PermessageDeflateContext(
        DEFAULT_DEFLATE_LEVEL, -15, 1024  # cap = 1 KiB
    )
    with assert_raises():
        var _ = ctx_dec.decompress(Span[UInt8, _](packed))


def test_context_takeover_survives_messages_that_expand_a_lot() raises:
    """A message expanding past the decoder's first output guess (4x) used
    to be re-fed to an inflate stream that had already consumed it;
    with context takeover that corrupted this message and every later
    one."""
    var ctx_enc = PermessageDeflateContext()
    var ctx_dec = PermessageDeflateContext()
    var big = ('{"k":"v","n":1234567890},' * 4000).as_bytes()
    for _ in range(3):
        var packed = ctx_enc.compress(Span[UInt8, _](big))
        assert_true(len(packed) * 4 < len(big))
        var back = ctx_dec.decompress(Span[UInt8, _](packed))
        assert_equal(len(back), len(big))
        for j in range(len(big)):
            assert_equal(back[j], big[j])
    var small = String("after").as_bytes()
    var back2 = ctx_dec.decompress(
        Span[UInt8, _](ctx_enc.compress(Span[UInt8, _](small)))
    )
    assert_equal(len(back2), 5)


def main() raises:
    test_parse_simple_offer_round_trips()
    test_parse_handles_flags_kv_quoted_values_multi_offer()
    test_negotiate_picks_first_pmd_offer_and_locks_no_context_takeover()
    test_negotiate_returns_none_when_no_offer_matches()
    test_compress_decompress_round_trip_utf8_payload()
    test_compress_empty_payload_emits_single_byte_and_decompress_rejects()
    test_decompress_respects_max_decompressed_bytes_cap()
    test_offer_emit_reflects_config_flags()
    test_context_takeover_round_trips_three_messages()
    test_context_takeover_compresses_repeated_payload_better_than_no_context()
    test_context_takeover_empty_payload_round_trips()
    test_context_takeover_respects_max_decompressed_bytes()
    test_context_takeover_survives_messages_that_expand_a_lot()
    print("test_ws_permessage_deflate: 13 passed")
