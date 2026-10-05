"""QPACK dynamic table + encoder/decoder stream instructions (RFC 9204).

Pins the dynamic-table machinery the static-only codec lacked: capacity
eviction + absolute index resolution, the encoder-stream insertion
instructions (literal name, name reference, duplicate, set capacity)
replayed into a table, the decoder-stream acknowledgements, the Required
Insert Count wire codec, and a full encoder -> decoder round-trip where a
field section references dynamic entries by relative and post-base index.
"""

from std.collections import List
from std.collections.span import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.qpack import QpackHeader
from flare.qpack.dynamic import (
    DEC_INSTR_INSERT_COUNT_INCREMENT,
    DEC_INSTR_SECTION_ACK,
    QpackDecoder,
    QpackDynamicTable,
    QpackEncoder,
    apply_encoder_instructions,
    apply_encoder_instructions_partial,
    decode_field_section_dynamic,
    decode_required_insert_count,
    encode_duplicate,
    encode_field_section_dynamic,
    encode_insert_count_increment,
    encode_insert_with_literal_name,
    encode_insert_with_name_ref,
    encode_required_insert_count,
    encode_section_ack,
    encode_set_capacity,
    entry_size,
    parse_decoder_instruction,
)


def test_entry_size() raises:
    # name(4) + value(3) + 32 overhead.
    assert_equal(entry_size(QpackHeader("name", "val")), UInt64(39))


def test_table_insert_and_index() raises:
    var t = QpackDynamicTable(4096)
    assert_true(t.insert(QpackHeader("a", "1")))
    assert_true(t.insert(QpackHeader("b", "2")))
    assert_equal(t.insert_count(), UInt64(2))
    # abs 0 is the first inserted.
    assert_equal(t.get_abs(0).name, String("a"))
    assert_equal(t.get_abs(1).value, String("2"))
    assert_equal(t.find(QpackHeader("b", "2")), 1)
    assert_equal(t.find_name("a"), 0)


def test_table_eviction() raises:
    # Capacity fits exactly two 33-byte entries (name 1 + val 0 + 32).
    var t = QpackDynamicTable(66)
    assert_true(t.insert(QpackHeader("a", "")))
    assert_true(t.insert(QpackHeader("b", "")))
    assert_equal(len(t.entries), 2)
    # Third insert evicts the oldest ("a").
    assert_true(t.insert(QpackHeader("c", "")))
    assert_equal(len(t.entries), 2)
    assert_equal(t.dropped, UInt64(1))
    assert_equal(t.insert_count(), UInt64(3))
    assert_equal(t.get_abs(1).name, String("b"))
    assert_equal(t.get_abs(2).name, String("c"))
    # abs 0 was evicted.
    var threw = False
    try:
        _ = t.get_abs(0)
    except:
        threw = True
    assert_true(threw)


def test_insert_too_big_fails() raises:
    var t = QpackDynamicTable(40)
    # entry size = 1 + 20 + 32 = 53 > 40.
    assert_false(t.insert(QpackHeader("k", "x" * 20)))


def test_required_insert_count_roundtrip() raises:
    var max_entries: UInt64 = 16
    # ric 0 encodes to 0.
    assert_equal(encode_required_insert_count(0, max_entries), UInt64(0))
    assert_equal(decode_required_insert_count(0, 10, max_entries), UInt64(0))
    # Non-zero round-trips through the wrapping encoder for a range of
    # values within the live window.
    for ric in range(1, 20):
        var enc = encode_required_insert_count(UInt64(ric), max_entries)
        var dec = decode_required_insert_count(enc, UInt64(ric), max_entries)
        assert_equal(dec, UInt64(ric))


def test_apply_encoder_instructions_literal() raises:
    var enc = List[UInt8]()
    encode_set_capacity(enc, 4096)
    encode_insert_with_literal_name(enc, "x-custom", "hello")
    # Advertised 4096. This built the table with 0 and still accepted
    # the 4096 capacity, which is the bug test_capacity_above_... pins.
    var t = QpackDynamicTable(4096)
    var n = apply_encoder_instructions(t, Span[UInt8, _](enc))
    assert_equal(n, 1)
    assert_equal(t.capacity, UInt64(4096))
    assert_equal(t.get_abs(0).name, String("x-custom"))
    assert_equal(t.get_abs(0).value, String("hello"))


def test_apply_encoder_instructions_name_ref_and_dup() raises:
    var t = QpackDynamicTable(4096)
    var enc = List[UInt8]()
    # Insert with static name ref: index 0 is ":authority" -> value.
    encode_insert_with_name_ref(enc, is_static=True, name_index=0, value="ex")
    var n = apply_encoder_instructions(t, Span[UInt8, _](enc))
    assert_equal(n, 1)
    assert_equal(t.get_abs(0).name, String(":authority"))
    assert_equal(t.get_abs(0).value, String("ex"))
    # Duplicate the most-recent (relative 0).
    var enc2 = List[UInt8]()
    encode_duplicate(enc2, 0)
    _ = apply_encoder_instructions(t, Span[UInt8, _](enc2))
    assert_equal(t.insert_count(), UInt64(2))
    assert_equal(t.get_abs(1).name, String(":authority"))


def test_decoder_stream_instructions() raises:
    var out = List[UInt8]()
    encode_section_ack(out, 5)
    encode_insert_count_increment(out, 3)
    var i0 = parse_decoder_instruction(Span[UInt8, _](out), 0)
    assert_equal(i0.kind, DEC_INSTR_SECTION_ACK)
    assert_equal(i0.value, UInt64(5))
    var i1 = parse_decoder_instruction(Span[UInt8, _](out), i0.offset)
    assert_equal(i1.kind, DEC_INSTR_INSERT_COUNT_INCREMENT)
    assert_equal(i1.value, UInt64(3))


def test_field_section_dynamic_roundtrip() raises:
    # Encoder inserts two entries, streams them to a decoder, then
    # encodes a field section referencing them; decoder resolves it.
    var enc_stream = List[UInt8]()
    var encoder = QpackEncoder(4096)
    encoder.set_capacity(4096, enc_stream)
    _ = encoder.insert("x-trace", "abc", enc_stream)
    _ = encoder.insert("x-shard", "07", enc_stream)

    var decoder = QpackDecoder(4096)
    var applied = decoder.feed_encoder_stream(Span[UInt8, _](enc_stream))
    assert_equal(applied, 2)
    assert_equal(decoder.pending_increment, 2)

    var headers = List[QpackHeader]()
    headers.append(QpackHeader("x-trace", "abc"))  # dynamic full match
    headers.append(QpackHeader("x-shard", "99"))  # dynamic name match
    headers.append(QpackHeader(":method", "GET"))  # static full match
    var field = List[UInt8]()
    encoder.encode(headers, field)

    var got = decoder.decode(Span[UInt8, _](field))
    assert_equal(len(got), 3)
    assert_equal(got[0].name, String("x-trace"))
    assert_equal(got[0].value, String("abc"))
    assert_equal(got[1].name, String("x-shard"))
    assert_equal(got[1].value, String("99"))
    assert_equal(got[2].name, String(":method"))
    assert_equal(got[2].value, String("GET"))

    # The decoder owes an Insert Count Increment of 2.
    var dec_stream = List[UInt8]()
    assert_true(decoder.take_increment(dec_stream))
    var instr = parse_decoder_instruction(Span[UInt8, _](dec_stream), 0)
    assert_equal(instr.kind, DEC_INSTR_INSERT_COUNT_INCREMENT)
    assert_equal(instr.value, UInt64(2))
    assert_false(decoder.take_increment(dec_stream))


def test_blocked_section_raises() raises:
    # A field section whose Required Insert Count exceeds what the
    # decoder has received must fail rather than mis-resolve.
    var encoder = QpackEncoder(4096)
    var es = List[UInt8]()
    _ = encoder.insert("a", "1", es)
    var headers = List[QpackHeader]()
    headers.append(QpackHeader("a", "1"))
    var field = List[UInt8]()
    encoder.encode(headers, field)
    # Fresh decoder that never saw the insert.
    var decoder = QpackDecoder(4096)
    var threw = False
    try:
        _ = decoder.decode(Span[UInt8, _](field))
    except:
        threw = True
    assert_true(threw)


def test_capacity_above_the_advertised_limit_is_refused() raises:
    """Set Dynamic Table Capacity took any value, so a peer could size
    our table past the limit we advertised (0 by default) and fill it.
    It is an encoder-stream error now, and the partial parser no longer
    swallows it as a truncated instruction."""
    from flare.qpack.dynamic import (
        apply_encoder_instructions_partial,
        encode_set_capacity,
    )

    var t = QpackDynamicTable(UInt64(0))
    var stream = List[UInt8]()
    encode_set_capacity(stream, UInt64(1 << 20))
    var raised = False
    try:
        _ = apply_encoder_instructions_partial(t, Span[UInt8, _](stream))
    except e:
        raised = "QPACK_ENCODER_STREAM_ERROR" in String(e)
    assert_true(raised, "a capacity above the advertised 0 was accepted")
    assert_equal(Int(t.capacity), 0)
    # Within the advertised limit is fine.
    var t2 = QpackDynamicTable(UInt64(4096))
    var ok_stream = List[UInt8]()
    encode_set_capacity(ok_stream, UInt64(1024))
    _ = apply_encoder_instructions_partial(t2, Span[UInt8, _](ok_stream))
    assert_equal(Int(t2.capacity), 1024)


def test_non_utf8_literal_on_the_encoder_stream_is_an_error() raises:
    """QPACK-03: an Insert With Literal Name whose value is not UTF-8
    is an encoder-stream error, not a truncated instruction to retry
    (the partial parser used to read the failure as truncation)."""
    var t = QpackDynamicTable(UInt64(4096))
    var stream = List[UInt8]()
    encode_set_capacity(stream, UInt64(1024))
    # 01H NNNNN: raw name "a" (len 1), then raw value of length 1: 0xFF.
    stream.append(UInt8(0x41))
    stream.append(UInt8(0x61))
    stream.append(UInt8(0x01))
    stream.append(UInt8(0xFF))
    var raised = False
    try:
        _ = apply_encoder_instructions_partial(t, Span[UInt8, _](stream))
    except e:
        raised = "QPACK_ENCODER_STREAM_ERROR" in String(e)
    assert_true(raised, "a non-UTF-8 literal was swallowed")
    assert_equal(t.insert_count(), 0)


def _partial_error(mut table: QpackDynamicTable, instr: List[UInt8]) -> String:
    """The error text of ``apply_encoder_instructions_partial``, or ""."""
    try:
        _ = apply_encoder_instructions_partial(table, Span[UInt8, _](instr))
    except e:
        return String(e)
    return String("")


def test_name_ref_into_an_empty_table_is_an_encoder_stream_error() raises:
    """QPACK-04: ``insert_count() - 1 - ip`` wrapped, ``get_abs`` raised an
    untagged error and the partial parser read it as a truncated
    instruction, so the stream stalled instead of failing."""
    var t = QpackDynamicTable(UInt64(4096))
    var instr = List[UInt8]()
    instr.append(UInt8(0x80))  # Insert With Name Reference, T=0, index 0
    instr.append(UInt8(0x00))  # empty value
    assert_true(
        "QPACK_ENCODER_STREAM_ERROR" in _partial_error(t, instr),
        "a dynamic name reference into an empty table stalled",
    )
    assert_equal(t.insert_count(), 0)
    # The all-at-once replayer refuses it too.
    var raised = False
    try:
        _ = apply_encoder_instructions(t, Span[UInt8, _](instr))
    except:
        raised = True
    assert_true(raised)


def test_name_ref_past_the_live_entries_is_an_encoder_stream_error() raises:
    var t = QpackDynamicTable(UInt64(66))
    assert_true(t.insert(QpackHeader("a", "b")))
    assert_true(t.insert(QpackHeader("c", "d")))  # evicts abs 0
    assert_equal(Int(t.dropped), 1)
    # Relative index 1 names abs 0, which was evicted.
    var evicted = List[UInt8]()
    evicted.append(UInt8(0x81))
    evicted.append(UInt8(0x00))
    assert_true("QPACK_ENCODER_STREAM_ERROR" in _partial_error(t, evicted))
    # Relative index 5 is beyond everything ever inserted.
    var far = List[UInt8]()
    far.append(UInt8(0x85))
    far.append(UInt8(0x00))
    assert_true("QPACK_ENCODER_STREAM_ERROR" in _partial_error(t, far))
    assert_equal(t.insert_count(), 2)
    # Relative index 0 (abs 1) is live and applies.
    var ok = List[UInt8]()
    ok.append(UInt8(0x80))
    ok.append(UInt8(0x01))
    ok.append(UInt8(0x78))  # value "x"
    var r = apply_encoder_instructions_partial(t, Span[UInt8, _](ok))
    assert_equal(r[0], 1)
    assert_equal(r[1], 3)


def test_duplicate_of_a_missing_entry_is_an_encoder_stream_error() raises:
    var t = QpackDynamicTable(UInt64(4096))
    var instr = List[UInt8]()
    instr.append(UInt8(0x00))  # Duplicate, relative index 0, empty table
    assert_true("QPACK_ENCODER_STREAM_ERROR" in _partial_error(t, instr))
    assert_true(t.insert(QpackHeader("a", "b")))
    var beyond = List[UInt8]()
    beyond.append(UInt8(0x03))  # relative index 3, only abs 0 exists
    assert_true("QPACK_ENCODER_STREAM_ERROR" in _partial_error(t, beyond))
    var ok = List[UInt8]()
    ok.append(UInt8(0x00))
    var r = apply_encoder_instructions_partial(t, Span[UInt8, _](ok))
    assert_equal(r[0], 1)
    assert_equal(t.insert_count(), 2)


def test_truncated_valid_name_ref_still_waits_for_more_bytes() raises:
    """The fix must not turn a chunk boundary into an error: a valid
    reference whose value literal is cut short is still retried."""
    var t = QpackDynamicTable(UInt64(4096))
    assert_true(t.insert(QpackHeader("a", "b")))
    var cut = List[UInt8]()
    cut.append(UInt8(0x80))  # valid reference to abs 0
    cut.append(UInt8(0x05))  # value length 5, no bytes follow
    var r = apply_encoder_instructions_partial(t, Span[UInt8, _](cut))
    assert_equal(r[0], 0)
    assert_equal(r[1], 0)
    assert_equal(t.insert_count(), 1)


def _decode_raises(sec: List[UInt8], table: QpackDynamicTable) -> Bool:
    try:
        _ = decode_field_section_dynamic(Span[UInt8, _](sec), table)
    except:
        return True
    return False


def test_ric_zero_section_cannot_read_the_dynamic_table() raises:
    """QPACK-01: RIC 0, Sign 1, Delta Base 0 made Base wrap to 2^64 - 1,
    so post-base index 1 resolved to absolute index 0 although the
    section declared no dynamic reference (RFC 9204 4.5.1.2, 4.5.1)."""
    var t = QpackDynamicTable(4096)
    assert_true(t.insert(QpackHeader("x-secret", "dynamic-entry-0")))
    var sec = List[UInt8]()
    sec.append(0x00)  # Required Insert Count 0
    sec.append(0x80)  # Sign 1, Delta Base 0
    sec.append(0x11)  # post-base indexed line, index 1
    assert_true(_decode_raises(sec, t), "RIC 0 / Sign 1 section was decoded")


def test_sign_set_with_delta_base_not_below_ric_is_refused() raises:
    """QPACK-01: Sign 1 requires Delta Base < Required Insert Count."""
    var t = QpackDynamicTable(4096)
    assert_true(t.insert(QpackHeader("a", "1")))
    assert_true(t.insert(QpackHeader("b", "2")))
    # RIC 1 (encoded 2), Sign 1, Delta Base 1 -> RIC <= Delta Base.
    var bad = List[UInt8]()
    bad.append(0x02)
    bad.append(0x81)
    bad.append(0x80)
    assert_true(_decode_raises(bad, t), "Sign 1 with Delta Base == RIC")
    # Delta Base 0 is valid: Base = 0, so only post-base lines resolve.
    var ok = List[UInt8]()
    ok.append(0x02)
    ok.append(0x80)
    ok.append(0x10)  # post-base index 0 -> absolute 0 < RIC 1
    var got = decode_field_section_dynamic(Span[UInt8, _](ok), t)
    assert_equal(len(got), 1)
    assert_equal(got[0].name, String("a"))


def test_post_base_reference_at_or_above_ric_is_refused() raises:
    """QPACK-01: an absolute index >= Required Insert Count is a
    decompression failure even when the table holds that entry."""
    var t = QpackDynamicTable(4096)
    assert_true(t.insert(QpackHeader("a", "1")))
    assert_true(t.insert(QpackHeader("b", "2")))
    var sec = List[UInt8]()
    sec.append(0x02)  # RIC 1 (MaxEntries 128)
    sec.append(0x00)  # Base = 1
    sec.append(0x10)  # post-base index 0 -> absolute 1 >= RIC
    assert_true(_decode_raises(sec, t), "absolute index 1 with RIC 1")
    # Pre-base relative index 0 -> absolute 0 is the legal reference.
    var ok = List[UInt8]()
    ok.append(0x02)
    ok.append(0x00)
    ok.append(0x80)
    var got = decode_field_section_dynamic(Span[UInt8, _](ok), t)
    assert_equal(len(got), 1)
    assert_equal(got[0].value, String("1"))


def test_pre_base_relative_index_beyond_base_is_refused() raises:
    """QPACK-01: a relative index >= Base must not wrap around."""
    var t = QpackDynamicTable(4096)
    assert_true(t.insert(QpackHeader("a", "1")))
    var sec = List[UInt8]()
    sec.append(0x02)  # RIC 1
    sec.append(0x00)  # Base = 1
    sec.append(0x81)  # pre-base relative index 1 >= Base
    assert_true(_decode_raises(sec, t), "relative index 1 with Base 1")


def test_truncated_prefix_without_sign_byte_is_refused() raises:
    """QPACK-02: ``FF 01`` is a complete 8-bit-prefix integer (256) that
    ends exactly at the end of the section, so the Sign / Delta Base byte
    is missing. The decoder read ``buf[2]`` one past the end and aborted
    the process; it must raise (RFC 9204 4.5.1)."""
    # Capacity 8192 -> MaxEntries 256, so Required Insert Count 256 decodes.
    var t = QpackDynamicTable(8192)
    var sec = List[UInt8]()
    sec.append(0xFF)
    sec.append(0x01)
    assert_true(_decode_raises(sec, t), "section without a Sign byte decoded")
    # A single byte is truncated too.
    var one = List[UInt8]()
    one.append(0x00)
    assert_true(_decode_raises(one, t), "one-byte prefix decoded")


def main() raises:
    test_entry_size()
    test_table_insert_and_index()
    test_table_eviction()
    test_insert_too_big_fails()
    test_required_insert_count_roundtrip()
    test_apply_encoder_instructions_literal()
    test_apply_encoder_instructions_name_ref_and_dup()
    test_decoder_stream_instructions()
    test_field_section_dynamic_roundtrip()
    test_blocked_section_raises()
    test_capacity_above_the_advertised_limit_is_refused()
    test_ric_zero_section_cannot_read_the_dynamic_table()
    test_sign_set_with_delta_base_not_below_ric_is_refused()
    test_post_base_reference_at_or_above_ric_is_refused()
    test_pre_base_relative_index_beyond_base_is_refused()
    test_truncated_prefix_without_sign_byte_is_refused()
    test_non_utf8_literal_on_the_encoder_stream_is_an_error()
    test_name_ref_into_an_empty_table_is_an_encoder_stream_error()
    test_name_ref_past_the_live_entries_is_an_encoder_stream_error()
    test_duplicate_of_a_missing_entry_is_an_encoder_stream_error()
    test_truncated_valid_name_ref_still_waits_for_more_bytes()
    print("test_qpack_dynamic: all dynamic-table tests passed")
