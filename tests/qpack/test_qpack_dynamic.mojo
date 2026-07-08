"""QPACK dynamic table + encoder/decoder stream instructions (RFC 9204).

Pins the dynamic-table machinery the static-only codec lacked: capacity
eviction + absolute index resolution, the encoder-stream insertion
instructions (literal name, name reference, duplicate, set capacity)
replayed into a table, the decoder-stream acknowledgements, the Required
Insert Count wire codec, and a full encoder -> decoder round-trip where a
field section references dynamic entries by relative and post-base index.
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.qpack import QpackHeader
from flare.qpack.dynamic import (
    DEC_INSTR_INSERT_COUNT_INCREMENT,
    DEC_INSTR_SECTION_ACK,
    QpackDecoder,
    QpackDynamicTable,
    QpackEncoder,
    apply_encoder_instructions,
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
    var t = QpackDynamicTable(0)
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
    print("test_qpack_dynamic: all dynamic-table tests passed")
