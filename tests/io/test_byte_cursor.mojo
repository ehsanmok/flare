"""Tests for :mod:`flare.io.byte_cursor` (ByteReader / ByteWriter).

Covers big- and little-endian integer reads/writes at every width,
borrowed ``read_bytes`` sub-spans, validated ``read_utf8`` (including
multibyte and rejection of malformed UTF-8), bounds-check raises on
truncated input, and writer->reader round-trips.
"""

from std.testing import assert_equal, assert_true

from flare.io import ByteReader, ByteWriter


def _bytes(*vals: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in vals:
        out.append(UInt8(v))
    return out^


def test_read_unsigned_be() raises:
    var raw = _bytes(
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44
    )
    var r = ByteReader(Span[UInt8, _](raw))
    assert_equal(Int(r.read_u8()), 0x12)
    assert_equal(Int(r.read_u8()), 0x34)
    assert_equal(Int(r.read_u16_be()), 0x5678)
    assert_equal(Int(r.read_u32_be()), 0x9ABCDEF0)
    assert_equal(Int(r.read_u8()), 0x11)
    assert_equal(r.remaining(), 3)


def test_read_unsigned_le() raises:
    var raw = _bytes(0x34, 0x12, 0x78, 0x56, 0x34, 0x12)
    var r = ByteReader(Span[UInt8, _](raw))
    assert_equal(Int(r.read_u16_le()), 0x1234)
    assert_equal(Int(r.read_u32_le()), 0x12345678)
    assert_equal(r.remaining(), 0)


def test_read_u64_round_trip_both_endians() raises:
    var w = ByteWriter()
    w.write_u64_be(0x0102030405060708)
    w.write_u64_le(0x0102030405060708)
    var buf = w.take()
    var r = ByteReader(Span[UInt8, _](buf))
    assert_equal(Int(r.read_u64_be()), 0x0102030405060708)
    assert_equal(Int(r.read_u64_le()), 0x0102030405060708)


def test_read_bytes_borrowed() raises:
    var raw = _bytes(0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63)
    var r = ByteReader(Span[UInt8, _](raw))
    var n = r.read_u32_be()
    assert_equal(Int(n), 3)
    var s = r.read_bytes(Int(n))
    assert_equal(len(s), 3)
    assert_equal(Int(s[0]), 0x61)
    assert_equal(Int(s[2]), 0x63)
    assert_equal(r.remaining(), 0)


def test_read_utf8_valid_ascii_and_multibyte() raises:
    # Mix of ASCII, 2-byte (ä, é), and 3-byte (€) sequences.
    var w = ByteWriter()
    w.write_str("héllo wörld €")
    var buf = w.take()
    var r = ByteReader(Span[UInt8, _](buf))
    var s = r.read_utf8(len(buf))
    assert_equal(s, "héllo wörld €")


def test_read_utf8_rejects_invalid() raises:
    # 0xFF is never a valid UTF-8 lead byte.
    var raw = _bytes(0x61, 0xFF, 0x62)
    var r = ByteReader(Span[UInt8, _](raw))
    var raised = False
    try:
        _ = r.read_utf8(3)
    except:
        raised = True
    assert_true(raised)
    # Cursor must not advance on a failed read.
    assert_equal(r.position(), 0)


def test_read_utf8_rejects_truncated_multibyte() raises:
    # 0xC3 expects a continuation byte; cut it short.
    var raw = _bytes(0xC3)
    var r = ByteReader(Span[UInt8, _](raw))
    var raised = False
    try:
        _ = r.read_utf8(1)
    except:
        raised = True
    assert_true(raised)


def test_read_past_end_raises() raises:
    var raw = _bytes(0x01, 0x02)
    var r = ByteReader(Span[UInt8, _](raw))
    assert_equal(Int(r.read_u8()), 0x01)
    var raised = False
    try:
        _ = r.read_u32_be()
    except:
        raised = True
    assert_true(raised)
    # Failed read leaves the cursor where it was.
    assert_equal(r.position(), 1)


def test_read_bytes_past_end_raises() raises:
    var raw = _bytes(0x01, 0x02, 0x03)
    var r = ByteReader(Span[UInt8, _](raw))
    var raised = False
    try:
        _ = r.read_bytes(4)
    except:
        raised = True
    assert_true(raised)


def test_skip() raises:
    var raw = _bytes(0x01, 0x02, 0x03, 0x04)
    var r = ByteReader(Span[UInt8, _](raw))
    r.skip(3)
    assert_equal(Int(r.read_u8()), 0x04)
    var raised = False
    try:
        r.skip(1)
    except:
        raised = True
    assert_true(raised)


def test_writer_round_trip_all_widths() raises:
    var w = ByteWriter()
    w.write_u8(0xAB)
    w.write_u16_be(0x1234)
    w.write_u16_le(0x1234)
    w.write_u32_be(0xDEADBEEF)
    w.write_u32_le(0xDEADBEEF)
    w.write_bytes(_bytes(0x10, 0x20))
    var buf = w.take()
    # take() leaves the writer empty.
    assert_equal(w.len(), 0)

    var r = ByteReader(Span[UInt8, _](buf))
    assert_equal(Int(r.read_u8()), 0xAB)
    assert_equal(Int(r.read_u16_be()), 0x1234)
    assert_equal(Int(r.read_u16_le()), 0x1234)
    assert_equal(Int(r.read_u32_be()), 0xDEADBEEF)
    assert_equal(Int(r.read_u32_le()), 0xDEADBEEF)
    assert_equal(Int(r.read_u8()), 0x10)
    assert_equal(Int(r.read_u8()), 0x20)
    assert_equal(r.remaining(), 0)


def test_writer_bytes_copies() raises:
    var w = ByteWriter()
    w.write_str("abc")
    var copy1 = w.bytes()
    w.write_str("d")  # bytes() returned a copy, original keeps growing
    assert_equal(len(copy1), 3)
    assert_equal(w.len(), 4)


def main() raises:
    test_read_unsigned_be()
    test_read_unsigned_le()
    test_read_u64_round_trip_both_endians()
    test_read_bytes_borrowed()
    test_read_utf8_valid_ascii_and_multibyte()
    test_read_utf8_rejects_invalid()
    test_read_utf8_rejects_truncated_multibyte()
    test_read_past_end_raises()
    test_read_bytes_past_end_raises()
    test_skip()
    test_writer_round_trip_all_widths()
    test_writer_bytes_copies()
    print("test_byte_cursor: 12 passed")
