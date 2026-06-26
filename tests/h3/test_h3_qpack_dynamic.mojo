"""H3 server <-> QPACK dynamic-table wiring (RFC 9204).

Exercises the per-connection dynamic table on :class:`H3Connection`:

1. Peer QPACK encoder-stream inserts (Set Capacity + Insert With
   Literal Name) replayed over :meth:`feed_uni_stream_chunk` land in
   the connection's dynamic table and owe an Insert Count Increment
   back via :meth:`take_qpack_decoder_frames`.
2. A request HEADERS field section that references a dynamic entry by
   relative index decodes correctly through the per-stream reader (the
   shared dynamic table resolves the reference).
3. An encoder-stream instruction split across two chunks is buffered
   and applied once the remainder arrives.
"""

from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.h3 import (
    H3_FRAME_TYPE_HEADERS,
    H3Connection,
    H3ConnectionConfig,
    encode_h3_frame,
)
from flare.qpack import QpackHeader
from flare.qpack.dynamic import (
    QpackDynamicTable,
    apply_encoder_instructions,
    encode_field_section_dynamic,
    encode_insert_with_literal_name,
    encode_set_capacity,
)


comptime _QPACK_ENCODER_STREAM: Int = 2
"""RFC 9114 §6.2.1 unidirectional stream type 0x02."""


def _conn_with_dynamic(capacity: UInt64 = 4096) raises -> H3Connection:
    var config = H3ConnectionConfig()
    config.qpack_max_table_capacity = capacity
    return H3Connection.with_config(config)


def _encoder_stream_inserts() raises -> List[UInt8]:
    """Set Capacity 4096 + Insert With Literal Name (x-custom)."""
    var enc = List[UInt8]()
    encode_set_capacity(enc, UInt64(4096))
    encode_insert_with_literal_name(enc, "x-custom", "dynamic-value")
    return enc^


def _mirror_table() raises -> QpackDynamicTable:
    """A peer-side mirror so the request field section can encode the
    dynamic reference the connection table will resolve."""
    var t = QpackDynamicTable(UInt64(4096))
    var enc = _encoder_stream_inserts()
    _ = apply_encoder_instructions(t, Span[UInt8, _](enc))
    return t^


def _dynamic_get_frame(path: String) raises -> List[UInt8]:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "GET"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":authority", "example.com"))
    headers.append(QpackHeader(":path", String(path)))
    headers.append(QpackHeader("x-custom", "dynamic-value"))
    var mirror = _mirror_table()
    var payload = List[UInt8]()
    encode_field_section_dynamic(headers, mirror, payload)
    var out = List[UInt8]()
    encode_h3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](payload), out)
    return out^


def test_encoder_stream_inserts_owe_increment() raises:
    var c = _conn_with_dynamic()
    var stream = List[UInt8]()
    stream.append(UInt8(_QPACK_ENCODER_STREAM))
    var enc = _encoder_stream_inserts()
    for i in range(len(enc)):
        stream.append(enc[i])
    c.feed_uni_stream_chunk(7, stream^)
    var dec = c.take_qpack_decoder_frames()
    assert_true(
        len(dec) > 0,
        "one applied insert must owe an Insert Count Increment",
    )
    # Drained once: a second take is empty.
    assert_equal(len(c.take_qpack_decoder_frames()), 0)


def test_request_resolves_dynamic_reference() raises:
    var c = _conn_with_dynamic()
    var stream = List[UInt8]()
    stream.append(UInt8(_QPACK_ENCODER_STREAM))
    var enc = _encoder_stream_inserts()
    for i in range(len(enc)):
        stream.append(enc[i])
    c.feed_uni_stream_chunk(7, stream^)

    c.feed_stream_chunk(0, _dynamic_get_frame("/dyn"))
    c.signal_end_of_stream(0)
    var req = c.take_request(0)
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/dyn"))
    assert_true(
        req.headers.contains("x-custom"),
        "dynamic-table header must decode into the request",
    )
    assert_equal(req.headers.get("x-custom"), String("dynamic-value"))


def test_split_encoder_chunk_buffers_then_applies() raises:
    """An encoder instruction straddling a chunk boundary must buffer
    and apply once the remainder arrives, then resolve the request."""
    var c = _conn_with_dynamic()
    var enc = _encoder_stream_inserts()
    # First chunk: type prefix + only the first 2 instruction bytes.
    var part1 = List[UInt8]()
    part1.append(UInt8(_QPACK_ENCODER_STREAM))
    part1.append(enc[0])
    part1.append(enc[1])
    c.feed_uni_stream_chunk(7, part1^)
    # Nothing whole applied yet (Insert With Literal Name truncated).
    var early = c.take_qpack_decoder_frames()

    var part2 = List[UInt8]()
    for i in range(2, len(enc)):
        part2.append(enc[i])
    c.feed_uni_stream_chunk(7, part2^)
    var late = c.take_qpack_decoder_frames()
    assert_true(
        len(early) + len(late) > 0,
        "the insert must apply once the remainder arrives",
    )

    c.feed_stream_chunk(0, _dynamic_get_frame("/split"))
    c.signal_end_of_stream(0)
    var req = c.take_request(0)
    assert_equal(req.url, String("/split"))
    assert_true(req.headers.contains("x-custom"))


def main() raises:
    test_encoder_stream_inserts_owe_increment()
    test_request_resolves_dynamic_reference()
    test_split_encoder_chunk_buffers_then_applies()
    print("test_h3_qpack_dynamic: 3 passed")
