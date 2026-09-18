"""HTTP/3 incremental response framing contracts."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from flare.http3 import (
    Http3ResponseReader,
    encode_response_headers,
    encode_response_data,
    encode_request_trailers,
)
from flare.qpack import QpackHeader
from flare.quic.varint import encode_varint


def test_h3_large_partial_data_frame_yields_immediately() raises:
    var reader = Http3ResponseReader()
    var wire = List[UInt8]()
    encode_response_headers(200, List[QpackHeader](), wire)
    wire.extend(encode_varint(UInt64(0)))
    wire.extend(encode_varint(UInt64(2 * 1024 * 1024)))
    wire.append(97)
    reader.feed(Span(wire))
    assert_true(reader.head_ready())
    assert_equal(len(reader.drain_body()), 1)
    assert_equal(len(reader.inbox), 0)
    reader.signal_fin()
    assert_true(reader.has_error(), "partial DATA frame cannot end cleanly")


def test_h3_informationals_trailers_and_length_after_draining() raises:
    var reader = Http3ResponseReader()
    var wire = List[UInt8]()
    encode_response_headers(103, List[QpackHeader](), wire)
    reader.feed(Span(wire))
    assert_false(reader.head_ready())
    wire = List[UInt8]()
    var fields: List[QpackHeader] = [
        QpackHeader("content-length", "3"),
        QpackHeader("x-value", "one"),
        QpackHeader("x-value", "two"),
    ]
    encode_response_headers(200, fields, wire)
    var data = List[UInt8](String("abc").as_bytes())
    encode_response_data(Span(data), wire)
    reader.feed(Span(wire))
    assert_equal(len(reader.drain_body()), 3)
    wire = List[UInt8]()
    var trailers: List[QpackHeader] = [QpackHeader("x-end", "yes")]
    encode_request_trailers(trailers, wire)
    reader.feed(Span(wire))
    reader.signal_fin()
    assert_false(reader.has_error())
    var response = reader.take_response()
    assert_equal(len(response.trailers), 1)
    assert_equal(len(response.headers), 3)


def test_h3_head_and_missing_final_headers() raises:
    var reader = Http3ResponseReader(method="HEAD")
    var wire = List[UInt8]()
    encode_response_headers(200, [QpackHeader("content-length", "12345")], wire)
    reader.feed(Span(wire))
    reader.signal_fin()
    assert_false(reader.has_error())
    var missing = Http3ResponseReader()
    missing.signal_fin()
    assert_true(missing.has_error())


def test_h3_field_section_budget_is_per_section() raises:
    """SETTINGS_MAX_FIELD_SECTION_SIZE bounds each section separately.

    RFC 9114 sec 4.2. The interim head's bytes used to stay on the
    books, so a run of 103 Early Hints plus an ordinary final head could
    trip the limit with no single section anywhere near it.
    """
    var big = String("v") * 200
    # A budget that comfortably fits any one of these sections but not
    # three of them added together.
    var reader = Http3ResponseReader(max_field_section_bytes=UInt64(400))
    for _ in range(3):
        var hint = List[UInt8]()
        encode_response_headers(103, [QpackHeader("link", big)], hint)
        reader.feed(Span(hint))
        assert_false(reader.has_error(), "an interim head must not accumulate")
        assert_false(reader.head_ready())
    var final = List[UInt8]()
    encode_response_headers(200, [QpackHeader("x-a", big)], final)
    reader.feed(Span(final))
    assert_false(reader.has_error(), "the final head fits its own budget")
    assert_true(reader.head_ready())
    assert_equal(reader.status, 200)


def test_h3_oversized_single_section_still_fails() raises:
    """The per-section reset must not disable the limit."""
    var reader = Http3ResponseReader(max_field_section_bytes=UInt64(64))
    var wire = List[UInt8]()
    encode_response_headers(200, [QpackHeader("x-a", String("v") * 500)], wire)
    reader.feed(Span(wire))
    assert_true(reader.has_error(), "one oversized section must still fail")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
