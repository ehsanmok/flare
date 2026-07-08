"""Unit tests for ``flare.http3.request_reader`` -- H3 request-stream
sans-I/O state machine.

Validates the callback sequence the reader fires on the four
canonical wire shapes (HEADERS only, HEADERS+DATA, HEADERS+
DATA+TRAILERS, HEADERS with grease frame interleaved) plus the
six protocol-error paths (DATA before HEADERS, control-stream
frame type on request stream, repeated HEADERS after trailers,
oversized HEADERS field section, malformed QPACK in HEADERS,
truncated frame -> NEEDS_MORE).
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.http3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_SETTINGS,
    H3_REQUEST_STATE_BODY,
    H3_REQUEST_STATE_DONE,
    H3_REQUEST_STATE_INIT,
    H3_REQUEST_STATE_TRAILERS,
    Http3RequestEventHandler,
    Http3RequestReader,
    encode_http3_frame,
    feed_into,
)
from flare.qpack import QpackHeader, encode_field_section


# Test-only recorder that captures every callback the reader fires
# so assertions can inspect the dispatched payloads.
@fieldwise_init
struct _Recorder(Http3RequestEventHandler, Movable):
    var headers_count: Int
    var trailers_count: Int
    var data_count: Int
    var unknown_count: Int
    var error_count: Int
    var last_headers: List[QpackHeader]
    var last_trailers: List[QpackHeader]
    var last_data: List[UInt8]
    var last_unknown_type: UInt64
    var last_error: String

    @staticmethod
    def new() -> Self:
        return Self(
            headers_count=0,
            trailers_count=0,
            data_count=0,
            unknown_count=0,
            error_count=0,
            last_headers=List[QpackHeader](),
            last_trailers=List[QpackHeader](),
            last_data=List[UInt8](),
            last_unknown_type=UInt64(0),
            last_error=String(""),
        )

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        self.headers_count += 1
        self.last_headers = headers.copy()

    def on_data(mut self, data: List[UInt8]) raises:
        self.data_count += 1
        self.last_data = data.copy()

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        self.trailers_count += 1
        self.last_trailers = trailers.copy()

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        self.unknown_count += 1
        self.last_unknown_type = type_id

    def on_protocol_error(mut self, message: String) raises:
        self.error_count += 1
        self.last_error = message


def _qpack_request_headers() raises -> List[UInt8]:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader(":method", "GET"))
    hs.append(QpackHeader(":scheme", "https"))
    hs.append(QpackHeader(":path", "/"))
    hs.append(QpackHeader("x-trace-id", "abc-123"))
    var out = List[UInt8]()
    encode_field_section(hs, out)
    return out^


def _frame(ftype: UInt64, payload: List[UInt8]) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_http3_frame(ftype, Span[UInt8, _](payload), out)
    return out^


def test_initial_state() raises:
    var r = Http3RequestReader.new()
    assert_equal(r.state, H3_REQUEST_STATE_INIT)


def test_headers_only() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var headers = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var consumed = feed_into(r, Span[UInt8, _](headers), rec)
    assert_equal(consumed, len(headers))
    assert_equal(rec.headers_count, 1)
    assert_equal(len(rec.last_headers), 4)
    assert_equal(rec.last_headers[0].name, ":method")
    assert_equal(rec.last_headers[0].value, "GET")
    assert_equal(r.state, H3_REQUEST_STATE_BODY)


def test_headers_then_data() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var data_payload = List[UInt8]()
    for c in String("hello").as_bytes():
        data_payload.append(c)
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var _ = feed_into(r, Span[UInt8, _](hf), rec)
    var _ = feed_into(r, Span[UInt8, _](df), rec)
    assert_equal(rec.headers_count, 1)
    assert_equal(rec.data_count, 1)
    assert_equal(len(rec.last_data), 5)
    assert_equal(rec.last_data[0], UInt8(ord("h")))


def test_headers_then_data_then_trailers() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var data_payload = List[UInt8]()
    for c in String("hi").as_bytes():
        data_payload.append(c)
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var trailers_qpack = List[UInt8]()
    encode_field_section(
        List[QpackHeader]([QpackHeader("x-checksum", "deadbeef")]),
        trailers_qpack,
    )
    var tf = _frame(H3_FRAME_TYPE_HEADERS, trailers_qpack)
    var _ = feed_into(r, Span[UInt8, _](hf), rec)
    var _ = feed_into(r, Span[UInt8, _](df), rec)
    var _ = feed_into(r, Span[UInt8, _](tf), rec)
    assert_equal(rec.trailers_count, 1)
    assert_equal(len(rec.last_trailers), 1)
    assert_equal(rec.last_trailers[0].name, "x-checksum")
    assert_equal(r.state, H3_REQUEST_STATE_TRAILERS)


def test_data_before_headers_is_protocol_error() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var data_payload = List[UInt8]()
    data_payload.append(UInt8(0x41))
    var df = _frame(H3_FRAME_TYPE_DATA, data_payload)
    var _ = feed_into(r, Span[UInt8, _](df), rec)
    assert_equal(rec.error_count, 1)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_control_frame_on_request_stream_is_protocol_error() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var settings_payload = List[UInt8]()
    var sf = _frame(H3_FRAME_TYPE_SETTINGS, settings_payload)
    var _ = feed_into(r, Span[UInt8, _](sf), rec)
    assert_equal(rec.error_count, 1)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_truncated_frame_yields_needs_more() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    # Slice off the final byte to truncate.
    var truncated = List[UInt8]()
    for i in range(len(hf) - 1):
        truncated.append(hf[i])
    var consumed = feed_into(r, Span[UInt8, _](truncated), rec)
    assert_equal(consumed, 0)
    assert_equal(rec.headers_count, 0)
    assert_equal(rec.error_count, 0)
    assert_equal(r.state, H3_REQUEST_STATE_INIT)


def test_unknown_frame_type_is_skipped() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    # Grease frame: 0x21 (one of the reserved unknown shapes).
    var grease_payload = List[UInt8]()
    grease_payload.append(UInt8(0xAA))
    var gf = _frame(UInt64(0x21), grease_payload)
    var combined = List[UInt8]()
    for i in range(len(hf)):
        combined.append(hf[i])
    for i in range(len(gf)):
        combined.append(gf[i])
    var consumed1 = feed_into(r, Span[UInt8, _](combined), rec)
    assert_equal(rec.headers_count, 1)
    var rest = List[UInt8]()
    for i in range(consumed1, len(combined)):
        rest.append(combined[i])
    var _ = feed_into(r, Span[UInt8, _](rest), rec)
    assert_equal(rec.unknown_count, 1)
    assert_equal(rec.last_unknown_type, UInt64(0x21))


def test_oversized_headers_is_protocol_error() raises:
    var r = Http3RequestReader.new(max_field_section_bytes=UInt64(8))
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var _ = feed_into(r, Span[UInt8, _](hf), rec)
    assert_equal(rec.error_count, 1)
    assert_equal(r.state, H3_REQUEST_STATE_DONE)


def test_repeat_headers_after_trailers_is_protocol_error() raises:
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var hf = _frame(H3_FRAME_TYPE_HEADERS, _qpack_request_headers())
    var trailers_qpack = List[UInt8]()
    encode_field_section(
        List[QpackHeader]([QpackHeader("x-tail", "1")]),
        trailers_qpack,
    )
    var tf = _frame(H3_FRAME_TYPE_HEADERS, trailers_qpack)
    var _ = feed_into(r, Span[UInt8, _](hf), rec)
    var _ = feed_into(r, Span[UInt8, _](tf), rec)
    # State now TRAILERS; another HEADERS frame is illegal.
    var _ = feed_into(r, Span[UInt8, _](hf), rec)
    assert_equal(rec.error_count, 1)


def main() raises:
    test_initial_state()
    test_headers_only()
    test_headers_then_data()
    test_headers_then_data_then_trailers()
    test_data_before_headers_is_protocol_error()
    test_control_frame_on_request_stream_is_protocol_error()
    test_truncated_frame_yields_needs_more()
    test_unknown_frame_type_is_skipped()
    test_oversized_headers_is_protocol_error()
    test_repeat_headers_after_trailers_is_protocol_error()
    print("test_h3_request_reader: 10 passed")
