"""Round-trip test: H3 response writer feeds the H3 request reader.

The writer emits HEADERS + DATA + trailing HEADERS bytes; the
reader (reused as a generic frame parser) confirms the bytes
parse back into the same field sets. This is a coarse codec
contract -- per-field-set tests live under tests/qpack and
tests/h3/test_request_reader.
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.http3 import (
    Http3RequestEventHandler,
    Http3RequestReader,
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
    feed_into,
)
from flare.qpack import QpackHeader


# Local recorder mirroring the one in test_request_reader.mojo so
# this test stays standalone.
@fieldwise_init
struct _Recorder(Http3RequestEventHandler, Movable):
    var headers_count: Int
    var trailers_count: Int
    var data_count: Int
    var error_count: Int
    var last_headers: List[QpackHeader]
    var last_trailers: List[QpackHeader]
    var last_data: List[UInt8]

    @staticmethod
    def new() -> Self:
        return Self(
            headers_count=0,
            trailers_count=0,
            data_count=0,
            error_count=0,
            last_headers=List[QpackHeader](),
            last_trailers=List[QpackHeader](),
            last_data=List[UInt8](),
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
        pass

    def on_protocol_error(mut self, message: String) raises:
        self.error_count += 1


def test_status_only() raises:
    var bytes = List[UInt8]()
    encode_response_headers(200, List[QpackHeader](), bytes)
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var _ = feed_into(r, Span[UInt8, _](bytes), rec)
    assert_equal(rec.headers_count, 1)
    # Pseudo-header :status MUST be present.
    assert_equal(rec.last_headers[0].name, ":status")
    assert_equal(rec.last_headers[0].value, "200")


def test_status_with_application_headers() raises:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader("Content-Type", "application/json"))
    hs.append(QpackHeader("X-Trace-ID", "abc"))
    var bytes = List[UInt8]()
    encode_response_headers(200, hs, bytes)
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var _ = feed_into(r, Span[UInt8, _](bytes), rec)
    assert_equal(rec.headers_count, 1)
    # Headers come back lowercased per RFC 9114 §4.2 lowercase
    # mandate -- the writer normalises before QPACK encoding.
    var found_ct = False
    var found_trace = False
    for i in range(len(rec.last_headers)):
        if rec.last_headers[i].name == "content-type":
            found_ct = True
            assert_equal(rec.last_headers[i].value, "application/json")
        if rec.last_headers[i].name == "x-trace-id":
            found_trace = True
    assert_true(found_ct)
    assert_true(found_trace)


def test_invalid_status_raises() raises:
    var bytes = List[UInt8]()
    var raised = False
    try:
        encode_response_headers(99, List[QpackHeader](), bytes)
    except:
        raised = True
    assert_true(raised)


def test_pseudo_header_in_application_headers_raises() raises:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader(":scheme", "https"))
    var bytes = List[UInt8]()
    var raised = False
    try:
        encode_response_headers(200, hs, bytes)
    except:
        raised = True
    assert_true(raised)


def test_data_frame_round_trip() raises:
    var hbytes = List[UInt8]()
    encode_response_headers(200, List[QpackHeader](), hbytes)
    var payload = List[UInt8]()
    for c in String("hello").as_bytes():
        payload.append(c)
    var dbytes = List[UInt8]()
    encode_response_data(Span[UInt8, _](payload), dbytes)
    var stream = List[UInt8]()
    for i in range(len(hbytes)):
        stream.append(hbytes[i])
    for i in range(len(dbytes)):
        stream.append(dbytes[i])
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var consumed1 = feed_into(r, Span[UInt8, _](stream), rec)
    assert_equal(rec.headers_count, 1)
    var rest = List[UInt8]()
    for i in range(consumed1, len(stream)):
        rest.append(stream[i])
    var _ = feed_into(r, Span[UInt8, _](rest), rec)
    assert_equal(rec.data_count, 1)
    assert_equal(len(rec.last_data), 5)
    assert_equal(rec.last_data[0], UInt8(ord("h")))


def test_trailers_round_trip() raises:
    var hbytes = List[UInt8]()
    encode_response_headers(200, List[QpackHeader](), hbytes)
    var payload = List[UInt8]()
    payload.append(UInt8(0x41))
    var dbytes = List[UInt8]()
    encode_response_data(Span[UInt8, _](payload), dbytes)
    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("X-Sum", "deadbeef"))
    var tbytes = List[UInt8]()
    encode_response_trailers(trailers, tbytes)
    var stream = List[UInt8]()
    for i in range(len(hbytes)):
        stream.append(hbytes[i])
    for i in range(len(dbytes)):
        stream.append(dbytes[i])
    for i in range(len(tbytes)):
        stream.append(tbytes[i])
    var r = Http3RequestReader.new()
    var rec = _Recorder.new()
    var consumed1 = feed_into(r, Span[UInt8, _](stream), rec)
    var rest1 = List[UInt8]()
    for i in range(consumed1, len(stream)):
        rest1.append(stream[i])
    var consumed2 = feed_into(r, Span[UInt8, _](rest1), rec)
    var rest2 = List[UInt8]()
    for i in range(consumed2, len(rest1)):
        rest2.append(rest1[i])
    var _ = feed_into(r, Span[UInt8, _](rest2), rec)
    assert_equal(rec.trailers_count, 1)
    assert_equal(len(rec.last_trailers), 1)
    assert_equal(rec.last_trailers[0].name, "x-sum")
    assert_equal(rec.last_trailers[0].value, "deadbeef")


def test_pseudo_header_in_trailers_raises() raises:
    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader(":path", "/x"))
    var bytes = List[UInt8]()
    var raised = False
    try:
        encode_response_trailers(trailers, bytes)
    except:
        raised = True
    assert_true(raised)


def main() raises:
    test_status_only()
    test_status_with_application_headers()
    test_invalid_status_raises()
    test_pseudo_header_in_application_headers_raises()
    test_data_frame_round_trip()
    test_trailers_round_trip()
    test_pseudo_header_in_trailers_raises()
    print("test_h3_response_writer: 7 passed")
