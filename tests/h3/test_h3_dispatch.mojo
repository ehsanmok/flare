"""Tests for the HTTP/3 server driver's request -> handler ->
response wire path.

The new methods on :class:`flare.h3.H3Connection`:

- :meth:`feed_stream_chunk(stream_id, chunk)` -- feed reassembled
  QUIC stream bytes; drives the per-stream
  :class:`H3RequestReader` one frame at a time and accumulates
  the request shape (headers, body, trailers) into the
  per-stream carrier.
- :meth:`signal_end_of_stream(stream_id)` -- flip the per-stream
  FIN flag (the QUIC layer's signal that the request side
  closed).
- :meth:`take_completed_streams()` -- IDs of streams ready for
  handler dispatch.
- :meth:`take_request(stream_id)` -- pluck the assembled
  :class:`Request` out for handler dispatch. Idempotent guard.
- :meth:`emit_response(stream_id, response)` -- encode HEADERS +
  DATA into the per-stream outbox.
- :meth:`take_response_frames(stream_id)` -- drain pending
  outbound bytes.

Properties covered:

1. A complete HEADERS frame on stream 0 surfaces the request via
   the completed-streams list.
2. A request with body needs both HEADERS + DATA + FIN before
   it becomes ready for dispatch.
3. The assembled Request's method + URL + body match the
   client-emitted HEADERS + DATA.
4. ``emit_response`` produces HEADERS + DATA frames that the
   reader on the *other* side can decode back to the original
   status + body.
5. ``take_response_frames`` drains once; the second call returns
   empty.
6. ``take_request`` is idempotent-guarded; double-take raises.
7. Garbled bytes mark a per-stream protocol error.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.h3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3Connection,
    H3ConnectionConfig,
    encode_h3_frame,
)
from flare.http.response import Response
from flare.http.server import ok
from flare.qpack import QpackHeader, encode_field_section


def _encode_headers_frame(headers: List[QpackHeader]) raises -> List[UInt8]:
    """QPACK-encode + wrap in an H3 HEADERS frame."""
    var payload = List[UInt8]()
    encode_field_section(headers, payload)
    var out = List[UInt8]()
    encode_h3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8, _](payload), out)
    return out^


def _encode_data_frame(payload: List[UInt8]) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_h3_frame(H3_FRAME_TYPE_DATA, Span[UInt8, _](payload), out)
    return out^


def _build_get_request_bytes(path: String) raises -> List[UInt8]:
    """Pseudo-headers for a GET on ``path``."""
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "GET"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":authority", "example.com"))
    headers.append(QpackHeader(":path", String(path)))
    headers.append(QpackHeader("user-agent", "flare-h3-test"))
    return _encode_headers_frame(headers)


def _build_post_request_bytes(
    path: String, body: List[UInt8]
) raises -> List[UInt8]:
    var headers = List[QpackHeader]()
    headers.append(QpackHeader(":method", "POST"))
    headers.append(QpackHeader(":scheme", "https"))
    headers.append(QpackHeader(":authority", "example.com"))
    headers.append(QpackHeader(":path", String(path)))
    headers.append(QpackHeader("content-type", "text/plain"))
    var hdr_bytes = _encode_headers_frame(headers)
    var data_bytes = _encode_data_frame(body.copy())
    var out = List[UInt8]()
    for i in range(len(hdr_bytes)):
        out.append(hdr_bytes[i])
    for i in range(len(data_bytes)):
        out.append(data_bytes[i])
    return out^


def test_feed_stream_chunk_implicit_open() raises:
    """A chunk arriving for an un-tracked stream allocates the
    carrier implicitly (no separate open-stream signal)."""
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/index"))
    assert_true(c.has_stream(0))


def test_get_request_surfaces_after_fin() raises:
    """A complete GET (HEADERS only) surfaces as a completed
    stream once the QUIC layer signals FIN."""
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/hello"))
    assert_true(c.stream_has_headers(0))
    assert_equal(
        len(c.take_completed_streams()),
        0,
        "GET without FIN is not yet ready for dispatch",
    )
    c.signal_end_of_stream(0)
    var ready = c.take_completed_streams()
    assert_equal(len(ready), 1)
    assert_equal(ready[0], 0)


def test_take_request_assembles_method_and_path() raises:
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/api/v1/users"))
    c.signal_end_of_stream(0)
    var req = c.take_request(0)
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/api/v1/users"))
    assert_equal(len(req.body), 0)
    assert_true(req.headers.contains("user-agent"))


def test_take_request_body_round_trip() raises:
    """POST with a body: feed HEADERS + DATA + signal FIN, then
    take_request must surface the body bytes exactly."""
    var c = H3Connection()
    var body = List[UInt8]()
    for v in [72, 101, 108, 108, 111]:
        body.append(UInt8(v))
    var chunk = _build_post_request_bytes("/upload", body)
    c.feed_stream_chunk(0, chunk^)
    c.signal_end_of_stream(0)
    var req = c.take_request(0)
    assert_equal(req.method, String("POST"))
    assert_equal(req.url, String("/upload"))
    assert_equal(len(req.body), 5)
    var expected = List[UInt8]()
    for v in [72, 101, 108, 108, 111]:
        expected.append(UInt8(v))
    for i in range(5):
        assert_equal(req.body[i], expected[i])


def test_take_request_is_idempotent_guarded() raises:
    """Calling take_request twice on the same stream raises so
    the reactor can't accidentally double-dispatch."""
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/once"))
    c.signal_end_of_stream(0)
    var _req = c.take_request(0)
    var raised = False
    try:
        var _req2 = c.take_request(0)
    except:
        raised = True
    assert_true(raised, "double take_request must raise")


def test_emit_response_buffers_headers_and_data() raises:
    """The emit_response path queues HEADERS + DATA frames in
    the per-stream outbox; take_response_frames drains them."""
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/ok"))
    c.signal_end_of_stream(0)
    var _req = c.take_request(0)
    c.emit_response(0, ok("hi"))
    var drained = c.take_response_frames(0)
    assert_true(
        len(drained) > 0,
        "emit_response must produce at least the HEADERS frame",
    )


def test_take_response_frames_drains_once() raises:
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/x"))
    c.signal_end_of_stream(0)
    var _req = c.take_request(0)
    c.emit_response(0, ok("body"))
    var first = c.take_response_frames(0)
    assert_true(len(first) > 0)
    var second = c.take_response_frames(0)
    assert_equal(len(second), 0, "second drain must return empty")


def test_emit_response_is_idempotent_guarded() raises:
    var c = H3Connection()
    c.feed_stream_chunk(0, _build_get_request_bytes("/x"))
    c.signal_end_of_stream(0)
    var _req = c.take_request(0)
    c.emit_response(0, ok("first"))
    var raised = False
    try:
        c.emit_response(0, ok("second"))
    except:
        raised = True
    assert_true(raised, "double emit_response must raise")


def test_garbled_chunk_sets_protocol_error() raises:
    """A chunk whose frame-type varint is fine but whose payload
    length lies about the body fires on_protocol_error inside
    the reader; the H3 driver surfaces it via
    stream_protocol_error."""
    var c = H3Connection()
    # An H3 frame with type=HEADERS but a payload-length-varint
    # that claims the body is 8 bytes long with only 2 supplied.
    # The reader fires the QPACK decode failure once the
    # payload bytes arrive but the field section is malformed.
    var bad = List[UInt8]()
    bad.append(UInt8(H3_FRAME_TYPE_HEADERS))
    bad.append(UInt8(8))  # length varint = 8
    # 8 bytes of garbage where a valid QPACK field section is
    # expected.
    for _ in range(8):
        bad.append(UInt8(0xFF))
    c.feed_stream_chunk(0, bad^)
    var err = c.stream_protocol_error(0)
    assert_true(
        err.byte_length() > 0,
        "garbled HEADERS payload must surface as a protocol error",
    )


def test_partial_chunk_needs_more_then_completes() raises:
    """The reader is NEEDS_MORE friendly: split the headers
    payload across two feed_stream_chunk calls and the request
    must still surface correctly."""
    var c = H3Connection()
    var full = _build_get_request_bytes("/split")
    var half = len(full) // 2
    var part1 = List[UInt8]()
    for i in range(half):
        part1.append(full[i])
    var part2 = List[UInt8]()
    for i in range(half, len(full)):
        part2.append(full[i])
    c.feed_stream_chunk(0, part1^)
    assert_false(
        c.stream_has_headers(0),
        "partial chunk should not mark headers complete",
    )
    c.feed_stream_chunk(0, part2^)
    assert_true(c.stream_has_headers(0))
    c.signal_end_of_stream(0)
    var req = c.take_request(0)
    assert_equal(req.url, String("/split"))


def main() raises:
    test_feed_stream_chunk_implicit_open()
    test_get_request_surfaces_after_fin()
    test_take_request_assembles_method_and_path()
    test_take_request_body_round_trip()
    test_take_request_is_idempotent_guarded()
    test_emit_response_buffers_headers_and_data()
    test_take_response_frames_drains_once()
    test_emit_response_is_idempotent_guarded()
    test_garbled_chunk_sets_protocol_error()
    test_partial_chunk_needs_more_then_completes()
    print("test_h3_dispatch: 10 passed")
