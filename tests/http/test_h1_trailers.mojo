"""Tests for HTTP/1.1 trailer-field handling (Track c02 / v0.7).

Covers both sides of the wire:

* Server emit (``serialize_streaming_response`` in
  ``flare/http/streaming_serialize.mojo``):
    - Empty trailer map -> wire ends ``0\\r\\n\\r\\n`` exactly as
      v0.6 (no behaviour change).
    - Non-empty trailer map -> wire ends ``0\\r\\n<trailer
      lines>\\r\\n`` and a ``Trailer:`` header lists the declared
      names (RFC 7230 §4.4).
    - Caller-supplied ``Trailer:`` header is dropped in favour of
      the auto-generated one (no duplicate / contradictory
      headers).

* Client decode (``_decode_chunked`` in ``flare/http/client.mojo``):
    - Plain chunked body without trailers -> empty ``trailers`` map.
    - Trailers after zero chunk -> populated ``trailers`` map.
    - Forbidden trailer name (``Transfer-Encoding``) -> raises.
    - Smuggling guard: response with both
      ``Transfer-Encoding: chunked`` and ``Content-Length`` ->
      raises with the RFC 7230 §3.3.3 reason.
    - Missing colon in trailer line -> raises.
"""

from std.collections import Optional
from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http import HeaderMap
from flare.http.body import Body
from flare.http.cancel import Cancel
from flare.http.client import _decode_chunked, _extract_body_and_trailers
from flare.http.streaming_response import StreamingResponse
from flare.http.streaming_serialize import serialize_streaming_response


# ── Helpers ─────────────────────────────────────────────────────────────


@fieldwise_init
struct _OneShot(Body, Copyable):
    """Minimal ``Body`` impl: emits one fixed chunk then EOF.

    Used to drive the chunked emission path without pulling in
    ``ChunkedBody`` / ``ChunkSource`` boilerplate."""

    var bytes: List[UInt8]
    var done: Bool

    @staticmethod
    def of(s: String) -> _OneShot:
        var b = List[UInt8]()
        for x in s.as_bytes():
            b.append(x)
        return _OneShot(bytes=b^, done=False)

    def content_length(self) -> Optional[Int]:
        return Optional[Int]()

    def next_chunk(mut self, cancel: Cancel) -> Optional[List[UInt8]]:
        if self.done:
            return Optional[List[UInt8]]()
        self.done = True
        return Optional[List[UInt8]](self.bytes.copy())


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _wire_str(wire: List[UInt8]) -> String:
    var s = String(capacity_bytes=len(wire) + 1)
    for b in wire:
        s += chr(Int(b))
    return s^


# ── Server-side emit ────────────────────────────────────────────────────


def test_empty_trailers_match_v06_wire_byte_for_byte() raises:
    """Without trailers the chunked terminator must remain
    ``0\\r\\n\\r\\n`` -- v0.6 wire-compat invariant."""
    var resp = StreamingResponse[_OneShot](
        status=200,
        body=_OneShot.of("hello"),
        reason="OK",
    )
    var wire = serialize_streaming_response(resp^, Cancel.never(), True)
    var s = _wire_str(wire)
    assert_true(s.endswith("0\r\n\r\n"))
    assert_false("Trailer:" in s)
    assert_false("Trailer: " in s)


def test_trailers_emit_after_zero_chunk_with_declared_header() raises:
    """A non-empty trailer map emits the trailer lines after the
    zero chunk and auto-declares the names via ``Trailer:``."""
    var resp = StreamingResponse[_OneShot](
        status=200,
        body=_OneShot.of("hello"),
        reason="OK",
    )
    resp.trailers.append("grpc-status", "0")
    resp.trailers.append("grpc-message", "ok")
    var wire = serialize_streaming_response(resp^, Cancel.never(), True)
    var s = _wire_str(wire)
    assert_true("Trailer: grpc-status, grpc-message\r\n" in s)
    var tail = "0\r\ngrpc-status: 0\r\ngrpc-message: ok\r\n\r\n"
    assert_true(s.endswith(tail))


def test_caller_supplied_trailer_header_dropped() raises:
    """Caller's manual ``Trailer:`` header is suppressed in favour
    of the serializer's auto-generated one."""
    var resp = StreamingResponse[_OneShot](
        status=200,
        body=_OneShot.of("hello"),
        reason="OK",
    )
    resp.headers.append("Trailer", "x-old-name")
    resp.trailers.append("grpc-status", "0")
    var wire = serialize_streaming_response(resp^, Cancel.never(), True)
    var s = _wire_str(wire)
    assert_false("Trailer: x-old-name" in s)
    assert_true("Trailer: grpc-status\r\n" in s)


# ── Client-side decode ──────────────────────────────────────────────────


def test_decode_chunked_no_trailers_returns_empty_trailer_map() raises:
    """Plain chunked body -> trailer map stays empty."""
    var raw = _bytes("5\r\nhello\r\n0\r\n\r\n")
    var trailers = HeaderMap()
    var body = _decode_chunked(raw, 0, trailers)
    assert_equal(len(body), 5)
    assert_equal(len(trailers._keys), 0)


def test_decode_chunked_with_trailers_populates_map() raises:
    """Populate the trailer map from gRPC-shaped trailer fields."""
    var raw = _bytes(
        "5\r\nhello\r\n0\r\ngrpc-status: 0\r\ngrpc-message: ok\r\n\r\n"
    )
    var trailers = HeaderMap()
    var body = _decode_chunked(raw, 0, trailers)
    assert_equal(len(body), 5)
    assert_equal(trailers.get("grpc-status"), "0")
    assert_equal(trailers.get("grpc-message"), "ok")


def test_decode_chunked_forbidden_trailer_raises() raises:
    """Trailer fields banned by RFC 7230 §4.1.2 (e.g.
    ``Transfer-Encoding``) raise rather than silently leaking."""
    var raw = _bytes("5\r\nhello\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n")
    var trailers = HeaderMap()
    with assert_raises():
        _ = _decode_chunked(raw, 0, trailers)


def test_decode_chunked_malformed_trailer_no_colon_raises() raises:
    """A trailer line without ``:`` is malformed; we surface the
    parse error rather than silently dropping the field."""
    var raw = _bytes("5\r\nhello\r\n0\r\nbroken-line-no-colon\r\n\r\n")
    var trailers = HeaderMap()
    with assert_raises():
        _ = _decode_chunked(raw, 0, trailers)


def test_smuggling_chunked_plus_content_length_raises() raises:
    """Both ``Transfer-Encoding: chunked`` AND ``Content-Length``
    in one response is the classic request-smuggling shape;
    RFC 7230 §3.3.3 mandates rejection."""
    var headers = HeaderMap()
    headers.append("Transfer-Encoding", "chunked")
    headers.append("Content-Length", "5")
    var raw = _bytes("5\r\nhello\r\n0\r\n\r\n")
    var trailers = HeaderMap()
    with assert_raises():
        _ = _extract_body_and_trailers(raw, 0, headers, trailers)


def main() raises:
    test_empty_trailers_match_v06_wire_byte_for_byte()
    test_trailers_emit_after_zero_chunk_with_declared_header()
    test_caller_supplied_trailer_header_dropped()
    test_decode_chunked_no_trailers_returns_empty_trailer_map()
    test_decode_chunked_with_trailers_populates_map()
    test_decode_chunked_forbidden_trailer_raises()
    test_decode_chunked_malformed_trailer_no_colon_raises()
    test_smuggling_chunked_plus_content_length_raises()
    print("test_h1_trailers: 8 passed")
