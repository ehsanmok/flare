"""Tests for ``serialize_streaming_response`` (v0.5.0 follow-up
/ Track 4 part 2 / C5).

The streaming serializer renders a ``StreamingResponse[B: Body]``
to wire bytes. These tests pin the framing semantics per RFC
7230:

- Known content length → ``Content-Length: n`` header + inline
  body bytes.
- Unknown content length → ``Transfer-Encoding: chunked`` header
  + per-chunk ``hex_length\\r\\n`` + bytes + ``\\r\\n`` framing
  + final ``0\\r\\n\\r\\n`` terminator.
- Cancel-aware mid-stream stop: chunked framing still writes the
  ``0\\r\\n\\r\\n`` terminator so the framing contract holds.
- Default reason phrase resolves from the status code when the
  caller doesn't supply one.
- User-set ``Content-Length`` / ``Transfer-Encoding`` headers
  are dropped (the serializer owns those).
- Keep-alive vs close disposition emits the right ``Connection``
  header.

The reactor adoption that calls this serializer per writable
edge is a focused follow-up — these tests exercise the framing
contract independently.
"""

from std.testing import (
    assert_equal,
    assert_true,
    TestSuite,
)
from std.collections import Optional

from flare.http import (
    StreamingResponse,
    InlineBody,
    ChunkedBody,
    ChunkSource,
    serialize_streaming_response,
    Cancel,
    CancelCell,
    CancelReason,
    Status,
)


# ── Test sources ───────────────────────────────────────────────────────────


@fieldwise_init
struct _OneShot(ChunkSource, Copyable, Movable):
    """Yields a single chunk then None."""

    var bytes: List[UInt8]
    var done: Bool

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.done or cancel.cancelled():
            return Optional[List[UInt8]]()
        self.done = True
        return Optional[List[UInt8]](self.bytes.copy())


@fieldwise_init
struct _Multi(ChunkSource, Copyable, Movable):
    """Yields ``n`` chunks each containing the bytes ``b'A' + i``."""

    var i: Int
    var n: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self.i >= self.n or cancel.cancelled():
            return Optional[List[UInt8]]()
        var out = List[UInt8]()
        out.append(UInt8(ord("A") + self.i))
        self.i += 1
        return Optional[List[UInt8]](out^)


# ── Helpers ────────────────────────────────────────────────────────────────


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _wire(wire: List[UInt8]) -> String:
    return String(unsafe_from_utf8=Span[UInt8, _](wire))


# ── Content-Length framing (InlineBody) ────────────────────────────────────


def test_inline_body_emits_content_length_header() raises:
    var body = InlineBody(_bytes("hello"))
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^, reason="OK"
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("HTTP/1.1 200 OK\r\n") >= 0)
    assert_true(s.find("Content-Length: 5\r\n") >= 0)
    # Body present after the empty-line.
    assert_true(s.find("\r\n\r\nhello") >= 0)
    # Should NOT have chunked framing.
    assert_true(s.find("Transfer-Encoding") < 0)


def test_inline_body_zero_length() raises:
    var body = InlineBody(List[UInt8]())
    var resp = StreamingResponse[InlineBody](
        status=Status.NO_CONTENT, body=body^
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("204 No Content") >= 0)
    assert_true(s.find("Content-Length: 0") >= 0)


# ── Chunked framing (ChunkedBody) ─────────────────────────────────────────


def test_chunked_body_emits_transfer_encoding() raises:
    var body = ChunkedBody[_Multi](source=_Multi(i=0, n=3))
    var resp = StreamingResponse[ChunkedBody[_Multi]](
        status=Status.OK, body=body^, reason="OK"
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=False
    )
    var s = _wire(wire)
    assert_true(s.find("HTTP/1.1 200 OK\r\n") >= 0)
    assert_true(s.find("Transfer-Encoding: chunked\r\n") >= 0)
    # Three chunks: 'A', 'B', 'C', each as ``1\r\n<byte>\r\n``.
    assert_true(s.find("\r\n\r\n1\r\nA\r\n1\r\nB\r\n1\r\nC\r\n0\r\n\r\n") >= 0)
    assert_true(s.find("Content-Length") < 0)


def test_chunked_body_empty_source_terminates_cleanly() raises:
    """Source returns None on the first call. The framing still
    emits the ``0\\r\\n\\r\\n`` terminator so the wire stays
    valid."""
    var body = ChunkedBody[_Multi](source=_Multi(i=0, n=0))
    var resp = StreamingResponse[ChunkedBody[_Multi]](
        status=Status.OK, body=body^
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("Transfer-Encoding: chunked\r\n") >= 0)
    # Body section ends with the terminator immediately after
    # the empty-line.
    assert_true(s.find("\r\n\r\n0\r\n\r\n") >= 0)


def test_chunked_body_hex_size_line_for_large_chunk() raises:
    """A 0x10 = 16-byte chunk emits ``10\\r\\n`` as the size line
    (lowercase hex, no leading 0x)."""
    var bytes = List[UInt8]()
    for _ in range(16):
        bytes.append(UInt8(ord("Z")))
    var src = _OneShot(bytes=bytes^, done=False)
    var body = ChunkedBody[_OneShot](source=src^)
    var resp = StreamingResponse[ChunkedBody[_OneShot]](
        status=Status.OK, body=body^
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("\r\n10\r\nZZZZZZZZZZZZZZZZ\r\n0\r\n\r\n") >= 0)


# ── Cancel-aware termination ───────────────────────────────────────────────


def test_chunked_body_pre_flipped_cancel_emits_zero_only() raises:
    """If cancel is flipped before serialize starts, the chunked
    framing emits only ``0\\r\\n\\r\\n`` — the framing contract
    still holds."""
    var body = ChunkedBody[_Multi](source=_Multi(i=0, n=10))
    var resp = StreamingResponse[ChunkedBody[_Multi]](
        status=Status.OK, body=body^
    )
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var wire = serialize_streaming_response(
        resp^, cell.handle(), keep_alive=False
    )
    var s = _wire(wire)
    assert_true(s.find("\r\n\r\n0\r\n\r\n") >= 0)


# ── User headers ───────────────────────────────────────────────────────────


def test_user_set_headers_emitted() raises:
    var body = InlineBody(_bytes("ok"))
    var resp = StreamingResponse[InlineBody](status=Status.OK, body=body^)
    resp.headers.set("X-Trace", "abc-123")
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("X-Trace: abc-123\r\n") >= 0)


def test_user_content_length_dropped_in_favour_of_serializer() raises:
    """If the user set Content-Length manually, the serializer's
    own header wins (and the user's stale value is dropped)."""
    var body = InlineBody(_bytes("hi"))
    var resp = StreamingResponse[InlineBody](status=Status.OK, body=body^)
    resp.headers.set("Content-Length", "9999")
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    # Real Content-Length is 2 (body "hi"), not 9999.
    assert_true(s.find("Content-Length: 2\r\n") >= 0)
    assert_true(s.find("Content-Length: 9999") < 0)


# ── Connection disposition ─────────────────────────────────────────────────


def test_keep_alive_emits_connection_keep_alive() raises:
    var body = InlineBody(_bytes(""))
    var resp = StreamingResponse[InlineBody](status=Status.OK, body=body^)
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("Connection: keep-alive\r\n") >= 0)


def test_close_emits_connection_close() raises:
    var body = InlineBody(_bytes(""))
    var resp = StreamingResponse[InlineBody](status=Status.OK, body=body^)
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=False
    )
    var s = _wire(wire)
    assert_true(s.find("Connection: close\r\n") >= 0)


# ── Default reason phrases ────────────────────────────────────────────────


def test_default_reason_for_404() raises:
    var body = InlineBody(_bytes(""))
    var resp = StreamingResponse[InlineBody](
        status=Status.NOT_FOUND, body=body^
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("404 Not Found\r\n") >= 0)


def test_default_reason_for_500() raises:
    var body = InlineBody(_bytes(""))
    var resp = StreamingResponse[InlineBody](
        status=Status.INTERNAL_SERVER_ERROR, body=body^
    )
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("500 Internal Server Error\r\n") >= 0)


def test_default_reason_for_unknown_status() raises:
    """Class-level fallback: 4xx unknown -> ``Client Error``."""
    var body = InlineBody(_bytes(""))
    var resp = StreamingResponse[InlineBody](status=499, body=body^)
    var wire = serialize_streaming_response(
        resp^, Cancel.never(), keep_alive=True
    )
    var s = _wire(wire)
    assert_true(s.find("499 Client Error\r\n") >= 0)


def main() raises:
    print("=" * 60)
    print(
        "test_streaming_serialize.mojo — RFC 7230 framing for"
        " StreamingResponse[B]"
    )
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
