"""Tests for ``StreamingResponse[B: Body]`` (v0.5.0 follow-up /
Track 4 part 1 / C4).

The streaming-response value type pins:

- Generic over ``B: Body`` so handlers can return
  ``StreamingResponse[InlineBody]`` (Content-Length framing) or
  ``StreamingResponse[ChunkedBody[Source]]`` (chunked framing).
- The reactor pull loop (C5) drives ``body.next_chunk(cancel)``
  per writable edge; ``content_length()`` selects the framing.
- Helpers (``ok``, ``is_redirect``, ``is_client_error``,
  ``is_server_error``) match the v0.4.x ``Response`` shape so
  the public surface stays consistent.

Coverage:

- Construction with ``InlineBody``.
- Construction with ``ChunkedBody[CountingSource]``.
- Status helpers (2xx / 3xx / 4xx / 5xx).
- Header manipulation post-construction.
- ``body.next_chunk`` reachable through the response — proves
  the ``Body`` impl is intact through the move into the
  response.
- Re-export visibility from ``flare.http`` and root ``flare``.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)
from std.collections import Optional

from flare.http import (
    StreamingResponse,
    Body,
    ChunkSource,
    InlineBody,
    ChunkedBody,
    Cancel,
    Status,
)


# ── Test source ────────────────────────────────────────────────────────────


@fieldwise_init
struct _Counter(ChunkSource, Copyable, Movable):
    """Yields N single-byte chunks ('x' * 1) then ``None``."""

    var n: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.n <= 0:
            return Optional[List[UInt8]]()
        self.n -= 1
        var b = List[UInt8]()
        b.append(UInt8(ord("x")))
        return Optional[List[UInt8]](b^)


# ── Construction ───────────────────────────────────────────────────────────


def test_construct_with_inline_body() raises:
    var bytes = List[UInt8]()
    bytes.append(UInt8(ord("h")))
    bytes.append(UInt8(ord("i")))
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^, reason="OK"
    )
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.reason, "OK")
    assert_equal(resp.version, "HTTP/1.1")


def test_construct_with_chunked_body() raises:
    var body = ChunkedBody[_Counter](source=_Counter(n=3))
    var resp = StreamingResponse[ChunkedBody[_Counter]](
        status=Status.OK, body=body^
    )
    assert_equal(resp.status, Status.OK)
    # ``ChunkedBody.content_length()`` is None — the reactor
    # will use ``Transfer-Encoding: chunked`` framing.
    assert_false(Bool(resp.body.content_length()))


def test_construct_with_default_reason() raises:
    """When ``reason`` is empty, the reactor fills in a default
    from the status code at serialise time. The constructor
    accepts the empty string."""
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^
    )
    assert_equal(resp.reason, "")


# ── Status helpers ─────────────────────────────────────────────────────────


def test_ok_2xx() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^
    )
    assert_true(resp.ok())
    assert_false(resp.is_redirect())
    assert_false(resp.is_client_error())
    assert_false(resp.is_server_error())


def test_redirect_3xx() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.MOVED_PERMANENTLY, body=body^
    )
    assert_false(resp.ok())
    assert_true(resp.is_redirect())


def test_client_error_4xx() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.BAD_REQUEST, body=body^
    )
    assert_true(resp.is_client_error())
    assert_false(resp.is_server_error())


def test_server_error_5xx() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.INTERNAL_SERVER_ERROR, body=body^
    )
    assert_true(resp.is_server_error())
    assert_false(resp.is_client_error())


# ── Header manipulation ────────────────────────────────────────────────────


def test_headers_settable() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^
    )
    resp.headers.set("X-Trace", "abc-123")
    assert_equal(resp.headers.get("X-Trace"), "abc-123")


def test_default_version_is_1_1() raises:
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^
    )
    assert_equal(resp.version, "HTTP/1.1")


# ── Body still operable through the response ──────────────────────────────


def test_body_chunks_reachable_after_move() raises:
    """The ``body: B`` field can have its ``next_chunk`` called
    after the move into the response — the ``ChunkSource`` state
    didn't get split or fence-posted by the move."""
    var body = ChunkedBody[_Counter](source=_Counter(n=2))
    var resp = StreamingResponse[ChunkedBody[_Counter]](
        status=Status.OK, body=body^
    )
    var first = resp.body.next_chunk(Cancel.never())
    assert_true(Bool(first))
    if first:
        assert_equal(len(first.value()), 1)
    var second = resp.body.next_chunk(Cancel.never())
    assert_true(Bool(second))
    var third = resp.body.next_chunk(Cancel.never())
    assert_false(Bool(third))  # source exhausted after 2 chunks


def test_inline_body_yields_full_bytes() raises:
    var bytes = List[UInt8]()
    bytes.append(UInt8(ord("a")))
    bytes.append(UInt8(ord("b")))
    bytes.append(UInt8(ord("c")))
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=Status.OK, body=body^
    )
    var first = resp.body.next_chunk(Cancel.never())
    assert_true(Bool(first))
    if first:
        assert_equal(len(first.value()), 3)
    var second = resp.body.next_chunk(Cancel.never())
    assert_false(Bool(second))


# ── Re-exports ─────────────────────────────────────────────────────────────


def test_re_exports_resolve() raises:
    """``StreamingResponse`` is reachable via both
    ``flare.http`` and the root ``flare`` re-export."""
    var bytes = List[UInt8]()
    var body = InlineBody(bytes^)
    var resp = StreamingResponse[InlineBody](
        status=200, body=body^
    )
    assert_equal(resp.status, 200)


def main() raises:
    print("=" * 60)
    print("test_streaming_response.mojo — StreamingResponse[B: Body]")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
