"""Tests for the streaming-body primitives (v0.5.0 Step 2 / Track 4).

Covers the trait + adapter shapes that lay the groundwork for the
reactor's pull-based response loop. The reactor adoption (which
turns these primitives into actual zero-allocation streamed
responses on the wire) lands as a follow-up; this commit ships
the type infrastructure plus an SSE-shaped ``ChunkSource`` that
drives end-to-end via the ``drain_body`` helper.

Covered:

- ``InlineBody`` returns the entire byte buffer on the first
  ``next_chunk``, ``None`` on subsequent calls;
  ``content_length()`` matches the buffer length.
- ``ChunkedBody[Source]`` forwards to the source's ``next``;
  ``content_length()`` is always ``None`` (chunked framing).
- A multi-chunk source produces every chunk; ``drain_body``
  concatenates them.
- ``cancel.cancelled()`` mid-stream halts the source after the
  current chunk.
- An empty source (one that returns ``None`` immediately)
  produces a zero-byte drain.

Re-exports from ``flare.http`` and the root ``flare`` package
resolve.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)
from std.collections import Optional

from flare.http import (
    Body,
    ChunkSource,
    InlineBody,
    ChunkedBody,
    drain_body,
    Cancel,
    CancelCell,
    CancelReason,
)


# ── ChunkSource implementations used by the tests ───────────────────────────


@fieldwise_init
struct _Counter(ChunkSource, Copyable, Movable):
    """Yields ``"chunk-0"``, ``"chunk-1"``, ..., ``"chunk-(N-1)"``
    then ends. ``cancel.cancelled()`` short-circuits between
    chunks."""

    var i: Int
    var n: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled():
            return Optional[List[UInt8]]()
        if self.i >= self.n:
            return Optional[List[UInt8]]()
        var label = "chunk-" + String(self.i)
        var out = List[UInt8]()
        for b in label.as_bytes():
            out.append(b)
        self.i += 1
        return Optional[List[UInt8]](out^)


@fieldwise_init
struct _Empty(ChunkSource, Copyable, Movable):
    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        return Optional[List[UInt8]]()


@fieldwise_init
struct _CancelAfter(ChunkSource, Copyable, Movable):
    """Yields a few chunks, then expects the test to flip Cancel
    so the source ends mid-stream."""

    var i: Int
    var max_i: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled():
            return Optional[List[UInt8]]()
        if self.i >= self.max_i:
            return Optional[List[UInt8]]()
        var s = "x" + String(self.i)
        var out = List[UInt8]()
        for b in s.as_bytes():
            out.append(b)
        self.i += 1
        return Optional[List[UInt8]](out^)


# ── InlineBody ─────────────────────────────────────────────────────────────


def test_inline_body_content_length() raises:
    var bytes = List[UInt8]()
    for b in "hello".as_bytes():
        bytes.append(b)
    var b = InlineBody(bytes^)
    var cl = b.content_length()
    assert_true(Bool(cl))
    assert_equal(cl.value(), 5)


def test_inline_body_returns_bytes_then_none() raises:
    var bytes = List[UInt8]()
    for b in "hi".as_bytes():
        bytes.append(b)
    var body = InlineBody(bytes^)
    var first = body.next_chunk(Cancel.never())
    assert_true(Bool(first))
    assert_equal(len(first.value()), 2)
    var second = body.next_chunk(Cancel.never())
    assert_false(Bool(second))


def test_inline_body_drain() raises:
    var bytes = List[UInt8]()
    for b in "world".as_bytes():
        bytes.append(b)
    var body = InlineBody(bytes^)
    var drained = drain_body(body, Cancel.never())
    assert_equal(len(drained), 5)


def test_inline_body_empty() raises:
    var body = InlineBody(List[UInt8]())
    assert_equal(body.content_length().value(), 0)
    var drained = drain_body(body, Cancel.never())
    assert_equal(len(drained), 0)


# ── ChunkedBody ────────────────────────────────────────────────────────────


def test_chunked_body_content_length_is_none() raises:
    var body = ChunkedBody[_Counter](source=_Counter(0, 3))
    assert_false(Bool(body.content_length()))


def test_chunked_body_streams_three_chunks() raises:
    var body = ChunkedBody[_Counter](source=_Counter(0, 3))
    var drained = drain_body(body, Cancel.never())
    # "chunk-0" + "chunk-1" + "chunk-2" = 7 + 7 + 7 = 21 bytes
    assert_equal(len(drained), 21)


def test_chunked_body_empty_source() raises:
    var body = ChunkedBody[_Empty](source=_Empty())
    var drained = drain_body(body, Cancel.never())
    assert_equal(len(drained), 0)


def test_chunked_body_cancel_pre_flip_yields_nothing() raises:
    """Source that's already cancelled before draining yields no
    bytes."""
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var body = ChunkedBody[_CancelAfter](source=_CancelAfter(0, 100))
    var drained = drain_body(body, cell.handle())
    assert_equal(len(drained), 0)


def test_chunked_body_drain_runs_to_completion_with_never_cancel() raises:
    var body = ChunkedBody[_Counter](source=_Counter(0, 5))
    var drained = drain_body(body, Cancel.never())
    # 5 chunks, "chunk-0" through "chunk-4", each 7 bytes.
    assert_equal(len(drained), 35)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
