"""Tests for :mod:`flare.http.request_chunks`.

Coverage:

1. ``RequestChunkSource.of`` builds a source with default chunk
   size; ``total()`` and ``remaining()`` reflect the request
   body length.
2. Iteration yields the entire body across N chunks for various
   body sizes (smaller than chunk, exact multiple, with
   remainder).
3. Empty body returns ``None`` immediately.
4. ``of_with_chunk_size`` accepts arbitrary positive chunk
   sizes; raises on ``chunk_size <= 0``.
5. Cancellation: a cancelled token returns ``None`` from
   ``next`` even if the body has bytes remaining.
6. ``remaining()`` decreases monotonically; ``total()`` is
   constant.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.cancel import Cancel, CancelCell, CancelReason
from flare.http.request import Request
from flare.http.request_chunks import RequestChunkSource


def _make_request_with_body(body: List[UInt8]) -> Request:
    var req = Request(method=String("POST"), url=String("/upload"))
    req.body = body.copy()
    return req^


def _bytes_of(values: List[Int]) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(values)):
        out.append(UInt8(values[i]))
    return out^


# ── Construction ──────────────────────────────────────────────────────────


def test_of_default_chunk_size_total_and_remaining() raises:
    var v = List[Int]()
    for i in range(100):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of(req)
    assert_equal(s.total(), 100)
    assert_equal(s.remaining(), 100)
    assert_equal(s.chunk_size, 65536)


def test_of_with_chunk_size_zero_raises() raises:
    var req = _make_request_with_body(List[UInt8]())
    var raised = False
    try:
        var _s = RequestChunkSource.of_with_chunk_size(req, 0)
    except:
        raised = True
    assert_true(raised)


def test_of_with_chunk_size_negative_raises() raises:
    var req = _make_request_with_body(List[UInt8]())
    var raised = False
    try:
        var _s = RequestChunkSource.of_with_chunk_size(req, -1)
    except:
        raised = True
    assert_true(raised)


# ── Iteration ─────────────────────────────────────────────────────────────


def test_iter_smaller_than_chunk_yields_one_chunk() raises:
    var v = List[Int]()
    for i in range(5):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 16)
    var cell = CancelCell()
    var c = cell.handle()
    var got = s.next(c)
    assert_true(got)
    assert_equal(len(got.value()), 5)
    assert_equal(s.remaining(), 0)
    var done = s.next(c)
    assert_false(done)
    cell.reset()


def test_iter_exact_multiple_of_chunk_size() raises:
    var v = List[Int]()
    for i in range(8):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 4)
    var cell = CancelCell()
    var c = cell.handle()
    var c0 = s.next(c)
    var c1 = s.next(c)
    var c2 = s.next(c)
    assert_true(c0)
    assert_true(c1)
    assert_false(c2)
    assert_equal(len(c0.value()), 4)
    assert_equal(len(c1.value()), 4)
    cell.reset()


def test_iter_with_remainder_emits_short_final_chunk() raises:
    var v = List[Int]()
    for i in range(10):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 4)
    var cell = CancelCell()
    var c = cell.handle()
    var c0 = s.next(c)
    var c1 = s.next(c)
    var c2 = s.next(c)
    var c3 = s.next(c)
    assert_true(c0)
    assert_true(c1)
    assert_true(c2)
    assert_false(c3)
    assert_equal(len(c0.value()), 4)
    assert_equal(len(c1.value()), 4)
    assert_equal(len(c2.value()), 2)
    cell.reset()


def test_iter_preserves_byte_values() raises:
    var v = List[Int]()
    for i in range(8):
        v.append(i * 7 % 256)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 3)
    var cell = CancelCell()
    var c = cell.handle()
    var collected = List[UInt8]()
    while True:
        var nxt = s.next(c)
        if not nxt:
            break
        var ch = nxt.value().copy()
        for k in range(len(ch)):
            collected.append(ch[k])
    assert_equal(len(collected), 8)
    for i in range(8):
        assert_equal(Int(collected[i]), (i * 7) % 256)
    cell.reset()


def test_iter_empty_body_yields_none_immediately() raises:
    var req = _make_request_with_body(List[UInt8]())
    var s = RequestChunkSource.of(req)
    var cell = CancelCell()
    var c = cell.handle()
    var first = s.next(c)
    assert_false(first)
    assert_equal(s.total(), 0)
    assert_equal(s.remaining(), 0)
    cell.reset()


# ── Cancellation ──────────────────────────────────────────────────────────


def test_cancel_short_circuits_to_none() raises:
    var v = List[Int]()
    for i in range(100):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 10)
    var cell = CancelCell()
    var c = cell.handle()
    cell.flip(CancelReason.SHUTDOWN)
    var got = s.next(c)
    assert_false(got)
    assert_equal(s.remaining(), 100)
    cell.reset()


# ── Bookkeeping ───────────────────────────────────────────────────────────


def test_remaining_decreases_monotonically_total_constant() raises:
    var v = List[Int]()
    for i in range(20):
        v.append(i)
    var req = _make_request_with_body(_bytes_of(v))
    var s = RequestChunkSource.of_with_chunk_size(req, 6)
    var cell = CancelCell()
    var c = cell.handle()
    var prev_remaining = s.remaining()
    assert_equal(s.total(), 20)
    while True:
        var nxt = s.next(c)
        if not nxt:
            break
        assert_true(s.remaining() < prev_remaining)
        assert_equal(s.total(), 20)
        prev_remaining = s.remaining()
    cell.reset()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
