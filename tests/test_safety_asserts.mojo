"""Bounds-check + ``debug_assert[assert_mode="safe"]`` harness for
the Track B substrate primitives.

This suite exercises the **happy paths** of every accessor / FFI
wrapper that recently grew an ``assert_mode="safe"`` precondition
guard, so that:

1. Default builds (``ASSERT=safe``) pay the assert cost on every
   call without the test catching anything (proves the guard
   doesn't fire on legal inputs — i.e. we have no false positives
   on the legal API surface).
2. ``-D ASSERT=all`` builds (CI's ``tests-asserts-all``) compile
   in *every* assert (both safe and default mode) and exercise
   every legal input through them.
3. ``--sanitize address`` builds (``tests-asan``) feed the same
   inputs through ASan, catching any heap-buffer-overflow or
   use-after-free that would slip past the asserts (e.g. a
   pointer arithmetic bug inside ``writev_buf_all`` that doesn't
   itself violate a precondition but leaves a stale pointer in
   the iovec array).

This is the contract test for the safety net documented in
``.cursor/rules/sanitizers-and-bounds-checking.mdc``. Adding a
new ``debug_assert[assert_mode="safe"]`` to flare? Add a happy-
path exerciser here so the next ``pixi run tests-asserts-all``
catches a regression.

Note: we do NOT test the *failure* path of ``assert_mode="safe"``
guards (that would require ``-D ASSERT=warn`` to keep the test
process alive after the assert prints, plus a stdout capture).
The asserts' failure semantics are tested upstream in the Mojo
stdlib's ``debug_assert`` test suite. flare's responsibility is
the precondition predicate itself.
"""

from std.testing import TestSuite, assert_equal, assert_true, assert_false

from flare.runtime import (
    BufferHandle,
    BufferPool,
    DateCache,
    IoVecBuf,
    is_io_uring_available,
    writev_buf_all,
)
from flare.http import (
    huffman_decode,
    huffman_encode,
    huffman_encoded_length,
    simd_cookie_scan,
    simd_memmem,
    simd_percent_decode,
)
from flare.http.response_pool import ResponsePool
from flare.http.response import Response


# ── IoVecBuf bounds-check happy paths ────────────────────────────


def test_iovec_set_at_every_legal_index() raises:
    """Every index in [0, n) must accept a set() call without
    tripping the bounds-check assert. Verifies the ``i < self._n``
    upper bound is non-strict in the right direction.
    """
    var iov = IoVecBuf(8)
    for i in range(8):
        iov.set(i, 0x1000 + i, 16)
    for i in range(8):
        assert_equal(iov.cell_ptr(i), 0x1000 + i)
        assert_equal(iov.cell_len(i), 16)


def test_iovec_set_zero_len_with_null_ptr_is_legal() raises:
    """``IoVecBuf.set`` allows ``ptr == 0`` when ``len == 0`` —
    matches POSIX ``writev(2)`` semantics for skip-this-cell.
    The assert predicate is ``n == 0 or ptr != 0``, so
    ``set(0, 0, 0)`` is legal and must not abort.
    """
    var iov = IoVecBuf(2)
    iov.set(0, 0, 0)
    iov.set(1, 0, 0)
    assert_equal(iov.cell_ptr(0), 0)
    assert_equal(iov.cell_len(0), 0)


def test_iovec_set_nonzero_len_with_real_ptr_is_legal() raises:
    """``ptr != 0 && n > 0`` is the common case — must not
    trip the dual ``ptr/len`` invariants.
    """
    var iov = IoVecBuf(1)
    iov.set(0, 0xDEADBEEF, 1024)
    assert_equal(iov.cell_ptr(0), 0xDEADBEEF)
    assert_equal(iov.cell_len(0), 1024)


# ── BufferPool bounds-check happy paths ──────────────────────────


def test_buffer_pool_acquire_at_each_size_class() raises:
    """The four documented size classes (1 KiB / 4 KiB / 16 KiB
    / 64 KiB) must all clear the ``min_capacity >= 0`` precondition.
    """
    var p = BufferPool()
    var h0 = p.acquire(min_capacity=512)  # → 1 KiB class
    assert_equal(h0.class_index, 0)
    var h1 = p.acquire(min_capacity=2048)  # → 4 KiB class
    assert_equal(h1.class_index, 1)
    var h2 = p.acquire(min_capacity=8192)  # → 16 KiB class
    assert_equal(h2.class_index, 2)
    var h3 = p.acquire(min_capacity=32768)  # → 64 KiB class
    assert_equal(h3.class_index, 3)
    p.release(h0^)
    p.release(h1^)
    p.release(h2^)
    p.release(h3^)


def test_buffer_pool_acquire_zero_min_capacity_is_legal() raises:
    """A 0-byte minimum is the documented "give me the smallest
    class" path — must not trip the ``>= 0`` precondition.
    """
    var p = BufferPool()
    var h = p.acquire(min_capacity=0)
    assert_equal(h.class_index, 0)


# ── ResponsePool happy paths ─────────────────────────────────────


def test_response_pool_with_capacity_clamps_zero_input() raises:
    """``with_capacity(0)`` is documented as defense-in-depth
    clamping (see body) — must not trip an assert and must
    yield a 1-slot pool.
    """
    var p = ResponsePool.with_capacity(0)
    assert_equal(p.capacity(), 1)


def test_response_pool_acquire_release_round_trip() raises:
    """Happy-path keep-alive recycle: acquire / release / acquire
    must not trip any debug_assert in the pool path.
    """
    var p = ResponsePool.with_capacity(2)
    var r1 = p.acquire(status=200)
    assert_equal(r1.status, 200)
    p.release(r1^)
    assert_equal(p.size(), 1)
    var r2 = p.acquire(status=204)
    assert_equal(r2.status, 204)
    assert_equal(p.size(), 0)


# ── DateCache happy paths ────────────────────────────────────────


def test_date_cache_construct_and_refresh() raises:
    """``DateCache.__init__`` calls ``_realtime_seconds()`` which
    calls ``clock_gettime(CLOCK_REALTIME, ...)``. The
    ``clock_gettime != 0`` assert must not fire on Linux / macOS.
    """
    var c = DateCache()
    assert_true(c.epoch_second() >= 0)
    c.refresh()
    assert_true(c.epoch_second() >= 0)


def test_date_cache_two_digit_writes_cover_full_range() raises:
    """The IMF-fixdate format writes hours, minutes, seconds, and
    day-of-month in the [0, 99] range — exercised by simply
    constructing the cache (which formats the current second).
    The ``_write_two_digits`` assert that ``n < 100`` must hold
    for every legal call site.
    """
    var c = DateCache()
    var bytes = c.current_bytes()
    assert_equal(len(bytes), 29)


# ── HPACK Huffman happy paths ────────────────────────────────────


def test_huffman_encode_byte_range_assert_holds() raises:
    """Every byte in [0, 255] is a legal input symbol — the
    ``sym >= 0 and sym <= 255`` assert in the encoder must hold
    for every call site of ``huffman_encode``.
    """
    var input = List[UInt8]()
    for i in range(256):
        input.append(UInt8(i))
    var output = List[UInt8]()
    huffman_encode(Span[UInt8, origin_of(input)](input), output)
    assert_true(len(output) > 0)


def test_huffman_decode_empty_input_is_legal() raises:
    """An empty input is a valid HPACK Huffman string (decodes to
    empty). The ``n >= 0`` assert at the decode entry point must
    not fire on an empty Span.
    """
    var empty = List[UInt8]()
    var output = List[UInt8]()
    huffman_decode(Span[UInt8, origin_of(empty)](empty), output)
    assert_equal(len(output), 0)


# ── SIMD parser happy paths ──────────────────────────────────────


def test_simd_memmem_empty_haystack_no_assert() raises:
    """An empty haystack is a legal input; the assert must not
    fire on ``len == 0``.
    """
    var hay = List[UInt8]()
    var needle = List[UInt8]()
    needle.append(UInt8(65))
    var off = simd_memmem(
        Span[UInt8, origin_of(hay)](hay),
        Span[UInt8, origin_of(needle)](needle),
    )
    assert_equal(off, -1)


def test_simd_percent_decode_empty_input_no_assert() raises:
    """Empty input → empty output, no assert fires."""
    var input = List[UInt8]()
    var output = List[UInt8]()
    simd_percent_decode(Span[UInt8, origin_of(input)](input), output)
    assert_equal(len(output), 0)


def test_simd_cookie_scan_empty_input_no_assert() raises:
    """Empty input → no offsets appended, no assert fires."""
    var input = List[UInt8]()
    var offsets = List[Int]()
    simd_cookie_scan(Span[UInt8, origin_of(input)](input), offsets)
    assert_equal(len(offsets), 0)


# ── io_uring happy paths (Linux-conditional) ─────────────────────


def test_io_uring_feature_detection_no_assert() raises:
    """``is_io_uring_available()`` runs through the syscall FFI on
    Linux and the comptime-no-op path on non-Linux. Neither must
    fire any debug_assert.
    """
    var available = is_io_uring_available()
    # Just verify the call returns; the value is platform-dependent.
    _ = available


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
