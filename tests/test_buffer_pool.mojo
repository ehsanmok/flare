"""Tests for ``BufferHandle`` + ``BufferPool``."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.runtime import BufferHandle, BufferPool


# ── Size-class table tests ──────────────────────────────────────────────────


def test_size_for_rounds_up_to_size_class() raises:
    assert_equal(BufferPool.size_for(1), 1024)
    assert_equal(BufferPool.size_for(1024), 1024)
    assert_equal(BufferPool.size_for(1025), 4 * 1024)
    assert_equal(BufferPool.size_for(4 * 1024), 4 * 1024)
    assert_equal(BufferPool.size_for(4 * 1024 + 1), 16 * 1024)
    assert_equal(BufferPool.size_for(16 * 1024), 16 * 1024)
    assert_equal(BufferPool.size_for(16 * 1024 + 1), 64 * 1024)
    assert_equal(BufferPool.size_for(64 * 1024), 64 * 1024)


def test_size_for_oversize_returns_caller_request_verbatim() raises:
    """Requests above the largest size class skip pool snapping
    and pass through the caller's exact byte count.
    """
    assert_equal(BufferPool.size_for(64 * 1024 + 1), 64 * 1024 + 1)
    assert_equal(BufferPool.size_for(1_000_000), 1_000_000)


# ── BufferHandle tests ──────────────────────────────────────────────────────


def test_handle_for_class_reserves_size_class_capacity() raises:
    var h = BufferHandle.for_class(0)
    assert_equal(h.class_index, 0)
    assert_true(h.bytes.capacity >= 1024)
    assert_equal(len(h.bytes), 0)

    var h2 = BufferHandle.for_class(3)
    assert_equal(h2.class_index, 3)
    assert_true(h2.bytes.capacity >= 64 * 1024)
    assert_equal(len(h2.bytes), 0)


def test_handle_reset_preserves_capacity() raises:
    var h = BufferHandle.for_class(2)
    var cap_before = h.bytes.capacity
    for i in range(1024):
        h.bytes.append(UInt8(i % 256))
    assert_equal(len(h.bytes), 1024)
    h.reset()
    assert_equal(len(h.bytes), 0)
    assert_true(h.bytes.capacity >= cap_before)


# ── BufferPool tests ────────────────────────────────────────────────────────


def test_pool_default_class_capacity_is_eight() raises:
    var p = BufferPool()
    assert_equal(p.class_capacity(), 8)
    for ci in range(4):
        assert_equal(p.size(ci), 0)


def test_pool_with_class_capacity_factory() raises:
    var p = BufferPool.with_class_capacity(16)
    assert_equal(p.class_capacity(), 16)


def test_pool_with_class_capacity_clamps_minimum_to_one() raises:
    var p = BufferPool.with_class_capacity(0)
    assert_equal(p.class_capacity(), 1)
    var p2 = BufferPool.with_class_capacity(-3)
    assert_equal(p2.class_capacity(), 1)


def test_pool_acquire_from_empty_constructs_fresh_class_0() raises:
    var p = BufferPool()
    var h = p.acquire(min_capacity=512)
    assert_equal(h.class_index, 0)
    assert_true(h.bytes.capacity >= 1024)


def test_pool_acquire_dispatches_to_correct_class() raises:
    var p = BufferPool()
    var h1k = p.acquire(min_capacity=900)
    var h4k = p.acquire(min_capacity=2000)
    var h16k = p.acquire(min_capacity=8000)
    var h64k = p.acquire(min_capacity=33_000)
    assert_equal(h1k.class_index, 0)
    assert_equal(h4k.class_index, 1)
    assert_equal(h16k.class_index, 2)
    assert_equal(h64k.class_index, 3)


def test_pool_acquire_oversize_bypasses_pool() raises:
    """Requests above 64 KiB are handed back as one-off allocations
    with the OVERSIZE class index. ``release`` will drop them
    rather than push into a non-existent bucket.
    """
    var p = BufferPool()
    var h = p.acquire(min_capacity=200_000)
    assert_equal(h.class_index, -1)
    assert_true(h.bytes.capacity >= 200_000)


def test_pool_release_oversize_does_not_grow_any_bucket() raises:
    var p = BufferPool()
    var h = p.acquire(min_capacity=200_000)
    p.release(h^)
    for ci in range(4):
        assert_equal(p.size(ci), 0)


def test_pool_release_then_acquire_recycles_capacity() raises:
    """Reserve large body in a 16 KiB-class buffer; release;
    re-acquire same class; verify the capacity is preserved
    (the actual B5 win).
    """
    var p = BufferPool()
    var h = p.acquire(min_capacity=8000)
    var marker_cap = h.bytes.capacity
    for i in range(5000):
        h.bytes.append(UInt8(i % 256))
    p.release(h^)
    assert_equal(p.size(2), 1)

    var h2 = p.acquire(min_capacity=8000)
    assert_equal(h2.class_index, 2)
    assert_equal(len(h2.bytes), 0)
    assert_true(h2.bytes.capacity >= marker_cap)
    assert_equal(p.size(2), 0)


def test_pool_release_past_class_capacity_drops_extras() raises:
    var p = BufferPool.with_class_capacity(2)
    p.release(BufferHandle.for_class(1))
    p.release(BufferHandle.for_class(1))
    assert_equal(p.size(1), 2)
    p.release(BufferHandle.for_class(1))
    assert_equal(p.size(1), 2)


def test_pool_buckets_are_independent() raises:
    """Releasing a 4 KiB buffer must not affect the 1 KiB / 16 KiB /
    64 KiB buckets.
    """
    var p = BufferPool()
    p.release(BufferHandle.for_class(1))
    p.release(BufferHandle.for_class(1))
    assert_equal(p.size(0), 0)
    assert_equal(p.size(1), 2)
    assert_equal(p.size(2), 0)
    assert_equal(p.size(3), 0)


def test_pool_acquire_release_acquire_lifo_within_class() raises:
    var p = BufferPool()
    var first = BufferHandle.for_class(2)
    var second = BufferHandle.for_class(2)
    p.release(first^)
    p.release(second^)
    assert_equal(p.size(2), 2)
    var got = p.acquire(min_capacity=8000)
    assert_equal(p.size(2), 1)
    var got2 = p.acquire(min_capacity=8000)
    assert_equal(p.size(2), 0)
    assert_equal(got.class_index, 2)
    assert_equal(got2.class_index, 2)


def test_pool_size_accessor_handles_out_of_range() raises:
    var p = BufferPool()
    assert_equal(p.size(-1), 0)
    assert_equal(p.size(4), 0)
    assert_equal(p.size(99), 0)


def test_pool_release_with_invalid_class_index_drops_silently() raises:
    """A handle with a corrupted ``class_index`` (out of [0,3]
    and not OVERSIZE) must not crash or grow any bucket.
    """
    var p = BufferPool()
    var h = BufferHandle(capacity=128, class_index=99)
    p.release(h^)
    for ci in range(4):
        assert_equal(p.size(ci), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
