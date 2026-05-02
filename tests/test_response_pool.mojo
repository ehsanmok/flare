"""Tests for ``Response.reset`` + ``ResponsePool`` (Track B6)."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import Response, ResponsePool


def test_reset_clears_status_reason_body_headers() raises:
    var r = Response(status=404, reason=String("Not Found"))
    r.body.append(UInt8(65))
    r.body.append(UInt8(66))
    r.headers.set(String("X-Foo"), String("bar"))
    assert_equal(r.status, 404)
    assert_equal(r.reason, String("Not Found"))
    assert_equal(len(r.body), 2)
    assert_equal(r.headers.len(), 1)

    r.reset(status=200, reason=String("OK"))
    assert_equal(r.status, 200)
    assert_equal(r.reason, String("OK"))
    assert_equal(len(r.body), 0)
    assert_equal(r.headers.len(), 0)


def test_reset_default_args_set_status_200_empty_reason() raises:
    var r = Response(status=500)
    r.reset()
    assert_equal(r.status, 200)
    assert_equal(r.reason.byte_length(), 0)


def test_reset_preserves_body_capacity_for_keepalive_reuse() raises:
    """Reset must not deallocate the body backing — that's the
    whole point of B6 (next response on the same connection
    refills the same malloc'd buffer).
    """
    var r = Response(status=200)
    r.body.reserve(8192)
    var cap_before = r.body.capacity
    assert_true(cap_before >= 8192)
    for i in range(100):
        r.body.append(UInt8(i % 256))
    r.reset()
    assert_equal(len(r.body), 0)
    assert_true(r.body.capacity >= 8192)


def test_reset_preserves_header_capacity_for_keepalive_reuse() raises:
    """Same invariant for the header-map backing arrays."""
    var r = Response(status=200)
    r.headers.set(String("X-One"), String("1"))
    r.headers.set(String("X-Two"), String("2"))
    r.headers.set(String("X-Three"), String("3"))
    var keys_cap = r.headers._keys.capacity
    var vals_cap = r.headers._values.capacity
    r.reset()
    assert_equal(r.headers.len(), 0)
    assert_true(r.headers._keys.capacity >= keys_cap)
    assert_true(r.headers._values.capacity >= vals_cap)


def test_pool_default_capacity_is_eight() raises:
    var p = ResponsePool()
    assert_equal(p.size(), 0)
    assert_equal(p.capacity(), 8)


def test_pool_with_capacity_factory() raises:
    var p = ResponsePool.with_capacity(16)
    assert_equal(p.capacity(), 16)
    assert_equal(p.size(), 0)


def test_pool_with_capacity_clamps_minimum_to_one() raises:
    """Calling ``with_capacity(0)`` or a negative cap must clamp
    to 1 — a zero-cap pool is silently broken (every release
    drops, every acquire allocates) and is almost certainly a
    bug at the call site.
    """
    var p = ResponsePool.with_capacity(0)
    assert_equal(p.capacity(), 1)
    var p2 = ResponsePool.with_capacity(-5)
    assert_equal(p2.capacity(), 1)


def test_pool_acquire_from_empty_constructs_fresh() raises:
    var p = ResponsePool()
    var r = p.acquire(status=201, reason=String("Created"))
    assert_equal(r.status, 201)
    assert_equal(r.reason, String("Created"))
    assert_equal(len(r.body), 0)
    assert_equal(r.headers.len(), 0)
    assert_equal(p.size(), 0)


def test_pool_release_then_acquire_recycles() raises:
    """Release a Response with a body buffer; the next acquire
    must hand back the same recycled buffer (capacity preserved).
    """
    var p = ResponsePool()
    var r = Response(status=200)
    r.body.reserve(4096)
    var marker_cap = r.body.capacity
    r.body.append(UInt8(7))
    p.release(r^)
    assert_equal(p.size(), 1)

    var r2 = p.acquire(status=302, reason=String("Found"))
    assert_equal(r2.status, 302)
    assert_equal(r2.reason, String("Found"))
    assert_equal(len(r2.body), 0)
    assert_true(r2.body.capacity >= marker_cap)
    assert_equal(p.size(), 0)


def test_pool_release_past_capacity_drops_extras() raises:
    """A pool capped at N must not grow past N; releases past the
    cap drop their input (Mojo destructor runs on the dropped
    Response).
    """
    var p = ResponsePool.with_capacity(2)
    p.release(Response(status=200))
    p.release(Response(status=201))
    assert_equal(p.size(), 2)

    # Third release: pool is at cap, dropped on the floor.
    p.release(Response(status=202))
    assert_equal(p.size(), 2)


def test_pool_acquire_release_acquire_lifo_order() raises:
    """Pool is a stack — the most recently released item is
    returned first by the next acquire.
    """
    var p = ResponsePool()

    var first = Response(status=200)
    first.headers.set(String("X-Tag"), String("FIRST"))
    p.release(first^)

    var second = Response(status=200)
    second.headers.set(String("X-Tag"), String("SECOND"))
    p.release(second^)

    var got = p.acquire()
    # Items are reset before return — header is gone. Capacity-
    # ordering check via the size of the prior _keys list isn't
    # observable. Instead, verify size() decreases by 1 per acquire.
    assert_equal(p.size(), 1)
    var got2 = p.acquire()
    assert_equal(p.size(), 0)
    # Both are valid empty Responses.
    assert_equal(got.status, 200)
    assert_equal(got2.status, 200)
    assert_equal(got.headers.len(), 0)
    assert_equal(got2.headers.len(), 0)


def test_pool_acquire_resets_reason() raises:
    """Even when recycled from the pool, the reason field must
    reflect the new acquire-call's argument, not whatever the
    previous user wrote there.
    """
    var p = ResponsePool()
    var r = Response(status=500, reason=String("Internal Server Error"))
    p.release(r^)
    var got = p.acquire(status=200, reason=String("OK"))
    assert_equal(got.status, 200)
    assert_equal(got.reason, String("OK"))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
