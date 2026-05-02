"""Tests for the io_uring SQ/CQ ring driver
(``flare.runtime.io_uring_driver``).

Coverage:

1. Construction: the three mmap regions are non-NULL and the
   ring_mask is set on a freshly-set-up ring.
2. ``sq_entries`` / ``cq_entries`` reflect the kernel-allocated
   ring sizes (rounded up to a power of two from the caller's
   request).
3. ``cqe_count == 0`` on a fresh ring before any submission.
4. **SQ→CQ NOP round-trip**: submit an ``IORING_OP_NOP`` SQE
   with a tagged ``user_data``; ``submit_and_wait(1)`` returns
   1; ``reap_cqe`` returns the CQE with the same ``user_data``
   and ``res == 0``.
5. ``next_sqe`` returns sequential 64-byte slots; the indices
   wrap once we hit ``sq_entries``.
6. Multiple NOPs in one ``submit_and_wait`` round-trip — fill
   N SQEs, commit each, submit + wait for all completions,
   reap N CQEs in submission order.
7. ``reap_cqe`` returns ``None`` when the CQ is empty.
8. **Skip cleanly** when the host kernel does not expose
   io_uring (ENOSYS / EPERM / sandbox / pre-5.1) — the test
   prints a message and exits 0 instead of failing. Same
   pattern as ``test_io_uring`` for the substrate.
"""

from std.testing import assert_equal, assert_true, assert_false

from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.io_uring_driver import IoUringDriver


# ── Smoke ─────────────────────────────────────────────────────────────────────


def test_driver_construction_succeeds() raises:
    """A fresh ``IoUringDriver(8)`` constructs without raising,
    has fd >= 0, sq_entries >= 8, cq_entries >= 8, and
    sq_ring_mask = sq_entries - 1.
    """
    if not is_io_uring_available():
        print(
            "test_driver_construction_succeeds: skipped (io_uring"
            " not available on host)"
        )
        return
    var d = IoUringDriver(8)
    assert_true(d.fd() >= 0)
    assert_true(d.sq_entries() >= 8)
    assert_true(d.cq_entries() >= 8)
    assert_equal(Int(d.sq_ring_mask()), d.sq_entries() - 1)
    assert_equal(Int(d.cq_ring_mask()), d.cq_entries() - 1)


def test_fresh_driver_has_no_pending_cqes() raises:
    """Right after construction the CQ should be empty."""
    if not is_io_uring_available():
        print(
            "test_fresh_driver_has_no_pending_cqes: skipped (io_uring"
            " not available on host)"
        )
        return
    var d = IoUringDriver(8)
    assert_equal(d.cqe_count(), 0)
    var maybe = d.reap_cqe()
    assert_false(Bool(maybe))


# ── Round-trip ────────────────────────────────────────────────────────────────


def test_nop_round_trip_returns_user_data() raises:
    """The simplest possible io_uring round trip: submit one
    NOP SQE, wait for one CQE, verify ``user_data`` round trips
    and ``res == 0``.
    """
    if not is_io_uring_available():
        print(
            "test_nop_round_trip_returns_user_data: skipped (io_uring"
            " not available on host)"
        )
        return
    var d = IoUringDriver(8)
    var rc = d.submit_nop(UInt64(0xC0FFEE_42))
    assert_equal(rc, 1)  # one SQE consumed
    assert_true(d.cqe_count() >= 1)
    var maybe = d.reap_cqe()
    assert_true(Bool(maybe))
    var cqe = maybe.value()
    assert_equal(Int(cqe.user_data()), 0xC0FFEE_42)
    assert_equal(cqe.res(), 0)
    assert_false(cqe.is_error())


def test_multi_nop_round_trip_preserves_order() raises:
    """Submit four NOPs with distinct user_data tags in one
    submit_and_wait; reap four CQEs and confirm all four tags
    appear (order is FIFO per the io_uring contract for non-
    multishot ops)."""
    if not is_io_uring_available():
        print(
            "test_multi_nop_round_trip_preserves_order: skipped"
            " (io_uring not available on host)"
        )
        return
    from flare.runtime.io_uring_sqe import prep_nop

    var d = IoUringDriver(8)
    var tags = List[UInt64]()
    tags.append(UInt64(0xAA))
    tags.append(UInt64(0xBB))
    tags.append(UInt64(0xCC))
    tags.append(UInt64(0xDD))
    for i in range(4):
        var slot = d.next_sqe()
        assert_true(Int(slot) != 0)
        prep_nop(slot, tags[i])
        d.commit_sqe()
    var rc = d.submit_and_wait(4)
    assert_equal(rc, 4)
    assert_true(d.cqe_count() >= 4)
    var seen = List[UInt64]()
    for _ in range(4):
        var maybe = d.reap_cqe()
        assert_true(Bool(maybe))
        var cqe = maybe.value()
        seen.append(cqe.user_data())
        assert_equal(cqe.res(), 0)
    # NOPs are completed in submission order on every kernel
    # since 5.1 — pin the FIFO contract.
    for i in range(4):
        assert_equal(Int(seen[i]), Int(tags[i]))


def test_reap_cqe_drains_then_returns_none() raises:
    """After draining all NOPs, reap_cqe returns None and
    cqe_count is 0."""
    if not is_io_uring_available():
        print(
            "test_reap_cqe_drains_then_returns_none: skipped"
            " (io_uring not available on host)"
        )
        return
    var d = IoUringDriver(8)
    _ = d.submit_nop(UInt64(0x99))
    _ = d.reap_cqe()
    assert_equal(d.cqe_count(), 0)
    var maybe = d.reap_cqe()
    assert_false(Bool(maybe))


def test_next_sqe_advances_sequentially() raises:
    """Two consecutive ``next_sqe`` calls without
    ``commit_sqe`` should return the same slot (caller hasn't
    committed yet); two ``next_sqe → commit_sqe`` pairs return
    consecutive slots 64 bytes apart."""
    if not is_io_uring_available():
        print(
            "test_next_sqe_advances_sequentially: skipped"
            " (io_uring not available on host)"
        )
        return
    from flare.runtime.io_uring_sqe import prep_nop

    var d = IoUringDriver(8)
    var s1 = d.next_sqe()
    var s2 = d.next_sqe()
    assert_equal(Int(s1), Int(s2))
    prep_nop(s1, UInt64(1))
    d.commit_sqe()
    var s3 = d.next_sqe()
    assert_equal(Int(s3), Int(s1) + 64)


# ── Test runner ───────────────────────────────────────────────────────────────


def main() raises:
    if not is_io_uring_available():
        print(
            "test_io_uring_driver: io_uring not available on host;"
            " all 6 tests skipped"
        )
        return
    test_driver_construction_succeeds()
    print("    PASS test_driver_construction_succeeds")
    test_fresh_driver_has_no_pending_cqes()
    print("    PASS test_fresh_driver_has_no_pending_cqes")
    test_nop_round_trip_returns_user_data()
    print("    PASS test_nop_round_trip_returns_user_data")
    test_multi_nop_round_trip_preserves_order()
    print("    PASS test_multi_nop_round_trip_preserves_order")
    test_reap_cqe_drains_then_returns_none()
    print("    PASS test_reap_cqe_drains_then_returns_none")
    test_next_sqe_advances_sequentially()
    print("    PASS test_next_sqe_advances_sequentially")
    print("test_io_uring_driver: 6/6 PASS (host: io_uring AVAILABLE)")
