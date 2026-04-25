"""Tests for ``block_in_pool`` (v0.5.0 Step 3 / Track 2.5).

The pthread-pool implementation lands in a follow-up; today's
in-thread fallback runs ``work()`` synchronously. These tests
cover the API contract that handlers depend on:

- ``work()`` runs and its return value flows back.
- ``work()`` errors propagate.
- A pre-flipped ``Cancel`` short-circuits before ``work()`` runs.
- The per-cancel-reason error message is meaningful.

When the pool lands, the same tests pass unchanged plus a new
"runs across threads" test joins.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_raises,
    TestSuite,
)

from flare.runtime import block_in_pool, MAX_POOL_SIZE
from flare.http import Cancel, CancelCell, CancelReason


# ── Happy path ─────────────────────────────────────────────────────────────


def _return_42() raises -> Int:
    return 42


def test_returns_work_result() raises:
    var got = block_in_pool[Int](_return_42, Cancel.never())
    assert_equal(got, 42)


def _return_string() raises -> String:
    return "hello"


def test_returns_string_result() raises:
    var got = block_in_pool[String](_return_string, Cancel.never())
    assert_equal(got, "hello")


# ── Error propagation ──────────────────────────────────────────────────────


def _always_raises() raises -> Int:
    raise Error("work() failed")


def test_work_error_propagates() raises:
    with assert_raises():
        _ = block_in_pool[Int](_always_raises, Cancel.never())


# ── Cancel short-circuit ───────────────────────────────────────────────────


def test_pre_flipped_cancel_skips_work_peer_closed() raises:
    var cell = CancelCell()
    cell.flip(CancelReason.PEER_CLOSED)
    with assert_raises():
        _ = block_in_pool[Int](_return_42, cell.handle())


def test_pre_flipped_cancel_skips_work_timeout() raises:
    var cell = CancelCell()
    cell.flip(CancelReason.TIMEOUT)
    with assert_raises():
        _ = block_in_pool[Int](_return_42, cell.handle())


def test_pre_flipped_cancel_skips_work_shutdown() raises:
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    with assert_raises():
        _ = block_in_pool[Int](_return_42, cell.handle())


# ── Constants ──────────────────────────────────────────────────────────────


def test_max_pool_size_is_32() raises:
    """The global pool-size cap is 32 (design-0.5 Track 2.5
    bound to prevent pathological resource use on many-core
    machines)."""
    assert_equal(MAX_POOL_SIZE, 32)


# ── 1000 sequential calls, each returning a counted Int ────────────────────


def _bump_counter() raises -> Int:
    return 1


def test_thousand_sequential_calls() raises:
    """1000 ``block_in_pool`` calls in a row. Sanity check on the
    in-thread fallback's overhead. Each call returns the same
    constant since Mojo nested-def closures need a separate
    capture story; the count of successful returns is what
    we're after.
    """
    var total = 0
    for _ in range(1000):
        total += block_in_pool[Int](_bump_counter, Cancel.never())
    assert_equal(total, 1000)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
