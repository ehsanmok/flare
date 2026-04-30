"""Tests for ``flare.runtime.handoff``.

Covers:

- :class:`HandoffQueue` push / pop / drain semantics on the
  single-threaded path.
- The queue refuses (returns False) when full instead of blocking.
- ``size`` reflects pending entries through push / pop / drain.
- Wrap-around: push capacity items, pop half, push half more, then
  drain — order is FIFO across the wrap.
- Refused-push counter is bumped on each rejection.
- :class:`HandoffPolicy` defaults to disabled.
- ``HandoffPolicy.from_env`` flips when ``FLARE_SOAK_WORKERS=on``.
"""

from std.testing import assert_equal, assert_false, assert_true
from std.os import setenv

from flare.runtime import HandoffPolicy, HandoffQueue, WorkerHandoffPool


def test_push_pop_basic() raises:
    var q = HandoffQueue(8)
    assert_equal(q.size(), 0)
    assert_true(q.push(101))
    assert_true(q.push(202))
    assert_equal(q.size(), 2)
    var a = q.pop()
    assert_true(Bool(a))
    assert_equal(a.value(), 101)
    var b = q.pop()
    assert_true(Bool(b))
    assert_equal(b.value(), 202)
    var c = q.pop()
    assert_false(Bool(c))


def test_push_full_refuses() raises:
    var q = HandoffQueue(2)
    assert_true(q.push(1))
    assert_true(q.push(2))
    assert_false(q.push(3))
    assert_equal(q.refused, 1)


def test_drain_empties() raises:
    var q = HandoffQueue(4)
    _ = q.push(10)
    _ = q.push(20)
    _ = q.push(30)
    var all = q.drain()
    assert_equal(len(all), 3)
    assert_equal(all[0], 10)
    assert_equal(all[1], 20)
    assert_equal(all[2], 30)
    assert_equal(q.size(), 0)


def test_wraparound_preserves_fifo() raises:
    var q = HandoffQueue(4)
    _ = q.push(1)
    _ = q.push(2)
    _ = q.push(3)
    _ = q.push(4)
    _ = q.pop()
    _ = q.pop()
    _ = q.push(5)
    _ = q.push(6)
    var all = q.drain()
    assert_equal(len(all), 4)
    assert_equal(all[0], 3)
    assert_equal(all[1], 4)
    assert_equal(all[2], 5)
    assert_equal(all[3], 6)


def test_handoff_policy_default_disabled() raises:
    var p = HandoffPolicy()
    assert_false(p.enabled)
    assert_equal(p.capacity, 64)
    assert_equal(p.steal_threshold, 4)


def test_handoff_policy_from_env_on() raises:
    """``FLARE_SOAK_WORKERS=on`` flips the policy enabled."""
    _ = setenv("FLARE_SOAK_WORKERS", "on", True)
    var p = HandoffPolicy.from_env(HandoffPolicy())
    assert_true(p.enabled)
    assert_equal(p.steal_threshold, 1)
    _ = setenv("FLARE_SOAK_WORKERS", "", True)


def test_handoff_policy_from_env_off() raises:
    """Anything other than ``on/1/true`` keeps the default."""
    _ = setenv("FLARE_SOAK_WORKERS", "no", True)
    var p = HandoffPolicy.from_env(HandoffPolicy())
    assert_false(p.enabled)


def test_metrics_counters() raises:
    var q = HandoffQueue(2)
    _ = q.push(1)
    _ = q.push(2)
    _ = q.push(3)  # refused
    _ = q.pop()
    assert_equal(q.pushes, 2)
    assert_equal(q.pops, 1)
    assert_equal(q.refused, 1)


def test_pool_disabled_short_circuits() raises:
    """When the policy is disabled, ``try_handoff`` rejects without push."""
    var pool = WorkerHandoffPool(HandoffPolicy(False, 8, 4), 4)
    assert_equal(pool.size(), 4)
    assert_false(pool.try_handoff(1, 42))
    var d = pool.drain_local(1)
    assert_equal(len(d), 0)


def test_pool_enabled_routes_fd() raises:
    """Enabled policy + try_handoff push goes to the right queue."""
    var pool = WorkerHandoffPool(HandoffPolicy(True, 8, 4), 4)
    assert_true(pool.try_handoff(2, 99))
    var d0 = pool.drain_local(0)
    var d2 = pool.drain_local(2)
    assert_equal(len(d0), 0)
    assert_equal(len(d2), 1)
    assert_equal(d2[0], 99)


def test_pool_peek_idle_excludes_self() raises:
    """``peek_idle_worker`` returns the peer with the shortest queue."""
    var pool = WorkerHandoffPool(HandoffPolicy(True, 8, 4), 3)
    _ = pool.try_handoff(0, 1)
    _ = pool.try_handoff(0, 2)
    _ = pool.try_handoff(1, 3)
    var idle = pool.peek_idle_worker(2)
    assert_equal(idle, 1)


def test_pool_disabled_peek_returns_minus_one() raises:
    var pool = WorkerHandoffPool(HandoffPolicy(False, 8, 4), 4)
    assert_equal(pool.peek_idle_worker(0), -1)


def main() raises:
    test_push_pop_basic()
    test_push_full_refuses()
    test_drain_empties()
    test_wraparound_preserves_fifo()
    test_handoff_policy_default_disabled()
    test_handoff_policy_from_env_on()
    test_handoff_policy_from_env_off()
    test_metrics_counters()
    test_pool_disabled_short_circuits()
    test_pool_enabled_routes_fd()
    test_pool_peek_idle_excludes_self()
    test_pool_disabled_peek_returns_minus_one()
    print("test_handoff: 12 passed")
