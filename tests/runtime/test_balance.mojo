"""Tests for ``flare.runtime._balance`` (accept-time connection balancing).

The ``Balancer`` only moves addresses and loads around a flat ``Int64``
block, so these tests use made-up stream addresses and a wake fd of 0
(which ``push`` skips); no sockets or reactors are involved.

Covers:

- A default ``Balancer`` and one opened without a group are disabled and
  every call is a no-op.
- ``pick`` keeps the connection when loads are even, when this worker is
  under the floor, and when the lead over the best peer is one.
- ``pick`` names the least-loaded live peer once the lead is bigger,
  counts a peer's pending inbox as load, and skips peers that are not
  live.
- ``push`` / ``pop`` are FIFO, ``pending`` tracks the inbox, a full
  inbox refuses further pushes.
- After ``close`` no push is accepted and what was queued can still be
  drained.
"""

from std.memory import Pointer, Layout, alloc
from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.runtime._balance import (
    Balancer,
    balance_group_alloc,
    balance_group_free,
    _INBOX_CAP,
    _FLOOR,
)
from flare.runtime.scheduler_stats import (
    WORKER_STAT_GROUP,
    WORKER_STAT_INDEX,
    WORKER_STAT_SLOTS,
    store_worker_stat,
)


def _stats_cell(group: Int, idx: Int) -> Int:
    """A zeroed worker stats cell that names ``group`` and worker ``idx``."""
    var p = alloc(Layout[Int64](count=WORKER_STAT_SLOTS)).unsafe_leak()
    for i in range(WORKER_STAT_SLOTS):
        p[unsafe_offset=i] = Int64(0)
    var addr = Int(p)
    store_worker_stat(addr, WORKER_STAT_GROUP, group)
    store_worker_stat(addr, WORKER_STAT_INDEX, idx)
    return addr


def _free_cell(addr: Int):
    Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr).unsafe_free()


def test_default_balancer_is_disabled() raises:
    var b = Balancer()
    assert_false(b.enabled())
    assert_equal(b.pick(1000), -1)
    assert_false(b.push(0, 42))
    assert_equal(b.pending(), 0)
    assert_equal(b.pop(), 0)
    b.publish(5)
    b.close()


def test_open_without_group_is_disabled() raises:
    var cell = _stats_cell(0, 0)
    var b = Balancer.open(cell, 0)
    assert_false(b.enabled())
    _free_cell(cell)


def test_pick_keeps_connection_when_even() raises:
    var g = balance_group_alloc(3)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var c2 = _stats_cell(g, 2)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    var b2 = Balancer.open(c2, 0)
    b0.publish(40)
    b1.publish(40)
    b2.publish(39)
    assert_equal(b0.pick(40), -1)
    assert_equal(b1.pick(40), -1)
    assert_equal(b2.pick(39), -1)
    _free_cell(c0)
    _free_cell(c1)
    _free_cell(c2)
    balance_group_free(g)


def test_pick_keeps_connection_below_floor() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    b1.publish(0)
    assert_equal(b0.pick(_FLOOR - 1), -1)
    assert_equal(b0.pick(_FLOOR + 2), 1)
    _free_cell(c0)
    _free_cell(c1)
    balance_group_free(g)


def test_pick_names_least_loaded_peer() raises:
    var g = balance_group_alloc(4)
    var cells = List[Int]()
    var bs = List[Balancer]()
    for i in range(4):
        var c = _stats_cell(g, i)
        cells.append(c)
        bs.append(Balancer.open(c, 0))
    bs[0].publish(30)
    bs[1].publish(12)
    bs[2].publish(9)
    bs[3].publish(20)
    assert_equal(bs[0].pick(30), 2)
    # A lead of exactly one is not worth a hand-off.
    bs[1].publish(29)
    bs[2].publish(29)
    bs[3].publish(29)
    assert_equal(bs[0].pick(30), -1)
    bs[3].publish(28)
    assert_equal(bs[0].pick(30), 3)
    for i in range(4):
        _free_cell(cells[i])
    balance_group_free(g)


def test_pick_counts_pending_as_load() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    b0.publish(20)
    b1.publish(10)
    assert_equal(b0.pick(20), 1)
    # Streams already queued for worker 1 count toward its load.
    for k in range(9):
        assert_true(b0.push(1, 100 + k))
    assert_equal(b0.pick(20), -1)
    # And this worker's own inbox counts toward its own.
    for k in range(5):
        assert_true(b1.push(0, 200 + k))
    assert_equal(b0.pick(20), 1)
    _free_cell(c0)
    _free_cell(c1)
    balance_group_free(g)


def test_pick_skips_peer_that_is_not_live() raises:
    var g = balance_group_alloc(3)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var c2 = _stats_cell(g, 2)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    var b2 = Balancer.open(c2, 0)
    b0.publish(30)
    b1.publish(3)
    b2.publish(10)
    assert_equal(b0.pick(30), 1)
    b1.close()
    assert_equal(b0.pick(30), 2)
    b2.close()
    assert_equal(b0.pick(30), -1)
    _free_cell(c0)
    _free_cell(c1)
    _free_cell(c2)
    balance_group_free(g)


def test_push_pop_is_fifo() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    assert_equal(b1.pending(), 0)
    assert_equal(b1.pop(), 0)
    assert_true(b0.push(1, 11))
    assert_true(b0.push(1, 22))
    assert_true(b0.push(1, 33))
    assert_equal(b1.pending(), 3)
    assert_equal(b0.pending(), 0)
    assert_equal(b1.pop(), 11)
    assert_equal(b1.pop(), 22)
    assert_equal(b1.pending(), 1)
    assert_equal(b1.pop(), 33)
    assert_equal(b1.pop(), 0)
    assert_equal(b1.pending(), 0)
    _free_cell(c0)
    _free_cell(c1)
    balance_group_free(g)


def test_push_rejects_bad_target() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var b0 = Balancer.open(c0, 0)
    assert_false(b0.push(-1, 7))
    assert_false(b0.push(2, 7))
    assert_equal(b0.pending(), 0)
    _free_cell(c0)
    balance_group_free(g)


def test_full_inbox_refuses_and_wraps() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    for k in range(_INBOX_CAP):
        assert_true(b0.push(1, 1000 + k))
    assert_false(b0.push(1, 9999))
    assert_equal(b1.pending(), _INBOX_CAP)
    # Free a few slots, then fill past the ring's end to exercise wrap.
    for k in range(10):
        assert_equal(b1.pop(), 1000 + k)
    for k in range(10):
        assert_true(b0.push(1, 2000 + k))
    assert_false(b0.push(1, 9999))
    for k in range(_INBOX_CAP - 10):
        assert_equal(b1.pop(), 1000 + 10 + k)
    for k in range(10):
        assert_equal(b1.pop(), 2000 + k)
    assert_equal(b1.pop(), 0)
    _free_cell(c0)
    _free_cell(c1)
    balance_group_free(g)


def test_close_refuses_pushes_and_leaves_queue_drainable() raises:
    var g = balance_group_alloc(2)
    var c0 = _stats_cell(g, 0)
    var c1 = _stats_cell(g, 1)
    var b0 = Balancer.open(c0, 0)
    var b1 = Balancer.open(c1, 0)
    assert_true(b0.push(1, 5))
    assert_true(b0.push(1, 6))
    b1.close()
    assert_false(b0.push(1, 7))
    assert_equal(b1.pending(), 2)
    assert_equal(b1.pop(), 5)
    assert_equal(b1.pop(), 6)
    assert_equal(b1.pop(), 0)
    _free_cell(c0)
    _free_cell(c1)
    balance_group_free(g)


def test_free_zero_group_is_noop() raises:
    balance_group_free(0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
