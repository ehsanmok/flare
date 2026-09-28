"""Tests for the DeadlineWatchdog (K2 preemptive-deadline mechanism)."""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc
from std.testing import assert_equal, assert_false, assert_true

from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.watchdog import DeadlineWatchdog


def _new_cell() -> Int:
    var p = alloc(Layout[Int64](count=1)).unsafe_leak()
    p.unsafe_write(Int64(0))
    return Int(p)


def _read_cell(addr: Int) -> Int:
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Int(
        Atomic[Int64].load[ordering=Ordering.ACQUIRE](
            p.unsafe_bitcast[Scalar[DType.int64]]()
        )
    )


def _free_cell(addr: Int):
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    p.unsafe_free()


def test_watchdog_flips_cell_on_deadline() raises:
    """An armed slot whose deadline passes gets its cancel cell flipped
    to CancelReason.TIMEOUT (2)."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, 10, cell)
    _ = libc_nanosleep_ms(80)
    assert_equal(_read_cell(cell), 2)  # TIMEOUT
    wd.stop()
    _free_cell(cell)


def test_watchdog_disarm_prevents_flip() raises:
    """A slot disarmed before its deadline is never flipped."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, 1_000, cell)  # far-future deadline
    assert_false(wd.disarm(0), "disarm reported a fire that did not happen")
    _ = libc_nanosleep_ms(40)
    assert_equal(_read_cell(cell), 0)  # still live
    wd.stop()
    _free_cell(cell)


def test_rearm_right_after_a_fire_keeps_its_deadline() raises:
    """The poller wrote TIMEOUT into the cell and then stored 0 into the
    slot to mark it fired. A worker that saw the cell flip and re-armed
    the slot for its next request straight away had that new deadline
    wiped by the poller's store. Each round waits for a fire and
    re-arms at once, the interleaving that lost it."""
    from flare.runtime.watchdog import _atomic_load, _slot_deadline_idx

    var wd = DeadlineWatchdog(poll_ms=1)
    var cell = _new_cell()
    for _ in range(200):
        var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=cell)
        Atomic[Int64].store[ordering=Ordering.RELEASE](
            p.unsafe_bitcast[Scalar[DType.int64]](), Int64(0)
        )
        wd.arm(0, 0, cell)
        while _read_cell(cell) == 0:
            pass
        wd.arm(0, 60_000, cell)  # the next request, at once
        _ = libc_nanosleep_ms(2)
        assert_true(
            _atomic_load(wd._block, _slot_deadline_idx(0)) > 0,
            "the fire wiped the next request's deadline",
        )
        assert_false(wd.disarm(0), "disarm saw a fire on the new deadline")
    wd.stop()
    _free_cell(cell)


def main() raises:
    test_watchdog_flips_cell_on_deadline()
    print("OK test_watchdog_flips_cell_on_deadline")
    test_watchdog_disarm_prevents_flip()
    print("OK test_watchdog_disarm_prevents_flip")
    test_rearm_right_after_a_fire_keeps_its_deadline()
    print("OK test_rearm_right_after_a_fire_keeps_its_deadline")
    print("test_watchdog: 3 passed")
