"""Tests for the DeadlineWatchdog (K2 preemptive-deadline mechanism)."""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc
from std.testing import assert_equal, assert_false, assert_true

from flare.runtime._libc_time import libc_nanosleep_ms, monotonic_now_ms
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


def _set_cell(addr: Int, v: Int64):
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    Atomic[Int64].store[ordering=Ordering.RELEASE](
        p.unsafe_bitcast[Scalar[DType.int64]](), v
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


def _wait_for_flip(cell: Int, limit_ms: Int) -> Bool:
    """True once the cell is flipped, False after ``limit_ms`` without."""
    var t0 = monotonic_now_ms()
    while monotonic_now_ms() - t0 < limit_ms:
        if _read_cell(cell) != 0:
            return True
        _ = libc_nanosleep_ms(1)
    return _read_cell(cell) != 0


def test_arm_with_an_expired_budget_fires_at_the_next_poll() raises:
    """A budget that is already spent gave a deadline <= 0, which the poller
    skips (``d > 0``) and which ``-1`` made the FIRING sentinel: the cell was
    never flipped and ``disarm`` could spin forever. The deadline is now
    clamped to at least 1, so the slot fires at the next poll."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, -(1 << 62), cell)
    assert_true(
        _wait_for_flip(cell, 2_000),
        "an expired budget never fired",
    )
    assert_equal(_read_cell(cell), 2)  # TIMEOUT
    assert_true(wd.disarm(0), "disarm did not report the fire")
    wd.stop()
    _free_cell(cell)


def test_arm_with_a_huge_budget_saturates_instead_of_wrapping() raises:
    """``now + budget_ms`` overflowing must not wrap into a past deadline
    (which, clamped, would fire at once): it saturates and never fires."""
    var cell = _new_cell()
    var wd = DeadlineWatchdog(poll_ms=1)
    wd.arm(0, 9223372036854775807, cell)
    assert_false(
        _wait_for_flip(cell, 50),
        "a huge budget fired immediately",
    )
    assert_false(wd.disarm(0), "disarm reported a fire that did not happen")
    wd.stop()
    _free_cell(cell)


def test_rearming_an_armed_slot_never_fires_the_old_deadline_into_the_new_cell() raises:
    """``arm`` stored the new cell's address before replacing the previous,
    expired deadline, so a poll in that window claimed the old deadline and
    wrote TIMEOUT into the new request's cell. ``arm`` now releases the old
    deadline first.

    The window is a few instructions wide and the poller cannot be stepped
    from outside, so this runs the real ``arm`` against the real poller for a
    bounded number of rounds. Before the fix a stale fire landed about once
    in 30 000 rounds; 1 000 000 rounds make a miss astronomically unlikely
    (and a pass can never be a false alarm: the new cell has a 60 s budget)."""
    var wd = DeadlineWatchdog(poll_ms=1)
    var cell_a = _new_cell()
    var cell_b = _new_cell()
    var stale = 0
    for _ in range(1_000_000):
        _set_cell(cell_a, 0)
        _set_cell(cell_b, 0)
        wd.arm(0, -1, cell_a)  # request A: deadline already passed
        wd.arm(0, 60_000, cell_b)  # request B, without disarming A
        _ = wd.disarm(0)  # waits out a fire in progress
        if _read_cell(cell_b) != 0:
            stale += 1
            break
    wd.stop()
    _free_cell(cell_a)
    _free_cell(cell_b)
    assert_equal(stale, 0, "a stale fire cancelled the new request's cell")


def main() raises:
    test_watchdog_flips_cell_on_deadline()
    print("OK test_watchdog_flips_cell_on_deadline")
    test_watchdog_disarm_prevents_flip()
    print("OK test_watchdog_disarm_prevents_flip")
    test_rearm_right_after_a_fire_keeps_its_deadline()
    print("OK test_rearm_right_after_a_fire_keeps_its_deadline")
    test_arm_with_an_expired_budget_fires_at_the_next_poll()
    print("OK test_arm_with_an_expired_budget_fires_at_the_next_poll")
    test_arm_with_a_huge_budget_saturates_instead_of_wrapping()
    print("OK test_arm_with_a_huge_budget_saturates_instead_of_wrapping")
    test_rearming_an_armed_slot_never_fires_the_old_deadline_into_the_new_cell()
    print(
        "OK"
        " test_rearming_an_armed_slot_never_fires_the_old_deadline_into_the_new_cell"
    )
    print("test_watchdog: 6 passed")
