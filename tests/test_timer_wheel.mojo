"""Tests for ``flare.runtime.TimerWheel`` (Phase 1.3)."""

from std.testing import (
    assert_equal,
    assert_not_equal,
    assert_true,
    assert_false,
    TestSuite,
)

from flare.runtime import TimerWheel


# ── Basic scheduling ──────────────────────────────────────────────────────────


def test_schedule_returns_unique_ids() raises:
    """Each schedule call returns a different, monotonic ID."""
    var tw = TimerWheel(now_ms=UInt64(0))
    var id1 = tw.schedule(10, UInt64(1))
    var id2 = tw.schedule(20, UInt64(2))
    var id3 = tw.schedule(30, UInt64(3))
    assert_true(id1 < id2)
    assert_true(id2 < id3)
    assert_not_equal(id1, UInt64(0))


def test_empty_wheel_active_count_zero() raises:
    """A fresh wheel has zero active timers."""
    var tw = TimerWheel(now_ms=UInt64(0))
    assert_equal(tw.active_count(), 0)


def test_schedule_increments_active_count() raises:
    """Scheduling increases active_count; advance past fire resets it."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(5, UInt64(1))
    _ = tw.schedule(10, UInt64(2))
    assert_equal(tw.active_count(), 2)
    var fired = List[UInt64]()
    tw.advance(UInt64(11), fired)
    assert_equal(tw.active_count(), 0)


# ── Fire timing ───────────────────────────────────────────────────────────────


def test_timer_fires_after_correct_delay() raises:
    """A 10ms timer fires on the tick at which now advances to 10+."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(10, UInt64(0xAA))
    var fired = List[UInt64]()
    tw.advance(UInt64(9), fired)
    assert_equal(len(fired), 0)
    tw.advance(UInt64(10), fired)
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(0xAA))


def test_multiple_timers_fire_in_order() raises:
    """Timers with different fire times fire in the correct order."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(30, UInt64(3))
    _ = tw.schedule(10, UInt64(1))
    _ = tw.schedule(20, UInt64(2))
    var fired = List[UInt64]()
    tw.advance(UInt64(100), fired)
    assert_equal(len(fired), 3)
    assert_equal(fired[0], UInt64(1))
    assert_equal(fired[1], UInt64(2))
    assert_equal(fired[2], UInt64(3))


def test_immediate_timer_fires_next_advance() raises:
    """After_ms=0 fires on the next non-zero advance."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(0, UInt64(0x11))
    var fired = List[UInt64]()
    tw.advance(UInt64(1), fired)
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(0x11))


def test_zero_advance_fires_nothing() raises:
    """Advancing to the same time fires no timers."""
    var tw = TimerWheel(now_ms=UInt64(100))
    _ = tw.schedule(10, UInt64(0xBB))
    var fired = List[UInt64]()
    tw.advance(UInt64(100), fired)
    assert_equal(len(fired), 0)


# ── Cancellation ──────────────────────────────────────────────────────────────


def test_cancel_returns_true_first_time() raises:
    """Cancel() returns True for an active, never-before-cancelled timer."""
    var tw = TimerWheel(now_ms=UInt64(0))
    var id = tw.schedule(100, UInt64(1))
    assert_true(tw.cancel(id))


def test_cancel_returns_false_twice() raises:
    """Second cancel() on the same id returns False."""
    var tw = TimerWheel(now_ms=UInt64(0))
    var id = tw.schedule(100, UInt64(1))
    assert_true(tw.cancel(id))
    assert_false(tw.cancel(id))


def test_cancel_unknown_id_returns_false() raises:
    """Cancel() on a never-issued ID returns False."""
    var tw = TimerWheel(now_ms=UInt64(0))
    assert_false(tw.cancel(UInt64(99999)))


def test_cancelled_timer_does_not_fire() raises:
    """A cancelled timer does not appear in fired list."""
    var tw = TimerWheel(now_ms=UInt64(0))
    var id1 = tw.schedule(5, UInt64(0x01))
    var id2 = tw.schedule(10, UInt64(0x02))
    _ = tw.cancel(id1)
    var fired = List[UInt64]()
    tw.advance(UInt64(100), fired)
    # Only token 0x02 should fire.
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(0x02))


# ── Wheel wrap / overflow ─────────────────────────────────────────────────────


def test_timer_past_one_rotation_fires_eventually() raises:
    """A timer scheduled beyond 512ms uses overflow and still fires."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(1000, UInt64(0xCAFE))
    var fired = List[UInt64]()
    tw.advance(UInt64(999), fired)
    assert_equal(len(fired), 0, "not yet time")
    tw.advance(UInt64(1000), fired)
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(0xCAFE))


def test_timer_at_exactly_512ms_fires() raises:
    """A timer at exactly the wheel size (promotes from overflow) fires."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(512, UInt64(0xDEAD))
    var fired = List[UInt64]()
    tw.advance(UInt64(512), fired)
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(0xDEAD))


def test_multiple_rotations_still_fire() raises:
    """Timers across >1 full wheel rotations all fire in order."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(100, UInt64(1))
    _ = tw.schedule(600, UInt64(2))
    _ = tw.schedule(1200, UInt64(3))
    var fired = List[UInt64]()
    tw.advance(UInt64(2000), fired)
    assert_equal(len(fired), 3)
    assert_equal(fired[0], UInt64(1))
    assert_equal(fired[1], UInt64(2))
    assert_equal(fired[2], UInt64(3))


# ── Stress: many timers ───────────────────────────────────────────────────────


def test_1000_short_timers_all_fire() raises:
    """1000 timers scheduled within the wheel all fire within one advance."""
    var tw = TimerWheel(now_ms=UInt64(0))
    for i in range(1000):
        var delay = (i % 500) + 1
        _ = tw.schedule(delay, UInt64(1_000_000 + i))
    var fired = List[UInt64]()
    tw.advance(UInt64(501), fired)
    assert_equal(len(fired), 1000)


def test_many_cancels_dont_leak() raises:
    """Scheduling and cancelling all timers leaves active_count at 0."""
    var tw = TimerWheel(now_ms=UInt64(0))
    var ids = List[UInt64]()
    for i in range(500):
        ids.append(tw.schedule(i + 1, UInt64(i)))
    for i in range(500):
        _ = tw.cancel(ids[i])
    assert_equal(tw.active_count(), 0)
    # And advancing past everything shouldn't fire anything.
    var fired = List[UInt64]()
    tw.advance(UInt64(2000), fired)
    assert_equal(len(fired), 0)


# ── now_ms and next_fire_ms ───────────────────────────────────────────────────


def test_now_ms_reflects_advance() raises:
    """Now_ms() tracks the wheel's current tick."""
    var tw = TimerWheel(now_ms=UInt64(100))
    assert_equal(tw.now_ms(), UInt64(100))
    var fired = List[UInt64]()
    tw.advance(UInt64(150), fired)
    assert_equal(tw.now_ms(), UInt64(150))


def test_next_fire_ms_returns_earliest() raises:
    """Next_fire_ms() returns the absolute time of the earliest pending timer.
    """
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(500, UInt64(1))
    _ = tw.schedule(200, UInt64(2))
    _ = tw.schedule(800, UInt64(3))
    assert_equal(tw.next_fire_ms(), UInt64(200))


def main() raises:
    print("=" * 60)
    print("test_timer_wheel.mojo — Phase 1.3 TimerWheel")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
