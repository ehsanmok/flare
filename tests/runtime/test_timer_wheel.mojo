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


def test_cancel_is_idempotent() raises:
    """First cancel() of an active timer returns True; the second
    cancel() of the same id returns False."""
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


def test_next_fire_ms_empty_returns_sentinel() raises:
    """No timers -> a far-future sentinel so the reactor uses its cap."""
    var tw = TimerWheel(now_ms=UInt64(1000))
    assert_true(tw.next_fire_ms() > UInt64(1000) + UInt64(1_000_000))


def test_next_fire_ms_overflow_only_returns_rotation() raises:
    """A timer past one full rotation (>512ms) yields a one-rotation
    lower-bound hint, never a value in the past.
    """
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(5000, UInt64(9))
    var nf = tw.next_fire_ms()
    assert_true(nf > UInt64(0))
    assert_true(nf <= UInt64(5000))


def test_next_fire_ms_overflow_only_is_lower_bound_after_advance() raises:
    """RT-01: overflow timers are promoted at the next slot-0 boundary, so
    with an empty wheel and a non-empty overflow list the hint must not
    exceed that boundary. A timer due at 512, observed at now=500, used to
    be reported as due at 1012 (now + 512) although it fires at 512."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(512, UInt64(7))  # delay 512 -> overflow list
    var fired = List[UInt64]()
    tw.advance(UInt64(500), fired)
    var hint = tw.next_fire_ms()
    assert_equal(hint, UInt64(512))
    # Ground truth: the wheel fires the timer at 512.
    var fired_at = UInt64(0)
    for t in range(501, 1100):
        tw.advance(UInt64(t), fired)
        if len(fired) > 0:
            fired_at = UInt64(t)
            break
    assert_equal(fired_at, UInt64(512))
    assert_true(hint <= fired_at)


def test_next_fire_ms_wheel_hint_capped_at_promotion_boundary() raises:
    """RT-01: a wheel timer further away than the next slot-0 boundary must
    not push the hint past it while the overflow list is non-empty (the
    overflow timer is promoted, and may fire, at the boundary)."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(700, UInt64(1))  # overflow, fires at 700
    var fired = List[UInt64]()
    tw.advance(UInt64(100), fired)
    _ = tw.schedule(511, UInt64(2))  # wheel slot 99, fires at 611
    # Boundary at 512 (= now 100 + (512 - slot 100)); wheel timer at 611.
    assert_equal(tw.next_fire_ms(), UInt64(512))


def test_next_fire_ms_overflow_hint_at_slot_zero() raises:
    """RT-01: at slot 0 the boundary is a full rotation away, so the hint
    for an overflow-only wheel stays now + 512 (no regression)."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(5000, UInt64(1))
    assert_equal(tw.next_fire_ms(), UInt64(512))


def test_next_fire_ms_recovers_after_advance() raises:
    """After the earliest timer fires, next_fire_ms tracks the next one
    (independent of active-timer count; bounded slot scan).
    """
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(50, UInt64(1))
    _ = tw.schedule(300, UInt64(2))
    assert_equal(tw.next_fire_ms(), UInt64(50))
    var fired = List[UInt64]()
    tw.advance(UInt64(60), fired)
    assert_equal(tw.next_fire_ms(), UInt64(300))


def test_next_fire_ms_cancel_is_lower_bound() raises:
    """Lazy cancel may leave a stale slot entry; next_fire_ms stays a
    valid lower bound (never later than the true next fire) and firms
    up once the wheel advances past the cancelled slot.
    """
    var tw = TimerWheel(now_ms=UInt64(0))
    var id1 = tw.schedule(100, UInt64(1))
    _ = tw.schedule(400, UInt64(2))
    _ = tw.cancel(id1)
    # Lower bound: <= the true next active fire (400).
    assert_true(tw.next_fire_ms() <= UInt64(400))
    var fired = List[UInt64]()
    tw.advance(UInt64(150), fired)
    assert_equal(len(fired), 0)  # id1 was cancelled, nothing fires
    assert_equal(tw.next_fire_ms(), UInt64(400))


def test_a_long_gap_jumps_instead_of_walking() raises:
    """A wheel anchored at 0 and advanced on the monotonic clock walked
    every millisecond since boot. The jump fires what is due, keeps
    what is not, and leaves the wheel on the new tick."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(10, UInt64(1))
    _ = tw.schedule(2_000, UInt64(2))
    var keep = tw.schedule(2_000_000_000_000, UInt64(3))
    var cancelled = tw.schedule(20, UInt64(4))
    _ = tw.cancel(cancelled)
    var fired = List[UInt64]()
    # About 31 years in ms. Walked a tick at a time this does not
    # finish; the jump makes it one pass over three timers.
    var now = UInt64(1_000_000_000_000)
    tw.advance(now, fired)
    assert_equal(len(fired), 2)
    assert_equal(fired[0], UInt64(1))
    assert_equal(fired[1], UInt64(2))
    assert_equal(tw.now_ms(), now)
    assert_equal(tw.active_count(), 1)
    # A timer armed after the jump still fires on time.
    _ = tw.schedule(5, UInt64(5))
    fired.clear()
    tw.advance(now + UInt64(5), fired)
    assert_equal(len(fired), 1)
    assert_equal(fired[0], UInt64(5))
    _ = keep


def test_overflow_timer_fires_on_time_after_a_jump() raises:
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(700, UInt64(9))  # overflow at schedule time
    var fired = List[UInt64]()
    tw.advance(UInt64(600), fired)  # jump: 600 > one rotation
    assert_equal(len(fired), 0)
    tw.advance(UInt64(699), fired)
    assert_equal(len(fired), 0)
    tw.advance(UInt64(700), fired)
    assert_equal(len(fired), 1)


def test_overflow_promoted_once_per_rotation_still_fires_on_time() raises:
    """Overflow is now scanned at each rotation boundary instead of on
    every tick. Stepped in under-a-rotation advances, a far timer still
    fires on its exact tick."""
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(5_003, UInt64(7))
    var fired = List[UInt64]()
    var t = UInt64(0)
    while t + UInt64(500) < UInt64(5_003):
        t += UInt64(500)
        tw.advance(t, fired)
    tw.advance(UInt64(5_002), fired)
    assert_equal(len(fired), 0)
    tw.advance(UInt64(5_003), fired)
    assert_equal(len(fired), 1)


def main() raises:
    print("=" * 60)
    print("test_timer_wheel.mojo — Phase 1.3 TimerWheel")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
