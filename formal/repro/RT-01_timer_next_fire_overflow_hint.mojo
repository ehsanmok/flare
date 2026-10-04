# PLATFORM: any
"""RT-01: TimerWheel.next_fire_ms is not a lower bound once an overflow
timer is within a rotation of firing.

Lean: Flare.Bugs.RT_01.nextFire_not_lower_bound (counterexample) and
Flare.Bugs.RT_01.nextFireFixed_lower_bound (fix meets spec).
flare/runtime/timer_wheel.mojo:310-333 @59bda50.

Expected (docstring): next_fire_ms() "is never later than the true next
fire, so a timer can never be missed".
Actual: overflow entries are only re-examined at slot-0 boundaries, so
between boundaries an overflow timer can be due in fewer than 512 ms.
With an empty wheel next_fire_ms() still returns now + 512. Here a timer
due at 512 is reported as due at 1012 after advancing to 500, and the
wheel does fire it at 512, so a reactor that slept until the hint would
fire it late (the reactor caps its poll at 100 ms, which bounds the
lateness in flare's own servers).

Minimal fix: the overflow fallback (and the wheel-slot result) must not
exceed the next slot-0 boundary, now + (512 - current_slot).
"""

from flare.runtime import TimerWheel


def main() raises:
    var tw = TimerWheel(now_ms=UInt64(0))
    _ = tw.schedule(512, UInt64(7))  # delay 512 -> overflow list
    var fired = List[UInt64]()
    tw.advance(UInt64(500), fired)
    var hint = tw.next_fire_ms()
    # Ground truth: the wheel fires the timer at 512.
    var fired_at = UInt64(0)
    for t in range(501, 1100):
        tw.advance(UInt64(t), fired)
        if len(fired) > 0:
            fired_at = UInt64(t)
            break
    if hint > fired_at:
        print(
            "BUG REPRODUCED: next_fire_ms() =",
            hint,
            "at now=500 but the timer fires at",
            fired_at,
        )
        raise Error("RT-01")
    print("OK: next_fire_ms() =", hint, "<= actual fire time", fired_at)
