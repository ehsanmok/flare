import Flare.L2_Machine.TimerWheel

/-!
# RT-01: `TimerWheel.next_fire_ms` overshoots when the only timers are in overflow

flare/runtime/timer_wheel.mojo `next_fire_ms` (pre-fix lines 310-333).

Status: resolved. While the overflow list is non-empty, `next_fire_ms` now
scans only up to, and falls back to, the next slot-0 boundary
`tick + (512 - slot)` (test: tests/runtime/test_timer_wheel.mojo::
test_next_fire_ms_overflow_only_is_lower_bound_after_advance). The
counterexample below is about the pre-fix definition `nextFireOld`.

Spec (`next_fire_ms` docstring): the reactor may sleep until the returned
time without missing a timer, i.e. the hint is a lower bound on the fire
time of every active timer.

What goes wrong: with no wheel slot occupied but a non-empty overflow
list, `next_fire_ms` returns `tick + 512`. An overflow timer is promoted at
the next slot-0 boundary `tick + (512 - slot)` and can fire there, so once
the wheel has advanced (`slot > 0`) the hint is late by up to 511 ms. A
reactor that sleeps for the hint fires the timer late.

Repro: formal/repro/RT-01_timer_next_fire_overflow_hint.mojo (now prints OK).
-/
namespace Flare.Bugs.RT_01
open Flare.L2.TimerWheel

/-- `schedule(512, token 7)` at t = 0 (goes to overflow), then advance to
t = 500. -/
def s : TW := (advance (schedule (init 0) 512 7).1 500).1

theorem s_inv : Inv s :=
  (advance_spec (inv_schedule (inv_init 0) 512 7) 500).1.inv

theorem s_state :
    s.entries 1 = some ⟨512, 7, true⟩ ∧ nextFireOld s = 1012 ∧ nextFire s = 512 := by
  native_decide

/-- **Counterexample** (pre-fix `nextFireOld`): the hint (1012) exceeds the
fire time (512) of the active timer 1. -/
theorem nextFire_not_lower_bound : ¬ ∀ x e, Act s x e → nextFireOld s ≤ e.fireAt := by
  intro h
  have hs := s_state
  have := h 1 ⟨512, 7, true⟩ ⟨hs.1, rfl⟩
  rw [hs.2.1] at this
  simp at this

/-- **Shipped code meets spec**: capping the scan and the fallback at
`tick + (512 - slot)` when the overflow list is non-empty makes the hint a
lower bound on every active timer, for every reachable wheel state. -/
theorem nextFire_lower_bound {t : TW} (h : Inv t) {x : Nat} {e : Entry} (hx : Act t x e) :
    nextFire t ≤ e.fireAt :=
  Flare.L2.TimerWheel.nextFire_lower_bound h hx

/-- The pre-fix hint was already correct whenever the overflow list is empty
(and the shipped hint is then the same value). -/
theorem nextFire_ok_without_overflow {t : TW} (h : Inv t) (hov : t.overflow = [])
    {x : Nat} {e : Entry} (hx : Act t x e) : nextFireOld t ≤ e.fireAt :=
  nextFireOld_lower_bound_no_overflow h hov hx

end Flare.Bugs.RT_01
