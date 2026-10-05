import Flare.L4_App.CircuitBreaker
import Flare.Bugs.APP_41

/-!
# APP-42: CircuitBreaker admits every request while HALF_OPEN

`serve` only tests `state == _CB_OPEN` (flare/http/reliability.mojo:451);
a HALF_OPEN state falls through to the inner call (:460). Worker copies
share the cell, so while the single probe is in flight every other request
also reaches the failing upstream. The docstring promises "one probe"
(:33, :409-410).

Repro: formal/repro/APP-42_circuitbreaker_halfopen_unbounded_probes.mojo.

Status: resolved. `serve` now fast-fails when the state is HALF_OPEN and
claims OPEN → HALF_OPEN with `_cell_cas`, so a worker that loses the race also
fast-fails (flare/http/reliability.mojo:471-491); the shipped model is
`Flare.L4.CircuitBreaker.stepShipped` = `stepG true true`. The counterexample
below is about the pre-fix `lts false false` (fix41 and fix42 both off).
Regression test: tests/http/test_reliability.mojo::
test_circuitbreaker_half_open_admits_only_the_probe.
-/
namespace Flare.Bugs.APP_42
open Flare.L4.CircuitBreaker

/-- threshold 1, cooldown 100: request 1 fails at t=0 (breaker opens);
at t=100 request 2 is the probe and, while it is in flight, request 3
arrives. -/
def trace : List Lbl := [.arrive 1 0, .finish 1 0 true, .arrive 2 100, .arrive 3 100]

theorem trace_state :
    runAll false false 1 100 initS trace
      = some ⟨⟨.half, 1, 0⟩, [⟨2, 100⟩, ⟨3, 100⟩], 100, 0, 2⟩ := by decide

/-- Counterexample: two requests are admitted during one half-open window
(both are in flight against the upstream). -/
theorem halfopen_admits_two : ¬ SingleProbe (lts false false 1 100) := by
  intro h
  have := h _ (reachable_of_runAll false false 1 100 trace _ trace_state) rfl
  simp at this

def HalfInv (s : S) : Prop := s.cell.st = .half → s.halfAdmits ≤ 1

theorem half_inductive (f41 : Bool) (thr cd : Int) :
    (lts f41 true thr cd).Inductive HalfInv where
  init := by intro s hs; subst hs; simp [HalfInv, initS]
  step := by
    intro s l s' hinv hstep
    simp only [lts, LTS.ofFn] at hstep
    cases l with
    | arrive id now =>
      simp only [stepG] at hstep
      split at hstep
      · injection hstep with hstep; subst hstep
        simp only [arrive]
        split
        · exact hinv
        · split
          · exact hinv
          · next hnh =>
            split
            · intro _; simp
            · next hno =>
              split
              · next hh => exact absurd ⟨trivial, hh⟩ hnh
              · exact hinv
      · cases hstep
    | finish id now failed =>
      simp only [stepG] at hstep
      split at hstep
      · split at hstep
        · injection hstep with hstep; subst hstep
          simp only [finish]
          split
          · split
            · intro h; simp at h
            · exact hinv
          · intro h; simp at h
        · cases hstep
      · cases hstep

/-- The fix (fast-fail while half-open, with an atomic OPEN -> HALF_OPEN
claim) meets the single-probe clause for every threshold and cooldown,
with or without the APP-41 fix. -/
theorem fixed_halfopen_one_probe (f41 : Bool) (thr cd : Int) :
    SingleProbe (lts f41 true thr cd) :=
  fun s hr => (half_inductive f41 thr cd).reachable s hr

/-- **Fix meets spec**: the shipped breaker lets one probe through while
half-open, for every threshold and cooldown. -/
theorem shipped_meets_spec (thr cd : Int) :
    SingleProbe (lts true true thr cd) :=
  fixed_halfopen_one_probe true thr cd

/-- Both fixes together satisfy both spec clauses. -/
theorem fixed_both (thr cd : Int) :
    SingleProbe (lts true true thr cd) ∧ CooldownOK (lts true true thr cd) cd :=
  ⟨fixed_halfopen_one_probe true thr cd, Flare.Bugs.APP_41.fixed_cooldown_respected true thr cd⟩

end Flare.Bugs.APP_42
