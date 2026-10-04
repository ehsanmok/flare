import Flare.L5_Concurrency.Watchdog

/-!
# CONC-01: a non-positive deadline is stored unchecked; -1 wedges the slot

`watchdog_arm` computes `deadline = Int64(monotonic_now_ms() + budget_ms)`
(flare/runtime/watchdog.mojo:107 @59bda50) and CASes it into the slot with
no range check. `-1` is the `_FIRING` sentinel (:46): the poller skips it
(`d > 0`, :162) and `_settle` (:81-87) waits for it to change, which never
happens. Any later `disarm` or `arm` of that slot spins forever.

Counterexample: clock at 1 ms, `budget_ms = -2`. The impl configuration
here allows any budget (`adm := true`); `Flare.L5.Watchdog.impl_safe`
shows the code is safe for budgets giving a deadline in `1..I64_MAX`.
Fix: clamp the deadline to ≥ 1 (`Flare.L5.Watchdog.fixed_safe`).
-/
namespace Flare.Bugs.CONC_01
open Flare.L5.Watchdog

/-- The code at 59bda50 with an unconstrained caller budget. -/
def cfgAnyBudget : Cfg :=
  { disarmFirst := false, clamp := false, allowRearm := false, adm := fun _ _ => true }

/-- arm(budget = -2) at t = 1 ms, then the request ends and disarm starts. -/
def trace : List Lbl :=
  [.w 0, .w 0, .w 0, .w (-2), .w 0, .w 0, .w 0]

/-- The run is valid and ends with the slot at FIRING, no poller claim, and
the worker inside `disarm`'s settle loop. -/
theorem trace_result :
    (exec cfgAnyBudget s0 trace).map (fun s => (s.slot, claimedP s.p, s.w)) =
      some (FIRING, false, WPc.dSettle) := by
  decide

/-- The wedged states: slot at FIRING, poller outside its claim window,
worker in disarm's settle loop. -/
def Stuck (s : St) : Prop := s.slot = FIRING ∧ claimedP s.p = false ∧ s.w = .dSettle

/-- `Stuck` is closed under every step, for any configuration: nothing can
take the slot out of FIRING and disarm never returns. -/
theorem stuck_closed (c : Cfg) : ∀ s l s', Stuck s → step c s l = some s' → Stuck s' := by
  rintro s l s' ⟨h1, h2, h3⟩ h
  simp only [FIRING] at h1
  cases l with
  | p =>
    simp only [step, Option.some.injEq] at h; subst h
    cases hp : s.p
    · simp [Stuck, pStep, hp, h1, h3, claimedP, FIRING]
    · simp [Stuck, pStep, hp, h1, h3, claimedP, FIRING]
    · simp only [pStep, hp]
      split
      · omega
      · simp [Stuck, h1, h3, claimedP, FIRING]
    all_goals simp [hp, claimedP] at h2
  | w b =>
    simp only [step, wStep, h3, FIRING, h1, if_true, Option.some.injEq] at h
    subst h; exact ⟨by simp [FIRING, h1], h2, h3⟩
  | rearm => simp [step, h3] at h
  | tick =>
    simp only [step, Option.some.injEq] at h; subst h
    exact ⟨by simp [FIRING, h1], h2, h3⟩

theorem stuck_run (c : Cfg) :
    ∀ {s ls s'}, Stuck s → (lts c).Run s ls s' → Stuck s' := by
  intro s ls s' hs hr
  induction hr with
  | nil => exact hs
  | cons hst _ ih => exact ih (stuck_closed c _ _ _ hs hst)

/-- Headline counterexample: a reachable state of the impl from which no
schedule ever lets `disarm` return, and in which FIRING is not owned by the
poller (the `FiringOwned` clause of the spec fails). -/
theorem arm_firing_sentinel :
    ∃ s, (lts cfgAnyBudget).Reachable s ∧ ¬ FiringOwned s ∧
      ∀ ls s', (lts cfgAnyBudget).Run s ls s' → s'.w = .dSettle := by
  cases h : exec cfgAnyBudget s0 trace with
  | none => have := trace_result; rw [h] at this; simp at this
  | some s =>
    have hr := trace_result
    rw [h] at hr
    simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at hr
    obtain ⟨e1, e2, e3⟩ := hr
    refine ⟨s, ⟨s0, trace, s0_init, run_of_exec _ _ _ _ h⟩, ?_, ?_⟩
    · intro hf; have := hf e1; rw [e2] at this; exact Bool.false_ne_true this
    · intro ls s' hrun
      exact (stuck_run cfgAnyBudget ⟨e1, e2, e3⟩ hrun).2.2

/-- The fix (deadline clamped to ≥ 1) meets the spec for every budget. -/
theorem implFixed_safe :
    ∀ s, (lts cfgFixed).Reachable s → Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  fixed_safe

/-- Clamp alone (no disarm-first) also suffices for this issue, under the
"arm only after disarm" discipline. -/
theorem clampOnly_safe :
    ∀ s, (lts { cfgAnyBudget with clamp := true }).Reachable s →
      Safe s ∧ DisarmCorrect s ∧ FiringOwned s :=
  safe_of_cfg _ (by simp [cfgAnyBudget]) (by
    intro n b _ _; simp only [deadlineOf, if_true]; omega)

end Flare.Bugs.CONC_01
