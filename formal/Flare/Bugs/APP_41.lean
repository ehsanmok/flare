import Flare.L4_App.CircuitBreaker

/-!
# APP-41: CircuitBreaker cooldown measured from the failing request's start

`serve` reads `now` once on entry (flare/http/reliability.mojo:449) and
passes it to `_record_failure(now)` (:463, :468), which stores it as the
opened-at timestamp (:440). A failure that takes longer than `cooldown_ms`
therefore opens the breaker with an already-expired cooldown, and the next
call is let through as a probe instead of fast-failing.

Repro: formal/repro/APP-41_circuitbreaker_cooldown_from_request_start.mojo.
-/
namespace Flare.Bugs.APP_41
open Flare.L4.CircuitBreaker

/-- threshold 1, cooldown 100: a request arrives at t=0 and fails at t=150;
a second request arrives at t=150. -/
def pre : List Lbl := [.arrive 1 0, .finish 1 150 true]
def lastL : Lbl := .arrive 2 150

theorem pre_state :
    runAll false false 1 100 initS pre = some ⟨⟨.opn, 1, 0⟩, [], 150, 150, 0⟩ := by decide

theorem last_step :
    stepG false false 1 100 ⟨⟨.opn, 1, 0⟩, [], 150, 150, 0⟩ lastL
      = some ⟨⟨.half, 1, 0⟩, [⟨2, 150⟩], 150, 150, 1⟩ := by decide

/-- Counterexample: the code violates the cooldown clause. The breaker
opened at t=150 and moves to half-open at t=150, 0 ns into a 100 ns
cooldown. -/
theorem slow_failure_skips_cooldown : ¬ CooldownOK (lts false false 1 100) 100 := by
  intro h
  have hr := reachable_of_runAll false false 1 100 pre _ pre_state
  obtain ⟨id, now, hl, hc⟩ := h _ lastL _ hr last_step rfl rfl
  simp only [lastL, Lbl.arrive.injEq] at hl
  obtain ⟨_, rfl⟩ := hl
  simp at hc

/-- Ghost invariant of the fixed model: while open, the stored opened-at
equals the true opening time. -/
def StampInv (s : S) : Prop := s.cell.st = .opn → s.cell.opened = s.openedAt

theorem stamp_inductive (f42 : Bool) (thr cd : Int) :
    (lts true f42 thr cd).Inductive StampInv where
  init := by intro s hs; subst hs; simp [StampInv, initS]
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
          · split
            · intro h; simp at h
            · split
              · exact hinv
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
            · intro _; simp
            · exact hinv
          · intro h; simp at h
        · cases hstep
      · cases hstep

/-- `finish` never produces HALF_OPEN from OPEN. -/
theorem finish_not_half (f41 : Bool) (thr : Int) (s : S) (r : Req) (now : Int) (b : Bool)
    (ho : s.cell.st = .opn) : (finish f41 thr s r now b).cell.st ≠ .half := by
  simp only [finish]
  split
  · split
    · simp
    · simp [ho]
  · simp

/-- The fix (stamp the opening with the completion time) meets the
cooldown clause, for every threshold and cooldown, with or without the
APP-42 fix. -/
theorem fixed_cooldown_respected (f42 : Bool) (thr cd : Int) :
    CooldownOK (lts true f42 thr cd) cd := by
  intro s l s' hr hstep ho hh
  have hinv := (stamp_inductive f42 thr cd).reachable s hr
  simp only [lts, LTS.ofFn] at hstep
  cases l with
  | arrive id now =>
    refine ⟨id, now, rfl, ?_⟩
    simp only [stepG] at hstep
    split at hstep
    · injection hstep with hstep; subst hstep
      simp only [arrive] at hh
      by_cases hc : now - s.cell.opened < cd
      · simp [ho, hc] at hh
      · have := hinv ho; omega
    · cases hstep
  | finish id now failed =>
    exfalso
    simp only [stepG] at hstep
    split at hstep
    · split at hstep
      · next r _ =>
        injection hstep with hstep; subst hstep
        exact finish_not_half true thr s r now failed ho hh
      · cases hstep
    · cases hstep

end Flare.Bugs.APP_41
