import Flare.Core.Word

/-!
# Retry and exponential backoff (flare/http/reliability.mojo)

* `budget` transliterates the un-jittered part of `_backoff_sleep_ms`
  (reliability.mojo:164-194): the cap loop with wrapping `Int`
  multiplication. `sleep` adds the full-jitter draw
  `random_ui64(0, capped)`, modelled as an arbitrary function whose
  result lies in `[0, capped]` (hypothesis `DrawOk`, a property of
  `random_ui64`, not proved here).
* `specBudget` is the documented schedule (docstring :173-178, and the
  `Retry` docstring :218-219): `min(initial · multiplier^(N-2), max)`.
* `serve` transliterates the `Retry.serve` attempt loop
  (reliability.mojo:233-271) over an arbitrary sequence of inner-handler
  outcomes; the client-side `_send_with_retry` (client.mojo:2160-2187)
  has the same shape.

Results (all general, not bounded):
* `budget_eq_spec`: for a sane policy (`initial > 0`, `multiplier ≥ 1`,
  `max > 0`, `max(initial, max)·multiplier < 2^63`) the implementation
  computes exactly the documented capped schedule, hence
  `budget_le_max` (never above `max_backoff_ms`), `budget_pos`, and
  `budget_mono` (non-decreasing in the attempt number).
* `sleep_bounds`: the jittered sleep is in `[0, min(initial·m^(N-2), max)]`.
* `serve_calls_bounded`, `serve_result_is_last`, `serve_retry_only_on_failure`,
  `serve_failure_exhausts`: the loop invokes the inner handler between 1 and
  `max_attempts` times, returns the last outcome, retries only after a
  failure (5xx or raise), and surfaces a failure only after exhausting all
  attempts.
* `uncapped_wraps` (observation, not filed): with `max_backoff_ms ≤ 0`
  (which the code treats as "no cap") the product wraps at attempt 59 for
  `initial = 100, multiplier = 2`, and the budget drops from
  `7.2·10^18` ms to `0`.
-/
namespace Flare.L4.Retry

def w (n : Int) : Int := (mojoInt n).toInt

theorem w_of_fits {n : Int} (h : fitsI64 n) : w n = n := mojoInt_toInt_of_fits n h

private theorem fits_of {n : Int} (h1 : -(2 ^ 63) ≤ n) (h2 : n ≤ 2 ^ 63 - 1) : fitsI64 n :=
  ⟨by unfold I64_MIN; omega, by unfold I64_MAX; omega⟩

structure Policy where
  maxAttempts : Int
  retryOnlyIdempotent : Bool
  initialBackoffMs : Int
  backoffMultiplier : Int
  maxBackoffMs : Int

/-- The `while i < attempt` cap loop, `n` = remaining iterations.
mirrors flare/http/reliability.mojo:182-190 @59bda50 -/
def capLoop (p : Policy) : Nat → Int → Int
  | 0, c => c
  | n + 1, c =>
    let nx := w (c * p.backoffMultiplier)
    if p.maxBackoffMs > 0 ∧ nx > p.maxBackoffMs then p.maxBackoffMs else capLoop p n nx

/-- Un-jittered budget; `0` means "do not sleep".
mirrors flare/http/reliability.mojo:180-194 @59bda50 -/
def budget (p : Policy) (attempt : Int) : Int :=
  if p.initialBackoffMs ≤ 0 ∨ attempt ≤ 1 then 0
  else
    let c := capLoop p (attempt - 2).toNat p.initialBackoffMs
    let c := if p.maxBackoffMs > 0 ∧ c > p.maxBackoffMs then p.maxBackoffMs else c
    if c ≤ 0 then 0 else c

/-- Jittered sleep: `random_ui64(0, UInt64(capped))`, abstracted as `draw`.
mirrors flare/http/reliability.mojo:164-195 @59bda50 -/
def sleep (p : Policy) (attempt : Int) (draw : Int → Int) : Int :=
  let b := budget p attempt
  if b ≤ 0 then 0 else draw b

/-- `random_ui64(0, n)` returns a value in `[0, n]` (environment fact). -/
def DrawOk (draw : Int → Int) : Prop := ∀ n, 0 < n → 0 ≤ draw n ∧ draw n ≤ n

/-- Documented schedule. -/
def specBudget (p : Policy) (attempt : Int) : Int :=
  min (p.initialBackoffMs * p.backoffMultiplier ^ (attempt - 2).toNat) p.maxBackoffMs

structure Sane (p : Policy) : Prop where
  init_pos : 0 < p.initialBackoffMs
  mult_ge : 1 ≤ p.backoffMultiplier
  max_pos : 0 < p.maxBackoffMs
  max_mul : p.maxBackoffMs * p.backoffMultiplier ≤ I64_MAX
  init_mul : p.initialBackoffMs * p.backoffMultiplier ≤ I64_MAX

theorem one_le_pow (m : Int) (hm : 1 ≤ m) : ∀ n : Nat, 1 ≤ m ^ n
  | 0 => by simp
  | n + 1 => by
    rw [Int.pow_succ]
    have := one_le_pow m hm n
    have : 1 * 1 ≤ m ^ n * m := Int.mul_le_mul this hm (by decide) (by omega)
    omega

theorem capLoop_spec (p : Policy) (h : Sane p) :
    ∀ (n : Nat) (c : Int), 0 < c → c * p.backoffMultiplier ≤ I64_MAX →
      min (capLoop p n c) p.maxBackoffMs = min (c * p.backoffMultiplier ^ n) p.maxBackoffMs
  | 0, c, _, _ => by simp [capLoop]
  | n + 1, c, hc, hf => by
    obtain ⟨_, hm, hmax, hmm, _⟩ := h
    unfold I64_MAX at hmm hf
    have hmul0 : c ≤ c * p.backoffMultiplier := by
      have := Int.mul_le_mul_of_nonneg_left hm (Int.le_of_lt hc); simpa using this
    have hnx : w (c * p.backoffMultiplier) = c * p.backoffMultiplier :=
      w_of_fits (fits_of (by omega) (by omega))
    have hpow : c * p.backoffMultiplier ^ (n + 1) = c * p.backoffMultiplier * p.backoffMultiplier ^ n := by
      rw [Int.pow_succ, Int.mul_comm (p.backoffMultiplier ^ n), Int.mul_assoc]
    simp only [capLoop, hnx]
    rw [hpow]
    have hp1 := one_le_pow _ hm n
    have hge : c * p.backoffMultiplier ≤ c * p.backoffMultiplier * p.backoffMultiplier ^ n := by
      have := Int.mul_le_mul_of_nonneg_left hp1 (show 0 ≤ c * p.backoffMultiplier by omega)
      simpa using this
    by_cases hb : p.maxBackoffMs > 0 ∧ c * p.backoffMultiplier > p.maxBackoffMs
    · rw [if_pos hb]; omega
    · rw [if_neg hb]
      have hle : c * p.backoffMultiplier ≤ p.maxBackoffMs := by omega
      have hf' : c * p.backoffMultiplier * p.backoffMultiplier ≤ I64_MAX := by
        unfold I64_MAX
        have := Int.mul_le_mul_of_nonneg_right hle (show 0 ≤ p.backoffMultiplier by omega)
        omega
      exact capLoop_spec p ⟨by omega, hm, hmax, hmm, by omega⟩ n _ (by omega) hf'

/-- The implementation computes exactly the documented capped schedule. -/
theorem budget_eq_spec (p : Policy) (h : Sane p) (attempt : Int) (ha : 2 ≤ attempt) :
    budget p attempt = specBudget p attempt := by
  have key := capLoop_spec p h (attempt - 2).toNat p.initialBackoffMs h.init_pos h.init_mul
  have hp1 := one_le_pow _ h.mult_ge (attempt - 2).toNat
  have hlow : p.initialBackoffMs ≤ p.initialBackoffMs * p.backoffMultiplier ^ (attempt - 2).toNat := by
    have := Int.mul_le_mul_of_nonneg_left hp1 (Int.le_of_lt h.init_pos); simpa using this
  have hi := h.init_pos
  have hmx := h.max_pos
  unfold budget specBudget
  rw [if_neg (by omega)]
  dsimp only
  generalize capLoop p (attempt - 2).toNat p.initialBackoffMs = c at key
  generalize p.initialBackoffMs * p.backoffMultiplier ^ (attempt - 2).toNat = s at key hlow
  by_cases hc : p.maxBackoffMs > 0 ∧ c > p.maxBackoffMs
  · rw [if_pos hc, if_neg (by omega)]; omega
  · rw [if_neg hc]
    have : min c p.maxBackoffMs = c := by omega
    rw [this] at key
    rw [if_neg (by omega)]; omega

theorem budget_le_max (p : Policy) (h : Sane p) (attempt : Int) (ha : 2 ≤ attempt) :
    budget p attempt ≤ p.maxBackoffMs := by
  rw [budget_eq_spec p h attempt ha]; unfold specBudget; omega

theorem budget_pos (p : Policy) (h : Sane p) (attempt : Int) (ha : 2 ≤ attempt) :
    0 < budget p attempt := by
  rw [budget_eq_spec p h attempt ha]; unfold specBudget
  have hp1 := one_le_pow _ h.mult_ge (attempt - 2).toNat
  have := Int.mul_le_mul_of_nonneg_left hp1 (Int.le_of_lt h.init_pos)
  have := h.max_pos; have := h.init_pos
  simp at *; omega

theorem budget_mono (p : Policy) (h : Sane p) (a b : Int) (ha : 2 ≤ a) (hab : a ≤ b) :
    budget p a ≤ budget p b := by
  rw [budget_eq_spec p h a ha, budget_eq_spec p h b (by omega)]
  unfold specBudget
  have hpow : p.backoffMultiplier ^ (a - 2).toNat ≤ p.backoffMultiplier ^ (b - 2).toNat := by
    obtain ⟨k, hk⟩ : ∃ k, (b - 2).toNat = (a - 2).toNat + k := ⟨(b - 2).toNat - (a - 2).toNat, by omega⟩
    rw [hk, Int.pow_add]
    have h1 := one_le_pow _ h.mult_ge k
    have h0 : 0 ≤ p.backoffMultiplier ^ (a - 2).toNat := by
      have := one_le_pow _ h.mult_ge (a - 2).toNat; omega
    have := Int.mul_le_mul_of_nonneg_left h1 h0
    simpa using this
  have := Int.mul_le_mul_of_nonneg_left hpow (Int.le_of_lt h.init_pos)
  omega

/-- The jittered sleep never exceeds the documented cap. -/
theorem sleep_bounds (p : Policy) (h : Sane p) (draw : Int → Int) (hd : DrawOk draw)
    (attempt : Int) (ha : 2 ≤ attempt) :
    0 ≤ sleep p attempt draw ∧ sleep p attempt draw ≤ specBudget p attempt := by
  have hb := budget_pos p h attempt ha
  have he := budget_eq_spec p h attempt ha
  unfold sleep
  rw [if_neg (by omega)]
  have := hd _ hb
  rw [← he]; exact this

/-- No sleep when backoff is disabled or before the first retry. -/
theorem sleep_disabled (p : Policy) (draw : Int → Int) (attempt : Int)
    (h : p.initialBackoffMs ≤ 0 ∨ attempt ≤ 1) : sleep p attempt draw = 0 := by
  unfold sleep budget; simp [h]

/-- Observation: with `max_backoff_ms = 0` (no cap) the product wraps. -/
def uncapped : Policy := ⟨100, true, 100, 2, 0⟩
set_option maxRecDepth 20000 in
theorem uncapped_wraps :
    budget uncapped 58 = 7205759403792793600 ∧ budget uncapped 59 = 0 :=
  ⟨by rfl, by rfl⟩

/-! ## The attempt loop -/

inductive Outcome
  | resp (status : Int)
  | err
  deriving DecidableEq, Repr

def Outcome.failed : Outcome → Bool
  | .resp st => decide (500 ≤ st)
  | .err => true

/-- The attempt loop; `outs a` is the outcome of the `a`-th inner call
(1-based). Returns the propagated outcome and the number of inner calls.
The `fuel = 0` exit corresponds to leaving `while attempt < max_attempts`,
which `serve_fuel_unreachable` shows never happens.
mirrors flare/http/reliability.mojo:244-271 @59bda50 -/
def loop (outs : Nat → Outcome) (maxA : Nat) (attempt : Nat) : Nat → Outcome × Nat
  | 0 => (.err, attempt)
  | fuel + 1 =>
    let a := attempt + 1
    match outs a with
    | .resp st => if st < 500 ∨ a = maxA then (.resp st, a) else loop outs maxA a fuel
    | .err => if a = maxA then (.err, a) else loop outs maxA a fuel

/-- `Retry.serve`: a single call when retries are not allowed or
`max_attempts <= 1`, otherwise the attempt loop.
mirrors flare/http/reliability.mojo:233-271 @59bda50 -/
def serve (outs : Nat → Outcome) (maxAttempts : Int) (allowRetry : Bool) : Outcome × Nat :=
  if !allowRetry ∨ maxAttempts ≤ 1 then (outs 1, 1)
  else loop outs maxAttempts.toNat 0 maxAttempts.toNat

theorem loop_props (outs : Nat → Outcome) (maxA : Nat) :
    ∀ fuel attempt, attempt + fuel = maxA → attempt < maxA →
      let r := loop outs maxA attempt fuel
      attempt < r.2 ∧ r.2 ≤ maxA ∧ r.1 = outs r.2 ∧
      (∀ j, attempt < j → j < r.2 → (outs j).failed = true) ∧
      (r.1.failed = true → r.2 = maxA)
  | 0, attempt, h1, h2 => by omega
  | fuel + 1, attempt, h1, h2 => by
    simp only [loop]
    split
    · next st hst =>
      by_cases hc : st < 500 ∨ attempt + 1 = maxA
      · rw [if_pos hc]
        refine ⟨by omega, by omega, hst.symm, fun j a b => by omega, ?_⟩
        intro hf; simp [Outcome.failed] at hf; omega
      · rw [if_neg hc]
        have ih := loop_props outs maxA fuel (attempt + 1) (by omega) (by omega)
        obtain ⟨i1, i2, i3, i4, i5⟩ := ih
        refine ⟨by omega, i2, i3, ?_, i5⟩
        intro j hj1 hj2
        by_cases hj : j = attempt + 1
        · subst hj; rw [hst]; simp [Outcome.failed]; omega
        · exact i4 j (by omega) hj2
    · next hst =>
      by_cases hc : attempt + 1 = maxA
      · rw [if_pos hc]
        exact ⟨by omega, by omega, hst.symm, fun j a b => by omega, fun _ => hc⟩
      · rw [if_neg hc]
        obtain ⟨i1, i2, i3, i4, i5⟩ := loop_props outs maxA fuel (attempt + 1) (by omega) (by omega)
        refine ⟨by omega, i2, i3, ?_, i5⟩
        intro j hj1 hj2
        by_cases hj : j = attempt + 1
        · subst hj; rw [hst]; rfl
        · exact i4 j (by omega) hj2

/-- The inner handler runs at least once and at most `max(1, max_attempts)` times. -/
theorem serve_calls_bounded (outs : Nat → Outcome) (m : Int) (ar : Bool) :
    1 ≤ (serve outs m ar).2 ∧ (serve outs m ar).2 ≤ max 1 m.toNat := by
  unfold serve
  split
  · constructor <;> omega
  · have := loop_props outs m.toNat m.toNat 0 (by omega) (by omega)
    simp only at this; omega

/-- The propagated outcome is the outcome of the last call. -/
theorem serve_result_is_last (outs : Nat → Outcome) (m : Int) (ar : Bool) :
    (serve outs m ar).1 = outs (serve outs m ar).2 := by
  unfold serve
  split
  · rfl
  · exact (loop_props outs m.toNat m.toNat 0 (by omega) (by omega)).2.2.1

/-- A retry happens only after a failed attempt (5xx or raise). -/
theorem serve_retry_only_on_failure (outs : Nat → Outcome) (m : Int) (ar : Bool) :
    ∀ j, 1 ≤ j → j < (serve outs m ar).2 → (outs j).failed = true := by
  unfold serve
  split
  · intro j a b; omega
  · intro j a b
    exact (loop_props outs m.toNat m.toNat 0 (by omega) (by omega)).2.2.2.1 j (by omega) b

/-- A failure is surfaced only after all `max_attempts` attempts (when
retries are allowed). -/
theorem serve_failure_exhausts (outs : Nat → Outcome) (m : Int) (hm : 1 < m)
    (hf : (serve outs m true).1.failed = true) : (serve outs m true).2 = m.toNat := by
  unfold serve at *
  rw [if_neg (by simp; omega)] at *
  exact (loop_props outs m.toNat m.toNat 0 (by omega) (by omega)).2.2.2.2 hf

/-- The final fall-through `return self.inner.serve(req)` at :271 is dead:
the loop always returns before its fuel (= `max_attempts`) runs out. -/
theorem serve_fuel_unreachable (outs : Nat → Outcome) (maxA : Nat) (h : 0 < maxA) :
    0 < (loop outs maxA 0 maxA).2 := by
  have := loop_props outs maxA maxA 0 (by omega) h
  simp only at this; omega

end Flare.L4.Retry
