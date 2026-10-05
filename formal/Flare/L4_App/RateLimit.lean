import Flare.Core.Word
import Flare.Core.Assumptions

/-!
# RateLimit: token bucket (flare/http/reliability.mojo)

`RateLimit[Inner]` keeps a leaked 3-slot `Int64` cell:
`[0]` = milli-tokens, `[1]` = last-refill timestamp (ns, `perf_counter_ns`),
`[2]` = spin lock. One token = 1000 milli-tokens; the bucket capacity is
`burst * 1000` milli-tokens. The whole read-modify-write runs under the
lock, so the shared cell is updated atomically per request and a
sequential model of `serve` is faithful (the lock linearises workers).

* `step` transliterates one `serve` with Mojo `Int` (= `Int64`, wrapping)
  arithmetic: every Mojo `+ - *` is wrapped with `w`, Mojo `//` is floor
  division (`Int.fdiv`) wrapped with `w`. It is the shipped code, with the
  APP-40 clamp of `elapsed` to `maxElapsed`; `stepOld` is the pre-fix code
  (59bda50), kept for the counterexample in `Flare.Bugs.APP_40`.
* `spec` is the textbook token bucket in exact arithmetic (RFC-less;
  written from the docstring "admits up to `rate_per_sec` requests per
  second with a bucket depth of `burst`"): refill
  `⌊elapsed·rate / 10⁶⌋` milli-tokens, clamp at the capacity, admit iff at
  least one token, then spend it.

Results:
* `step_eq_spec`: for a sane configuration and any idle time the shipped
  `step` computes exactly the spec tokens and decision (general theorem; no
  no-overflow hypothesis, the clamp provides it).
* `step_inv`: the invariant `0 ≤ tokens ≤ cap` is preserved (general).
* `step_last_ok`: the clock carry never runs ahead of `now`, never goes
  backwards, and leaves less than one milli-token period (+1 ns) uncredited
  (general): the remainder fix is sound.
* `stepOld_eq_spec`, `stepOld_inv`, `stepOld_last_ok`: the same for the
  pre-fix `stepOld` under the extra hypothesis that the refill product
  `elapsed * rate` fits in `Int64`. Without it the invariant is false: see
  `Flare.Bugs.APP_40`.
-/
namespace Flare.L4.RateLimit

/-- Mojo `Int` arithmetic result: wrap to 64-bit two's complement. -/
def w (n : Int) : Int := (mojoInt n).toInt

/-- Mojo `a // b` on `Int`: floor division, then wrap. -/
def fdivM (a b : Int) : Int := w (Int.fdiv a b)

theorem w_of_fits {n : Int} (h : fitsI64 n) : w n = n := mojoInt_toInt_of_fits n h

theorem fdiv_pos (a b : Int) (hb : 0 < b) : Int.fdiv a b = a / b := by
  rw [Int.fdiv_eq_ediv]; simp [Int.le_of_lt hb]

/-- Bucket state: slot 0 (milli-tokens) and slot 1 (last refill, ns). -/
structure State where
  tokens : Int
  last : Int
  deriving Repr, DecidableEq

/-- Constructor state: full bucket, clock stamped (reliability.mojo:354-356). -/
def init (burst t0 : Int) : State := { tokens := w (burst * 1000), last := t0 }

/-- The body of `serve` after the clamped `elapsed` has been computed
(reliability.mojo:372-391): refill, clock carry, capacity clamp, admit.
mirrors flare/http/reliability.mojo:384-401 (fixed, APP-40) -/
def core (rate burst : Int) (s : State) (now elapsed : Int) : State × Bool :=
  let refill := fdivM (w (elapsed * rate)) 1000000
  let last1 := if refill > 0 then w (s.last + fdivM (w (refill * 1000000)) rate) else s.last
  let cap := w (burst * 1000)
  let nt0 := w (s.tokens + refill)
  let nt1 := if nt0 ≥ cap then cap else nt0
  let last2 := if nt0 ≥ cap then now else last1
  let allow := decide (nt1 ≥ 1000)
  let nt2 := if allow then w (nt1 - 1000) else nt1
  ({ tokens := nt2, last := last2 }, allow)

/-- Clamped elapsed time (reliability.mojo:366-371).
mirrors flare/http/reliability.mojo:372-374 (fixed, APP-40) -/
def elapsedOf (s : State) (now : Int) : Int :=
  let elapsed0 := w (now - s.last)
  if elapsed0 < 0 then 0 else elapsed0

/-- One pre-fix `serve` call with `rate_per_sec > 0` (the `<= 0`
pass-through branch does not touch the cell): `elapsed` is multiplied by
`rate` unclamped, which wraps after a long idle time (APP-40). `burst` is
the defaulted field value (`burst if burst > 0 else rate_per_sec`).
mirrors flare/http/reliability.mojo:358-394 @59bda50 (pre-fix) -/
def stepOld (rate burst : Int) (s : State) (now : Int) : State × Bool :=
  core rate burst s now (elapsedOf s now)

/-- The longest idle time that still matters: an empty bucket is full after
`⌊burst·10⁹/rate⌋ + 1` ns, so a longer `elapsed` is clamped to this before
the refill product is formed (`max_elapsed`).
mirrors flare/http/reliability.mojo:381-383 (fixed, APP-40) -/
def maxElapsed (rate burst : Int) : Int :=
  w (fdivM (w (w (burst * 1000) * 1000000)) rate + 1)

/-- One shipped `serve` call with `rate_per_sec > 0`: returns the new cell
and whether the request is admitted.
mirrors flare/http/reliability.mojo:361-404 (fixed, APP-40) -/
def step (rate burst : Int) (s : State) (now : Int) : State × Bool :=
  let e := elapsedOf s now
  core rate burst s now (if e > maxElapsed rate burst then maxElapsed rate burst else e)

/-- Specification: ideal token bucket in exact integer arithmetic.
`elapsed` ns have passed since the last credited instant. -/
def spec (rate cap tokens elapsed : Int) : Int × Bool :=
  let t := min cap (tokens + elapsed * rate / 1000000)
  if 1000 ≤ t then (t - 1000, true) else (t, false)

/-- The configuration and clock hypotheses under which the 64-bit
implementation is exact: positive rate, capacity in `[0, 2^62]`, clock
readings in `[0, 2^63)`, and the refill product representable. -/
structure Sane (rate burst : Int) (s : State) (now : Int) : Prop where
  rate_pos : 0 < rate
  rate_le : rate ≤ 2 ^ 62
  cap_nonneg : 0 ≤ burst * 1000
  cap_le : burst * 1000 ≤ 2 ^ 62
  now_nonneg : 0 ≤ now
  now_le : now ≤ I64_MAX
  last_nonneg : 0 ≤ s.last
  last_le : s.last ≤ now
  tok_nonneg : 0 ≤ s.tokens
  tok_le : s.tokens ≤ burst * 1000
  prod_fits : (now - s.last) * rate ≤ I64_MAX

private theorem fits_of {n : Int} (h1 : -(2 ^ 63) ≤ n) (h2 : n ≤ 2 ^ 63 - 1) : fitsI64 n :=
  ⟨by unfold I64_MIN; omega, by unfold I64_MAX; omega⟩

/-- `core` is exact for any elapsed value `E ≥ 0` whose refill product
fits in `Int64`: it computes the spec's tokens and decision. -/
theorem core_eq_spec (rate burst : Int) (s : State) (now E : Int)
    (hr : 0 < rate) (hc0 : 0 ≤ burst * 1000) (hc1 : burst * 1000 ≤ 2 ^ 62)
    (ht0 : 0 ≤ s.tokens) (ht1 : s.tokens ≤ burst * 1000)
    (hE : 0 ≤ E) (hp : E * rate ≤ I64_MAX) :
    ((core rate burst s now E).1.tokens, (core rate burst s now E).2)
      = spec rate (burst * 1000) s.tokens E := by
  unfold I64_MAX at hp
  have hP0 : 0 ≤ E * rate := Int.mul_nonneg hE (by omega)
  have hP : w (E * rate) = E * rate := w_of_fits (fits_of (by omega) (by omega))
  have hcap : w (burst * 1000) = burst * 1000 := w_of_fits (fits_of (by omega) (by omega))
  have hR : fdivM (E * rate) 1000000 = E * rate / 1000000 := by
    unfold fdivM; rw [fdiv_pos _ _ (by decide)]
    exact w_of_fits (fits_of (by omega) (by omega))
  simp only [core, spec, hP, hR, hcap]
  generalize E * rate = P at hP0 hp ⊢
  have hnt : w (s.tokens + P / 1000000) = s.tokens + P / 1000000 :=
    w_of_fits (fits_of (by omega) (by omega))
  have hsub : ∀ x, 0 ≤ x → x ≤ 2 ^ 62 → w (x - 1000) = x - 1000 := fun x a b =>
    w_of_fits (fits_of (by omega) (by omega))
  rw [hnt]
  by_cases hge : s.tokens + P / 1000000 ≥ burst * 1000
  · have hm : min (burst * 1000) (s.tokens + P / 1000000) = burst * 1000 := by omega
    rw [if_pos hge, hm]
    by_cases ha : 1000 ≤ burst * 1000
    · simp [ha, hsub _ hc0 hc1]
    · simp [ha]
  · have hm : min (burst * 1000) (s.tokens + P / 1000000) = s.tokens + P / 1000000 := by omega
    rw [if_neg hge, hm]
    by_cases ha : 1000 ≤ s.tokens + P / 1000000
    · simp [ha, hsub (s.tokens + P / 1000000) (by omega) (by omega)]
    · simp [ha]

theorem elapsedOf_eq (s : State) (now : Int) (hl0 : 0 ≤ s.last) (hl1 : s.last ≤ now)
    (hn1 : now ≤ I64_MAX) : elapsedOf s now = now - s.last := by
  unfold I64_MAX at hn1
  have he : w (now - s.last) = now - s.last := w_of_fits (fits_of (by omega) (by omega))
  simp only [elapsedOf, he]; rw [if_neg (by omega)]

/-- Under `Sane`, every intermediate Mojo value of the pre-fix code is
exact, so its token count and decision equal the spec's with
`elapsed = now - last`. -/
theorem stepOld_eq_spec (rate burst : Int) (s : State) (now : Int)
    (h : Sane rate burst s now) :
    ((stepOld rate burst s now).1.tokens, (stepOld rate burst s now).2)
      = spec rate (burst * 1000) s.tokens (now - s.last) := by
  unfold stepOld
  rw [elapsedOf_eq s now h.last_nonneg h.last_le h.now_le]
  exact core_eq_spec rate burst s now _ h.rate_pos h.cap_nonneg h.cap_le h.tok_nonneg h.tok_le
    (by have := h.last_le; omega) h.prod_fits

/-- The spec preserves `0 ≤ tokens ≤ cap` for any `elapsed ≥ 0`. -/
theorem spec_inv (rate cap tokens elapsed : Int) (hr : 0 ≤ rate) (he : 0 ≤ elapsed)
    (h0 : 0 ≤ tokens) (h1 : tokens ≤ cap) :
    0 ≤ (spec rate cap tokens elapsed).1 ∧ (spec rate cap tokens elapsed).1 ≤ cap := by
  have : 0 ≤ elapsed * rate / 1000000 := Int.ediv_nonneg (Int.mul_nonneg he hr) (by decide)
  simp only [spec]
  split <;> simp <;> omega

/-- Invariant `0 ≤ tokens ≤ burst·1000` is preserved by the pre-fix `serve`
whenever the refill product does not overflow. -/
theorem stepOld_inv (rate burst : Int) (s : State) (now : Int) (h : Sane rate burst s now) :
    0 ≤ (stepOld rate burst s now).1.tokens ∧ (stepOld rate burst s now).1.tokens ≤ burst * 1000 := by
  have e := congrArg Prod.fst (stepOld_eq_spec rate burst s now h)
  simp only at e
  rw [e]
  exact spec_inv _ _ _ _ (Int.le_of_lt h.rate_pos) (by have := h.last_le; omega) h.tok_nonneg h.tok_le

/-- The clock carry of the pre-fix code: the new `last`
lies in `[last, now]`, and the time left uncredited is less than one
milli-token period plus one nanosecond: `(now - last') * rate < 10⁶ + rate`. -/
theorem stepOld_last_ok (rate burst : Int) (s : State) (now : Int) (h : Sane rate burst s now) :
    s.last ≤ (stepOld rate burst s now).1.last ∧ (stepOld rate burst s now).1.last ≤ now ∧
    (now - (stepOld rate burst s now).1.last) * rate < 1000000 + rate := by
  obtain ⟨hr, hr2, hc0, hc1, hn0, hn1, hl0, hl1, ht0, ht1, hp⟩ := h
  unfold I64_MAX at hn1 hp
  have he : w (now - s.last) = now - s.last := w_of_fits (fits_of (by omega) (by omega))
  have hP0 : 0 ≤ (now - s.last) * rate := Int.mul_nonneg (by omega) (by omega)
  have hP : w ((now - s.last) * rate) = (now - s.last) * rate :=
    w_of_fits (fits_of (by omega) (by omega))
  have hcap : w (burst * 1000) = burst * 1000 := w_of_fits (fits_of (by omega) (by omega))
  have hR : fdivM ((now - s.last) * rate) 1000000 = (now - s.last) * rate / 1000000 := by
    unfold fdivM; rw [fdiv_pos _ _ (by decide)]
    exact w_of_fits (fits_of (by omega) (by omega))
  simp only [stepOld, core, elapsedOf, he, if_neg (show ¬ now - s.last < 0 by omega), hP, hR, hcap]
  have hlast0 : now = s.last + (now - s.last) := by omega
  generalize hE : now - s.last = E at hP0 hp hlast0 ⊢
  have hR0 : 0 ≤ E * rate / 1000000 := Int.ediv_nonneg hP0 (by decide)
  have hlo : E * rate / 1000000 * 1000000 ≤ E * rate := Int.ediv_mul_le _ (by decide)
  have hhi : E * rate < (E * rate / 1000000 + 1) * 1000000 :=
    Int.lt_ediv_add_one_mul_self _ (by decide)
  generalize E * rate / 1000000 = R at hR0 hlo hhi ⊢
  have hRM : w (R * 1000000) = R * 1000000 := w_of_fits (fits_of (by omega) (by omega))
  have hCq0 : 0 ≤ R * 1000000 / rate := Int.ediv_nonneg (by omega) (by omega)
  have hCq1 : R * 1000000 / rate ≤ R * 1000000 := Int.ediv_le_self _ (by omega)
  have hC : fdivM (R * 1000000) rate = R * 1000000 / rate := by
    unfold fdivM; rw [fdiv_pos _ _ hr]
    exact w_of_fits (fits_of (by omega) (by omega))
  have hC1 : R * 1000000 / rate * rate ≤ R * 1000000 := Int.ediv_mul_le _ (by omega)
  have hC2 : R * 1000000 < (R * 1000000 / rate + 1) * rate :=
    Int.lt_ediv_add_one_mul_self _ hr
  rw [hRM, hC]
  generalize R * 1000000 / rate = C at hCq0 hCq1 hC1 hC2 ⊢
  have hCE : C ≤ E := by
    have : C * rate ≤ E * rate := by omega
    exact Int.le_of_mul_le_mul_right this hr
  have hlast : w (s.last + C) = s.last + C := w_of_fits (fits_of (by omega) (by omega))
  have key : (E - C) * rate < 1000000 + rate := by
    have : (E - C) * rate = E * rate - C * rate := Int.sub_mul _ _ _
    rw [this]; rw [Int.add_mul] at hC2; omega
  rw [hlast]
  have hnt : w (s.tokens + R) = s.tokens + R := w_of_fits (fits_of (by omega) (by omega))
  rw [hnt]
  by_cases hge : s.tokens + R ≥ burst * 1000
  · simp only [if_pos hge]
    refine ⟨by omega, Int.le_refl _, ?_⟩
    simp; omega
  · simp only [if_neg hge]
    by_cases hR1 : R > 0
    · simp only [if_pos hR1]
      refine ⟨by omega, by omega, ?_⟩
      have : now - (s.last + C) = E - C := by omega
      rw [this]; exact key
    · simp only [if_neg hR1]
      have hR00 : R = 0 := by omega
      subst hR00
      refine ⟨Int.le_refl _, hl1, ?_⟩
      have : now - s.last = E := by omega
      rw [this]; omega

/-! ## The shipped `step` (APP-40 fixed) -/

/-- Saturation: if `E ≥ ⌊cap·10⁶/rate⌋ + 1`, the spec refill reaches the
capacity, so the spec result does not depend on how much larger `E` is. -/
theorem spec_saturates (rate cap tokens E M : Int) (hr : 0 < rate) (h0 : 0 ≤ tokens)
    (hM : M = cap * 1000000 / rate + 1) (hE : M ≤ E) (_hc : 0 ≤ cap) :
    spec rate cap tokens E = spec rate cap tokens M := by
  have k1 : cap * 1000000 < M * rate := by
    rw [hM]; exact Int.lt_ediv_add_one_mul_self _ hr
  have k2 : M * rate ≤ E * rate := Int.mul_le_mul_of_nonneg_right hE (Int.le_of_lt hr)
  have q1 : cap ≤ M * rate / 1000000 := by
    rw [Int.le_ediv_iff_mul_le (by decide)]; omega
  have q2 : cap ≤ E * rate / 1000000 := by
    rw [Int.le_ediv_iff_mul_le (by decide)]; omega
  have m1 : min cap (tokens + E * rate / 1000000) = cap := by omega
  have m2 : min cap (tokens + M * rate / 1000000) = cap := by omega
  simp only [spec, m1, m2]

/-- Hypotheses for the shipped `step`: a sane configuration (rate and
`burst·10⁹` below 2⁶²) and clock readings in `[0, 2⁶³)`. There is no
hypothesis on the refill product: the clamp provides it. -/
structure SaneFix (rate burst : Int) (s : State) (now : Int) : Prop where
  rate_pos : 0 < rate
  rate_le : rate ≤ 2 ^ 62
  cap_nonneg : 0 ≤ burst * 1000
  capm_le : burst * 1000 * 1000000 ≤ 2 ^ 62
  now_le : now ≤ I64_MAX
  last_nonneg : 0 ≤ s.last
  last_le : s.last ≤ now
  tok_nonneg : 0 ≤ s.tokens
  tok_le : s.tokens ≤ burst * 1000

/-- The wrapped `max_elapsed` is the exact value. -/
theorem maxElapsed_eq (rate burst : Int) (hr : 0 < rate) (hr2 : rate ≤ 2 ^ 62)
    (hc0 : 0 ≤ burst * 1000) (hc1 : burst * 1000 * 1000000 ≤ 2 ^ 62) :
    maxElapsed rate burst = burst * 1000 * 1000000 / rate + 1 := by
  have hcap : w (burst * 1000) = burst * 1000 := w_of_fits (fits_of (by omega) (by omega))
  have hcm : w (burst * 1000 * 1000000) = burst * 1000 * 1000000 :=
    w_of_fits (fits_of (by omega) (by omega))
  have hq0 : 0 ≤ burst * 1000 * 1000000 / rate := Int.ediv_nonneg (by omega) (by omega)
  have hq1 : burst * 1000 * 1000000 / rate ≤ burst * 1000 * 1000000 :=
    Int.ediv_le_self _ (by omega)
  have hwq : w (burst * 1000 * 1000000 / rate) = burst * 1000 * 1000000 / rate :=
    w_of_fits (fits_of (by omega) (by omega))
  have hwq1 : w (burst * 1000 * 1000000 / rate + 1) = burst * 1000 * 1000000 / rate + 1 :=
    w_of_fits (fits_of (by omega) (by omega))
  unfold maxElapsed fdivM
  rw [hcap, hcm, fdiv_pos _ _ hr, hwq, hwq1]

theorem maxElapsed_mul_le (rate burst : Int) (hr : 0 < rate) (hr2 : rate ≤ 2 ^ 62)
    (hc0 : 0 ≤ burst * 1000) (hc1 : burst * 1000 * 1000000 ≤ 2 ^ 62) :
    maxElapsed rate burst * rate ≤ burst * 1000 * 1000000 + rate := by
  rw [maxElapsed_eq rate burst hr hr2 hc0 hc1, Int.add_mul, Int.one_mul]
  have := Int.ediv_mul_le (burst * 1000 * 1000000) (show rate ≠ 0 by omega)
  omega

/-- **The fix meets the spec for every idle time**: with a sane
configuration and any clock readings `0 ≤ last ≤ now < 2^63`, the shipped
`step` computes exactly the ideal token bucket over the true elapsed time
`now - last`, with no overflow hypothesis. -/
theorem step_eq_spec (rate burst : Int) (s : State) (now : Int)
    (h : SaneFix rate burst s now) :
    ((step rate burst s now).1.tokens, (step rate burst s now).2)
      = spec rate (burst * 1000) s.tokens (now - s.last) := by
  obtain ⟨hr, hr2, hc0, hc1, hn1, hl0, hl1, ht0, ht1⟩ := h
  have hMdef := maxElapsed_eq rate burst hr hr2 hc0 hc1
  have hMr := maxElapsed_mul_le rate burst hr hr2 hc0 hc1
  have hq0 : 0 ≤ burst * 1000 * 1000000 / rate := Int.ediv_nonneg (by omega) (by omega)
  unfold step
  rw [elapsedOf_eq s now hl0 hl1 hn1]
  dsimp only
  have cmp := core_eq_spec rate burst s now
  by_cases hgt : now - s.last > maxElapsed rate burst
  · rw [if_pos hgt]
    rw [cmp _ hr hc0 (by omega) ht0 ht1 (by rw [hMdef]; omega) (by unfold I64_MAX; omega)]
    exact (spec_saturates rate (burst * 1000) s.tokens (now - s.last) _ hr ht0
      hMdef (by omega) hc0).symm
  · rw [if_neg hgt]
    have hle : (now - s.last) * rate ≤ maxElapsed rate burst * rate :=
      Int.mul_le_mul_of_nonneg_right (by omega) (Int.le_of_lt hr)
    exact cmp _ hr hc0 (by omega) ht0 ht1 (by omega) (by unfold I64_MAX; omega)

/-- The invariant `0 ≤ tokens ≤ burst·1000` is preserved by the shipped
`serve` for every idle time. -/
theorem step_inv (rate burst : Int) (s : State) (now : Int) (h : SaneFix rate burst s now) :
    0 ≤ (step rate burst s now).1.tokens ∧ (step rate burst s now).1.tokens ≤ burst * 1000 := by
  have e := congrArg Prod.fst (step_eq_spec rate burst s now h)
  simp only at e
  rw [e]
  exact spec_inv _ _ _ _ (Int.le_of_lt h.rate_pos) (by have := h.last_le; omega)
    h.tok_nonneg h.tok_le

/-- The clock carry of the shipped code: the new `last` lies in
`[last, now]` and less than one milli-token period (+1 ns) is left
uncredited. Past the clamp the bucket is full and the clock is `now`. -/
theorem step_last_ok (rate burst : Int) (s : State) (now : Int) (h : SaneFix rate burst s now) :
    s.last ≤ (step rate burst s now).1.last ∧ (step rate burst s now).1.last ≤ now ∧
    (now - (step rate burst s now).1.last) * rate < 1000000 + rate := by
  have hr := h.rate_pos
  have hr2 := h.rate_le
  have hc0 := h.cap_nonneg
  have hc1 := h.capm_le
  have hn1 := h.now_le
  have hl0 := h.last_nonneg
  have hl1 := h.last_le
  have ht0 := h.tok_nonneg
  have ht1 := h.tok_le
  have hMdef := maxElapsed_eq rate burst hr hr2 hc0 hc1
  have hMr := maxElapsed_mul_le rate burst hr hr2 hc0 hc1
  have hE := elapsedOf_eq s now hl0 hl1 hn1
  by_cases hgt : now - s.last > maxElapsed rate burst
  · have hq0 : 0 ≤ burst * 1000 * 1000000 / rate := Int.ediv_nonneg (by omega) (by omega)
    have hM0 : 0 ≤ maxElapsed rate burst := by omega
    have hP0 : 0 ≤ maxElapsed rate burst * rate := Int.mul_nonneg hM0 (by omega)
    have hP : w (maxElapsed rate burst * rate) = maxElapsed rate burst * rate := by
      apply w_of_fits; apply fits_of <;> unfold I64_MAX at * <;> omega
    have hR : fdivM (maxElapsed rate burst * rate) 1000000
        = maxElapsed rate burst * rate / 1000000 := by
      unfold fdivM; rw [fdiv_pos _ _ (by decide)]
      exact w_of_fits (fits_of (by omega) (by unfold I64_MAX at *; omega))
    have k1 : burst * 1000 * 1000000 < maxElapsed rate burst * rate := by
      rw [hMdef]; exact Int.lt_ediv_add_one_mul_self _ hr
    have hq : burst * 1000 ≤ maxElapsed rate burst * rate / 1000000 := by
      rw [Int.le_ediv_iff_mul_le (by decide)]; omega
    have hnt : w (s.tokens + maxElapsed rate burst * rate / 1000000)
        = s.tokens + maxElapsed rate burst * rate / 1000000 :=
      w_of_fits (fits_of (by omega) (by unfold I64_MAX at *; omega))
    have hcap : w (burst * 1000) = burst * 1000 := w_of_fits (fits_of (by omega) (by omega))
    have hlast : (step rate burst s now).1.last = now := by
      unfold step
      simp only [hE, if_pos hgt, core, hP, hR, hnt, hcap]
      rw [if_pos (by omega)]
    rw [hlast]
    refine ⟨hl1, Int.le_refl _, ?_⟩
    simp; omega
  · have hsame : step rate burst s now = stepOld rate burst s now := by
      unfold step stepOld
      rw [hE]
      simp only [if_neg hgt]
    rw [hsame]
    have hle : (now - s.last) * rate ≤ maxElapsed rate burst * rate :=
      Int.mul_le_mul_of_nonneg_right (by omega) (Int.le_of_lt hr)
    exact stepOld_last_ok rate burst s now
      ⟨hr, hr2, hc0, by omega, by omega, hn1, hl0, hl1, ht0, ht1, by unfold I64_MAX; omega⟩

/-- Exact overflow threshold: the refill product overflows iff
`elapsed > ⌊(2^63 - 1) / rate⌋` (for `rate > 0`, `elapsed ≥ 0`). -/
theorem overflow_iff (rate e : Int) (hr : 0 < rate) :
    e * rate ≤ I64_MAX ↔ e ≤ I64_MAX / rate := by
  unfold I64_MAX
  constructor
  · intro h; exact (Int.le_ediv_iff_mul_le hr).mpr h
  · intro h; exact (Int.le_ediv_iff_mul_le hr).mp h

/-- Concrete thresholds (ns of idle time before the product wraps). -/
theorem threshold_rate_1e6 : I64_MAX / 1000000 = 9223372036854 := by decide
theorem threshold_rate_1e5 : I64_MAX / 100000 = 92233720368547 := by decide
theorem threshold_rate_1e3 : I64_MAX / 1000 = 9223372036854775 := by decide

end Flare.L4.RateLimit
