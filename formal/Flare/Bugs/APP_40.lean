import Flare.L4_App.RateLimit

/-!
# APP-40: RateLimit refill product wraps after a long idle period

`var refill = (elapsed * rate) // 1_000_000`
(flare/http/reliability.mojo:374 @59bda50) is computed in 64-bit `Int`.
`elapsed` is the time since the last credited instant, which grows without
bound while no request arrives. Once `elapsed > ⌊(2^63-1)/rate⌋` the
product wraps (2.56 h at 1e6 req/s, 25.6 h at 1e5, 106.7 days at 1e3),
`refill` becomes a huge negative number, the stored token count goes
negative and a full bucket rejects requests.

Repro: formal/repro/APP-40_ratelimit_refill_overflow.mojo.
-/
namespace Flare.Bugs.APP_40
open Flare.L4.RateLimit

/-- Full bucket (rate 1e6/s, burst 1e6 → 1e9 milli-tokens), last refill at
t = 0, request at t = 9 300 s. -/
def s0 : State := { tokens := 1000000000, last := 0 }
def now0 : Int := 9300000000000

/-- The implementation rejects and stores the exact negative milli-token
count observed by the Mojo repro (-9 145 744 073 710). -/
theorem impl_result :
    step 1000000 1000000 s0 now0 = ({ tokens := -9145744073710, last := 0 }, false) := by
  native_decide

/-- The spec admits (the bucket is full). -/
theorem spec_result : spec 1000000 (1000000 * 1000) s0.tokens (now0 - s0.last)
    = (1000000000 - 1000, true) := by decide

/-- Counterexample: the implementation's decision differs from the spec's
and the token invariant `0 ≤ tokens` is broken. -/
theorem full_bucket_rejected_after_idle :
    (step 1000000 1000000 s0 now0).2 ≠ (spec 1000000 (1000000 * 1000) s0.tokens (now0 - s0.last)).2
    ∧ ¬ (0 ≤ (step 1000000 1000000 s0 now0).1.tokens) := by
  rw [impl_result, spec_result]; decide

/-- The product indeed exceeds `Int64`: 9.3e12 ns · 1e6 > 2^63 - 1. -/
theorem product_overflows : ¬ fitsI64 (now0 * 1000000) := by decide

/-- Minimal fix: clamp `elapsed` to the time needed to fill an empty bucket
before multiplying.
mirrors the proposed fix to flare/http/reliability.mojo:370-374 @59bda50 -/
def maxElapsed (rate burst : Int) : Int :=
  w (fdivM (w (w (burst * 1000) * 1000000)) rate + 1)

def stepFixed (rate burst : Int) (s : State) (now : Int) : State × Bool :=
  let e := elapsedOf s now
  core rate burst s now (if e > maxElapsed rate burst then maxElapsed rate burst else e)

private theorem fits_of {n : Int} (h1 : -(2 ^ 63) ≤ n) (h2 : n ≤ 2 ^ 63 - 1) : fitsI64 n :=
  ⟨by unfold I64_MIN; omega, by unfold I64_MAX; omega⟩

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

/-- The fix meets the spec for every idle time: with a sane configuration
(`0 < rate ≤ 2^62`, `0 ≤ burst·1000·10⁶ ≤ 2^62`) and any clock readings
`0 ≤ last ≤ now < 2^63`, the fixed step computes exactly the ideal token
bucket over the true elapsed time `now - last`, with no overflow
hypothesis. -/
theorem implFixed_refines_spec (rate burst : Int) (s : State) (now : Int)
    (hr : 0 < rate) (hr2 : rate ≤ 2 ^ 62)
    (hc0 : 0 ≤ burst * 1000) (hc1 : burst * 1000 * 1000000 ≤ 2 ^ 62)
    (hl0 : 0 ≤ s.last) (hl1 : s.last ≤ now) (hn1 : now ≤ I64_MAX)
    (ht0 : 0 ≤ s.tokens) (ht1 : s.tokens ≤ burst * 1000) :
    ((stepFixed rate burst s now).1.tokens, (stepFixed rate burst s now).2)
      = spec rate (burst * 1000) s.tokens (now - s.last) := by
  have hcap : w (burst * 1000) = burst * 1000 := w_of_fits (fits_of (by omega) (by omega))
  have hcm : w (burst * 1000 * 1000000) = burst * 1000 * 1000000 :=
    w_of_fits (fits_of (by omega) (by omega))
  have hq0 : 0 ≤ burst * 1000 * 1000000 / rate := Int.ediv_nonneg (by omega) (by omega)
  have hq1 : burst * 1000 * 1000000 / rate ≤ burst * 1000 * 1000000 :=
    Int.ediv_le_self _ (by omega)
  have hMdef : maxElapsed rate burst = burst * 1000 * 1000000 / rate + 1 := by
    have hwq : w (burst * 1000 * 1000000 / rate) = burst * 1000 * 1000000 / rate :=
      w_of_fits (fits_of (by omega) (by omega))
    have hwq1 : w (burst * 1000 * 1000000 / rate + 1) = burst * 1000 * 1000000 / rate + 1 :=
      w_of_fits (fits_of (by omega) (by omega))
    unfold maxElapsed fdivM
    rw [hcap, hcm, fdiv_pos _ _ hr, hwq, hwq1]
  have hMr : maxElapsed rate burst * rate ≤ burst * 1000 * 1000000 + rate := by
    rw [hMdef, Int.add_mul, Int.one_mul]
    have := Int.ediv_mul_le (burst * 1000 * 1000000) (show rate ≠ 0 by omega)
    omega
  unfold stepFixed
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

end Flare.Bugs.APP_40
