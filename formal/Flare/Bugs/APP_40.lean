import Flare.L4_App.RateLimit

/-!
# APP-40: RateLimit refill product wraps after a long idle period

`var refill = (elapsed * rate) // 1_000_000`
(flare/http/reliability.mojo:374 @59bda50, pre-fix) is computed in 64-bit `Int`.
`elapsed` is the time since the last credited instant, which grows without
bound while no request arrives. Once `elapsed > ⌊(2^63-1)/rate⌋` the
product wraps (2.56 h at 1e6 req/s, 25.6 h at 1e5, 106.7 days at 1e3),
`refill` becomes a huge negative number, the stored token count goes
negative and a full bucket rejects requests.

Repro: formal/repro/APP-40_ratelimit_refill_overflow.mojo.

Status: resolved. `serve` clamps `elapsed` to `max_elapsed` before the
product; the shipped model is `Flare.L4.RateLimit.step` (`maxElapsed`), and
the counterexample below is about the explicitly pre-fix `stepOld`.
Regression test: tests/http/test_reliability.mojo::
test_ratelimit_full_bucket_admits_after_a_long_idle_period.
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
    stepOld 1000000 1000000 s0 now0 = ({ tokens := -9145744073710, last := 0 }, false) := by
  native_decide

/-- The spec admits (the bucket is full). -/
theorem spec_result : spec 1000000 (1000000 * 1000) s0.tokens (now0 - s0.last)
    = (1000000000 - 1000, true) := by decide

/-- Counterexample: the implementation's decision differs from the spec's
and the token invariant `0 ≤ tokens` is broken. -/
theorem full_bucket_rejected_after_idle :
    (stepOld 1000000 1000000 s0 now0).2 ≠ (spec 1000000 (1000000 * 1000) s0.tokens (now0 - s0.last)).2
    ∧ ¬ (0 ≤ (stepOld 1000000 1000000 s0 now0).1.tokens) := by
  rw [impl_result, spec_result]; decide

/-- The product indeed exceeds `Int64`: 9.3e12 ns · 1e6 > 2^63 - 1. -/
theorem product_overflows : ¬ fitsI64 (now0 * 1000000) := by decide

/-- **Fix meets spec**: the shipped `step` (which clamps `elapsed` to
`maxElapsed` before multiplying) computes exactly the ideal token bucket
over the true elapsed time `now - last` for every idle time, with a sane
configuration (`0 < rate ≤ 2^62`, `0 ≤ burst·1000·10⁶ ≤ 2^62`) and any clock
readings `0 ≤ last ≤ now < 2^63`. No overflow hypothesis. -/
theorem implFixed_refines_spec (rate burst : Int) (s : State) (now : Int)
    (hr : 0 < rate) (hr2 : rate ≤ 2 ^ 62)
    (hc0 : 0 ≤ burst * 1000) (hc1 : burst * 1000 * 1000000 ≤ 2 ^ 62)
    (hl0 : 0 ≤ s.last) (hl1 : s.last ≤ now) (hn1 : now ≤ I64_MAX)
    (ht0 : 0 ≤ s.tokens) (ht1 : s.tokens ≤ burst * 1000) :
    ((step rate burst s now).1.tokens, (step rate burst s now).2)
      = spec rate (burst * 1000) s.tokens (now - s.last) :=
  step_eq_spec rate burst s now ⟨hr, hr2, hc0, hc1, hn1, hl0, hl1, ht0, ht1⟩

/-- The repro's state on the shipped code: the full bucket admits. -/
theorem shipped_admits_after_idle : (step 1000000 1000000 s0 now0).2 = true := by
  native_decide

end Flare.Bugs.APP_40
