import Flare.L1_Encoding.CivilTime
/-!
# Civil time on 64-bit `Int` (runtime/date_cache.mojo)

`CivilTime.lean` models Mojo `Int` as unbounded. Here every `+`, `-` and `*`
of `civil_to_unix_seconds` / `unix_seconds_to_civil` wraps to 64 bits (`W`,
two's complement, which is what Mojo `Int` does on the 64-bit targets flare
supports); `//` and `%` by a positive constant cannot overflow and are left
as floor division / modulus.

Results:
* `civilToUnix64_eq`: for every 64-bit input (years within 400 of `-2^63`
  and months beyond `±2^55` excepted) the 64-bit forward function is the
  exact result wrapped; `civilToUnix64_eq_iff`: it is exact iff the exact
  result is representable.
* `civilToUnix_inRange` / `civilToUnix64_exact`: exact for `|year| ≤ 2^38`
  with the other fields within `±2^30`; `jan1_inRange_iff`: 1 January is
  representable exactly for years `-292277022656 .. 292277026596`;
  `civilToUnix64_wraps`: year `2^39` wraps.
* `httpdate_exact`: the only in-tree forward caller (`_httpdate_to_unix`,
  4-digit year, 2-digit fields) never overflows. (Before the ENC-02 fix it
  was already unaffected: `daysFromCivilOld_eq_of_year_nonneg`.)
* `unixToCivil64_eq`: the inverse equals the unbounded model for every
  64-bit input, although `days * 86400` wraps near `-2^63`
  (`inverse_intermediate_wraps`).
-/
namespace Flare.L1.CivilTime

/-- Two's-complement wrap of an integer to 64 bits. -/
def W (x : Int) : Int := (x + 2 ^ 63) % 2 ^ 64 - 2 ^ 63

/-- Representable as a 64-bit Mojo `Int`. -/
def InRange (x : Int) : Prop := -2 ^ 63 ≤ x ∧ x < 2 ^ 63

theorem W_of_le (x : Int) (h1 : -2 ^ 63 ≤ x) (h2 : x < 2 ^ 63) : W x = x := by
  unfold W; omega

theorem W_inRange (x : Int) : InRange (W x) := by unfold W InRange; omega

theorem W_eq_self_iff (x : Int) : W x = x ↔ InRange x := by
  unfold W InRange; omega

theorem W_add_W (a b : Int) : W (W a + b) = W (a + b) := by unfold W; omega
theorem W_add_W' (a b : Int) : W (a + W b) = W (a + b) := by unfold W; omega
theorem W_sub_W (a b : Int) : W (W a - b) = W (a - b) := by unfold W; omega
theorem W_sub_W' (a b : Int) : W (a - W b) = W (a - b) := by unfold W; omega
theorem W_mul_W (a c : Int) : W (W a * c) = W (a * c) := by
  unfold W
  have h : (((a + 2 ^ 63) % 2 ^ 64 - 2 ^ 63) * c + 2 ^ 63) % 2 ^ 64 = (a * c + 2 ^ 63) % 2 ^ 64 := by
    have e : ((a + 2 ^ 63) % 2 ^ 64 - 2 ^ 63) * c = a * c - 2 ^ 64 * ((a + 2 ^ 63) / 2 ^ 64 * c) := by
      rw [Int.emod_def, Int.sub_mul, Int.sub_mul, Int.add_mul, Int.mul_assoc]; omega
    rw [e]
    omega
  rw [h]

/-- `civil_to_unix_seconds` on 64-bit `Int`: every `+`, `-` and `*` wraps;
`//` by a positive constant cannot overflow.
mirrors flare/runtime/date_cache.mojo:71-98 (fixed, ENC-02) -/
def civilToUnix64 (y m d hh mm ss : Int) : Int :=
  let year := W (y - (if m ≤ 2 then 1 else 0))
  let era := year / 400
  let yoe := W (year - W (era * 400))
  let ms := W (m + (if m ≤ 2 then 9 else -3))
  let doy := W (W (W (W (153 * ms) + 2) / 5 + d) - 1)
  let doe := W (W (W (W (yoe * 365) + yoe / 4) - yoe / 100) + doy)
  let dse := W (W (W (era * 146097) + doe) - 719468)
  W (W (W (W (dse * 86400) + W (hh * 3600)) + W (mm * 60)) + ss)

theorem W_mul_W' (a c : Int) : W (c * W a) = W (c * a) := by
  rw [Int.mul_comm, W_mul_W, Int.mul_comm]

/-- The 64-bit result is the exact result wrapped, for every 64-bit input
except years within 400 of the minimum and months beyond ±2^55 (the
inputs to a division must not wrap). -/
theorem civilToUnix64_eq (y m d hh mm ss : Int) (hy1 : -2 ^ 63 + 400 ≤ y) (hy2 : y < 2 ^ 63)
    (hm1 : -2 ^ 55 ≤ m) (hm2 : m ≤ 2 ^ 55) :
    civilToUnix64 y m d hh mm ss = W (civilToUnix y m d hh mm ss) := by
  simp only [civilToUnix64, civilToUnix, daysFromCivil, shiftYear, shiftMonth, mStart, startOf]
  by_cases hm : m ≤ 2 <;> simp only [hm, ↓reduceIte, Int.sub_zero] <;>
  simp (disch := omega) only [W_of_le] <;>
  (try simp (disch := omega) only [W_add_W, W_add_W', W_sub_W, W_mul_W]) <;>
  congr 1 <;> omega

theorem civilToUnix64_eq_iff (y m d hh mm ss : Int) (hy1 : -2 ^ 63 + 400 ≤ y) (hy2 : y < 2 ^ 63)
    (hm1 : -2 ^ 55 ≤ m) (hm2 : m ≤ 2 ^ 55) :
    civilToUnix64 y m d hh mm ss = civilToUnix y m d hh mm ss ↔ InRange (civilToUnix y m d hh mm ss) := by
  rw [civilToUnix64_eq _ _ _ _ _ _ hy1 hy2 hm1 hm2, W_eq_self_iff]

/-- Every input with `|year| ≤ 2^38` and the other fields within `±2^30`
gives a representable result, so the 64-bit function is exact there. -/
theorem civilToUnix_inRange (y m d hh mm ss : Int) (hy : -2 ^ 38 ≤ y ∧ y ≤ 2 ^ 38)
    (hm : -2 ^ 30 ≤ m ∧ m ≤ 2 ^ 30) (hd : -2 ^ 30 ≤ d ∧ d ≤ 2 ^ 30)
    (hh' : -2 ^ 30 ≤ hh ∧ hh ≤ 2 ^ 30) (hmm : -2 ^ 30 ≤ mm ∧ mm ≤ 2 ^ 30)
    (hss : -2 ^ 30 ≤ ss ∧ ss ≤ 2 ^ 30) : InRange (civilToUnix y m d hh mm ss) := by
  simp only [InRange, civilToUnix, daysFromCivil, shiftYear, shiftMonth, mStart, startOf]
  by_cases h1 : m ≤ 2 <;> simp only [h1, ↓reduceIte] <;> omega

theorem civilToUnix64_exact (y m d hh mm ss : Int) (hy : -2 ^ 38 ≤ y ∧ y ≤ 2 ^ 38)
    (hm : -2 ^ 30 ≤ m ∧ m ≤ 2 ^ 30) (hd : -2 ^ 30 ≤ d ∧ d ≤ 2 ^ 30)
    (hh' : -2 ^ 30 ≤ hh ∧ hh ≤ 2 ^ 30) (hmm : -2 ^ 30 ≤ mm ∧ mm ≤ 2 ^ 30)
    (hss : -2 ^ 30 ≤ ss ∧ ss ≤ 2 ^ 30) :
    civilToUnix64 y m d hh mm ss = civilToUnix y m d hh mm ss :=
  (civilToUnix64_eq_iff _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega)).mpr
    (civilToUnix_inRange _ _ _ _ _ _ hy hm hd hh' hmm hss)

/-- The exact year range for 1 January 00:00:00: representable iff
`-292277022656 ≤ y ≤ 292277026596` (Int64 seconds span
-292277022657-01-27 .. 292277026596-12-04). -/
theorem jan1_inRange_iff (y : Int) (hy : -2 ^ 50 ≤ y ∧ y ≤ 2 ^ 50) :
    InRange (civilToUnix y 1 1 0 0 0) ↔ -292277022656 ≤ y ∧ y ≤ 292277026596 := by
  simp only [InRange, civilToUnix, daysFromCivil, shiftYear, shiftMonth, mStart, startOf]
  simp only [show (1 : Int) ≤ 2 from by decide, ↓reduceIte]
  omega

/-- Overflow past the range: 1 January of year 2^39 wraps. -/
theorem civilToUnix64_wraps : civilToUnix64 (2 ^ 39) 1 1 0 0 0 ≠ civilToUnix (2 ^ 39) 1 1 0 0 0 := by
  rw [Ne, civilToUnix64_eq_iff _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega),
    jan1_inRange_iff _ (by omega)]
  omega

/-- HTTP-date inputs (`_httpdate_to_unix`, flare/http/conditional.mojo:239-261
@59bda50): a 4-digit year, month index + 1, and 2-digit day/hour/minute/second
never overflow. -/
theorem httpdate_exact (y mon d hh mm ss : Int) (hy : 0 ≤ y ∧ y ≤ 9999) (hm : 0 ≤ mon ∧ mon ≤ 11)
    (hd : 0 ≤ d ∧ d ≤ 99) (hh' : 0 ≤ hh ∧ hh ≤ 99) (hmm : 0 ≤ mm ∧ mm ≤ 99) (hss : 0 ≤ ss ∧ ss ≤ 99) :
    civilToUnix64 y (mon + 1) d hh mm ss = civilToUnix y (mon + 1) d hh mm ss :=
  civilToUnix64_exact _ _ _ _ _ _ (by omega) (by omega) (by omega) (by omega) (by omega) (by omega)

/-- Day-number to date part of `unix_seconds_to_civil` on 64-bit `Int`.
mirrors flare/runtime/date_cache.mojo:152-163 (fixed, ENC-02) -/
def civilFromDays64 (z : Int) : Int × Int × Int :=
  let days := W (z + 719468)
  let era := days / 146097
  let doe := W (days - W (era * 146097))
  let yoe := W (W (W (doe - doe / 1460) + doe / 36524) - doe / 146096) / 365
  let y := W (yoe + W (era * 400))
  let doy := W (doe - W (W (W (365 * yoe) + yoe / 4) - yoe / 100))
  let mp := W (W (5 * doy) + 2) / 153
  let d := W (W (doy - W (W (153 * mp) + 2) / 5) + 1)
  let m := if mp < 10 then W (mp + 3) else W (mp - 9)
  (if m ≤ 2 then W (y + 1) else y, m, d)

/-- `unix_seconds_to_civil` on 64-bit `Int`.
mirrors flare/runtime/date_cache.mojo:130-174 (fixed, ENC-02) -/
def unixToCivil64 (s : Int) : Civil :=
  let days := s / 86400
  let sod := W (s - W (days * 86400))
  let dow := W (days + 4) % 7
  let dow := if dow < 0 then W (dow + 7) else dow
  let c := civilFromDays64 days
  ⟨c.1, c.2.1, c.2.2, sod / 3600, (sod % 3600) / 60, sod % 60, dow⟩

macro "rw_W_exact " e:term : tactic => `(tactic| rw [W_of_le $e (by omega) (by omega)])

theorem civilFromDays64_eq (z : Int) (hz1 : -2 ^ 50 ≤ z) (hz2 : z ≤ 2 ^ 50) :
    civilFromDays64 z = civilFromDays z := by
  simp only [civilFromDays64, civilFromDays, yoeOf, startOf, mpOf, mStart]
  rw_W_exact (z + 719468)
  generalize hd : z + 719468 = days
  have hd1 : -2 ^ 51 ≤ days := by omega
  have hd2 : days ≤ 2 ^ 51 := by omega
  generalize he : days / 146097 = era
  have : era * 146097 ≤ days ∧ days < era * 146097 + 146097 := by omega
  rw_W_exact (era * 146097); rw_W_exact (days - era * 146097)
  generalize hdoe : days - era * 146097 = doe
  have : 0 ≤ doe ∧ doe ≤ 300000 := by omega
  rw_W_exact (doe - doe / 1460); rw_W_exact (doe - doe / 1460 + doe / 36524); rw_W_exact (doe - doe / 1460 + doe / 36524 - doe / 146096)
  obtain ⟨yoe, hy⟩ : ∃ yoe, (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365 = yoe := ⟨_, rfl⟩
  simp only [hy]
  have : 0 ≤ yoe ∧ yoe ≤ 1000 := by omega
  rw_W_exact (era * 400); rw_W_exact (yoe + era * 400)
  rw_W_exact (365 * yoe); rw_W_exact (365 * yoe + yoe / 4); rw_W_exact (365 * yoe + yoe / 4 - yoe / 100)
  rw_W_exact (doe - (365 * yoe + yoe / 4 - yoe / 100))
  generalize hdoy : doe - (365 * yoe + yoe / 4 - yoe / 100) = doy
  have : -400000 ≤ doy ∧ doy ≤ 400000 := by omega
  rw_W_exact (5 * doy); rw_W_exact (5 * doy + 2)
  generalize hmp : (5 * doy + 2) / 153 = mp
  have : -20000 ≤ mp ∧ mp ≤ 20000 := by omega
  rw_W_exact (153 * mp); rw_W_exact (153 * mp + 2); rw_W_exact (doy - (153 * mp + 2) / 5); rw_W_exact (doy - (153 * mp + 2) / 5 + 1)
  rw_W_exact (mp + 3); rw_W_exact (mp - 9); rw_W_exact (yoe + era * 400 + 1)

theorem unixToCivil64_eq (s : Int) (hs : InRange s) : unixToCivil64 s = unixToCivil s := by
  unfold InRange at hs
  simp only [unixToCivil64, unixToCivil]
  rw [W_sub_W', civilFromDays64_eq _ (by omega) (by omega)]
  rw_W_exact (s - s / 86400 * 86400); rw_W_exact (s / 86400 + 4); rw_W_exact ((s / 86400 + 4) % 7 + 7)

/-- For `s` near `-2^63` the intermediate `days * 86400` does wrap;
`unixToCivil64_eq` shows the result is still exact. -/
theorem inverse_intermediate_wraps : ¬ InRange ((-2 ^ 63) / 86400 * 86400) := by
  unfold InRange; omega

/-- Before the ENC-02 fix, any non-negative civil year (so every HTTP-date
year, including 0000-01/02 whose March-based year is -1) was already on the
exact side: the pre-fix day count equals the shipped one. -/
theorem daysFromCivilOld_eq_of_year_nonneg (y m d : Int) (hy : 0 ≤ y) :
    daysFromCivilOld y m d = daysFromCivil y m d := by
  by_cases hs : 0 ≤ shiftYear y m
  · exact daysFromCivilOld_eq _ _ _ hs
  have hm : m ≤ 2 := by
    by_cases hm : m ≤ 2
    · exact hm
    · simp only [shiftYear, hm, ↓reduceIte] at hs; omega
  have hy0 : y = 0 := by simp only [shiftYear, hm, ↓reduceIte] at hs; omega
  subst hy0
  simp only [daysFromCivilOld, daysFromCivil, shiftYear, hm, ↓reduceIte, startOf]
  rw [if_neg (by decide)]
  omega

/-- The digit loop of `_parse_int_at` over the bytes `p[off:off+length]`.
mirrors flare/http/conditional.mojo:207-216 @59bda50 -/
def parseDigits (v : Int) : List UInt8 → Int
  | [] => v
  | c :: cs => if c.toNat < 48 ∨ c.toNat > 57 then -1 else parseDigits (v * 10 + (c.toNat - 48 : Nat)) cs

theorem parseDigits_range (cs : List UInt8) : ∀ v : Int, 0 ≤ v →
    parseDigits v cs = -1 ∨ (0 ≤ parseDigits v cs ∧ parseDigits v cs < (v + 1) * 10 ^ cs.length) := by
  induction cs with
  | nil => intro v hv; right; simp only [parseDigits, List.length_nil, Int.pow_zero]; omega
  | cons c cs ih =>
    intro v hv
    simp only [parseDigits]
    split
    · left; rfl
    · have hd : (c.toNat - 48 : Nat) ≤ 9 := by omega
      rcases ih (v * 10 + (c.toNat - 48 : Nat)) (by omega) with h | ⟨h1, h2⟩
      · left; exact h
      · right
        refine ⟨h1, ?_⟩
        have hp : (0 : Int) ≤ 10 ^ cs.length := Int.pow_nonneg (by decide)
        have : (v * 10 + ((c.toNat - 48 : Nat) : Int) + 1) * 10 ^ cs.length ≤ (v + 1) * 10 * 10 ^ cs.length :=
          Int.mul_le_mul_of_nonneg_right (by omega) hp
        rw [List.length_cons, Int.pow_succ, Int.mul_comm (10 ^ cs.length) 10, ← Int.mul_assoc]
        omega

/-- `_parse_int_at(p, off, 2)` and `(…, 4)` return -1 or a value below 100 / 10000,
which is what `httpdate_exact` assumes. -/
theorem parseDigits_two (a b : UInt8) :
    parseDigits 0 [a, b] = -1 ∨ (0 ≤ parseDigits 0 [a, b] ∧ parseDigits 0 [a, b] < 100) := by
  have := parseDigits_range [a, b] 0 (by decide); simpa using this

theorem parseDigits_four (a b c d : UInt8) :
    parseDigits 0 [a, b, c, d] = -1 ∨ (0 ≤ parseDigits 0 [a, b, c, d] ∧ parseDigits 0 [a, b, c, d] < 10000) := by
  have := parseDigits_range [a, b, c, d] 0 (by decide); simpa using this

end Flare.L1.CivilTime
