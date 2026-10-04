import Flare.Core
/-!
# Civil time: `days_from_civil` / `civil_from_days` (runtime/date_cache.mojo)

flare converts between Unix seconds and proleptic Gregorian civil dates with
Howard Hinnant's era-based identities (`civil_to_unix_seconds`,
`unix_seconds_to_civil`). Callers: HTTP-date parsing for conditional
requests (http/conditional.mojo:261), the IMF-fixdate `Date` cache, and
ISO-8601 logging (http/structured_logger.mojo:127).

Spec. A day-numbering is a function `f y m d` with `f 1970 1 1 = 0` and
`f (next date) = f date + 1` for every valid date (`DayNumbering`), where
`next` and `monthLen` follow the Gregorian leap rule (`IsLeap`). This
characterizes the Unix day number of every date.

Model. Mojo `Int` arithmetic is modeled in unbounded `Int`; Mojo `//` and
`%` are floor division / modulus, which coincide with Lean's `Int./` and
`Int.%` for the positive divisors used here. 64-bit overflow is not modeled
(all intermediates stay below `2^40` for years in `[-10^6, 10^6]`).

The era step in flare is Hinnant's C++ formula written for *truncating*
division, `(year if year >= 0 else year - 399) // 400`, but Mojo `//`
floors. The two agree for `year ≥ 0`, i.e. dates from 0000-03-01 on
(`daysFromCivil_eq_floor`, `civilFromDays_eq_floor`); before that the
result is off by one day. That is finding ENC-02 (`Flare.Bugs.ENC_02`).
The `…Floor` variants below (era = `year // 400`, `days // 146097`) are the
fixed functions; all calendar theorems are proved for them over all of
`Int`, and transferred to the flare functions on the range where they
coincide.
-/
namespace Flare.L1.CivilTime

set_option linter.unusedSimpArgs false

/-! ## Spec -/

def IsLeap (y : Int) : Prop := y % 4 = 0 ∧ (y % 100 ≠ 0 ∨ y % 400 = 0)

instance (y : Int) : Decidable (IsLeap y) := by unfold IsLeap; infer_instance

def monthLen (y m : Int) : Int :=
  if m = 2 then (if IsLeap y then 29 else 28)
  else if m = 4 ∨ m = 6 ∨ m = 9 ∨ m = 11 then 30 else 31

def Valid (y m d : Int) : Prop := 1 ≤ m ∧ m ≤ 12 ∧ 1 ≤ d ∧ d ≤ monthLen y m

instance (y m d : Int) : Decidable (Valid y m d) := by unfold Valid; infer_instance

def next (y m d : Int) : Int × Int × Int :=
  if d < monthLen y m then (y, m, d + 1)
  else if m < 12 then (y, m + 1, 1) else (y + 1, 1, 1)

/-- A day numbering anchored at the Unix epoch. -/
def DayNumbering (f : Int → Int → Int → Int) : Prop :=
  f 1970 1 1 = 0 ∧
    ∀ y m d, Valid y m d → f (next y m d).1 (next y m d).2.1 (next y m d).2.2 = f y m d + 1

/-! ## Implementation -/

/-- March-based year. mirrors flare/runtime/date_cache.mojo:91 @59bda50 -/
def shiftYear (y m : Int) : Int := y - (if m ≤ 2 then 1 else 0)

/-- March-based month in `[0, 11]`. mirrors flare/runtime/date_cache.mojo:94 @59bda50 -/
def shiftMonth (m : Int) : Int := m + (if m ≤ 2 then 9 else -3)

/-- Day-of-year where March-based month `mp` starts.
mirrors flare/runtime/date_cache.mojo:95,159 @59bda50 -/
def mStart (mp : Int) : Int := (153 * mp + 2) / 5

/-- Days of an era before year-of-era `yoe`.
mirrors flare/runtime/date_cache.mojo:96,157 @59bda50 -/
def startOf (yoe : Int) : Int := 365 * yoe + yoe / 4 - yoe / 100

/-- mirrors flare/runtime/date_cache.mojo:155 @59bda50 -/
def yoeOf (doe : Int) : Int := (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365

/-- mirrors flare/runtime/date_cache.mojo:158 @59bda50 -/
def mpOf (doy : Int) : Int := (5 * doy + 2) / 153

/-- `civil_to_unix_seconds` day part.
mirrors flare/runtime/date_cache.mojo:91-97 @59bda50 -/
def daysFromCivil (y m d : Int) : Int :=
  let year := shiftYear y m
  let era := (if 0 ≤ year then year else year - 399) / 400
  let yoe := year - era * 400
  let doy := mStart (shiftMonth m) + d - 1
  let doe := startOf yoe + doy
  era * 146097 + doe - 719468

/-- mirrors flare/runtime/date_cache.mojo:71-98 @59bda50 -/
def civilToUnix (y m d hh mm ss : Int) : Int :=
  daysFromCivil y m d * 86400 + hh * 3600 + mm * 60 + ss

/-- The day part of `unix_seconds_to_civil`.
mirrors flare/runtime/date_cache.mojo:152-163 @59bda50 -/
def civilFromDays (z : Int) : Int × Int × Int :=
  let days := z + 719468
  let era := (if 0 ≤ days then days else days - 146096) / 146097
  let doe := days - era * 146097
  let yoe := yoeOf doe
  let y := yoe + era * 400
  let doy := doe - startOf yoe
  let mp := mpOf doy
  let d := doy - mStart mp + 1
  let m := if mp < 10 then mp + 3 else mp - 9
  (if m ≤ 2 then y + 1 else y, m, d)

structure Civil where
  year : Int
  month : Int
  day : Int
  hour : Int
  minute : Int
  second : Int
  dow : Int

/-- mirrors flare/runtime/date_cache.mojo:130-174 @59bda50 -/
def unixToCivil (s : Int) : Civil :=
  let days := s / 86400
  let sod := s - days * 86400
  let dow := (days + 4) % 7
  let dow := if dow < 0 then dow + 7 else dow
  let c := civilFromDays days
  ⟨c.1, c.2.1, c.2.2, sod / 3600, (sod % 3600) / 60, sod % 60, dow⟩

/-- `daysFromCivil` with a floor era (`year // 400`): the fixed function. -/
def daysFromCivilFloor (y m d : Int) : Int :=
  let year := shiftYear y m
  let era := year / 400
  let yoe := year - era * 400
  let doy := mStart (shiftMonth m) + d - 1
  let doe := startOf yoe + doy
  era * 146097 + doe - 719468

/-- `civilFromDays` with a floor era (`days // 146097`): the fixed function. -/
def civilFromDaysFloor (z : Int) : Int × Int × Int :=
  let days := z + 719468
  let era := days / 146097
  let doe := days - era * 146097
  let yoe := yoeOf doe
  let y := yoe + era * 400
  let doy := doe - startOf yoe
  let mp := mpOf doy
  let d := doy - mStart mp + 1
  let m := if mp < 10 then mp + 3 else mp - 9
  (if m ≤ 2 then y + 1 else y, m, d)

/-! ## Where flare agrees with the floor form -/

theorem daysFromCivil_eq_floor (y m d : Int) (h : 0 ≤ shiftYear y m) :
    daysFromCivil y m d = daysFromCivilFloor y m d := by
  simp only [daysFromCivil, daysFromCivilFloor, if_pos h]

theorem civilFromDays_eq_floor (z : Int) (h : -719468 ≤ z) :
    civilFromDays z = civilFromDaysFloor z := by
  simp only [civilFromDays, civilFromDaysFloor, if_pos (show 0 ≤ z + 719468 by omega)]

/-! ## Arithmetic lemmas -/

/-- The era decomposition collapses to the closed Gregorian day count. -/
theorem daysFloor_closed (y m d : Int) :
    daysFromCivilFloor y m d =
      365 * shiftYear y m + shiftYear y m / 4 - shiftYear y m / 100 + shiftYear y m / 400 +
        mStart (shiftMonth m) + d - 1 - 719468 := by
  simp only [daysFromCivilFloor, startOf]
  generalize shiftYear y m = Y
  omega

theorem isLeap_era (e yoe : Int) : IsLeap (e * 400 + yoe) ↔ IsLeap yoe := by
  unfold IsLeap; omega

/-- `yoeOf` inverts `startOf` on one era. -/
theorem yoeOf_startOf (yoe doy : Int) (h0 : 0 ≤ yoe) (h1 : yoe ≤ 399) (h2 : 0 ≤ doy)
    (h3 : doy ≤ 365) (h4 : doy = 365 → IsLeap (yoe + 1)) : yoeOf (startOf yoe + doy) = yoe := by
  have hs : startOf yoe = 36524 * (yoe / 100) + 1461 * ((yoe % 100) / 4) + 365 * (yoe % 4) := by
    unfold startOf; omega
  have hy : yoe = 100 * (yoe / 100) + 4 * ((yoe % 100) / 4) + yoe % 4 := by omega
  have h4' : doy = 365 → yoe % 4 = 3 ∧ ((yoe % 100) / 4 ≠ 24 ∨ yoe / 100 = 3) := by
    intro e; have := h4 e; unfold IsLeap at this; omega
  have ha : 0 ≤ yoe / 100 ∧ yoe / 100 ≤ 3 := by omega
  have hb : 0 ≤ (yoe % 100) / 4 ∧ (yoe % 100) / 4 ≤ 24 := by omega
  have hc : 0 ≤ yoe % 4 ∧ yoe % 4 ≤ 3 := by omega
  rw [hs]; conv => rhs; rw [hy]
  generalize yoe / 100 = a at *
  generalize (yoe % 100) / 4 = b at *
  generalize yoe % 4 = c at *
  unfold yoeOf
  generalize hd : 36524 * a + 1461 * b + 365 * c + doy = doe
  by_cases hs : doe = 146096
  · subst hs
    have : a = 3 ∧ b = 24 ∧ c = 3 := by omega
    obtain ⟨rfl, rfl, rfl⟩ := this; decide
  · have e1 : doe / 146096 = 0 := by omega
    have e2 : doe / 36524 = a := by omega
    have e3 : doe / 1460 = 25 * a + b ∨ doe / 1460 = 25 * a + b + 1 := by omega
    rw [e1, e2]
    rcases e3 with e3 | e3 <;> rw [e3] <;> omega

/-- `yoeOf` splits any day-of-era into a year-of-era and a day-of-year. -/
theorem yoeOf_bounds (doe : Int) (h0 : 0 ≤ doe) (h1 : doe ≤ 146096) :
    0 ≤ yoeOf doe ∧ yoeOf doe ≤ 399 ∧ 0 ≤ doe - startOf (yoeOf doe) ∧
      doe - startOf (yoeOf doe) ≤ 365 ∧
      (doe - startOf (yoeOf doe) = 365 → IsLeap (yoeOf doe + 1)) := by
  unfold startOf IsLeap
  generalize hy : yoeOf doe = yoe
  unfold yoeOf at hy
  by_cases hs : doe = 146096
  · subst hs; subst hy; decide
  · have e1 : doe / 146096 = 0 := by omega
    have hA : 0 ≤ doe / 36524 ∧ doe / 36524 ≤ 3 := by omega
    generalize hAe : doe / 36524 = A at *
    have hB : 0 ≤ (doe - 36524 * A) / 1461 ∧ (doe - 36524 * A) / 1461 ≤ 24 := by omega
    generalize hBe : (doe - 36524 * A) / 1461 = B at *
    have e3 : doe / 1460 = 25 * A + B ∨ doe / 1460 = 25 * A + B + 1 := by omega
    rw [e1] at hy
    rcases e3 with e3 | e3 <;> rw [e3] at hy
    all_goals
      have hy4 : yoe / 4 = 25 * A + B := by omega
      have hy100 : yoe / 100 = A := by omega
      have hyr : 100 * A + 4 * B ≤ yoe ∧ yoe ≤ 100 * A + 4 * B + 3 := by omega
      have hy1 : (yoe + 1) % 4 = 0 ↔ yoe = 100 * A + 4 * B + 3 := by omega
      have hy2 : (yoe + 1) % 100 = 0 → B = 24 := by omega
      rw [hy4, hy100]
      omega

theorem mpOf_bounds (doy : Int) (h0 : 0 ≤ doy) (h1 : doy ≤ 365) :
    0 ≤ mpOf doy ∧ mpOf doy ≤ 11 ∧ mStart (mpOf doy) ≤ doy ∧ doy < mStart (mpOf doy + 1) := by
  unfold mpOf mStart; omega

theorem mpOf_mStart (mp k : Int) (_h0 : 0 ≤ mp) (_h1 : mp ≤ 11) (h2 : 0 ≤ k)
    (h3 : k < mStart (mp + 1) - mStart mp) : mpOf (mStart mp + k) = mp := by
  unfold mpOf mStart at *; omega

/-! ## The floor form is a day numbering -/

theorem daysFloor_epoch : daysFromCivilFloor 1970 1 1 = 0 := by decide

theorem daysFloor_next (y m d : Int) (h : Valid y m d) :
    daysFromCivilFloor (next y m d).1 (next y m d).2.1 (next y m d).2.2 =
      daysFromCivilFloor y m d + 1 := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  simp only [next]
  by_cases hd : d < monthLen y m
  · simp only [if_pos hd, daysFloor_closed]; omega
  · rw [if_neg hd]
    have hd' : d = monthLen y m := by omega
    by_cases hm : m < 12
    · rw [if_pos hm]
      simp only [daysFloor_closed]
      have : m = 1 ∨ m = 2 ∨ m = 3 ∨ m = 4 ∨ m = 5 ∨ m = 6 ∨ m = 7 ∨ m = 8 ∨ m = 9 ∨
          m = 10 ∨ m = 11 := by omega
      rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
        simp (config := { decide := true }) only [monthLen, shiftYear, shiftMonth, mStart,
          if_true, if_false] at hd' ⊢ <;>
        first
        | omega
        | (split at hd' <;> rename_i hl <;> unfold IsLeap at hl <;> omega)
    · rw [if_neg hm]
      have : m = 12 := by omega
      subst this
      simp only [daysFloor_closed]
      simp (config := { decide := true }) only [monthLen, shiftYear, shiftMonth, mStart,
        if_true, if_false] at hd' ⊢
      omega

theorem daysFloor_spec : DayNumbering daysFromCivilFloor :=
  ⟨daysFloor_epoch, daysFloor_next⟩

/-! ## The floor forms are mutually inverse -/

theorem shift_inv (y m : Int) (h1 : 1 ≤ m) (h2 : m ≤ 12) :
    0 ≤ shiftMonth m ∧ shiftMonth m ≤ 11 ∧
      (if shiftMonth m < 10 then shiftMonth m + 3 else shiftMonth m - 9) = m ∧
      (if (if shiftMonth m < 10 then shiftMonth m + 3 else shiftMonth m - 9) ≤ 2
        then shiftYear y m + 1 else shiftYear y m) = y := by
  unfold shiftMonth shiftYear
  by_cases h : m ≤ 2
  · simp only [if_pos h]
    rw [if_neg (by omega), if_pos (by omega)]; omega
  · simp only [if_neg h]
    rw [if_pos (by omega), if_neg (by omega)]; omega

theorem valid_month (y m d : Int) (h : Valid y m d) :
    d - 1 < mStart (shiftMonth m + 1) - mStart (shiftMonth m) ∧
      0 ≤ mStart (shiftMonth m) ∧ mStart (shiftMonth m) + d - 1 ≤ 365 := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  have : m = 1 ∨ m = 2 ∨ m = 3 ∨ m = 4 ∨ m = 5 ∨ m = 6 ∨ m = 7 ∨ m = 8 ∨ m = 9 ∨
      m = 10 ∨ m = 11 ∨ m = 12 := by omega
  rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp (config := { decide := true }) only [monthLen, shiftMonth, mStart, if_true,
      if_false, true_and] at h4 ⊢ <;>
    first
    | omega
    | (split at h4 <;> omega)

theorem civilFloor_daysFloor (y m d : Int) (h : Valid y m d) :
    civilFromDaysFloor (daysFromCivilFloor y m d) = (y, m, d) := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  obtain ⟨hs0, hs1, hsm, hsy⟩ := shift_inv y m h1 h2
  -- month length in March-based terms
  have hlen1 := valid_month y m d ⟨h1, h2, h3, h4⟩
  have hlen2 : shiftMonth m = 11 → d = 29 → IsLeap y := by
    intro h11 h29
    have : m = 2 := by unfold shiftMonth at h11; split at h11 <;> omega
    subst this
    unfold monthLen at h4
    rw [if_pos rfl] at h4
    by_cases hl : IsLeap y
    · exact hl
    · rw [if_neg hl] at h4; omega
  have hlen : d - 1 < mStart (shiftMonth m + 1) - mStart (shiftMonth m) ∧
      (shiftMonth m = 11 → d = 29 → IsLeap y) := ⟨hlen1.1, hlen2⟩
  have hlen' : 0 ≤ mStart (shiftMonth m) ∧ mStart (shiftMonth m) + d - 1 ≤ 365 := hlen1.2
  have hmp := mpOf_mStart (shiftMonth m) (d - 1) hs0 hs1 (by omega) hlen.1
  generalize hY : shiftYear y m = Y at *
  have hyoe := yoeOf_startOf (Y - Y / 400 * 400) (mStart (shiftMonth m) + d - 1)
    (by omega) (by omega) (by omega) (by omega) (by
      intro e
      have h11 : shiftMonth m = 11 := by
        have := mpOf_bounds (mStart (shiftMonth m) + d - 1) (by omega) (by omega)
        unfold mStart at *; omega
      have h29 : d = 29 := by rw [h11] at e; unfold mStart at e; omega
      have hl := hlen.2 h11 h29
      have hyY : y = Y + 1 := by
        rw [← hsy]; unfold shiftMonth at h11 ⊢; split <;> simp_all <;> omega
      have := (isLeap_era (Y / 400) (Y - Y / 400 * 400 + 1)).1
      rw [hyY] at hl
      exact this (by rw [show Y / 400 * 400 + (Y - Y / 400 * 400 + 1) = Y + 1 by omega]; exact hl))
  have hst : 0 ≤ startOf (Y - Y / 400 * 400) ∧ startOf (Y - Y / 400 * 400) ≤ 145731 := by
    unfold startOf; omega
  unfold civilFromDaysFloor daysFromCivilFloor
  simp only [hY]
  have hera : (Y / 400 * 146097 + (startOf (Y - Y / 400 * 400) + (mStart (shiftMonth m) + d - 1))
      - 719468 + 719468) / 146097 = Y / 400 := by omega
  rw [hera]
  have hdoe : Y / 400 * 146097 + (startOf (Y - Y / 400 * 400) + (mStart (shiftMonth m) + d - 1))
      - 719468 + 719468 - Y / 400 * 146097 =
      startOf (Y - Y / 400 * 400) + (mStart (shiftMonth m) + d - 1) := by omega
  rw [hdoe, hyoe]
  have hdoy : startOf (Y - Y / 400 * 400) + (mStart (shiftMonth m) + d - 1) -
      startOf (Y - Y / 400 * 400) = mStart (shiftMonth m) + (d - 1) := by omega
  rw [hdoy, hmp]
  have hyy : Y - Y / 400 * 400 + Y / 400 * 400 = Y := by omega
  rw [hsm] at hsy
  rw [hyy, hsm, hsy]
  simp only [Prod.mk.injEq, true_and]
  omega

theorem civilFloor_valid (z : Int) :
    Valid (civilFromDaysFloor z).1 (civilFromDaysFloor z).2.1 (civilFromDaysFloor z).2.2 := by
  unfold civilFromDaysFloor
  simp only
  generalize hE : (z + 719468) / 146097 = era
  generalize hD : z + 719468 - era * 146097 = doe
  have hd0 : 0 ≤ doe ∧ doe ≤ 146096 := by omega
  obtain ⟨hy0, hy1, hdy0, hdy1, hleap⟩ := yoeOf_bounds doe hd0.1 hd0.2
  generalize hyo : yoeOf doe = yoe at *
  generalize hdy : doe - startOf yoe = doy at *
  obtain ⟨hm0, hm1, hm2, hm3⟩ := mpOf_bounds doy hdy0 hdy1
  generalize hmp : mpOf doy = mp at *
  unfold mStart at hm2 hm3
  unfold Valid monthLen mStart
  by_cases hlt : mp < 10
  · simp only [if_pos hlt]
    rw [if_neg (show ¬ mp + 3 ≤ 2 by omega), if_neg (show ¬ mp + 3 = 2 by omega)]
    have : mp = 0 ∨ mp = 1 ∨ mp = 2 ∨ mp = 3 ∨ mp = 4 ∨ mp = 5 ∨ mp = 6 ∨ mp = 7 ∨ mp = 8 ∨
        mp = 9 := by omega
    rcases this with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp (config := { decide := true }) only [if_true, if_false, true_and] at hm2 hm3 ⊢ <;> omega
  · simp only [if_neg hlt]
    rw [if_pos (show mp - 9 ≤ 2 by omega)]
    have : mp = 10 ∨ mp = 11 := by omega
    rcases this with rfl | rfl
    · simp (config := { decide := true }) only [if_true, if_false, true_and] at hm2 hm3 ⊢; omega
    · simp (config := { decide := true }) only [if_true, if_false, true_and] at hm2 hm3 ⊢
      have hl : doy = 365 → IsLeap (yoe + era * 400 + 1) := by
        intro e
        rw [show yoe + era * 400 + 1 = era * 400 + (yoe + 1) by omega, isLeap_era]
        exact hleap e
      by_cases hL : IsLeap (yoe + era * 400 + 1)
      · rw [if_pos hL]; omega
      · rw [if_neg hL]
        have : doy ≠ 365 := fun e => hL (hl e)
        omega

theorem daysFloor_civilFloor (z : Int) :
    daysFromCivilFloor (civilFromDaysFloor z).1 (civilFromDaysFloor z).2.1
      (civilFromDaysFloor z).2.2 = z := by
  unfold civilFromDaysFloor
  simp only
  generalize hE : (z + 719468) / 146097 = era
  generalize hD : z + 719468 - era * 146097 = doe
  have hd0 : 0 ≤ doe ∧ doe ≤ 146096 := by omega
  obtain ⟨hy0, hy1, hdy0, hdy1, -⟩ := yoeOf_bounds doe hd0.1 hd0.2
  generalize hyo : yoeOf doe = yoe at *
  generalize hdy : doe - startOf yoe = doy at *
  obtain ⟨hm0, hm1, hm2, hm3⟩ := mpOf_bounds doy hdy0 hdy1
  generalize hmp : mpOf doy = mp at *
  have hsm : shiftMonth (if mp < 10 then mp + 3 else mp - 9) = mp := by
    unfold shiftMonth
    by_cases h : mp < 10
    · simp only [if_pos h]; rw [if_neg (by omega)]; omega
    · simp only [if_neg h]; rw [if_pos (by omega)]; omega
  have hsy : shiftYear (if (if mp < 10 then mp + 3 else mp - 9) ≤ 2 then yoe + era * 400 + 1
      else yoe + era * 400) (if mp < 10 then mp + 3 else mp - 9) = yoe + era * 400 := by
    unfold shiftYear
    by_cases h : mp < 10
    · simp only [if_pos h]; rw [if_neg (by omega), if_neg (by omega)]; omega
    · simp only [if_neg h]; rw [if_pos (by omega), if_pos (by omega)]; omega
  unfold daysFromCivilFloor
  simp only
  rw [hsy, hsm, show (yoe + era * 400) / 400 = era by omega,
    show yoe + era * 400 - era * 400 = yoe by omega]
  omega

/-! ## Transfer to the flare functions (dates from 0000-03-01 on) -/

theorem shiftYear_nonneg_of_days (y m d : Int) (h : Valid y m d)
    (hz : -719468 ≤ daysFromCivilFloor y m d) : 0 ≤ shiftYear y m := by
  have := valid_month y m d h
  have := h.2.2.1
  rw [daysFloor_closed] at hz
  omega

theorem next_valid (y m d : Int) (h : Valid y m d) :
    Valid (next y m d).1 (next y m d).2.1 (next y m d).2.2 := by
  obtain ⟨h1, h2, h3, h4⟩ := h
  unfold next
  by_cases hd : d < monthLen y m
  · rw [if_pos hd]; dsimp only; exact ⟨h1, h2, by omega, by omega⟩
  · rw [if_neg hd]
    by_cases hm : m < 12
    · rw [if_pos hm]; dsimp only
      refine ⟨by omega, by omega, by omega, ?_⟩
      unfold monthLen; split <;> (try split) <;> omega
    · rw [if_neg hm]; dsimp only
      refine ⟨by omega, by omega, by omega, ?_⟩
      unfold monthLen; split <;> (try split) <;> omega

theorem daysFromCivil_next (y m d : Int) (h : Valid y m d) (hy : 0 ≤ shiftYear y m) :
    daysFromCivil (next y m d).1 (next y m d).2.1 (next y m d).2.2 = daysFromCivil y m d + 1 := by
  have hn := daysFloor_next y m d h
  have hz : -719468 ≤ daysFromCivilFloor y m d := by
    have := valid_month y m d h; have := h.2.2.1; rw [daysFloor_closed]; omega
  rw [daysFromCivil_eq_floor y m d hy, daysFromCivil_eq_floor _ _ _
    (shiftYear_nonneg_of_days _ _ _ (next_valid y m d h) (by rw [hn]; omega)), hn]

theorem civilFromDays_daysFromCivil (y m d : Int) (h : Valid y m d) (hy : 0 ≤ shiftYear y m) :
    civilFromDays (daysFromCivil y m d) = (y, m, d) := by
  have := valid_month y m d h
  have := h.2.2.1
  have hz : -719468 ≤ daysFromCivilFloor y m d := by rw [daysFloor_closed]; omega
  rw [daysFromCivil_eq_floor y m d hy, civilFromDays_eq_floor _ hz, civilFloor_daysFloor y m d h]

theorem civilFromDays_valid (z : Int) (hz : -719468 ≤ z) :
    Valid (civilFromDays z).1 (civilFromDays z).2.1 (civilFromDays z).2.2 := by
  rw [civilFromDays_eq_floor z hz]; exact civilFloor_valid z

theorem daysFromCivil_civilFromDays (z : Int) (hz : -719468 ≤ z) :
    daysFromCivil (civilFromDays z).1 (civilFromDays z).2.1 (civilFromDays z).2.2 = z := by
  rw [civilFromDays_eq_floor z hz]
  have h1 := daysFloor_civilFloor z
  rw [daysFromCivil_eq_floor _ _ _
    (shiftYear_nonneg_of_days _ _ _ (civilFloor_valid z) (by rw [h1]; exact hz)), h1]

/-! ## Seconds -/

theorem unixToCivil_fields (s : Int) :
    0 ≤ (unixToCivil s).hour ∧ (unixToCivil s).hour < 24 ∧
    0 ≤ (unixToCivil s).minute ∧ (unixToCivil s).minute < 60 ∧
    0 ≤ (unixToCivil s).second ∧ (unixToCivil s).second < 60 ∧
    (unixToCivil s).dow = (s / 86400 + 4) % 7 := by
  simp only [unixToCivil]
  refine ⟨by omega, by omega, by omega, by omega, by omega, by omega, ?_⟩
  rw [if_neg (by omega)]

theorem unixToCivil_valid (s : Int) (hs : -719468 * 86400 ≤ s) :
    Valid (unixToCivil s).year (unixToCivil s).month (unixToCivil s).day :=
  civilFromDays_valid (s / 86400) (by omega)

theorem civilToUnix_unixToCivil (s : Int) (hs : -719468 * 86400 ≤ s) :
    let c := unixToCivil s
    civilToUnix c.year c.month c.day c.hour c.minute c.second = s := by
  simp only [unixToCivil, civilToUnix]
  rw [daysFromCivil_civilFromDays _ (by omega)]
  omega

theorem unixToCivil_civilToUnix (y m d hh mm ss : Int) (h : Valid y m d)
    (hy : 0 ≤ shiftYear y m) (hh0 : 0 ≤ hh) (hh1 : hh < 24) (hm0 : 0 ≤ mm) (hm1 : mm < 60)
    (hs0 : 0 ≤ ss) (hs1 : ss < 60) :
    let c := unixToCivil (civilToUnix y m d hh mm ss)
    c.year = y ∧ c.month = m ∧ c.day = d ∧ c.hour = hh ∧ c.minute = mm ∧ c.second = ss := by
  simp only [unixToCivil, civilToUnix]
  have e : (daysFromCivil y m d * 86400 + hh * 3600 + mm * 60 + ss) / 86400 = daysFromCivil y m d := by
    omega
  rw [e, civilFromDays_daysFromCivil y m d h hy]
  refine ⟨rfl, rfl, rfl, by omega, by omega, by omega⟩

end Flare.L1.CivilTime
