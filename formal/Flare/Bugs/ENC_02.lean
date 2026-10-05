import Flare.L1_Encoding.CivilTime
/-!
# ENC-02: civil-time conversion is off by one day before 0000-03-01

Status: resolved. flare/runtime/date_cache.mojo now uses the floor era
(`year // 400`, `days // 146097`); `Flare.L1.CivilTime.daysFromCivil` /
`civilFromDays` mirror the shipped code and the counterexamples below are
about the pre-fix `daysFromCivilOld` / `civilFromDaysOld`.

Pre-fix code, flare/runtime/date_cache.mojo:92 and :153 @59bda50:

    var era = (year if year >= 0 else year - 399) // 400
    var era = (days if days >= 0 else days - 146096) // 146097

These are Howard Hinnant's era formulas written for C++ *truncating*
division. Mojo `//` floors, so for negative arguments the `- 399` /
`- 146096` adjustment is applied on top of a floor and the era comes out
one too small (except when `year ≡ 399 (mod 400)` /
`days ≡ 146096 (mod 146097)`). The day-of-era then lands in the next era's
range and the result is one day early.

Spec: the comment above `civil_to_unix_seconds` states the arithmetic "is
exact across the proleptic Gregorian calendar", and `unix_seconds_to_civil`
documents "negative is fine". In the model that is `DayNumbering`: anchored
at 1970-01-01 = 0 and increasing by exactly one per calendar day.

What goes wrong:
* `counterexample`: 28 Feb of year -1 (not a leap year) is followed by
  1 Mar of year -1, but `days_from_civil` returns -719836 and -719834
  (two days apart). Every date whose March-based year is negative and not
  `≡ 399 (mod 400)` (i.e. outside the years -1, -401, ...) is one day early.
* `inverse_counterexample`: `unix_seconds_to_civil` maps the correct day
  number of -1-03-01 to -1-03-02; it is wrong for every day before
  0000-03-01 except the last day of each 400-year era (29 Feb of a year
  divisible by 400).

Reach: in-tree inputs are HTTP-dates with a 4-digit year (`year ≥ 0`, for
which the forward function was exact: `daysFromCivilOld_eq`) and
realtime-clock seconds (after 1970). The defect is in the public helpers'
documented domain only, so severity is Low.

Fix: `era = year // 400` and `era = days // 146097` (the shipped
`daysFromCivil`, `civilFromDays`); `fixed_spec`, `fixed_left_inverse`,
`fixed_right_inverse` prove the shipped pair is the Gregorian day
numbering and a bijection on all of `Int`.
-/
namespace Flare.Bugs.ENC_02
open Flare.L1.CivilTime

theorem feb28_valid : Valid (-1) 2 28 := by decide

theorem next_feb28 : next (-1) 2 28 = (-1, 3, 1) := by decide

theorem observed :
    daysFromCivilOld (-1) 2 28 = -719836 ∧ daysFromCivilOld (-1) 3 1 = -719834 := by
  decide

theorem counterexample : ¬ DayNumbering daysFromCivilOld := by
  intro ⟨_, h⟩
  have := h (-1) 2 28 feb28_valid
  rw [next_feb28] at this
  revert this; decide

theorem inverse_counterexample :
    civilFromDaysOld (daysFromCivil (-1) 3 1) = (-1, 3, 2) := by
  decide

theorem fixed_spec : DayNumbering daysFromCivil := daysFloor_spec

theorem fixed_left_inverse (y m d : Int) (h : Valid y m d) :
    civilFromDays (daysFromCivil y m d) = (y, m, d) :=
  civilFloor_daysFloor y m d h

theorem fixed_right_inverse (z : Int) :
    daysFromCivil (civilFromDays z).1 (civilFromDays z).2.1 (civilFromDays z).2.2 = z :=
  daysFloor_civilFloor z

end Flare.Bugs.ENC_02
