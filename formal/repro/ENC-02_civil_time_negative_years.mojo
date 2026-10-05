# PLATFORM: any
# RESOLVED: ENC-02 fixed on fix/formal-findings
"""ENC-02: civil_to_unix_seconds / unix_seconds_to_civil are one day off
before 0000-03-01.

Lean: Flare.Bugs.ENC_02.counterexample (days_from_civil(-1-03-01) minus
days_from_civil(-1-02-28) is 2, not 1) and
Flare.Bugs.ENC_02.inverse_counterexample (the correct day number of
-1-03-01 decodes as -1-03-02); fixed functions proved correct in
Flare.Bugs.ENC_02.fixed_spec / fixed_left_inverse / fixed_right_inverse.
flare/runtime/date_cache.mojo:92 and :153 @59bda50.

Expected (date_cache.mojo:69-70: "exact across the proleptic Gregorian
calendar"; :138 "negative is fine"): consecutive days differ by 86400 s and
unix_seconds_to_civil inverts civil_to_unix_seconds.
Before the fix: Hinnant's era formula `(year if year >= 0 else year - 399) // 400`
assumes truncating division; Mojo `//` floors, so the era is one too small
for negative March-based years and the result is one day early.

Minimal fix:
    var era = year // 400          (line 92)
    var era = days // 146097       (line 153)
"""

from flare.runtime.date_cache import (
    civil_to_unix_seconds,
    unix_seconds_to_civil,
)


def main() raises:
    var feb28 = civil_to_unix_seconds(-1, 2, 28, 0, 0, 0)
    var mar1 = civil_to_unix_seconds(-1, 3, 1, 0, 0, 0)
    var gap = mar1 - feb28
    # -1-03-01 is 719834 days before the epoch (0000-03-01 is 719468 days
    # before it, and year -1 from March has 365 days + 1 day for 0000-02-29).
    var back = unix_seconds_to_civil(-719834 * 86400)
    var bad = (
        gap != 86400 or back.year != -1 or back.month != 3 or back.day != 1
    )
    if bad:
        print(
            "BUG REPRODUCED: civil_to_unix_seconds(-1-02-28 -> -1-03-01) gap =",
            gap,
            "s (want 86400); unix_seconds_to_civil(-719834 days) =",
            back.year,
            back.month,
            back.day,
            "(want -1 3 1)",
        )
        raise Error("ENC-02")
    print("OK: consecutive days before year 0 differ by 86400 s and round-trip")
