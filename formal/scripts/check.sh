#!/usr/bin/env bash
# Soundness gate for the Lean development under formal/.
#  1. no `sorry` / `admit` anywhere in Flare/
#  2. no user `axiom` declarations (environment facts live in
#     Flare/Core/Assumptions.lean as hypotheses, never axioms)
#  3. no `native_decide` (it trusts the compiler)
#  4. `#print axioms` for every theorem listed in Flare/Audit.lean and
#     Flare/Audit/*.lean; any axiom beyond the allowed set fails the gate.
#  5. REPORT.md is up to date with report/ (scripts/stitch_report.py --check).
#  6. no theorem statement or spec definition changed without a re-lock
#     (scripts/spec_guard.py --check against spec.lock).
#
# `check.sh --fast` runs gates 1-3, 5 and 6 only (no lake build, no axiom
# audit); the pre-commit hook uses it after an incremental `lake build`.
set -u
cd "$(dirname "$0")/.."
fail=0
fast=0
[ "${1:-}" = "--fast" ] && fast=1

# scripts/code_grep.py blanks out comments and strings first, so doc text may
# mention "admit" or "axiom".
if python3 scripts/code_grep.py '\b(sorry|admit)\b'; then
  echo "FAIL: sorry/admit found"; fail=1
fi
if python3 scripts/code_grep.py '^\s*((private|protected|noncomputable|unsafe)\s+)*axiom\s'; then
  echo "FAIL: user axiom declared"; fail=1
fi
if python3 scripts/code_grep.py '\bnative_decide\b'; then
  echo "FAIL: native_decide found"; fail=1
fi

if [ $fast -eq 1 ]; then
  python3 scripts/stitch_report.py --check || { echo "FAIL: REPORT.md"; fail=1; }
  python3 scripts/spec_guard.py --check ${SPEC_GUARD_ARGS:-} || { echo "FAIL: spec.lock"; fail=1; }
  [ $fail -eq 0 ] && echo "formal-check --fast: OK"
  exit $fail
fi

lake build || { echo "FAIL: lake build"; exit 1; }
out=""; rc=0
for a in Flare/Audit.lean Flare/Audit/*.lean; do
  [ -e "$a" ] || continue
  o="$(lake env lean "$a" 2>&1)" || { rc=1; echo "$o"; echo "FAIL: $a did not elaborate"; }
  out="$out
$o"
done
echo "$out" > .lake/axioms.txt
if [ $rc -ne 0 ]; then fail=1; fi
if echo "$out" | grep -q 'sorryAx'; then echo "FAIL: sorryAx in audited theorem"; fail=1; fi
# Allowed: the three standard axioms.
stray=$(echo "$out" | tr '\n' ' ' | grep -o 'depends on axioms: \[[^]]*\]' \
  | sed 's/.*\[//; s/\]//' | tr ',' '\n' | tr -d ' ' | sort -u \
  | grep -v -x -e propext -e Quot.sound -e Classical.choice || true)
if [ -n "$stray" ]; then echo "FAIL: unexpected axioms: $stray"; fail=1; fi
n_thm=$(cat Flare/Audit.lean Flare/Audit/*.lean 2>/dev/null | grep -c '^#print axioms')
echo "audited theorems: $n_thm; details in formal/.lake/axioms.txt"
python3 scripts/stitch_report.py --check || { echo "FAIL: REPORT.md"; fail=1; }
python3 scripts/spec_guard.py --check || { echo "FAIL: spec.lock"; fail=1; }
[ $fail -eq 0 ] && echo "formal-check: OK"
exit $fail
