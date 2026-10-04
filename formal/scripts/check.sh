#!/usr/bin/env bash
# Soundness gate for the Lean development under formal/.
#  1. no `sorry` / `admit` anywhere in Flare/
#  2. no user `axiom` declarations (environment facts live in
#     Flare/Core/Assumptions.lean as hypotheses, never axioms)
#  3. `native_decide` only inside Flare/Bugs/ (it trusts the compiler)
#  4. `#print axioms` for every theorem listed in Flare/Audit.lean and
#     Flare/Audit/*.lean; any axiom beyond the allowed set fails the gate.
#  5. REPORT.md is up to date with report/ and pairs every finding with a
#     Bugs file and a repro (scripts/stitch_report.py --check).
set -u
cd "$(dirname "$0")/.."
fail=0

# scripts/code_grep.py blanks out comments and strings first, so doc text may
# mention "admit" or "axiom".
if python3 scripts/code_grep.py '\b(sorry|admit)\b'; then
  echo "FAIL: sorry/admit found"; fail=1
fi
if python3 scripts/code_grep.py '^\s*((private|protected|noncomputable|unsafe)\s+)*axiom\s'; then
  echo "FAIL: user axiom declared"; fail=1
fi
if python3 scripts/code_grep.py '\bnative_decide\b' Flare/Bugs/ Flare/Audit; then
  echo "FAIL: native_decide outside Flare/Bugs/"; fail=1
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
# Allowed: the three standard axioms, plus native_decide's trust axiom
# (Lean.ofReduceBool, or the per-theorem `<thm>._native.native_decide.ax_*`
# that Lean 4.33 emits; native_decide itself is confined to Bugs/ above).
stray=$(echo "$out" | tr '\n' ' ' | grep -o 'depends on axioms: \[[^]]*\]' \
  | sed 's/.*\[//; s/\]//' | tr ',' '\n' | tr -d ' ' | sort -u \
  | grep -v -x -e propext -e Quot.sound -e Classical.choice -e Lean.ofReduceBool \
  | grep -v -e '\.native_decide\.ax_' || true)
if [ -n "$stray" ]; then echo "FAIL: unexpected axioms: $stray"; fail=1; fi
n_thm=$(cat Flare/Audit.lean Flare/Audit/*.lean 2>/dev/null | grep -c '^#print axioms')
n_rb=$(echo "$out" | tr '\n' ' ' | grep -o 'depends on axioms: \[[^]]*\]' \
  | grep -c -e 'Lean.ofReduceBool' -e '\.native_decide\.ax_' || true)
echo "audited theorems: $n_thm (of which using native_decide: $n_rb); details in formal/.lake/axioms.txt"
python3 scripts/stitch_report.py --check || { echo "FAIL: REPORT.md"; fail=1; }
[ $fail -eq 0 ] && echo "formal-check: OK"
exit $fail
