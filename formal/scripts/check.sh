#!/usr/bin/env bash
# Soundness gate for the Lean development under formal/.
#  1. no `sorry` / `admit` anywhere in Flare/
#  2. no user `axiom` declarations (environment facts live in
#     Flare/Core/Assumptions.lean as hypotheses, never axioms)
#  3. `native_decide` only inside Flare/Bugs/ (it trusts the compiler)
#  4. `#print axioms` for every theorem listed in Flare/Audit.lean; any
#     `sorryAx` fails the gate.
set -u
cd "$(dirname "$0")/.."
fail=0

if grep -rnwE 'sorry|admit' --include='*.lean' Flare/ ; then
  echo "FAIL: sorry/admit found"; fail=1
fi
if grep -rnE '^\s*(private\s+)?axiom\s' --include='*.lean' Flare/ ; then
  echo "FAIL: user axiom declared"; fail=1
fi
if grep -rln 'native_decide' --include='*.lean' Flare/ | grep -v -e '^Flare/Bugs/' -e '^Flare/Audit.lean' ; then
  echo "FAIL: native_decide outside Flare/Bugs/"; fail=1
fi

lake build || { echo "FAIL: lake build"; exit 1; }
out="$(lake env lean Flare/Audit.lean 2>&1)"; rc=$?
echo "$out" > .lake/axioms.txt
if [ $rc -ne 0 ]; then echo "$out"; echo "FAIL: Audit.lean did not elaborate"; fail=1; fi
if echo "$out" | grep -q 'sorryAx'; then echo "FAIL: sorryAx in audited theorem"; fail=1; fi
n_thm=$(grep -c '^#print axioms' Flare/Audit.lean)
n_rb=$(echo "$out" | grep -c 'Lean.ofReduceBool' || true)
echo "audited theorems: $n_thm (of which using native_decide: $n_rb); details in formal/.lake/axioms.txt"
[ $fail -eq 0 ] && echo "formal-check: OK"
exit $fail
