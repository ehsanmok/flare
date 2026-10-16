#!/usr/bin/env bash
# formal-precommit: the drift gate behind the `formal-drift` pre-commit hook.
#
#  1. A staged change to a Mojo symbol mirrored by a pinned model, without a
#     refreshed anchor, blocks the commit (scripts/anchors.py check --staged).
#  2. If anything under formal/ is staged: incremental `lake build`, the fast
#     soundness gates and the spec guard against the index (check.sh --fast).
#  3. Differential tests for the targets the staged change touches
#     (difftest/run.py --quick --affected --staged).
#
# pre-commit stashes unstaged changes first, so the working tree is the index.
# Escape hatch: FORMAL_SKIP=1 git commit ...  (say why in the commit message).
# Run under the formal env: pixi run -e formal formal-precommit
set -u
cd "$(git rev-parse --show-toplevel)"

if [ "${FORMAL_SKIP:-0}" = "1" ]; then
  echo "formal-precommit: skipped (FORMAL_SKIP=1)"
  exit 0
fi

fail=0
echo "== formal: anchors"
python3 formal/scripts/anchors.py check --staged --fail-on pinned || fail=1

if git diff --cached --name-only | grep -q '^formal/'; then
  echo "== formal: lake build"
  (cd formal && lake build 2>&1 | tail -3; exit "${PIPESTATUS[0]}") || { echo "FAIL: lake build"; fail=1; }
  echo "== formal: fast gates + spec guard"
  SPEC_GUARD_ARGS=--staged bash formal/scripts/check.sh --fast || fail=1
fi

echo "== formal: difftest (affected targets)"
python3 formal/difftest/run.py --quick --affected --staged || fail=1

if [ $fail -ne 0 ]; then
  cat >&2 <<'EOF'

formal-precommit failed. In Cursor, run /formal-verify to let the agent sync
the models; or fix by hand (formal/README.md, "The factory loop").
Bypass only with a reason: FORMAL_SKIP=1 git commit ...
EOF
fi
exit $fail
