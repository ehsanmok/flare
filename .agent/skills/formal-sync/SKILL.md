---
name: formal-sync
description: Bring stale Lean impl models in formal/ back in line with changed Mojo code in flare/, re-prove, triage broken proofs as stale-model vs real-bug, and refresh the fidelity anchors. Use when anchors.py reports stale anchors, the formal-drift pre-commit hook blocks a commit, or the stop hook asks for a formal sync.
---

# formal-sync

Goal: every stale **pinned** anchor touched by the current change is in sync again. That means the impl model mirrors the Mojo code, `lake build` passes, the difftest agrees, and the anchor is refreshed. Tracked anchors are optional; do them when they are cheap.

Read "Rules for agents" in `formal/README.md` first. They apply throughout.

## 1. Find the work

```bash
python3 formal/scripts/anchors.py check --base HEAD --json         # anchors this change made stale
python3 formal/scripts/anchors.py check --staged --fail-on pinned  # what the hook will block on
```

Each row gives `lean` (file:line of the anchor), `mojo`, `symbols` and `at` (the commit where the anchor was last confirmed). Work pinned rows first, grouped by Lean file.

## 2. For each stale anchor

1. **See what changed in the Mojo code.**
   `git diff <at> -- <mojo file>`, narrowed to the anchored symbols. For the full current text, read the symbol in the working tree.
2. **Read the model** at the anchor line: the `def` right below the doc comment, plus any helpers it calls in the same file.
3. **Classify the change:**
   - *No semantic change* (renames of locals, refactors that keep behaviour, logging): the model is still right, so skip to step 5.
   - *Behaviour change*: update the impl model so it mirrors the new control flow. Keep the existing conventions: fixed-width arithmetic (`UInt64`, `Int64` wrap for Mojo `Int`), the same limits, and the same order of checks. Never edit `spec` definitions or theorem statements (the spec guard fails if you do).
4. **Re-prove.** Run `cd formal && pixi run -e formal lake build` and fix the proofs that broke. If a proof cannot be repaired because the theorem is now false:
   - Look for a concrete counterexample: an `example : ¬ spec (impl input) := by decide` on a small input, or run the difftest (step 6) and read its minimized input.
   - If the new Mojo behaviour violates the spec, it's a **real bug**. Stop editing proofs. Follow the Issues convention in `formal/README.md` (counterexample in the report to the user, fix with a regression test in `tests/`) and tell the user. The code change is what's wrong, not the theorem.
   - If you believe the spec itself should change, stop and ask the user. Never change it yourself.
5. **Refresh the anchor** once the model mirrors the code and the build is green:
   `python3 formal/scripts/anchors.py refresh formal/<file>.lean:<line>`
   A symbol that was renamed or moved shows up as MISSING. In that case write a new anchor with `anchors.py make 'flare/x.mojo#New.name'` and replace the old one by hand.

## 3. Verify

```bash
python3 formal/difftest/run.py --affected --base HEAD                 # Lean vs Mojo on generated inputs
SPEC_GUARD_ARGS= bash formal/scripts/check.sh --fast                  # sorry/axiom gates, report, spec guard
python3 formal/scripts/anchors.py check --base HEAD --fail-on pinned  # nothing pinned left stale
```

If a difftest mismatch shows up, use the `formal-difftest` skill to triage it.

## 4. Report

Tell the user which models you updated, which proofs changed (and why), any real bugs you found (with the counterexample), and any tracked anchors you left stale.
