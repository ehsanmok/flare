# /formal-verify

Run the Lean verification factory on the current change and fix what it finds.

1. Run the same checks the `formal-drift` pre-commit hook runs, against the working tree:
   ```bash
   python3 formal/scripts/anchors.py check --base HEAD
   python3 formal/difftest/run.py --quick --affected --base HEAD
   ```
   If anything under `formal/` changed, also run `cd formal && pixi run -e formal lake build` and `SPEC_GUARD_ARGS= bash formal/scripts/check.sh --fast`.
2. Dispatch:
   - Stale **pinned** anchors, or a broken build after a Mojo change: follow the `formal-sync` skill.
   - The change is large and touches protocol, parser or resource-accounting logic with no model covering it (`python3 formal/scripts/anchors.py who-models <file>:<line>` returns nothing): propose the `formal-kernel` skill to the user before starting it. Writing a kernel needs their approval of the spec.
   - A difftest mismatch: follow the `formal-difftest` skill.
3. Re-run step 1 until it is clean, or until what remains needs a human decision: a real bug, a spec change, or stale tracked anchors the user chose to leave.
4. Summarize: models updated, proofs changed, anchors refreshed, bugs found (with counterexamples), and anything left for the user.

Never edit theorem statements, spec definitions or `formal/spec.lock`, and never use `FORMAL_SKIP=1` on the user's behalf.
