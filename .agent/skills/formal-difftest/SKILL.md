---
name: formal-difftest
description: Add a differential-testing target that runs a Lean impl/spec model from formal/ against the real Mojo code, or triage a difftest mismatch (drift vs spec vs harness). Use when adding an oracle target, extending formal/difftest, or when formal/difftest/run.py reports MISMATCH.
---

# formal-difftest

The difftest closes the gap between a hand-written Lean transliteration and the Mojo code. Both run on the same generated inputs and must produce the same text. Pieces:

- `formal/Oracle/Registry.lean`: a target name mapped to `impl` (and optionally `spec`) functions over raw bytes. It's built as the `flare-oracle` executable.
- `formal/difftest/drivers/dt_<family>.mojo`: the Mojo side. Each driver handles every target in its family; shared I/O lives in `_dtio.mojo`.
- `formal/difftest/targets.py`: per target, the driver, the anchored Mojo symbols, the Lean models, the fuzz seeds, the generator and `max_len`.
- `formal/difftest/run.py`: generates inputs, runs both sides, delta-minimizes mismatches, and appends them to `regressions/<target>.txt`.

## Add a target

1. **Fix the input layout.** Decide how the raw input bytes map to arguments, for example "byte 0 selects the prefix width, the rest is the buffer". Write it in the docstrings on both sides. Keep inputs short: 8 to 32 bytes finds most bugs, and minimization stays fast.
2. **Lean.** Add an entry to `targets` in `Oracle/Registry.lean`. Render results as `OK:<payload>` or `ERR`: hex via `okHex` for bytes, `s!"OK:{a},{b}"` for numbers. Collapse every error to `ERR` unless both sides expose the same error classes. If the model has an executable spec, add it as `spec` and set `specMax` if the spec is slow.
3. **Mojo.** Add a branch to the family driver (or a new `dt_<family>.mojo`, copying an existing one). It calls the real flare function and renders the exact same text. Catch raises and print `ERR`.
4. **Manifest.** Add a row to `targets.py`. `symbols` must be anchor refs that resolve (`python3 formal/scripts/anchors.py make '<ref>'`). If good inputs are rare (for example valid Huffman codes), use `derive` to feed another target's outputs in.
5. **Run.** `python3 formal/difftest/run.py --targets <name> --cases 5000`. Check that both `OK` and `ERR` outcomes occur. A target that only ever answers `ERR` isn't testing anything.

## Triage a mismatch

`run.py` prints the minimized input and both answers, and has already saved them to `regressions/<target>.txt`.

- **drift** (Mojo differs from the Lean impl): first check whether the target's anchors are stale (`python3 formal/scripts/anchors.py check`).
  - Stale anchor and the Mojo change was intended: update the model (the `formal-sync` skill). The regression entry stays as a test.
  - Anchors fresh: the transliteration was wrong all along, or the input layout differs between the two sides. Compare them on the minimized input by hand.
  - The Mojo answer violates the spec (check the theorem, or evaluate the spec in Lean with `#eval`): it's a real bug. Follow the Issues convention in `formal/README.md`.
- **spec** (the Lean impl differs from the Lean spec): the proofs should have ruled this out. Check that the theorem covers this input domain (hypotheses, `specMax`). This is the most serious class, so report it to the user.
- **harness** (`BAD:`): the target name or input format disagrees between the two sides, or a driver crashed.

Never "fix" a mismatch by changing the spec, deleting a regression line, or narrowing a generator to avoid the input.
