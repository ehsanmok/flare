---
name: formal-kernel
description: Ship a large flare change with a small Lean-verified kernel. Extract the decision logic of the change into a pure sans-I/O Mojo function, write its Lean spec (human-approved), impl model, theorems, oracle target, difftest driver and obligation record. Use for big changes to protocol state machines, parsers, or resource accounting (buffers, windows, credits, pools) where full verification is impractical.
---

# formal-kernel

A change of thousands of lines is not verified line by line. Its **kernel** is: the 20 to 150 lines that decide what happens (state transitions, accounting, accept or reject), pulled out as a pure function. The big change calls the kernel, Lean proves the kernel meets its spec, and the difftest checks that the Mojo kernel behaves like the Lean model.

Read "Rules for agents" in `formal/README.md` first. Worked example: `formal/obligations/uring-bufring-ledger.toml` (the issue #37 retrospective).

## 1. Find the kernel

Pick the logic whose bugs would be silent and costly: an invariant over counters (conservation, no double free, windows never negative), a protocol state machine, or a parser's accept/reject decision. A good kernel:
- takes plain values and returns plain values (no sockets, no FFI, no allocation it doesn't return);
- can be stated as `spec (step s e)` or as an invariant preserved by every event;
- is called from every path in the big change that makes that decision. If one path skips it, the proof says nothing about that path.

## 2. Extract it in Mojo

- Put it in a sans-I/O module, next to the code that uses it or under `flare/*/proto/`, and add the file to `SANS_IO_FILES` in `tests/tools/check_sans_io.sh`.
- Shape: a small `struct` holding the state plus a `step`/`on_<event>` method per event, or pure functions.
- Route the big change's decision points through it, then run the existing tests.

## 3. Write the spec first, then STOP

Create `formal/Flare/Kernels/<Name>.lean` with:
- the state and event types;
- the spec: an invariant or an abstract step function, written from the RFC or the intended behaviour, never from the Mojo code. Tag its doc comment `[spec]`, or name it `spec*` / `*Spec`.

**Show the spec to the user and wait for approval.** Once they approve, they run `pixi run -e formal formal-spec-lock` themselves. Never run it yourself.

## 4. Impl model, theorems, anchor

- Write the impl model as a transliteration of the Mojo kernel. Its doc comment carries an anchor from `python3 formal/scripts/anchors.py make 'flare/x.mojo#Ledger.on_cqe+Ledger.on_close'`.
- State and prove the theorems: preservation of the invariant for every event, or refinement of the spec step, plus any boundary facts. No `sorry`.
- Import the file from `formal/Flare/Kernels.lean` (create it if needed), and import that from `formal/Flare.lean`.
- `formal/tiers.toml` already pins `Flare/Kernels/**`.

## 5. Oracle target and difftest driver

Follow the `formal-difftest` skill. For a stateful kernel the input bytes encode an **event trace**: each byte or byte-group is one event. The output is the observable state after each event, or the first rejected event. Both sides must render the same text.

## 6. Obligation record

Write `formal/obligations/<slug>.toml`:

```toml
id = "uring-bufring-ledger"
issue = "https://github.com/ehsanmok/flare/issues/37"
kernel = "flare/http/_bufring_ledger.mojo#BufLedger"   # anchor ref (no sha)
model = "Flare/Kernels/BufLedger.lean"
theorems = ["conserves", "no_double_return"]
difftest = ["bufring_ledger.trace"]
status = "proved"   # draft | spec-approved | proved
```

## 7. Verify and report

`cd formal && pixi run -e formal lake build`, `python3 formal/difftest/run.py --targets <yours>`, then `pixi run -e formal formal-check`. Report what the kernel is, which paths call it, which theorems hold, and anything you left out of the kernel (and why).
