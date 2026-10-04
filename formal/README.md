# flare/formal

These are Lean 4 models of flare, with proofs about them and Mojo repros for every issue the proofs turned up. [`REPORT.md`](REPORT.md) has the findings.

## Build and check

```bash
pixi run -e formal formal-build    # lake build (core Lean 4.33, no Mathlib)
pixi run -e formal formal-check    # no sorry/axiom, native_decide only in Bugs/, #print axioms audit
pixi run formal-repros             # run every Mojo repro, print OPEN/FIXED/ERROR/SKIP
python3 formal/scripts/stitch_report.py   # rebuild REPORT.md from report/ (formal-check fails if stale)
```

On macOS, `# PLATFORM: linux` repros run in a Linux container through `repro/linux.sh` when Docker (OrbStack or Docker Desktop) is running. The container keeps its own copy of the repo and its own pixi environment. Set `FORMAL_REPRO_LINUX=all` to also run every portable repro on Linux, or `off` to skip the container. Do Linux flip checks inside the container's copy:

```bash
formal/repro/linux.sh formal/repro/RT-03_uring_poll_blocks_unarmed.mojo
FLARE_LINUX_NOSYNC=1 formal/repro/linux.sh --exec 'sed -i ... flare/runtime/uring_reactor.mojo'
```

## Layout

| Path | Contents |
|---|---|
| `Flare/Core/` | bytes, Mojo-width words, the LTS/refinement vocabulary, environment assumptions (hypotheses, not axioms) |
| `Flare/L1_Encoding/` | pure codecs: byte order, sockaddr, cursors, UTF-8 (including lossy decoding), QUIC and protobuf varints, HPACK integers, Huffman against RFC 7541 Appendix B, civil time in `Int64`, Mojo's `Int(String)` |
| `Flare/L2_Machine/` | OS-facing abstract machines: sockets, write loops, reactor, timer wheel (including `UInt64` time and jump order), io_uring rings, frame demux, queues, pools, UDP batch `msghdr` layout, UNIX listener takeover, hostname validation, Happy Eyeballs order |
| `Flare/L3_Protocol/` | HTTP/1.1 server and client framing, WebSocket frames and handshakes, HTTP/2 + HPACK (with a refinement of the RFC 9113 §5.1 stream states), QUIC (stream states, ACK generation, transport parameters), QPACK, HTTP/3 |
| `Flare/L4_App/` | connection state machine (with liveness, streaming bodies, TLS interest, `100 Continue`), router, middleware, negotiation, CORS, rate limit, cookies, redirects, client pool and leases, drain, h2c and WebSocket hand-off |
| `Flare/L5_Concurrency/` | interleaving semantics: watchdog, AsyncRT cell, thread handles, scheduler, shared listener, start/teardown bookkeeping |
| `Flare/Machine.lean` | the top-level network abstract machine (one reactor worker) that composes the layers |
| `Flare/MachineHttp.lean` | that machine running the HTTP/1.1 connection state machine (`L4_App/ConnSM`) |
| `Flare/MachineWorkers.lean` | several workers sharing one fd table; worker progress |
| `Flare/MachineWheel.lean` | that machine on the real timer wheel (`L2_Machine/TimerWheel`), any firing order |
| `Flare/Bugs/` | one file per confirmed issue: a concrete counterexample and a proof that the minimal fix meets the spec |
| `Flare/Docs.lean` | aggregate of the `DOC-*` findings from checking `docs/security.md`, `docs/threat-model.md` and `docs/features.md` against the code |
| `Flare/Audit.lean`, `Flare/Audit/*.lean` | `#print axioms` lines for the headline theorems |
| `repro/` | one self-contained Mojo repro per confirmed issue, plus `run_all.sh` |
| `report/` | per-layer report sections, stitched into `REPORT.md` by `scripts/stitch_report.py` |

## Conventions

**Fidelity header.** Every impl model starts with a doc comment pointing at the Mojo code it transliterates:

```lean
/-- mirrors flare/http2/state.mojo:1005-1333 @59bda50 -/
```

This lets anyone line a model up against the source and spot drift.

**Spec vs Impl.** Each component pairs two things:

- `spec`: written from the RFC and independent of flare.
- `impl`: a transliteration of the Mojo code, keeping its control flow, fixed-width arithmetic (`UInt64`, `Int64` wrap for Mojo `Int`, wrapping `UInt32` ring counters) and limits.

Theorems relate the two: refinement, round trips, invariants, termination and progress, no overflow, and chunking independence.

**Semantics.** Pure codecs are total functions. Stateful components are small-step LTSs (`Flare.LTS`), with an executable step function and a lemma that the two agree.

**Issues.** When a proof fails because the code is wrong, the issue gets three things:

1. A counterexample file, `Flare/Bugs/<AREA>_<NN>.lean`, that proves `¬ spec (impl input)` on a concrete input with `decide`, `rfl` or `native_decide`.
2. A proof that `implFixed` meets the spec, so the minimal fix is known to be enough.
3. A repro, `repro/<AREA>-<NN>_<slug>.mojo`.

Suspected issues that Lean refutes are recorded in the report under "checked, not a bug".

**Repro contract** (enforced by `repro/run_all.sh`):

- The file opens with a header comment: `# PLATFORM: any|linux|macos`, plus `# SKIP: <reason>` if it cannot run deterministically here.
- A docstring gives the issue ID, the Lean theorem, the flare `file:line @59bda50`, expected vs actual behaviour, and the minimal fix.
- While the bug is present it prints a line starting with `BUG REPRODUCED:` and raises, so the exit code is non-zero.
- Once the bug is fixed it prints `OK:` and exits 0.
- Run it from the repo root: `pixi run mojo -I . formal/repro/<file>.mojo`.

**Trust base.**

- Environment facts are hypotheses in `Flare/Core/Assumptions.lean`, never `axiom`s.
- OpenSSL, rustls and zlib are black boxes.
- `native_decide` is allowed only in `Flare/Bugs/`, and the axiom audit reports it.
