---
description: flare project guide for coding agents (commands, tests, architecture, formal-verification rules)
alwaysApply: true
---

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

flare is a networking library for Mojo: HTTP/1.1, HTTP/2 and HTTP/3 (over QUIC) server and client, WebSocket, gRPC, TLS, TCP/UDP/UDS and DNS, all running on one non-blocking reactor. The Mojo code is mirrored by Lean 4 models under `formal/`, which are proved against the RFCs.

## Constraints

Every feature, fix and optimization must meet all of these:

1. **Least code for the full outcome.** Write the smallest change that delivers the whole result. Reuse what exists before adding anything, don't add speculative knobs or abstractions, and don't stop short of the outcome just to keep the change small.
2. **Security + correctness + performance, together.** Each change accounts for all three, and none is traded away for another without the user's sign-off. An optimization must keep every limit, bounds check, sanitized error and RFC behaviour (see `docs/security.md` and `docs/threat-model.md`). A security or correctness fix states what it costs on the hot path. Back each claim with evidence: tests for correctness, the fuzz and formal checks where they apply, and benchmark numbers from one run for performance.
3. **Minimal allocation, reuse what is allocated.** Avoid allocating on the hot path. Reuse buffers through the existing patterns: caller-owned `mut out: List[UInt8]` encoders, per-connection buffers, and the pools in `flare/runtime/buffer_pool.mojo`. Reuse must not weaken constraint 2. A reused buffer never exposes the previous connection's or request's bytes. Pooled and retained buffers have caps, so a peer cannot pin memory with one large request. Every slot is returned exactly once.
4. **No README changes unless explicitly requested.** Leave `README.md` untouched even when a change makes it stale. Mention the stale part to the user instead.
5. **No new dependencies without sign-off.** Adding a conda, pypi or cargo package or a new FFI library needs the user's approval. Each one adds supply-chain and threat-model surface.
6. **Every change ships its proof.** A bug fix includes a regression test that fails without the fix. A new test file needs `pixi run tests-gen`, a new example needs an `example-*` task, and a new parser or codec gets a fuzz harness in `fuzz/`.
7. **Fail closed.** Untrusted input that is malformed or over a limit is rejected with a sanitized 4xx/5xx or a protocol error. It is never accepted leniently by default, and internal details never reach the peer.

## Commands

Everything runs through pixi. Every task is defined in `pixi.toml`, and the environments and task table are documented in `docs/development.md`.

```bash
pixi install                                    # default env: tests, examples, format-check
pixi install -e dev                             # adds mojodoc + pre-commit
pixi run tests                                  # full suite (per-area aggregate binaries) + every example
pixi run mojo -I . tests/http/test_router.mojo  # run one test file
pixi run test-<name>                            # per-file task, e.g. test-quic-varint
pixi run tests-gen                              # REQUIRED after adding/removing a test file (regenerates tests/_agg/)
pixi run format-check                           # CI check; `pixi run -e dev format` to fix
pixi run bash benchmark/scripts/_make_self_signed.sh   # cert/key needed by the TLS tests
```

Structural lints that CI runs on a bare checkout:
- `check-sans-io`: the sans-I/O codec files listed in `tests/tools/check_sans_io.sh` must not import runtime/io/tcp/udp/uds/tls/net.
- `check-no-http-http2-cycle`: `flare/http2` and `flare/http3` may reach `flare.http` only through `flare.http.wire` (shared `Request`/`Response`/`HeaderMap`/`Method`/`Status`) and `flare.http.proto`.
- `check-reactor-size`: a 600-line cap on files under `flare/http/_reactor/`, with a dated allowlist.
- `check-example-tasks`: every file in `examples/` needs an `example-*` task in `pixi.toml`, and that task must be in the `examples` aggregate.

Other environments: `-e fuzz` (`fuzz-all`, `fuzz-<name>`, `prop-<name>`), `-e bench` (`bench-vs-baseline-quick` etc.; methodology in `docs/benchmark.md`), `-e formal` (see below). `pixi run interop-smoke` and `pixi run conformance` run curl/h2load, h2spec and Autobahn against flare.

Build modes (`docs/build.md`): production and benchmarks use `mojo build -D ASSERT=none`, and CI uses `-D ASSERT=all`. To pass extra defines to the test runner, set `MOJO_DEFINES="-D ASSERT=all"` and use a separate `BUILD_DIR`. Some QUIC/H3/TLS tests depend on `build-rustls-quic`, a cargo build of the rustls C-ABI shim in `flare/tls/ffi/rustls_wrapper/`.

## Tests

- Each test file defines `test_*` functions and a `main()` that calls `TestSuite.discover_tests[__functions_in_module()]().run()`.
- `pixi run tests` does not run files one at a time. `tests/tools/gen_test_aggregates.py` combines each test area into one generated binary in `tests/_agg/`, because compiling the source graph is the slow part. Never hand-edit `tests/_agg/`. A new test file that isn't regenerated into an aggregate silently stops running, and CI fails on drift. Tests that mutate process-global state are excluded from aggregation and run as separate processes; the exclude lists in the generator and the runner script must match.
- Integration tests that need a real port use `flare.testing.fork_server`. Handler unit tests use the in-process `TestClient[H]` or `H2cTestClient[H]`.

## Architecture

The layers are strict, and each imports only from layers below it (details in `docs/architecture.md`):

```
flare.http / http2 / http3   servers, clients, Router, middleware, extractors
flare.ws  grpc  openapi      WebSocket, gRPC, OpenAPI
flare.quic  qpack            QUIC v1 (sans-I/O codec + live UDP reactor), QPACK
flare.tls  crypto            TLS (OpenSSL for h1/h2; rustls via FFI for QUIC), HMAC, base64url
flare.tcp  udp  uds  dns     sockets
flare.net  io                addresses, buffered readers
flare.runtime                reactor (kqueue / epoll / io_uring), TimerWheel, Scheduler
```

Key ideas that span multiple files:
- **Sans-I/O codecs + byte drivers.** Protocol parsing and state machines (`flare.http.proto.*`, `flare.http2`, `flare.http3`, `flare.quic`, `flare.qpack`) are pure and take bytes in and give bytes out. Encoders append to a caller-owned `mut out: List[UInt8]`. Parsers dispatch to a caller handler trait (for example `parse_frame_into[H]`, `feed_into[H]`) rather than returning a union. The reactor-facing code drives these codecs.
- **Thread-per-core reactor.** Each worker runs one event loop with no locks on the hot path. `flare/runtime/reactor.mojo` abstracts kqueue/epoll. Each connection's state machine (READING → WRITING → READING/CLOSING) lives in `flare/http/_server_reactor_impl.mojo` and `flare/http/_reactor/`. It exposes `on_readable`/`on_writable`/`on_timeout` but does not own the reactor or the timers. `Scheduler[F]` is generic over a `Frontend` trait, and the HTTP worker bring-up plugs in from `flare.http.multicore`, so the dependency edge runs http → runtime and never the reverse. Background on threading: `docs/threading.md` and `docs/concurrency.md`.
- **Handlers compose by types.** `Handler` is a trait. `Router`, middleware (`struct X[Inner: Handler]`), typed extractors (`Extracted[T]`) and `ComptimeRouter[ROUTES]` nest as structs and are monomorphised. `CancelHandler` receives a `Cancel` token that the reactor flips on peer FIN, deadline or drain. `flare.prelude` is the public import surface.
- **HTTP/3 path.** `QuicListener` (in `flare.quic.server`) decrypts datagrams, routes STREAM payloads to a per-connection `Http3Connection`, and `HttpServer.serve_http3[H]` drains the completed requests into the handler on each reactor tick.

## Formal verification (from `.agent/rules/formal-factory.mdc`)

Lean models in `formal/Flare/` mirror Mojo symbols. A model's doc comment carries an anchor of the form `mirrors flare/x.mojo#symbol sha=... at=...`. The `formal-drift` pre-commit hook blocks a commit when it makes a `pinned` model's anchor stale (tiers are set in `formal/tiers.toml`).

- Before changing Mojo code, run `python3 formal/scripts/anchors.py who-models flare/x.mojo:LINE` to find the models that mirror it.
- After the change, run `python3 formal/scripts/anchors.py check --base HEAD` to list stale anchors, and `python3 formal/difftest/run.py --affected --base HEAD` to compare the Lean oracle against the Mojo code. Run `lake build` with `pixi run -e formal lake build`, in `formal/`. `pixi run -e formal formal-status` shows everything on one screen.
- Hard rules:
  1. Never weaken a claim. Don't edit theorem statements, spec definitions (`spec*`/`*Spec` names, `Prop`-valued defs, `*Spec.lean`/`*Rfc.lean` files, anything tagged `[spec]`) or `formal/spec.lock`. Never run `formal-spec-lock` or `spec_guard.py --lock`. If a spec looks wrong, stop and ask.
  2. Refresh an anchor (`anchors.py refresh`) only when the model actually mirrors the current Mojo code and `lake build` passes.
  3. When a proof breaks after a code change, first decide whether the model is stale or the code has a real bug: look for a concrete counterexample and run the difftest. For a real bug, follow the Issues convention in `formal/README.md`: fix the code, add a regression test in `tests/`, then update the model. Don't keep pre-fix model variants.
  4. No `sorry`, `admit`, `axiom` or `native_decide`.
  5. Don't bypass the hook with `FORMAL_SKIP=1` unless the user asks.
- The detailed workflows are the skills in `.agent/skills/` (`formal-sync` for syncing models after a code change, `formal-kernel` for large protocol or resource-accounting changes, `formal-difftest` for oracle targets and mismatches), also available as `/formal-verify`. The hooks in `.agent/hooks/` (wired in `.claude/settings.json`) deny re-locking specs, ask before skipping the formal gate (`FORMAL_SKIP=1`, `git commit --no-verify`), and send you back once at turn end if pinned anchors are stale.

## Agent config layout

`.agent/` is the agent-agnostic source of truth for this guide (`.agent/AGENT.md`), skills, commands, hooks and rules. `.cursor/` and `.claude/` contain only symlinks into it plus each tool's own config: `.claude/CLAUDE.md` and `.cursor/rules/AGENT.md` (always applied via the frontmatter above) both link to `.agent/AGENT.md`. Edit files under `.agent/`, not the symlinks.
