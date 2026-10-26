# Development

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install                  # lean: tests, examples, microbench, format-check
pixi install -e dev           # adds mojodoc + pre-commit
```

flare uses six pixi environments:

| Env | Adds | What it unlocks |
|---|---|---|
| `default` | nothing | `tests`, `examples`, microbenchmarks, `format-check` |
| `dev` | `mojodoc`, `pre-commit` | `docs`, `docs-build`, `format` (with hook install) |
| `fuzz` | `dev` + `mozz` | `fuzz-*` / `prop-*` |
| `bench` | `dev` + `go`, `nginx`, `wrk`, `wrk2`, `rust` | `bench-vs-baseline*`, `bench-tail-quick`, `bench-mixed-keepalive`, `bench-soak-*` |
| `metrics` | `lizard` | `complexity`, `coverage`, `metrics` |
| `formal` | `lean4` | `formal-build`, `formal-check`, `formal-status`, `formal-trust`, `difftest*` (see [`formal/`](../formal/)) |

Common tasks (run with `pixi run [--environment <env>] <task>`):

| Task | Env | What it does |
|---|---|---|
| `tests` | `default` | Full unit + integration suite plus every example under [`examples/`](../examples/) |
| `format-check` / `format` | `default` / `dev` | `mojo format` over `flare`, `tests`, `benchmark`, `examples`, `fuzz` |
| `check-sans-io` / `check-no-http-http2-cycle` / `check-reactor-size` / `check-example-tasks` | `default` | The four structural lints CI runs on a bare checkout: the sans-io core imports no I/O, `flare.http` and `flare.http2` stay acyclic, per-file size caps with a dated allowlist, and every example is run by something. A few seconds each, no toolchain needed |
| `interop-smoke` | `default` | Talk to flare with software we did not write: curl and h2load on every wire, plus flare's own streaming client pulling a megabyte on each |
| `conformance` | `default` | h2spec and the Autobahn WebSocket suite, each gated against a documented known-fail list; a leg whose binary is not provisioned skips rather than passing |
| `formal-check` / `difftest` / `formal-status` / `formal-trust` | `formal` | Build the Lean models and audit their axioms; run them against the Mojo code on generated inputs; show stale anchors, unlocked specs and verified kernels on one screen; list the definitions each audited theorem's statement depends on |
| `docs` / `docs-build` | `dev` | mojodoc-rendered package docstring (live or static) |
| `fuzz-all` | `fuzz` | Every harness in [`fuzz/`](../fuzz/) (63 harnesses, 9M+ runs combined) |
| `fuzz-<name>` / `prop-<name>` | `fuzz` | Single harness - see [`pixi.toml`](../pixi.toml) for the full list |
| `bench-vs-baseline-quick` | `bench` | flare vs Go `net/http`, throughput config (~7 min) |
| `bench-vs-baseline` | `bench` | flare vs all baselines (Go, nginx, hyper, axum, actix_web), all configs |
| `bench-tail-quick` | `bench` | Tail-percentile harness at the calibrated peak rate |
| `bench-mixed-keepalive` | `bench` | Mixed keepalive / non-keepalive workload |
| `bench-soak-{slow_clients,churn,mixed,smoke,extended}` | `bench` | 24 h soak harnesses for long-running operational gates |
| `bench-tls-setup` | `bench` | Generate self-signed cert + key for the TLS benches |
| `perf-server-alloc` | `dev` (Linux) | Repeatable allocation + CPU profile of the bench server (heaptrack + `strace -c` + `perf record`) - outputs land under `build/perf-profile/` |

```bash
pixi run tests                                          # full suite + every example under examples/
pixi run tests-gen                                      # regenerate tests/_agg after adding a test file
pixi run mojo -I . tests/http/test_router.mojo          # one test file on its own
pixi run --environment fuzz fuzz-all                    # 63 harnesses
pixi run --environment bench bench-vs-baseline-quick    # ~7 min
```

The full task list (per-component + the every-individual-fuzz-harness breakdown) lives in [`pixi.toml`](../pixi.toml). The architecture / benchmark / security / cookbook tour is in this directory ([index](README.md)).
