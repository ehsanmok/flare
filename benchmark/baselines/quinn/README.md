# quinn HTTP/3 baseline

`quinn` is the canonical Rust QUIC implementation; paired with
`h3-quinn` it provides a clean reference HTTP/3 server to compare
flare's own h3 throughput against. Same idea as the
`benchmark/baselines/hyper/` baseline: a small Rust binary built
via `cargo build --release --locked` that serves the same
"Hello, World!" body the v0.6 throughput harness uses, but over
UDP + QUIC + h3 instead of TCP + TLS + h2.

## Build + run

```bash
# Build (idempotent if cached; first build ~90-180s).
pixi run -e bench cargo build --release --locked \
    --manifest-path benchmark/baselines/quinn/Cargo.toml

# Start the server on port 8443 with FLARE_BENCH_WORKERS tokio
# worker threads (default 4); writes the PID to
# benchmark/results/.server.pid.
FLARE_BENCH_PORT=8443 benchmark/baselines/quinn/run.sh

# Probe with h2load --npn-list=h3 once it's up.
benchmark/baselines/quinn/check.sh
```

## Route surface

Mirrors `benchmark/baselines/hyper/src/main.rs` so the
cross-framework bench compares the same payload across the wire
shapes:

| route       | method | body                                         |
|-------------|--------|----------------------------------------------|
| `/`         | GET    | `"Hello, World!"` (13 bytes)                 |
| `/plaintext`| GET    | `"Hello, World!"` (13 bytes)                 |
| `/4kb`      | GET    | 4096-byte buffer of `'x'`                    |
| `/64kb`     | GET    | 65536-byte buffer of `'x'`                   |
| `/1mb`      | GET    | 1048576-byte buffer of `'x'`                 |
| `/16mb`     | GET    | 16777216-byte buffer of `'x'`                |
| `/upload`   | POST   | echoes the byte count of the request body    |

## Pinned dependencies

```toml
[dependencies]
quinn          = "0.11"
h3             = "0.0.6"
h3-quinn       = "0.0.7"
rustls         = "0.23"
rustls-pemfile = "2"
rcgen          = "0.13"
```

Cargo.lock pins the exact patch revisions so bench numbers are
reproducible across machines.

## TLS

The server generates a self-signed Ed25519 certificate at
startup via `rcgen`; the bench client must skip cert
verification. Every cross-framework HTTP/3 baseline runs this
way -- `quiche-server`, `neqo-server`, `msquic_demo` all
generate ephemeral certs -- so cert management stays out of
the bench loop and the QUIC + h3 throughput measurement
remains isolated.

## Cross-validation

The bench harness (`benchmark/scripts/bench_h3.sh`) runs the
same `h2load --npn-list=h3` workload against flare, this quinn
baseline, and the matching `benchmark/baselines/quiche/`
baseline. Each baseline serves the same hello-world body; the
harness computes the five-run median + p99 / p99.9 / p99.99 /
sigma and writes the result table to
`benchmark/results/v0.8/h3/`. The cross-framework table
published in `docs/benchmark.md` is the v0.8 hard-gate HTTP/3
throughput row.
