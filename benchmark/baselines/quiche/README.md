# quiche HTTP/3 baseline

Cloudflare's `quiche` ships a reference HTTP/3 + QUIC stack on
top of a low-level sans-I/O API. This baseline drives the
`quiche` 0.22 crate directly over a `mio` UDP event loop --
the same shape Cloudflare's `examples/http3-server.rs` walks --
so the cross-framework HTTP/3 bench has a second independent
reference implementation alongside `benchmark/baselines/quinn/`.

## Build + run

```bash
# Build (idempotent if cached; first build ~90-300s for the
# boringssl-vendored dependency tree).
pixi run -e bench cargo build --release --locked \
    --manifest-path benchmark/baselines/quiche/Cargo.toml

# Start the server on port 8443; writes the PID to
# benchmark/results/.server.pid.
FLARE_BENCH_PORT=8443 benchmark/baselines/quiche/run.sh

# Probe with h2load --npn-list=h3 once it's up.
benchmark/baselines/quiche/check.sh
```

## Route surface

Mirrors `benchmark/baselines/hyper/src/main.rs` so the
cross-framework bench compares the same payload across the
wire shapes:

| route       | method | body                                         |
|-------------|--------|----------------------------------------------|
| `/`         | GET    | `"Hello, World!"` (13 bytes)                 |
| `/plaintext`| GET    | `"Hello, World!"` (13 bytes)                 |
| `/4kb`      | GET    | 4096-byte buffer of `'x'`                    |
| `/64kb`     | GET    | 65536-byte buffer of `'x'`                   |
| `/1mb`      | GET    | 1048576-byte buffer of `'x'`                 |
| `/16mb`     | GET    | 16777216-byte buffer of `'x'`                |
| `/upload`   | POST   | echoes "0" (h3 body drain not measured here) |

The /upload route returns a fixed string for the h3 baseline
(rather than echoing the byte count like the hyper baseline)
because the bench harness is throughput-oriented and the
echo-byte-count round-trip is already exercised by the hyper
+ go_nethttp h1 baselines.

## Pinned dependencies

```toml
[dependencies]
quiche = { version = "0.22", features = ["boringssl-vendored"] }
mio    = "0.8"
ring   = "0.17"
rcgen  = "0.13"
```

`boringssl-vendored` builds BoringSSL from source so the
baseline binary doesn't depend on a system-wide BoringSSL
version that may not be present on the EPYC dev-box. Cargo.lock
pins the exact patch revisions so the bench numbers are
reproducible across machines.

## TLS

The server generates a self-signed Ed25519 certificate at
startup via `rcgen` and writes it to
`/tmp/flare_bench_quiche_{cert,key}.pem`; the bench client
must skip cert verification. Mirrors the cert handling of
the quinn baseline so the two h3 baselines are byte-for-byte
comparable.

## Cross-validation

The bench harness (`benchmark/scripts/bench_h3.sh`) runs the
same `h2load --npn-list=h3` workload against flare,
`benchmark/baselines/quinn/`, and this quiche baseline.
Five-run median + p99 / p99.9 / p99.99 / sigma are written to
`benchmark/results/v0.8/h3/`; the cross-framework table
published in `docs/benchmark.md` is the v0.8 hard-gate HTTP/3
throughput row.
