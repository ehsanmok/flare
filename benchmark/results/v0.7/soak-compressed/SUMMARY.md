# v0.7 Compressed Soak

Operational evidence for the v0.7 release. Compressed shape (1-2 h
total wall-clock) per the v0.7 release-readiness plan; the full 24 h
soak with the v0.6 + v0.7 stack is a v0.7.x line item, deferred so
the release isn't blocked on a wall-clock window.

Captured on commit `7cfaccc`
(`ci(asan): extend default ASan inventory to FFI surfaces post-OwnedDLHandle port`,
the tip of v0.7 work prior to this publication commit). Host:
`ehsan-dev` (Linux EPYC 7R32 dev-box, kernel 6.8). Driver:
`benchmark/scripts/_run_soak.sh` per workload, `wrk` with workload-
specific Lua scripts.

## Results

### Smoke tier (3 workloads × 60 s each)

`pixi run --environment bench bench-soak-smoke`

| Workload | Conns | Req/s | Total | non-2xx | sock-err | RSS start | RSS max | RSS end | fd start | fd max | fd end | p99 (ms) | pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| slow_clients | 256 | 2,543 | 152,759 | 0 | 0 | 32,256 KB | 33,792 KB | 33,792 KB | 45 | 301 | 45 | 1.06 | true |
| churn | 64 | 27,333 | 1,639,991 | 0 | 0 | 31,744 KB | 31,744 KB | 31,744 KB | 45 | 109 | 45 | 2.39 | true |
| mixed | 64 | 51,076 | 3,064,583 | 0 | 0 | 32,256 KB | 33,280 KB | 33,280 KB | 45 | 109 | 45 | 2.64 | true |

### Extended tier (mixed × 600 s = 10 min)

`pixi run --environment bench bash benchmark/scripts/_run_soak.sh --workload=mixed --duration-secs=600`

| Workload | Conns | Req/s | Total | non-2xx | sock-err | RSS start | RSS max | RSS end | fd start | fd max | fd end | p99 (ms) | pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| mixed (extended) | 64 | 51,050 | 30,631,489 | 0 | 0 | 31,744 KB | 32,256 KB | 32,256 KB | 45 | 109 | 104 | 2.64 | true |

## What this rules out

* **Memory leaks under sustained load** — RSS drift over the 10 min
  extended mixed run is +512 KB across 30.6 M requests. RSS is
  bounded; there's no slow leak in the v0.7 hot path.
* **fd exhaustion** — fd-count max stayed at 109 across all four
  runs, well below any reasonable rlimit. The fd-end value of 104
  on the extended run reflects in-flight keep-alive sockets at
  drain time (the harness counts before the post-drain settle).
* **Server-side error generation** — zero non-2xx responses across
  35 M+ requests. The full stack (Compress / Cors / Logger /
  RequestId / Router) doesn't intermittently 5xx under load.
* **Socket-level instability** — zero connect / read / write /
  timeout errors across all four runs. The reactor's accept +
  recv + send + close loop is steady.

## What this does NOT rule out

* **24-hour drift** — a real RSS leak that adds 1 KB / 100 K
  requests would be invisible at 600 s but visible at 24 h. The
  v0.6 24 h soak (per `benchmark/results/2026-05-04T1817-ehsan-dev-8fcf86b/`)
  was the canonical long-window proof for the v0.6 stack; the
  v0.7 stack hasn't been soak-tested at the 24 h window. v0.7.x
  line item.
* **Concurrent fan-out beyond 256 connections** — `slow_clients`
  used `wrk -c 256`; production loads with thousands of concurrent
  keep-alives haven't been characterised.
* **TLS-side soak** — the soak harness drives plaintext only.
  TLS handshake under sustained load (cert reload, session
  resumption when it ships) is its own gate.
* **Multi-worker behaviour** — the soak runs the single-worker
  reactor (`flare`). Multi-worker (`flare_mc`) was characterised
  in v0.6 but not re-soaked for v0.7.

## Reproducing

```bash
pixi run --environment bench bench-soak-smoke
pixi run --environment bench bash benchmark/scripts/_run_soak.sh \
    --workload=mixed --duration-secs=600
```

Per-run artefact directories live alongside this SUMMARY:

* `smoke/slow_clients/` — 60 s slow-client workload
* `smoke/churn/` — 60 s connection-churn workload
* `smoke/mixed-60s/` — 60 s mixed-keepalive workload
* `extended-mixed-10min/` — 600 s mixed-keepalive workload

Each directory contains:

* `summary.json` — gate verdict + p50 / p75 / p90 / p99
  percentiles + RSS / fd timeseries summary.
* `wrk.txt` — raw wrk output.
* `observe.jsonl` — per-second observer samples (RSS, fd_count).
* `server.stdout` / `server.stderr` — flare bench server logs.
* `observer.stderr` — observer-process stderr.
