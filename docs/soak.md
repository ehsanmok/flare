# Soak harness — slow-client / churn / mixed-load

The soak harness runs a flare HTTP server under sustained load and
watches the three operational signals that microbenchmarks miss:

- **RSS over time** — does memory grow linearly, plateau, or
  spike under churn?
- **File descriptors** — are accept-loop / TLS / connection
  bookkeeping leaking fds under churn?
- **Tail-latency drift** — does p99 stay flat at hour 24 or does
  a slow pathology creep in?

Throughput says "is it fast right now"; soak says "is it still
alive at 4 a.m. on day 2".

## Three tiers, one harness

The soak driver lives in
[`benchmark/scripts/_run_soak.sh`](../benchmark/scripts/_run_soak.sh).
A single set of scripts runs at three tiers via the
`SOAK_DURATION_SECS` env knob (defaults to 60 s):

| Tier | Per-workload duration | Total wall time | When to run |
|---|---|---|---|
| **smoke** | 60 s | ~3 min | PR / iterative dev (`pixi run --environment bench bench-soak-smoke`) |
| **extended** | 300 s | ~15 min | Before pushing larger changes (`pixi run --environment bench bench-soak-extended`) |
| **release gate** | 86 400 s (24 h) | ~24 h per workload, ~3 days total | Linux EPYC, manual one-shot pre-tag |

Release-gate invocation pattern (one workload per box-day, run
serially or in parallel on different EPYC boxes):

```bash
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-slow-clients
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-churn
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-mixed
```

Same `_run_soak.sh` driver, same `summary.json` schema, same
gate logic — only the duration changes. The 24 h gate is the
release-blocking one; smoke and extended are catch-loud-failures
filters.

## Workloads + gates

All three workloads target `/plaintext` on the flare bench
server boot from
[`benchmark/baselines/flare/main.mojo`](../benchmark/baselines/flare/main.mojo)
(same entry point the bench-vs-baseline harness uses, so soak
numbers are directly comparable). The wrk lua scripts live in
[`benchmark/scripts/wrk_soak_*.lua`](../benchmark/scripts/).

### slow-client

256 concurrent connections, each issuing a short POST request
every ~100 ms (wrk's `delay()` model approximates the design
doc's "1 byte / 100 ms" intent within wrk's protocol shape).
The gate is the design doc's slow-client gate:

- **`pass = errors == 0 && rss_end <= 2 * rss_start`**
- 24 h release-gate variant additionally requires `rss_end ≈
  rss_start` after the first hour (i.e. RSS-flat).

The lua approximation does NOT byte-trickle inside a single
request body the way a true byte-trickle harness would — that
would test flare's `read_body_timeout_ms` deadline-fires path
end-to-end. The deadline path itself is tested in
[`tests/test_server_deadlines.mojo`](../tests/test_server_deadlines.mojo);
the soak harness covers the resource-exhaustion shape (many
connections held).

### churn

64 concurrent connections, every request sets `Connection:
close` so the server closes after each response. wrk reopens
for the next request. Effective rate is bounded by ephemeral-
port turnover on the box. Gate:

- **`pass = errors == 0 && fd_end <= fd_start + 16`**
- 16-fd slack covers timer / wakeup / log fds beyond the
  per-connection fds. The `fd_end` measurement happens after a
  3 s post-wrk drain pause so in-flight connections finish their
  close handshake before the observer's last sample.

### mixed

64 concurrent connections, ~20 % tagged with `Connection:
close` (every 5th request), the remaining 80 % standard
HTTP/1.1 keep-alive. Catches regressions in the connection-
disposition path that pure keep-alive load doesn't exercise.
Gate:

- **`pass = errors == 0 && rss_end <= 2 * rss_start`**

## Output schema

Each per-workload run writes
`build/soak/<workload>/<timestamp>-<host>-<commit>/summary.json`
with the following fields. The schema is stable so EPYC release-
gate runs can be aggregated by S3.8 publication tooling without
script edits:

```json
{
  "workload":          "slow_clients",
  "tier":              "smoke",
  "duration_secs":     60,
  "wrk_threads":       2,
  "wrk_connections":   256,
  "commit":            "9755049",
  "host":              "ehsan-dev",
  "wrk": {
    "requests_total":           7424,
    "requests_per_sec":         2461.3,
    "duration_secs_actual":     3.02,
    "p50_ms":                   341.0,
    "p75_ms":                   612.0,
    "p90_ms":                   970.0,
    "p99_ms":                   2070.0,
    "socket_errors_connect":    0,
    "socket_errors_read":       0,
    "socket_errors_write":      0,
    "socket_errors_timeout":    0,
    "non_2xx_3xx":              0
  },
  "rss_kb_start":      193552,
  "rss_kb_end":        195088,
  "rss_kb_max":        195088,
  "fd_count_start":    55,
  "fd_count_end":      55,
  "fd_count_max":      311,
  "observe_samples":   8,
  "gates": {
    "rss_within_2x":   true,
    "fd_end_bounded":  true,
    "server_alive":    true,
    "no_non_2xx":      true
  },
  "pass":              true
}
```

Companion files in the same directory:

- `wrk.txt` — raw wrk stdout including the latency distribution.
- `observe.jsonl` — per-second (or per-5-s for the 24 h tier)
  RSS / fd-count samples. One JSON object per line:
  `{"ts_ms": 12345, "rss_kb": ..., "hwm_kb": ..., "peak_kb":
  ..., "fd_count": ...}`.
- `server.{stdout,stderr}` — flare bench server output.
- `observer.stderr` — observer-side stderr (rare unless
  `/proc/$PID` becomes unreadable mid-run).

## CI integration

The 60 s smoke tier (`bench-soak-smoke`) is a candidate for the
nightly CI matrix once the bench env's runtime cost (Go +
nginx + wrk install, ~3-5 min) fits the workflow's budget.
Until then, the smoke runs locally on every soak-touching
change; the 24 h release gate stays manual on EPYC per the
design doc's "1 h smoke on every PR, 24 h nightly only" framing
(simply scaled up for our smaller-team release cadence).

## Dev-box smoke + extended results (Ubuntu 22.04, 6 vCPU AWS)

These are NOT release-gate numbers. They are smoke artefacts
captured on the maintainer's AWS Ubuntu 22.04 dev box (glibc 2.35,
x86_64) at commit
[`9755049`](https://github.com/ehsanmok/flare/commit/9755049).
The release-gate p99.9 / p99.99 numbers + 24 h flat-RSS proof are
captured on Linux EPYC and live in the per-tag release notes.

What the tables below DO prove: the soak harness fires cleanly,
the gates evaluate against real data, and the dev-box server
holds steady under all three workloads at the smoke + extended
durations (no crashes, no fd leaks, RSS within ~1 % of cold-start
across both tiers).

### Smoke tier (60 s/workload, ~3 min total)

| Workload | req/s | Total req | p50 (ms) | p99 (ms) | RSS start (KB) | RSS end (KB) | RSS max (KB) | fd start | fd end | fd max | non-2xx | Pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| slow-client | 2 546.4 | 152 948 | 0.18 | 1.07 | 192 588 | 194 124 | 194 124 | 55 | 55 | 311 | 0 | yes |
| churn | 27 805.5 | 1 668 403 | 2.00 | 2.34 | 193 488 | 194 000 | 194 000 | 55 | 55 | 119 | 0 | yes |
| mixed | 49 544.7 | 2 972 718 | 1.01 | 2.76 | 193 492 | 194 004 | 194 004 | 55 | 55 | 119 | 0 | yes |

### Extended tier (300 s/workload, ~15 min total)

| Workload | req/s | Total req | p50 (ms) | p99 (ms) | RSS start (KB) | RSS end (KB) | RSS max (KB) | fd start | fd end | fd max | non-2xx | Pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| slow-client | 2 547.8 | 764 471 | 0.19 | 0.85 | 193 492 | 195 028 | 195 028 | 55 | 55 | 311 | 0 | yes |
| churn | 27 805.0 | 8 341 534 | 1.99 | 2.34 | 194 196 | 194 708 | 194 708 | 55 | 55 | 119 | 0 | yes |
| mixed | 50 072.9 | 15 021 927 | 0.99 | 2.70 | 192 152 | 192 664 | 192 664 | 55 | 55 | 119 | 0 | yes |

Two cross-tier observations worth a note:

- **RSS deltas are essentially identical** between smoke (60 s)
  and extended (300 s): ~0.5–1.5 MB across all three workloads
  in both tiers. That's the right shape: a 5x duration increase
  did not produce a 5x RSS increase, suggesting per-request
  allocator churn is bounded rather than leaking. The 24 h gate
  is what pins this assertion long-term.
- **fd_count returns to baseline** in both tiers across all
  workloads (`fd_end == fd_start == 55`). The 3 s post-wrk drain
  pause is what makes this measurement honest — without it, the
  observer would race wrk-exit and report ~30–250 in-flight fds
  as a "leak". The drain pause is documented at the top of
  [`_run_soak.sh`](../benchmark/scripts/_run_soak.sh).

## Limitations

- **Linux only.** `/proc/<pid>/status` is the RSS source; macOS
  would need `ps -o rss=` fallback. The release gate runs on
  Linux EPYC anyway, so this is the only platform the gate
  needs.
- **wrk-driven slow-client is an approximation** — see the
  slow-client section above. The byte-trickle path in flare's
  reactor is exercised by unit tests instead.
- **The smoke / extended tiers cannot prove "RSS flat after 1
  hour"** — that signal lives only in the 24 h release-gate
  run. Smoke / extended only catch loud failures (server died,
  RSS doubled, fds leaked beyond a small constant).
