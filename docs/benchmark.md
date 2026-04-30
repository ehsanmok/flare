# Benchmarks

Reproducible measurements with pinned toolchains, integrity-gated
baselines, and a 5-run median with stdev gate. The
[single-worker Linux plaintext table](#single-worker-linux-aws-epyc-7r32)
is the closest single number to a production-shape headline.

> **Read the worker count.** Throughout this page, every
> comparison is explicitly framed as **single-worker** or
> **multi-worker**. Multi-worker comparisons require multi-worker
> baselines: an `N`-worker flare against an `N`-thread Go,
> `N`-worker nginx, etc. Comparing `N`-worker flare to a 1-thread
> Go is throughput-per-machine, not throughput-per-core, and we
> do not publish a "vs `Go net/http`" ratio for it. The
> [Multi-worker baselines: pending publication](#multi-worker-baselines-pending-publication)
> section names the gap explicitly.

---

## Workload + harness shape

The headline harness is **wrk2 in calibrated-peak mode** against
a 13-byte plaintext body. Calibrated-peak means a four-phase
run: (1) a 5 s settle phase at a low fixed rate so JIT, branch
caches, and TCP slow-start are out of the way; (2) a brief
overdrive probe (`-R 10000000`) that establishes a ceiling;
(3) a five-step binary search for the highest fixed rate where
**p99 ≤ a configurable budget (default 50 ms) AND wrk2's
achieved rate is at least 90 % of the requested rate** — that
"achieved ≥ 90 %" rule rejects the case where the load gen has
piled up requests at its own queue while the server falls behind
(which is what overdrive-only peak-finders silently report as
peak); (4) five 30 s measurement rounds at 90 % of the
calibrated peak that report the latency distribution.

Calibrated-peak replaces the earlier "two-phase" harness. The
two-phase harness measured peak with one wrk2 overdrive run and
sustained at 90 % of *that* number; on a single-worker server the
overdrive-vs-sustainable gap was small (~10 %), but on a
multi-worker server the overdrive number over-reports the
sustainable peak by 30–60 % (the kernel's accept queue absorbs
the extra load briefly, then the server falls behind and tail
explodes). The calibrated-peak path closes that gap and is what
every multi-worker number in this document publishes.

wrk2 (rather than wrk) closes the
[coordinated-omission](https://highscalability.com/blog/2015/10/5/your-load-generator-is-probably-lying-to-you-take-the-red-pi.html)
hole that makes wrk's default mode silently inflate p99 and
hide p99.9 / p99.99 once the server is anywhere near capacity:
wrk2 sends at constant throughput so queue time at the gen is
counted, which is what production clients actually observe
under load.

1. **wrk2 + tail percentiles.** Every measurement run captures
   p50 / p75 / p90 / p99 / **p99.9 / p99.99 / p99.999** via
   `wrk2 --latency`. The summary headline req/s is **peak
   capacity** from the find-peak phase; the latency columns
   reflect tail behaviour at 90 %-of-peak sustained load. The
   `_install_wrk2.sh` step builds a pinned wrk2 commit when the
   platform has no conda-forge package (linux-64 today). Tail
   numbers are reproducible across machines because the
   toolchain is pinned in `[feature.bench.dependencies]`.

2. **Multiple workloads**, not one:

   - **`micro-static`** ([`throughput.yaml`](../benchmark/configs/throughput.yaml))
     — the per-core plaintext parity gate. The headline tables
     below.
   - **`mixed-keepalive`**
     ([`mixed_keepalive.yaml`](../benchmark/configs/mixed_keepalive.yaml)
     + [`wrk_mixed_keepalive.lua`](../benchmark/scripts/wrk_mixed_keepalive.lua))
     — 80 % keep-alive, 20 % `Connection: close`. Catches
     regressions in flare's keep-alive book-keeping and
     close-after disposition that pure keep-alive loads can't
     exercise. `pixi run --environment bench bench-mixed-keepalive`.
   - **`uploads`** ([`uploads.yaml`](../benchmark/configs/uploads.yaml))
     — POSTs of 4 KB / 64 KB / 1 MB / 16 MB. The 1 MB and 16 MB
     cases drive the zero-copy reactor adoption.
   - **`downloads`** ([`downloads.yaml`](../benchmark/configs/downloads.yaml))
     — GETs returning 4 KB / 64 KB / 1 MB / 16 MB streamed
     bodies. Headline target for the streaming-body reactor
     adoption: "no per-client allocation proportional to body
     size." The Go baseline serves matching `/4kb` / `/64kb` /
     `/1mb` / `/16mb` routes so the comparison is
     apples-to-apples.
   - **`slow-clients`** ([`slow_clients.yaml`](../benchmark/configs/slow_clients.yaml))
     — 256 connections, each trickling 1 byte / 100 ms.
     Validates that the `read_body_timeout_ms` deadline reclaims
     worker slots from slow-body DoS attempts.
   - **`churn`** ([`churn.yaml`](../benchmark/configs/churn.yaml))
     — 10 K open / send / close cycles per second. Stresses
     `accept()` throughput, the `Pool[ConnHandle]` allocator,
     and the kernel's ephemeral-port + TIME_WAIT bookkeeping.

---

## Server throughput (TFB plaintext)

The workload spec is `GET /plaintext` returning the 13-byte
body `Hello, World!` with `Content-Type: text/plain`,
HTTP/1.1 keep-alive on, no gzip, no logging. Mojo nightly is
pinned per the `[dependencies]` block in
[`pixi.toml`](../pixi.toml). Workload definitions live in
[`benchmark/configs/throughput.yaml`](../benchmark/configs/throughput.yaml).

The published headline numbers below are taken on the boxes
flare's release process targets (Apple M-series for the macOS
column, AWS EPYC 7R32 for the Linux column). Per-tag refreshes
land in the GitHub release notes for the matching tag; this
page tracks the methodology + most recent dev-box smoke.

### Single-worker, macOS Apple M-series

All rows are **single-worker** (`flare` 1 reactor, Go
`GOMAXPROCS=1`). This is the per-core request-processing
comparison; multi-worker numbers live in the next section.

| Server | Workers | Peak req/s | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|---:|
| **flare (reactor)** | 1 | **157,459** | 0.39 ms | 0.80 ms | **1.10x** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 143,500 | 0.44 ms | 0.86 ms | 1.00x |

flare is ~1.10x Go's stdlib `net/http` at the same worker count.

### Single-worker, Linux AWS EPYC 7R32

`Linux 6.8.0-1027-aws`, Mojo nightly, Go `1.24.13`, nginx `1.25.3`.
Different machine — absolute req/s is not comparable across the
macOS and Linux tables (different OS, scheduler, CPU); only the
intra-platform ratios are.

All rows are **single-worker** (flare 1 reactor, nginx
`worker_processes 1`, Go `GOMAXPROCS=1`).

| Server | Workers | Peak req/s | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|---:|
| nginx | 1 | 81,612 | 0.40 ms | 0.79 ms | 2.00x |
| **flare (reactor)** | 1 | **79,965** | 0.78 ms | 1.53 ms | **1.96x** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 40,739 | 1.59 ms | 3.10 ms | 1.00x |

flare sits within 2 % of nginx's single-worker throughput and is
about 1.96x Go `net/http` per core. The flare-vs-Go ratio is wider
on Linux (1.96x vs 1.10x) because Go's scheduler and `netpoll`
overhead is a larger share of each request on the slower EPYC core
than on an Apple M-series P-core. Absolute req/s is lower on EPYC
for reasons independent of flare; see
[the platform footnote](#platform-footnote).

### Tail latencies under sustained load (dev-box smoke)

The wrk2 two-phase harness produces full p50 / p99 / p99.9 /
p99.99 columns at 90 %-of-peak sustained load. Numbers below
are smoke-quality — taken on the maintainer's AWS Ubuntu 22.04
dev box (6 vCPU, glibc 2.35) at commit
[`9025444`](https://github.com/ehsanmok/flare/commit/9025444),
not the EPYC headline machine — but they prove the harness
works and demonstrate the tail-discipline shape flare's
release-tag numbers will carry.

| Workload | Server | Workers | Peak req/s | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stdev% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `throughput` | **flare** | 1 | **76,710** | **1.22** | **3.06** | **3.35** | **3.76** | 1.27 |
| `throughput` | Go `net/http` | 1 | 40,896 | 1.37 | 3.21 | 3.72 | 4.53 | 1.57 |
| `mixed_keepalive` | **flare** | 1 | **75,958** | **1.23** | **3.09** | **3.34** | **3.46** | 1.27 |
| `mixed_keepalive` | Go `net/http` | 1 | 41,027 | 1.38 | 3.22 | 3.77 | 4.57 | 1.57 |

Same single-worker discipline as the prior tables. flare
holds 1.87× Go's peak req/s; the tail stays disciplined out
to p99.99 (3.76 ms vs Go's 4.53 ms on `throughput`,
3.46 ms vs 4.57 ms on `mixed_keepalive`). The `mixed_keepalive`
configuration adds 20 % `Connection: close` to the load —
flare's close-after-disposition handling doesn't introduce
tail bumps. Both servers are stable under the 3 % stdev gate
across the 5-run measurement phase.

### Multi-worker scaling, Linux EPYC

**Worker-count discipline:** the tables below show two things,
kept separate because they answer different questions:

1. flare scaling its **own** worker count from 1 to 4 (the
   per-server scaling claim).
2. flare's 4-worker run against the three production-grade Rust
   web frameworks (`hyper`, `axum`, `actix_web`) at matched 4
   worker threads on the **same** Linux EPYC host.

We do **not** publish a "vs Go" or "vs nginx" ratio for the
4-worker `flare_mc` row, because the `bench_vs_baseline.sh` Go
and nginx baselines pin themselves to a single worker:
[`benchmark/baselines/go_nethttp/run.sh`](../benchmark/baselines/go_nethttp/run.sh)
exports `GOMAXPROCS=1`, and the nginx config in
[`benchmark/baselines/nginx/`](../benchmark/baselines/nginx/) sets
`worker_processes 1`. The Rust baselines all run on a 4-worker
tokio runtime (or 4-worker actix system), which is the
apples-to-apples shape.

`HttpServer.serve(handler, num_workers=N)` with `N >= 2` binds a
**single shared listener** and registers it in every worker's
reactor with `EPOLLEXCLUSIVE` (Linux ≥ 4.5). The kernel wakes
exactly one waiter per accept event in FIFO order across workers
blocked in `epoll_wait`, so a worker actively running a handler is
not woken — fair-by-construction across *idle* workers. The
earlier per-worker `SO_REUSEPORT` listener path hashed accepts by
5-tuple stateless of worker readiness; on a 64-core EPYC under
sustained 8-thread / 256-connection load that distribution was
fair on average but bimodal across single 30 s runs (one run
clean, the next p99 in the seconds because the hot worker's
queue stalled). The shared-listener path replaces that with
fair-accept across idle workers + sticky per-connection
execution; the `bind_reuseport` helper is preserved for
backwards-compat tests but no longer the default.

The load generator is
[`throughput_mc.yaml`](../benchmark/configs/throughput_mc.yaml)
(`wrk2 -t8 -c256 -d30s --latency`) with the calibrated
sustainable-peak harness from
[`bench_vs_baseline.sh`](../benchmark/scripts/bench_vs_baseline.sh).
The single-threaded `throughput.yaml` pins `wrk` to one thread and
64 connections, which cannot drive enough concurrent load to show
worker scaling no matter what the server does.

#### flare own worker scaling, EPYC 7R32, throughput_mc

| Server | Workers | Req/s (median) | stdev% | p50 | p99 | vs flare 1w |
|---|---:|---:|---:|---:|---:|---:|
| flare (single-threaded) | 1 | 53,589 | 0.21 | 0.97 ms | 2.04 ms | 1.00x |
| **flare_mc (shared listener)** | **4** | **146,068** | **0.35** | **1.07 ms** | **2.30 ms** | **2.73x** |

#### flare_mc vs Rust frameworks, EPYC 7R32, 4 worker threads, throughput_mc

| Target | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) | stable |
|---|---:|---:|---:|---:|---:|---:|---|
| actix_web | 263,970 | 0.21 | 1.19 | 2.84 | **21.06** | **26.74** | true |
| axum | 201,003 | 0.17 | 1.29 | 2.84 | 3.29 | 6.81 | true |
| hyper | 218,702 | 0.27 | 1.24 | 2.80 | 3.25 | 3.64 | true |
| **flare_mc (4 w, shared listener)** | **146,068** | **0.35** | **1.07** | **2.30** | **2.88** | **3.30** | true |
| flare (1 w) | 53,589 | 0.21 | 0.97 | 2.04 | 2.39 | 2.67 | true |

Reading order:

1. **Tail latency: flare_mc has the best p99 / p99.9 / p99.99 of
   the five frameworks** at this workload (p99 = 2.30 ms vs
   hyper 2.80 / axum 2.84 / actix_web 2.84; p99.99 = 3.30 ms vs
   hyper 3.64 / axum 6.81 / actix_web 26.74). actix_web's
   p99.99 spike is the same SO_REUSEPORT distribution variance
   the earlier multi-listener path fell into; actix_web also
   uses per-worker `SO_REUSEPORT` listeners by default, and the
   wrk2-corrected tail picks that up. axum / hyper run on the
   `tokio` multi-thread runtime with a single shared listener
   and work-stealing — the same kernel-fairness story flare_mc
   now adopts.
2. **Throughput: flare_mc lands at 53–67 % of the Rust
   frameworks** on this workload (146 K vs hyper 218 K, axum
   201 K, actix_web 263 K). This is the per-worker handler-cost
   gap, not a runtime-architecture gap; the tail numbers are the
   evidence the runtime architecture is now sound. flare does
   not claim throughput parity with hyper here.
3. **stdev across 5 runs: flare_mc 0.35 %**, well under the
   5 % stability gate, within noise of the Rust frameworks
   (0.17 – 0.27 %). The earlier SO_REUSEPORT bimodal (one run
   p99 = 2 ms, the next p99 = 1.7 s on the same binary) is gone.
4. **Single-worker no-regression: 53,589 req/s @ p99 = 2.04 ms**.
   The single-worker reactor loop and the public `serve` API are
   unchanged; the better p99 vs the earlier dev-box smoke
   (2.04 ms vs 3.06 ms) comes from the calibrated
   sustainable-peak harness being honest about the saturation
   knee, not from a runtime change.

The single-worker flare / nginx / Go comparison from the previous
section still applies per-core; multiplying by `N` workers is the
right rough sanity-check for what `flare_mc` at `N` workers looks
like next to `nginx` at `N` workers or Go with `GOMAXPROCS=N`,
modulo kernel-side cross-core costs. The published cross-server
multicore table is gated on actually running the apples-to-apples
matrix; see below.

On macOS loopback `flare_mc` saturates at ~140K req/s regardless
of worker count because `wrk` and the server compete for the same
single-client CPU. That ceiling is the testbed, not flare. The
4-worker `flare_mc` row is within noise of the 1-worker flare row
on macOS — exactly why the Linux table above is the headline.

### Multi-worker baselines: published (Rust) + pending (Go / nginx)

The matched-worker Rust comparison is published. `hyper`, `axum`,
and `actix_web` baselines live under
[`benchmark/baselines/`](../benchmark/baselines), pinned via
`Cargo.lock` and built on the same `rust 1.94 +
sysroot_linux-64 2.34.*` conda-forge toolchain. The numbers are
in the `flare_mc vs Rust frameworks` table above; the raw run
data is at
[`benchmark/results/throughput_mc-vs-rust/`](../benchmark/results/throughput_mc-vs-rust)
(env, integrity gate, per-target JSON, raw wrk2 stdout).

| Server | Workers | Status |
|---|---:|---|
| flare_mc (shared listener) | 4 | numbers above (Linux EPYC) |
| Rust hyper (tokio multi-thread, 4 worker threads) | 4 | published (Linux EPYC) |
| Rust axum (4 worker threads) | 4 | published (Linux EPYC) |
| Rust actix_web (4 worker threads) | 4 | published (Linux EPYC) |
| nginx | 4 (`worker_processes 4`) | not yet published; needs config + harness run |
| Go `net/http` | 4 (`GOMAXPROCS=4`) | not yet published; needs `run.sh` knob + harness run |

Until the nginx / Go multi-worker rows exist, the doc does not
assert "flare_mc is `Nx` of nginx multi-worker" or "flare_mc is
`Nx` of Go GOMAXPROCS=N". The single-worker per-core table
(above) and the matched-worker Rust comparison are the
apples-to-apples points flare commits to publishing.

Reproduce the multi-worker comparison on a Linux box with
multiple physical cores:

```bash
pixi run --environment bench bash benchmark/scripts/bench_vs_baseline.sh \
    --only=flare,flare_mc,hyper,axum,actix_web --configs=throughput_mc
```

### Platform footnote

Three things about the Linux column are deliberate, not "flare can
only hit 80K/s in production":

1. **`GOMAXPROCS=1`, `worker_processes 1`, and single-thread flare.**
   Every baseline runs on one logical core so the comparison is
   apples-to-apples about per-core request-processing cost. This
   models the cheapest hosting tier (one vCPU) rather than peak
   throughput on the box. Production deployments on either platform
   should scale with worker count (nginx, Go) or with `SO_REUSEPORT`
   sharding (flare).
2. **`wrk` and the server are not CPU-pinned.** On a 64-vCPU AWS
   instance the Linux scheduler migrates both processes across cores
   between slices, causing L1/L2 misses and occasional SMT-sibling
   contention. Pinning `wrk` and the server to two different
   physical cores on the same NUMA node typically recovers 15 to
   30 % for Go on EPYC (a known `net/http` behaviour on
   shared-scheduler Linux, which is also where the flare-vs-Go ratio
   shift between the two platforms comes from). The harness
   intentionally does not pin so the numbers match an un-tuned
   deployment.
3. **c5-class EC2 does not turbo like M-series.** Single-thread
   throughput on EPYC 7R32 is roughly half of an Apple M-series
   P-core for HTTP plaintext. That is microarchitecture, not a
   scheduler or runtime property. flare and nginx both drop by about
   2x between the two tables; Go drops by about 3.5x because its
   goroutine plus `netpoll` overhead is a bigger percentage of each
   request on the slower core.

---

## Soak: long-running operational gates

The throughput tables above answer "is it fast right now". The
soak harness answers "is it still alive at 4 a.m. on day 2".
Three operational signals microbenchmarks miss:

- **RSS over time** — does memory grow linearly, plateau, or
  spike under churn?
- **File descriptors** — are accept-loop / TLS / connection
  bookkeeping leaking fds under churn?
- **Tail-latency drift** — does p99 stay flat at hour 24 or does
  a slow pathology creep in?

### Three tiers, one harness

The driver lives in
[`benchmark/scripts/_run_soak.sh`](../benchmark/scripts/_run_soak.sh).
A single set of scripts runs at three tiers via the
`SOAK_DURATION_SECS` env knob (defaults to 60 s):

| Tier | Per-workload duration | Total wall time | When to run |
|---|---|---|---|
| **smoke** | 60 s | ~3 min | PR / iterative dev (`pixi run --environment bench bench-soak-smoke`) |
| **extended** | 300 s | ~15 min | Before pushing larger changes (`pixi run --environment bench bench-soak-extended`) |
| **release gate** | 86 400 s (24 h) | ~24 h per workload, ~3 days serial | Linux EPYC, manual one-shot pre-tag |

Release-gate invocation pattern (one workload per box-day, run
serially or in parallel on different EPYC boxes):

```bash
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-slow-clients
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-churn
SOAK_DURATION_SECS=86400 pixi run --environment bench bench-soak-mixed
```

Same `_run_soak.sh` driver, same `summary.json` schema, same gate
logic — only the duration changes. The 24 h gate is the
release-blocking one; smoke and extended are catch-loud-failures
filters.

### Workloads + gates

All three workloads target `/plaintext` on the flare bench server
boot from
[`benchmark/baselines/flare/main.mojo`](../benchmark/baselines/flare/main.mojo)
— the **same** entry point the bench-vs-baseline throughput
harness uses, so soak numbers are directly comparable to the
single-worker throughput tables above. The wrk lua scripts live
in
[`benchmark/scripts/wrk_soak_*.lua`](../benchmark/scripts/).

#### slow-client

256 concurrent connections, each issuing a short POST request
every ~100 ms (wrk's `delay()` model is the closest approximation
to "1 byte / 100 ms" inside wrk's protocol shape). Gate:

- **`pass = errors == 0 && rss_end <= 2 * rss_start`**
- 24 h release-gate variant additionally requires `rss_end ≈
  rss_start` after the first hour (RSS-flat).

The lua approximation does not byte-trickle inside a single
request body the way a true byte-trickle harness would; the
`read_body_timeout_ms` deadline path is exercised end-to-end in
[`tests/test_server_deadlines.mojo`](../tests/test_server_deadlines.mojo)
instead. Soak covers the resource-exhaustion shape (many
connections held under pressure).

#### churn

64 concurrent connections, every request sets `Connection: close`
so the server closes after each response. wrk reopens for the
next request. Effective rate is bounded by ephemeral-port
turnover. Gate:

- **`pass = errors == 0 && fd_end <= fd_start + 16`**
- 16-fd slack covers timer / wakeup / log fds beyond the
  per-connection fds. The `fd_end` measurement happens after a
  3 s post-wrk drain pause so in-flight connections finish their
  close handshake before the observer's last sample.

#### mixed

64 concurrent connections, ~20 % tagged with `Connection: close`
(every 5th request), the remaining 80 % standard HTTP/1.1
keep-alive. Catches regressions in the connection-disposition
path that pure keep-alive load doesn't exercise. Gate:

- **`pass = errors == 0 && rss_end <= 2 * rss_start`**

### Output schema

Each per-workload run writes
`build/soak/<workload>/<timestamp>-<host>-<commit>/summary.json`
with the following fields. The schema is stable so EPYC release-
gate runs can be aggregated by per-tag publication tooling without
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
- `observer.stderr` — observer-side stderr.

### Dev-box smoke + extended results (Ubuntu 22.04, 6 vCPU AWS)

These are NOT release-gate numbers. They are smoke artefacts
captured on the maintainer's AWS Ubuntu 22.04 dev box (glibc
2.35, x86_64) at commit
[`9755049`](https://github.com/ehsanmok/flare/commit/9755049).
The release-gate p99.9 / p99.99 numbers + 24 h flat-RSS proof are
captured on Linux EPYC and live in the per-tag release notes.

What the tables prove on this hardware: the harness fires
cleanly, the gates evaluate against real data, and the dev-box
server holds steady under all three workloads at the smoke +
extended durations (no crashes, no fd leaks, RSS within ~1 % of
cold-start across both tiers).

#### Smoke tier (60 s/workload, ~3 min total)

| Workload | req/s | Total req | p50 (ms) | p99 (ms) | RSS start (KB) | RSS end (KB) | RSS max (KB) | fd start | fd end | fd max | non-2xx | Pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| slow-client | 2 546.4 | 152 948 | 0.18 | 1.07 | 192 588 | 194 124 | 194 124 | 55 | 55 | 311 | 0 | yes |
| churn | 27 805.5 | 1 668 403 | 2.00 | 2.34 | 193 488 | 194 000 | 194 000 | 55 | 55 | 119 | 0 | yes |
| mixed | 49 544.7 | 2 972 718 | 1.01 | 2.76 | 193 492 | 194 004 | 194 004 | 55 | 55 | 119 | 0 | yes |

#### Extended tier (300 s/workload, ~15 min total)

| Workload | req/s | Total req | p50 (ms) | p99 (ms) | RSS start (KB) | RSS end (KB) | RSS max (KB) | fd start | fd end | fd max | non-2xx | Pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| slow-client | 2 547.8 | 764 471 | 0.19 | 0.85 | 193 492 | 195 028 | 195 028 | 55 | 55 | 311 | 0 | yes |
| churn | 27 805.0 | 8 341 534 | 1.99 | 2.34 | 194 196 | 194 708 | 194 708 | 55 | 55 | 119 | 0 | yes |
| mixed | 50 072.9 | 15 021 927 | 0.99 | 2.70 | 192 152 | 192 664 | 192 664 | 55 | 55 | 119 | 0 | yes |

Two cross-tier observations:

- **RSS deltas are essentially identical** between smoke (60 s)
  and extended (300 s): ~0.5–1.5 MB across all three workloads
  in both tiers. A 5x duration increase did not produce a 5x
  RSS increase — per-request allocator churn is bounded rather
  than leaking. The 24 h gate is what pins this assertion
  long-term.
- **fd_count returns to baseline** in both tiers across all
  workloads (`fd_end == fd_start == 55`). The 3 s post-wrk drain
  pause documented at the top of
  [`_run_soak.sh`](../benchmark/scripts/_run_soak.sh) is what
  makes this measurement honest — without it the observer
  would race wrk-exit and report ~30–250 in-flight fds as a
  false-positive "leak".

### Limitations

- **Linux only.** `/proc/<pid>/status` is the RSS source; macOS
  would need `ps -o rss=` fallback. The release gate runs on
  Linux EPYC anyway.
- **wrk-driven slow-client is an approximation** — see the
  slow-client section above. The byte-trickle path is exercised
  by unit tests instead.
- **The smoke and extended tiers cannot prove "RSS flat after 1
  hour"** — that signal lives only in the 24 h release-gate
  run. Smoke / extended catch only loud failures (server died,
  RSS doubled, fds leaked beyond a small constant).

---

## Methodology

The TFB plaintext workload (TechEmpower test #6) is `GET /plaintext`
returning the 13-byte body `Hello, World!` with `Content-Type:
text/plain`, HTTP/1.1 keep-alive on, no gzip, no logging.

Measurement rules:

- **Response-byte integrity:** before any measurement round, each
  baseline is probed once and its response bytes are diffed against
  the workload spec. A target producing a different status, body
  length, or non-whitelisted header is **rejected** before the
  measurement starts. Headers allowed to vary per target: `Date`,
  `Server`, `Connection`, `Keep-Alive`.
- **Pinned toolchains:** Go and nginx pin to `[feature.bench.
  dependencies]`; the conda-forge `wrk` package is on PATH for
  ad-hoc use; **wrk2** is built from a pinned commit by
  `bench-install-wrk2` (the harness drives wrk2 explicitly via
  `build/wrk2/wrk2`, not whatever `wrk` is on PATH).
- **Two-phase wrk2:** each (target, config) tuple runs one
  `warmup_seconds` find-peak phase at `-R 10000000` (saturates
  any flare-grade server), then five `wrk_duration_seconds`
  measurement rounds at `-R = peak * sustain_rps_pct%` (default
  90 %). The headline req/s is the peak from phase 1; the
  latency distribution is the median of the middle three runs
  from phase 2. The run **fails the stability gate** if stdev
  on phase-2 req/s exceeds 3 %.
- **Load generator:** wrk2 with `--latency` for the headline
  bench (CO-corrected tail percentiles up to p99.999). The
  conda-forge `wrk` package is still on PATH for ad-hoc use.
  Never `ab` or `h2load`, for consistency with published
  TFB-style numbers. Two configs ship today —
  [`throughput.yaml`](../benchmark/configs/throughput.yaml) (`-t1
  -c64 -d30s`) for per-core request-processing cost, and
  [`throughput_mc.yaml`](../benchmark/configs/throughput_mc.yaml)
  (`-t8 -c256 -d30s`) for saturating a thread-per-core server. Server
  and `wrk` run on the same host over loopback.
- **Per-run provenance:** every run writes its own directory under
  `benchmark/results/<yyyy-mm-ddTHHMM>-<host>-<git-sha>/` containing
  `env.json` (CPU model, OS, kernel tunables, exact toolchain
  versions), `integrity.md`, per-tuple result JSONs, `summary.md`,
  and raw `wrk` stdout under `RAW/`.

This protocol (integrity check, pinned toolchains, 5-run median with
stdev gate) is stricter than TFB's own single 15 s round on shared
hardware. It is closer to the reproducibility setups in
[simdjson](https://github.com/simdjson/simdjson/blob/master/doc/performance.md)
and [rapidjson](https://rapidjson.org/md_doc_performance.html).

---

## HTTP parsing microbenchmark

Apple M-series (`pixi run bench-compare`):

| Operation | Latency |
|---|---|
| Parse HTTP request (headers + body) | 1.7 us |
| Parse HTTP response | 2.2 us |
| Encode HTTP request | 0.7 us |
| Encode HTTP response | 0.9 us |
| Header serialization | 0.12 us |

On EPYC 7R32 (Linux, AVX2) the same ops are about 1.4x slower
per-op (e.g. request parse 2.35 us, response parse 6.45 us),
consistent with the single-core throughput gap in the
server-throughput tables above. Run `pixi run bench-compare` on
either platform to reproduce.

A reminder from the criticism: a parser is not the bottleneck on a
13-byte response. The microbenchmark is useful as a guard against
parser regressions, not as a headline.

---

## WebSocket SIMD masking

RFC 6455 requires XOR-masking every client-to-server byte. SIMD gives
a 14-35x speedup for payloads above 128 bytes.

Apple M-series (NEON, SIMD-32):

| Payload | Scalar | SIMD-32 |
|---|---|---|
| 1 KB | 3.2 GB/s | 112.6 GB/s |
| 64 KB | 3.4 GB/s | 47.8 GB/s |
| 1 MB | 3.4 GB/s | 54.8 GB/s |

EPYC 7R32 (Linux, AVX2, SIMD-32) is in the same regime — peak
90.6 GB/s at 1 KB (58x scalar), 52.8 GB/s at 64 KB, 34.7 GB/s at
1 MB — about 20 % under Apple M-series at the L1-resident sizes
and within noise at the L2/L3-resident sizes.

---

## Reproduce locally

```bash
# Throughput + tail percentiles (the single-worker headline numbers above)
pixi run --environment bench bench-install-wrk2        # one-time build (pinned wrk2 commit)
pixi run --environment bench bench-vs-baseline-quick   # flare vs Go on throughput, ~7 min
pixi run --environment bench bench-vs-baseline         # + nginx + latency_floor, ~20 min

# Mixed-keepalive (80% keep-alive, 20% close)
pixi run --environment bench bench-mixed-keepalive

# Ad-hoc tail percentile probe (no integrity check, no 5-run gate)
pixi run --environment bench bench-tail-quick          # wrk2 --latency at fixed rate

# TLS bench setup (self-signed cert under build/)
pixi run --environment bench bench-tls-setup
```

The TLS bench configs `tls_plaintext.yaml` (steady-state TLS
throughput, connections kept open) and `tls_handshake.yaml`
(handshake-per-request, `Connection: close`) are wired into the
harness and drive a TLS-terminating flare server on
`127.0.0.1:8443`. The reactor-state-machine TLS handshake that
ties these configs into the cancel-aware reactor loop is a
follow-up; the blocking `handshake_fd(fd)` path the configs use
today is in place.

Results land under `benchmark/results/<timestamp>-<host>-<commit>/`.
