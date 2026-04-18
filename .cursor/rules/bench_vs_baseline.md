# Flare vs Industry Baselines: Realistic Single-Threaded Targets

This document sets realistic performance targets for flare's HTTP server against
industry-standard single-threaded web servers, and defines the benchmark
methodology to measure progress consistently.

---

## 1. Current Position

Flare's HTTP server as of Stage 1 (local commit `7588ac2`, unreleased):

- **Throughput**: ~121K req/s plaintext, single-threaded, wrk loopback,
  Apple M-series (macOS 25.3, mojo 0.26.3.0.dev2026041520)
- **I/O model**: **single-threaded reactor** (kqueue on macOS, epoll on Linux)
  via libc FFI. Non-blocking sockets, per-connection state machine.
- **Parsing**: zero-copy header parsing, 8KB buffered reads.
- **Keep-alive**: HTTP/1.1, `readable → writable` collapsed in one event
  iteration to avoid extra reactor round-trips.

Compared to v0.2.0's ~50K req/s blocking baseline, Stage 1 more than
doubles plaintext throughput while keeping the public API byte-for-byte
identical.

### Latest benchmark (local M-series, 2026-04-18)

| Target                 | Req/s (median) | stdev% | p50 (ms) | p99 (ms) | vs Go net/http |
|------------------------|---------------:|-------:|---------:|---------:|---------------:|
| **flare** (Stage 1)    |    **121,807** |   0.81 |     0.52 |     1.05 |       **0.86x** |
| go_nethttp (1 thread)  |        141,161 |   0.34 |     0.45 |     0.85 |          1.00x |
| go_fasthttp (1 thread) |        266,595 |   0.10 |     0.20 |     0.34 |          1.88x |

Methodology: wrk `-t1 -c64 -d30s --latency`, 5 runs, median of middle 3,
variance-gated at stdev/mean < 3%, full integrity check beforehand (every
target's /plaintext body byte-diffed against the 13-byte spec). See
`benchmark/scripts/bench_vs_baseline.sh` and
`benchmark/results/<ts>-<host>-<commit>/summary.md` for raw outputs.

Progression within Stage 1:
- After Phase 1.5 (reactor replaces blocking server): 105,148 req/s
- After Phase 1.7 optimisation passes: **121,807 req/s** (+16%)

**Gap to the Phase 1.7 milestone gate** (flare ≥ 1.10× Go net/http):
we're at 0.86× of Go net/http (need 1.10×, so ~27% more req/s).
Remaining levers we know about but haven't landed:
- Comptime specialisation of `HttpServer.serve[handler]` so the handler
  inlines into `on_readable` (currently an uninlinable runtime function
  pointer).
- Pre-cached response bytes for identical `(status, headers, body)`
  tuples (the TFB plaintext case in particular).
- `writev` for header + body instead of one concatenated buffer.
- io_uring on Linux — Stage 3, not this stage.

Blocking I/O on a single thread has a hard architectural ceiling around
100-200K req/s. Flare is solidly inside that ceiling now; further gains
need compiler-level or syscall-batching work.

---

## 2. Tier Map of Single-Threaded HTTP Servers

Numbers are "hello world" plaintext, single thread/worker, wrk loopback on
modern x86_64. Order-of-magnitude only — hardware and kernel tuning move these
numbers significantly.

| Tier | Server | Language | Req/s (1 thread) | I/O model |
|---|---|---|---|---|
| **Flare today** | flare | Mojo | ~50K | blocking |
| **Approachable** | Node.js `http` | JS | 30-50K | libuv async |
| | Python uvloop + httptools | Python | 40-70K | async |
| **Next step up** | Go `net/http` (`GOMAXPROCS=1`) | Go | 80-150K | goroutines on epoll |
| | nginx (1 worker, static) | C | 100-200K | epoll |
| **Mid-tier realistic** | Go `fasthttp` (`GOMAXPROCS=1`) | Go | 250-400K | epoll + zero-alloc parser |
| | Rust `hyper` minimal (1 worker) | Rust | 300-500K | tokio/epoll |
| | Rust `actix-web` (1 worker) | Rust | 300-450K | tokio/epoll |
| | drogon (1 thread) | C++ | 300-500K | epoll |
| **Single-threaded kings** | may_minihttp | Rust | 500-700K | stackful coroutines |
| | h2o (1 thread) | C | 400-600K | epoll + custom parser |
| | picohttp / picoev | C | 500-700K | hand-tuned event loop |
| | **uWebSockets** (1 thread) | C++ | **800K-1M+** | epoll + zero-alloc + SSE |

uWebSockets is the ceiling reference, not a target. It assumes a world-class
event loop, hand-tuned C++, per-CPU-cache tricks, and non-standard parsing.
Matching it from blocking I/O is not physically possible.

---

## 3. Realistic Milestones

Targets are ordered by achievability given flare's current architecture. Each
milestone requires completing the previous one.

### Milestone 1: Beat Go `net/http` with `GOMAXPROCS=1` (near-term)

- **Current gap**: ~2-3x
- **Why this one**: Go `net/http` is the industry baseline. Every backend
  engineer has an intuition for it. Beating it from Mojo blocking I/O is a
  credible, defensible headline.
- **How**: better parser (already 9x faster than lightbug), tighter syscall
  loop, possibly batched writes via `writev`, response encoding into a single
  stack buffer when size is known, skip `setsockopt` when timeouts are 0.
- **Expected ceiling from this**: ~120-180K req/s on M-series, before hitting
  the blocking-I/O wall.

### Milestone 2: Match Go `fasthttp` with `GOMAXPROCS=1` (stretch, still blocking I/O)

- **Current gap**: ~5-8x
- **Why this one**: `fasthttp` is a hand-tuned zero-allocation Go server. Being
  within 50% of it from blocking I/O means flare's parsing, allocation, and
  socket paths are world-class for the model.
- **How**: eliminate remaining allocations on the hot path (request builder,
  response builder), comptime-build common response prefixes, arena-style
  reusable buffers across keep-alive requests, SIMD for common header scans.
- **Expected ceiling from this**: ~200-300K req/s, near the blocking-I/O wall.

### Milestone 3: Match Rust `hyper` with 1 worker (requires async)

- **Current gap**: ~6-10x
- **Why this one**: `hyper` is the canonical Rust async HTTP server. Matching
  it means flare has real async I/O — epoll on Linux, kqueue on macOS — and
  can handle C10K+ from one thread.
- **How**: full async rewrite once Mojo asyncio is mature enough. This is a
  different architectural generation of flare, not an optimization of the
  current one.

### Milestone 4: Touch h2o / may_minihttp (long-term)

- **Current gap**: ~10-15x
- **Why this one**: These are the single-threaded kings short of uWebSockets.
  Reaching them means SIMD header parsing, pipelining, branch-predicted fast
  paths for common request shapes, custom allocators.
- **When**: year+ after Milestone 3.

---

## 4. Benchmark Sources

| Source | What's there | Why it matters |
|---|---|---|
| [TechEmpower Framework Benchmarks](https://www.techempower.com/benchmarks/) | 600+ frameworks, reproducible Docker setups, per-test rankings (plaintext, JSON, db, updates, fortunes). **Gold standard.** | Every framework's numbers here. Published ~2x/year. Exact setup reproducible locally. |
| [the-benchmarker/web-frameworks](https://github.com/the-benchmarker/web-frameworks) | Single-repo side-by-side benchmarks for 100+ frameworks using wrk. Docker-based. | More approachable than TFB for quick comparisons. Same wrk methodology flare already uses. |
| [uWebSockets benchmarks](https://github.com/uNetworking/uWebSockets/tree/master/benchmarks) | uWS's own numbers and comparison scripts. | Lets you reproduce the ceiling on your hardware. |
| [Rust hyper benchmarks](https://github.com/hyperium/hyper/tree/master/benches) | Hyper's own suite. | Canonical Rust async numbers. |
| [fasthttp benchmarks](https://github.com/valyala/fasthttp#http-server-performance-comparison-with-nethttp) | fasthttp vs net/http comparison. | Easy reference. |
| [h2o benchmarks](https://h2o.examp1e.net/benchmarks.html) | Official h2o numbers. | Reference for the C tier. |

---

## 5. Benchmark Methodology (to standardize)

All comparisons in this document and in future flare reports must use the
following setup to be apples-to-apples.

### 5.1 Hardware + OS baseline

Record with every run:

- CPU model, core count, frequency governor setting
- OS and kernel version
- Loopback MTU (`ifconfig lo` on macOS, `ip link show lo` on Linux)
- TCP tuning: `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog` (Linux)

### 5.2 Canonical wrk invocation

```bash
# Warmup
wrk -t1 -c64 -d10s http://127.0.0.1:8080/plaintext

# Measurement (report this)
wrk -t1 -c64 -d30s --latency http://127.0.0.1:8080/plaintext
```

Rationale:
- `-t1`: single wrk thread so client isn't the bottleneck but doesn't
  oversaturate a single-threaded server with synthetic concurrency
- `-c64`: enough open connections to measure keep-alive behaviour; not so
  many that queue buildup dominates
- `-d30s`: long enough for JIT / TLB / cache effects to settle, short enough
  to iterate
- `--latency`: reports p50/p99/max which are required to detect tail-latency
  regressions (remember the 151 → 0 timeout fix)

Also report `wrk -t1 -c1 -d30s` (single-connection latency floor) for
per-request cost comparison.

### 5.3 Server endpoint

All servers must serve the exact same response for the comparison to be
meaningful:

```
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
Content-Length: 13

Hello, World!
```

No gzip, no cookies, no logging. Keep-alive enabled on both sides. This
matches the TFB "plaintext" test.

### 5.4 What to record

Per run, in `benchmark/results/<yyyy-mm-dd>-<server>-<config>.md`:

| Field | Example |
|---|---|
| Server | flare v0.2.0 / Go 1.23 net/http / fasthttp v1.55 |
| Config | 1 thread, keep-alive on, no timeouts |
| wrk invocation | `wrk -t1 -c64 -d30s ...` |
| Requests/sec | 50,035 |
| Transfer/sec | 7.23 MB |
| Latency p50 | 1.2 ms |
| Latency p99 | 3.8 ms |
| Latency max | 12.1 ms |
| Timeouts | 0 |
| Socket errors | 0 |

---

## 6. Concrete Near-Term Plan

Write a reproducible comparison harness that runs flare against the three
primary baselines on identical hardware with identical wrk config.

### 6.1 Targets

Ordered by priority:

1. **Go `net/http`** (`GOMAXPROCS=1`) — primary target, the one flare must
   beat to claim industry competitiveness.
2. **Go `fasthttp`** (`GOMAXPROCS=1`) — stretch target, ceiling of
   blocking-I/O-friendly Go.
3. **nginx** (1 worker, static "Hello, World!") — sanity baseline for the C
   tier and a reference for "how fast can a mature production HTTP server go
   on this hardware".

### 6.2 Harness layout

```
benchmark/
  baselines/
    go_nethttp/
      main.go              # net/http hello-world server
      run.sh               # GOMAXPROCS=1 go run main.go
    go_fasthttp/
      main.go              # fasthttp hello-world server
      run.sh               # GOMAXPROCS=1 go run main.go
    nginx/
      nginx.conf           # 1 worker, static text response
      run.sh               # nginx -c ./nginx.conf
  scripts/
    bench_vs_baseline.sh   # runs all 4 servers, records results
  results/
    <yyyy-mm-dd>-<server>.md
```

### 6.3 Driver script contract

`bench_vs_baseline.sh` must:

1. Start one server at a time on `127.0.0.1:8080`
2. Warm up: `wrk -t1 -c64 -d10s`
3. Measure 3 runs: `wrk -t1 -c64 -d30s --latency`
4. Take the median req/s of the three runs
5. Also record `wrk -t1 -c1 -d30s --latency` for single-connection latency
6. Stop the server cleanly
7. Write `results/<yyyy-mm-dd>-<server>-<commit>.md` with the full wrk output

### 6.4 Reporting

Generate a summary table in `benchmark/results/README.md` after each run:

```
| Server            | Req/s (median) | p50     | p99    | vs flare |
|-------------------|----------------|---------|--------|----------|
| flare v0.2.0      | 50,035         | 1.2 ms  | 3.8 ms | 1.00x    |
| Go net/http (1t)  | 130,000        | 0.48 ms | 1.2 ms | 2.60x    |
| Go fasthttp (1t)  | 340,000        | 0.18 ms | 0.6 ms | 6.79x    |
| nginx (1 worker)  | 175,000        | 0.36 ms | 1.0 ms | 3.50x    |
```

This becomes the public narrative: "flare is X% of Go stdlib on a single
thread" is a clear, defensible, reproducible claim.

---

## 7. Non-Goals

Explicit non-targets for now. Revisit when async lands.

- **uWebSockets**, **may_minihttp**, **h2o**, **picoev** — all require
  event-loop I/O. Referenced only as ceilings.
- **Multi-threaded throughput** — flare is single-threaded by design until
  Mojo asyncio stabilizes. TFB's multi-thread plaintext numbers (5M+ req/s)
  are not a target.
- **HTTPS/TLS throughput** — separate benchmark track. Needs its own harness
  with OpenSSL session reuse tuning before it's apples-to-apples.
- **HTTP/2** — out of scope for flare v0.2 line entirely.

---

## 8. Status

| Item | State |
|---|---|
| Baseline harness (Go net/http, fasthttp, nginx) | **DONE** — `pixi run --environment bench bench-vs-baseline` |
| First comparison run vs Go `net/http` | **DONE** — flare = 0.86× |
| First comparison run vs `fasthttp` | **DONE** — flare = 0.46× |
| First comparison run vs nginx | **IN PROGRESS** — nginx config needs macOS fix (current run shows broken values) |
| `benchmark/results/README.md` summary table | **DONE** |
| Milestone gate: flare ≥ 1.10× Go net/http | **NOT YET MET** (at 0.86×) |
| Phase 1.8 hardening: soak tests | Deferred — covered by benchmark harness 30s-per-run wrk coverage until we have a thread primitive |
| Phase 1.8 hardening: 7-day nightly green | **Calendar-gated** — clock starts once commits land on main |

Section 1 ("Current Position") has the measured gap and the list of
remaining perf levers. Re-run `pixi run --environment bench
bench-vs-baseline` after any hot-path change and commit the
`benchmark/results/<dated>/summary.md` snapshot.
