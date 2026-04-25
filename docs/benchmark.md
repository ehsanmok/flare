# Benchmarks

Reproducible measurements with pinned toolchains, integrity-gated
baselines, and a 5-run median with stdev gate. Numbers below are from
v0.4.1 on the workloads that have stabilised; the v0.5 redesign (wrk2
+ tail percentiles + mixed workloads) is in progress and called out
where it lands.

If you only want one number, the
[`Server throughput (TFB plaintext)`](#server-throughput-tfb-plaintext)
table on Linux is the closest to a production-shape headline.

---

## v0.5 methodology change (in progress)

The v0.4.x harness used `wrk -t1 -c64 -d30s` against a 13-byte
plaintext body. That measures peak request-processing cost on a
single core for a trivial response. Real services live somewhere
else: tail-of-tail latency under contention, body sizes spread across
multiple orders of magnitude, mixed keep-alive vs. close, slow
clients, cert handshake handling, churn.

The v0.5 redesign is therefore three changes:

1. **`wrk` → `wrk2`**, run in constant-throughput mode (`wrk2 -R`).
   `wrk` reports latency as time spent waiting for *responses*, not
   time spent waiting for *the load generator to be ready to send the
   next request*. That's the
   [coordinated-omission](https://highscalability.com/blog/2015/10/5/your-load-generator-is-probably-lying-to-you-take-the-red-pi.html)
   bug and it makes p99.9 / p99.99 unreliable. `wrk2` fixes it.

   *Status (v0.5.0 Step 1):* the `wrk2` switch is staged but not
   yet on the wire — `conda-forge` does not currently pin a `wrk2`
   build for `linux-64`, and the `pixi`-pinned bench env is the
   one place v0.4.x committed to. The harness change lands once
   the env is repinned (a small standalone commit; the YAML
   schema and the per-config `wrk_script` field below already
   accommodate `wrk2` invocation). Until then, bench numbers in
   this doc stay on `wrk` (the v0.4.1 baseline).

2. **Tail percentiles** — p50, p90, p99, **p99.9, p99.99** —
   replace the single p50 / p99 row once `wrk2` is on the wire.

3. **Multiple workloads**, not one:
   - `micro-static` (the v0.4.x parity gate against
     [`plaintext.yaml`](../benchmark/workloads/plaintext.yaml))
   - **`mixed-keepalive`** (80 % keep-alive, 20 % `Connection:
     close`,
     [`mixed_keepalive.yaml`](../benchmark/configs/mixed_keepalive.yaml)
     + a wrk Lua script at
     [`benchmark/scripts/wrk_mixed_keepalive.lua`](../benchmark/scripts/wrk_mixed_keepalive.lua)).
     **Landed in v0.5.0 Step 1.** Run with:
     ```bash
     pixi run --environment bench bench-mixed-keepalive
     ```
     Catches regressions in flare's keep-alive book-keeping and
     close-after disposition that pure keep-alive loads can't
     exercise.
   - `uploads` (POSTs of 4 KB / 64 KB / 1 MB / 16 MB) — needs the
     streaming-body work; **lands in v0.5.0 Step 2**.
   - `downloads` (GETs returning 4 KB / 64 KB / 1 MB / 16 MB
     streamed bodies) — needs the streaming-body work; **lands in
     v0.5.0 Step 2**.
   - `slow-clients` (256 connections, each sending 1 byte / 100 ms,
     server holds) — exercises the
     `read_body_timeout_ms` deadline that landed in v0.5.0
     Step 1; the harness version of the workload sits behind the
     same `wrk2` repin as above.
   - `churn` (10 K open / send / close cycles per second) — same
     story; harness lands with the env repin.

The Linux throughput table below stays as the v0.4.1 wrk baseline
so the release-to-release regression check has a stable signal.

---

## Server throughput (TFB plaintext)

Measured on Apple M-series (macOS) and AWS EPYC 7R32 (Linux),
Mojo `0.26.3.0.dev2026042005` nightly. The workload spec lives at
[`benchmark/workloads/plaintext.yaml`](../benchmark/workloads/plaintext.yaml).

### macOS, Apple M-series

| Server | Req/s (median) | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|
| **flare (reactor)** | **157,459** | 0.39 ms | 0.80 ms | **1.10x** |
| Go `net/http` (1 thread) | 143,500 | 0.44 ms | 0.86 ms | 1.00x |

flare is roughly 1.10x faster than Go's stdlib `net/http` at the
same thread count, a roughly 3x jump over the v0.2.0 blocking server.

### Linux, AWS EPYC 7R32 (64 vCPU)

`Linux 6.8.0-1027-aws`, Mojo `0.26.3.0.dev2026042005`, Go `1.24.13`,
nginx `1.25.3`, `wrk` `d40fce9`. Same harness, different machine —
absolute req/s is not comparable across the two tables (different
OS, scheduler, CPU); only the intra-platform ratios are.

| Server | Req/s (median) | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|
| nginx (1 worker) | 81,612 | 0.40 ms | 0.79 ms | 2.00x |
| **flare (reactor)** | **79,965** | 0.78 ms | 1.53 ms | **1.96x** |
| Go `net/http` (1 thread) | 40,739 | 1.59 ms | 3.10 ms | 1.00x |

On Linux flare sits within 2 % of nginx's single-worker throughput
and is about 1.96x Go `net/http`. The flare-vs-Go ratio is wider on
Linux (1.96x vs 1.10x) because Go's scheduler and `netpoll` overhead
is a larger share of each request on the slower EPYC core than on an
Apple M-series P-core. Absolute req/s is lower on EPYC for reasons
independent of flare; see [the platform footnote](#platform-footnote).

### Multicore on Linux EPYC

`HttpServer.serve(handler, num_workers=N)` with `N >= 2` binds N
`SO_REUSEPORT` listeners on N pthread workers. The load generator is
[`throughput_mc.yaml`](../benchmark/configs/throughput_mc.yaml) (`wrk
-t8 -c256 -d30s`) — the single-threaded `throughput.yaml` config
pins `wrk` to one thread and 64 connections, which cannot drive
enough concurrent load to show worker scaling no matter what the
server does.

| Server | Req/s (median) | stdev% | p50 | p99 | vs Go | vs 1-thread flare |
|---|---:|---:|---:|---:|---:|---:|
| Go `net/http` | 36,613 | 0.99 | 6.98 ms | 13.37 ms | 1.00x | 0.62x |
| flare (single-threaded) | 58,812 | 2.89 | 4.41 ms | 4.64 ms | 1.61x | 1.00x |
| nginx (1 worker) | 70,592 | 1.63 | 3.53 ms | 4.23 ms | 1.93x | 1.20x |
| **flare_mc (4 workers, pinned)** | **257,461** | **1.56** | **0.97 ms** | **1.58 ms** | **7.03x** | **4.38x** |

`flare_mc` at 4 pinned workers is **4.38x** the single-threaded flare
reactor — near-linear scaling — **3.65x nginx (1 worker)**, and
**7.03x Go `net/http`**. Tail latency collapses from 4.64 ms p99
(single-thread flare, saturated on 256 concurrent connections) to
1.58 ms p99 (multicore), because each worker gets its own
un-contended reactor. The flare-vs-Go gap widens here (7x vs 2x
under single-thread `throughput`) because Go's `net/http` +
`netpoll` overhead grows faster than flare's `SO_REUSEPORT` sharding
as concurrency climbs on a slower EPYC core.

On macOS loopback (`-t1 -c64 -d30s`) `flare_mc` saturates at
~140K req/s regardless of worker count because `wrk` and the server
compete for the same single-client CPU. That ceiling is the testbed,
not flare:

| Server | Req/s (median) | stdev% | vs 1-thread flare |
|---|---:|---:|---:|
| flare (single-threaded) | 149,597 | 1.56 | 1.00x |
| flare_mc (4 workers, pinned) | 148,694 | 2.51 | **0.99x** (saturated) |
| Go `net/http` (`GOMAXPROCS=1`) | 140,560 | 0.64 | 0.94x |

The 4-worker `flare_mc` row is within noise of the 1-worker flare row
— which is exactly why the Linux table above exists. Run it yourself
with:

```
pixi run --environment bench -- bash benchmark/scripts/bench_vs_baseline.sh \
    --only=flare,flare_mc,go_nethttp,nginx --configs=throughput_mc
```

on a Linux box with multiple physical cores.

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
- **Pinned toolchains:** Go and `wrk` versions are pinned in
  `pixi.toml` under `[feature.bench.dependencies]` so the comparison
  does not silently drift across machines. v0.5 adds `wrk2` to the
  same pin.
- **Warmup + 5-run measurement:** each (target, config) tuple runs
  one 10 s warmup followed by five 30 s measurement rounds. The
  median of the middle three is reported. The run **fails the
  stability gate** if stdev exceeds 3 %.
- **Load generator:** `wrk` for v0.4.x, transitioning to `wrk2` in
  v0.5. Never `ab` or `h2load`, for consistency with published
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
# v0.4.1 baseline (wrk, the headline numbers above)
pixi run --environment bench bench-vs-baseline-quick   # flare vs Go, ~7 min
pixi run --environment bench bench-vs-baseline         # + nginx + latency_floor, ~20 min

# v0.5.0 Step 1 — mixed-keepalive workload (80% keep-alive, 20% close)
pixi run --environment bench bench-mixed-keepalive
```

Results land under `benchmark/results/<timestamp>-<host>-<commit>/`.

The full v0.5 matrix (`wrk2` / tail percentiles / uploads /
downloads / slow-clients / churn / 24-hour soak) is staged with
the Tracks that unlock each one (streaming bodies, server TLS,
the bench env repin for `wrk2`). See
[`operational-guarantees.md`](operational-guarantees.md) for the
release each row targets.
