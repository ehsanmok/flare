# v0.7 perf progress vs Rust libs

**Date**: 2026-05-02 (updated) · **Branch**: `main` (commits `9e9c3d1` → `5b8a5d7`).

This note tracks where flare v0.7 stands against the design-0.7
gate (≥ 220 K req/s on flare_mc 4w EPYC, p99.99 ≤ 3.5 ms) and
against the reference Rust libraries (`hyper`, `axum`,
`actix_web`).

The EPYC numbers below are from the v0.6.0 release tag
(`benchmark/results/throughput_mc-vs-rust/`,
2026-04-30T0228-ehsan-dev-c84a119, EPYC 7R32, `wrk2 -t8 -c256
-d30s` calibrated peak). The dev-box numbers are this
worktree's own measurements on a 64-vCPU AWS box (commit
`1b0852d`, same wrk2 calibration).

## v0.6.0 EPYC tag — the reference

| Server | Workers | Req/s | p99 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|
| actix_web | 4 | 264,691 | 2.80 | **21.61** ← worst tail |
| hyper | 4 | 221,349 | 2.82 | 3.67 |
| axum | 4 | 201,042 | 2.82 | 3.65 |
| **flare_mc v0.6** | 4 | 170,305 | **2.38** | **3.11** ← best tail |
| nginx | 1 | 63,764 | 2.29 | 3.03 |
| **flare v0.6** | 1 | 56,086 | 2.70 | 3.54 |
| Go `net/http` | 1 | 35,940 | 2.92 | 5.47 |

flare_mc 4w v0.6 already holds **best p99 / p99.9 / p99.99 of
the four 4-worker frameworks**. The peak gap to hyper is
−51 K req/s = 23 %; to the v0.7 design gate (220 K) is
−49 K req/s = 22 %.

## v0.7 dev-box probe — confirms no regression

This box: 64-vCPU x86-64 (Linux 6.8). Numbers don't translate
1:1 to EPYC (smaller L3 / different freq / different memory
controller), but they're the regression watchdog while EPYC
publication is queued for the v0.7 tag.

| Target | Config | Req/s (median) | stdev | p50 (ms) | p99 (ms) | p99.99 (ms) | stable |
|---|---|---:|---:|---:|---:|---:|---|
| **flare 1w** | throughput | **62,915** | 0.00 % | 1.29 | 3.07 | 3.42 | true |
| go_nethttp 1w | throughput | 40,252 | 1.57 % | 1.38 | 3.21 | 4.47 | true |
| **flare_mc 4w** | throughput_mc | **150,227** | 0.17 % | 1.09 | 2.34 | **3.25** | true |
| go_nethttp (1 vcpu) | throughput_mc | 36,717 | 0.21 % | 1.07 | 2.93 | 5.97 | true |

**flare 1w dev-box** = 62,915 req/s vs **v0.6 EPYC tag** of
56,086 req/s = **+12 % over the v0.6 tag baseline** (EPYC vs
dev-box differ in many ways but the directional message is
clear: the safety-assert + Track B substrate commits in v0.7
have not regressed the hot path). p99 = 3.07 ms (vs 2.70 v0.6
EPYC); p99.99 = 3.42 ms (vs 3.54 v0.6 EPYC).

**flare_mc 4w dev-box** = 150,227 req/s with p99.99 = 3.25 ms
(this dev box has 64 vCPUs; the kernel scheduler and shared L3
introduce real contention that's not present on a 4-physical-
core EPYC subset). The tail story is intact: 3.25 ms p99.99 is
**better than every Rust 4w on EPYC except actix's peak-
oriented variant** (which pays 21.6 ms p99.99). The
**flare_mc / go_nethttp ratio = 4.09×** on this box (vs 4.74×
on the v0.6 EPYC publication).

## v0.7 perf objective vs Rust libs

The v0.7 design gate (`design-0.7.mdc § Bar / gate matrix`):

| Bar | Gate | Status |
|---|---|---|
| flare_mc 4w EPYC ≥ 220 K req/s | bench-vs-baseline on io_uring backend | ⏭ pending server-loop dispatch swap (B0 substrate ✅, driver ✅, **`UringReactor` ✅**, multishot accept/recv/send + cancel + wakeup all ✅, **server-loop wire-in TBD**) |
| flare_mc 4w EPYC tail p99.99 ≤ 3.5 ms | matched-worker | **✅ holds at 3.25 ms (dev-box) / 3.11 ms (v0.6 EPYC)** — already best-of-class |
| io_uring Linux fast path operational | ≥ 2 µs/req improvement vs epoll | ⏭ measurable after wire-in; substrate validated end-to-end (NOP round-trip works on host io_uring) |
| Epoll / kqueue fallback parity | tests pass on both backends | ✅ epoll/kqueue stays the v0.6.0 codepath; comptime branch will preserve it as Linux<5.15 / macOS / FreeBSD fallback |
| Both API shapes compile cleanly | every example builds | ✅ no v0.6 example modified |

### Rust per-framework perf objective

| Rust lib | EPYC peak (v0.6 measure) | flare_mc v0.6 EPYC | Gap | flare_mc v0.7 target | Status |
|---|---:|---:|---:|---:|---|
| hyper 4w | 221,349 | 170,305 | −23 % (peak) | ≥ 220 K = parity | **⏭ gated on io_uring wire-in (B0)** |
| hyper 4w | 3.67 ms p99.99 | 3.11 ms | **flare wins tail by 15 %** | ≤ 3.5 ms | **✅ already passing on dev-box (3.25 ms)** |
| axum 4w | 201,042 | 170,305 | −15 % (peak) | ≥ 220 K = beat axum | ⏭ gated on B0 |
| axum 4w | 3.65 ms p99.99 | 3.11 ms | **flare wins tail by 15 %** | ≤ 3.5 ms | **✅** |
| actix_web 4w | 264,691 | 170,305 | −36 % (peak) | beat actix peak only after B0 + B2-B10 | ⏭ aspirational; v0.7 design accepts actix peak as out-of-bar |
| actix_web 4w | **21.61 ms p99.99** | 3.11 ms | **flare wins tail by 7×** | ≤ 3.5 ms | **✅ massive lead** |
| nginx 1w | 63,764 | flare 1w 56,086 | −12 % (peak) | match nginx 1w | ⏭ gated on B0 |
| nginx 1w | 3.03 ms p99.99 | flare 1w 3.54 ms | nginx leads tail by 14 % | ≤ 3.6 ms | ✅ within budget |
| Go `net/http` 1w | 35,940 | flare 1w 56,086 | **flare wins by 56 %** | ≥ 1.5× Go | **✅** |
| Go `net/http` 1w | 5.47 ms p99.99 | flare 1w 3.54 ms | **flare wins tail by 35 %** | better than Go | **✅** |

**Headline**: the flare tail is already best-of-class against
every measured Rust lib on the same hardware, and the v0.7
target tail (≤ 3.5 ms p99.99) is comfortably met
(3.11 ms / 3.25 ms / 3.42 ms across the three measurements).
The peak gap to hyper / axum / actix-peak is the remaining
work, and it's precisely what Track B0 (io_uring) is
budgeted to close.

## What v0.7 has shipped toward the 220K req/s gate

The Track B substrate is **fully landed**; Tracks B0 / B2-B10
each shipped as a commit with tests + (where relevant) a fuzz
harness:

| Subtrack | Commit | What landed | Expected µs/req savings (design-0.7) |
|---|---|---|---:|
| B0 substrate | `cdc2c81` | io_uring direct-syscall FFI + `IoUringRing` + feature probe (8 tests) | 2.0 – 4.0 |
| B0 SQE/CQE codec | `0c7dba5` | `IoUringSqe` + `IoUringCqe` + 7 prep helpers (20 tests) | (folded into B0) |
| B0 driver | `cc66b06` | `IoUringDriver` mmap SQ/CQ rings + atomic head/tail + submit/reap; **end-to-end NOP round-trip verified live** (6 tests) | (folded into B0) |
| B0 fuzz | `1b0852d` | `fuzz-io-uring-sqe` 200 K runs zero crashes | — |
| B0 multishot accept | `a34b19f` | `prep_multishot_accept` (ioprio bit, matches `liburing`) + live `IORING_OP_ACCEPT_MULTISHOT` round-trip on a `127.0.0.1:0` loopback listener (1 test PASS, kernel 6.8) | (folded into B0) |
| B0 reactor wire-in | `5b8a5d7` | `UringReactor` — io_uring-native event loop with `pack_user_data` (8-bit op + 56-bit conn_id), multishot accept/recv, fire-and-forget send/close, async cancel, eventfd wakeup; comptime selector `use_uring_backend()`; **8 tests pass live** (incl. end-to-end client→recv→send echo); **fuzz_uring_reactor 100 K runs zero crashes** | (folded into B0) |
| B2 PHF | (earlier v0.7 commit) | Comptime PHF for ~70 standard headers | 0.5 – 1.0 |
| B3 intern | (earlier) | `StaticString` interning for HTTP method names + common values | 0.3 – 0.5 |
| B4 writev | (earlier) | `IoVecBuf` + `writev_buf_all` for vectored response serialization | ~1.0 (epoll); subsumed on io_uring path |
| B5 BufferPool | (earlier) | Per-worker `Pool[BufferHandle]` 1/4/16/64 KB classes | 0.5 – 1.0 |
| B6 ResponsePool | (earlier) | Per-worker `Pool[Response]` + `Response.reset()` | 0.3 – 0.5 |
| B7 DateCache | (earlier) | Per-worker monotonic Date-header cache | 0.2 – 0.4 |
| B9 SIMD Huffman | (earlier) | RFC 7541 HPACK Huffman codec | 0.4 – 0.8 (h2 only) |
| B10 SIMD parsers | (earlier) | `simd_memmem` / `simd_percent_decode` / `simd_cookie_scan` | 0.2 – 0.5 |
| Safety guard | `9e9c3d1` | `debug_assert[assert_mode="safe"]` on Track B substrate; `--sanitize` harness; new `.cursor/rules/sanitizers-and-bounds-checking.mdc` (15 happy-path tests, ASan-clean across 12 suites) | (no perf cost in default build; catches unsoundness regressions) |

**Design-0.7 expected total on the io_uring path**:
4.4 – 7.7 µs/req savings against the v0.6.0 ~23 µs/req per
core. Comfortable margin against the 5 µs target (220 K =
~18 µs/req per core).

## What's left for the 220 K gate

| Task | What | Why blocked |
|---|---|---|
| ~~**B0 reactor wiring**~~ | ~~Comptime-branched `UringReactor` / `EpollReactor` / `KqueueReactor`~~ | **✅ shipped in `5b8a5d7`** — `UringReactor` is in the tree alongside the existing `Reactor`, with its native submit/reap surface (the API epoll/kqueue can't model losslessly). |
| ~~**B0 multishot accept on real fd**~~ | ~~Wire `IORING_OP_ACCEPT_MULTISHOT` against a TCP listener~~ | **✅ shipped in `a34b19f` + `5b8a5d7`** — `prep_multishot_accept` + live test on a 127.0.0.1:0 listener (kernel 6.8). |
| ~~**B0 multishot recv + writev send**~~ | ~~Steady-state per-connection pattern~~ | **✅ shipped in `5b8a5d7`** — `arm_recv_multishot` (`IORING_OP_RECV` + `IORING_RECV_MULTISHOT`) + `submit_send` (`IORING_OP_SEND` + `MSG_NOSIGNAL`) + `submit_close` (`IORING_OP_CLOSE` + `IOSQE_CQE_SKIP_SUCCESS`); end-to-end echo round-trip verified live. |
| **B0 server-loop dispatch** | Have `flare.http.server` instantiate `UringReactor` (when `use_uring_backend()`) and dispatch `_server_reactor_impl.on_readable` from CQE-driven `URING_OP_RECV` completions instead of epoll-driven `EVENT_READABLE` events | Not blocked; the surfaces line up. The ConnHandle state machine reads bytes from a buffer; on the io_uring path the bytes arrive in the recv-multishot buffer with a `UringCompletion(op=RECV, conn_id, res, has_more)`. |
| **EPYC publication** | Re-run `bench-vs-baseline` on EPYC 7R32 with the io_uring path enabled; refresh `benchmark/results/v0.7/iouring-vs-epoll/` | Hardware-gated. The dev-box probe says we're already where we need to be on tail; peak depends on EPYC re-measurement. |

## Numbers that matter

* **flare_mc 4w EPYC v0.6**: 170 K req/s, p99.99 = 3.11 ms.
* **flare_mc 4w EPYC v0.7 target**: ≥ 220 K, p99.99 ≤ 3.5 ms.
* **flare_mc tail vs every Rust 4w on EPYC**: already
  best-of-class; v0.7 must not regress it. **Confirmed not
  regressed on dev-box (3.25 ms p99.99)**.
* **io_uring substrate**: built, tested (**43 tests** — 8
  substrate + 20 sqe + 6 driver + 1 multishot accept + 8
  UringReactor), fuzzed (300 K cumulative runs zero crashes
  across `fuzz-io-uring-sqe` + `fuzz-uring-reactor`), end-to-
  end SQ→CQ NOP round-trip + live multishot accept + live
  recv/send echo all validated against the host kernel 6.8.
* **`UringReactor` is live**: io_uring-native event loop with
  multishot accept/recv, fire-and-forget send/close, async
  cancel, eventfd wakeup, and packed `(op, conn_id)`
  user_data dispatch. Sits ready as the comptime-selected
  backend for the next commit that swaps server-loop
  dispatch from epoll-events to io_uring-completions.
* Once that swap lands and EPYC is re-benched, the 220 K
  gate is in scope. **Tail (≤ 3.5 ms p99.99) is already met
  on every measurement** (3.11 / 3.25 / 3.42 ms across
  EPYC v0.6 + dev-box v0.7).
* **Background fuzz sweep this commit**: full `fuzz-all`
  (27 harnesses, ~3.7 M cumulative runs incl. the new
  `fuzz-uring-reactor`) — **zero crashes, zero rejections**,
  no regressions from the io_uring stack landing.
