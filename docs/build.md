# Build modes

flare ships safety asserts on every FFI / unsafe-pointer
boundary, plus a sanitizer harness that runs the FFI-heavy
test surface under AddressSanitizer + ThreadSanitizer. This
page covers the three knobs you actually pick from when
building flare: the assert mode, the optimisation level,
and the sanitizer pass.

## Quick reference

| Use case | Build flags |
|---|---|
| **Production / benchmark** | `mojo build -D ASSERT=none -I . myapp.mojo -o myapp` |
| **Development (default)** | `mojo build -I . myapp.mojo -o myapp` |
| **CI / aggressive asserts** | `mojo build -D ASSERT=all -I . myapp.mojo -o myapp` |
| **Sanitizer (ASan)** | `mojo build --sanitize address -D ASSERT=all -I . tests/test_X.mojo -o test_X_asan` |
| **Sanitizer (TSan)** | `mojo build --sanitize thread -D ASSERT=all -I . tests/test_X.mojo -o test_X_tsan` |

`mojo build` defaults to `-O3`; no separate optimisation
flag is needed.

---

## Assert modes (`-D ASSERT=...`)

The Mojo stdlib `debug_assert` reads a comptime-defined
`ASSERT` value (default `safe`) and gates assertion checks
on it.

| Mode | Behaviour | When |
|---|---|---|
| `none` | All `debug_assert` calls compile out. Maximum perf, zero safety. | **Production deployments + benchmarks.** Matches `cargo build --release` (no `debug_assert!` after macro expansion). |
| `safe` | Only asserts marked `[assert_mode="safe"]` run; default-mode asserts compile out. | **Dev default.** Catches use-after-free, EBADF, EFAULT in the FFI layer before they become silent kernel-mode UB. ~1 cmp+je per FFI call site. |
| `all` | Every `debug_assert` runs (both `assert_mode="safe"` and the default flavour). | **CI gate.** Used by `pixi run tests-asserts-all` and the sanitizer-build path. Catches `O(n)` invariants the default `safe` build elides. |
| `warn` | Same instrumentation as `all`, but assert failures `print` and don't `abort()`. | **Fuzzing.** Useful when you want to keep iterating after observed failures. |

flare's bench harness builds with `-D ASSERT=none` so the
numbers in [`docs/benchmark.md`](benchmark.md) compare
against Rust's `cargo build --release --locked` posture
(both sides, no debug asserts, full `-O3`). Flipping the
asserts off is the difference between flare's HEAD multi-
worker numbers landing at parity with actix_web and
landing 4-15% behind on the same hardware.

For local development, the default `mojo build my_app.mojo`
or `mojo run my_app.mojo` keeps `ASSERT=safe` on. The
overhead is small but real (~3-4% throughput on the
plaintext keep-alive workload); the trade is worth it
because the asserts catch the kind of FFI mistakes that
otherwise show up as nondescript `EBADF` / `EFAULT` failures
many call-frames away from the actual cause.

---

## Running the test suite

`pixi run tests` does **not** run one `mojo` invocation per
test file. Each file is a standalone Mojo program, so the
per-file chain re-elaborated flare's ~90k-line source graph
274 times over: one representative file measured 1.70s to
compile against 0.31s to run. Instead, the tests of each
area under `tests/` are compiled into a single binary:

```bash
pixi run tests        # aggregate build + run (the CI gate)
pixi run tests-gen    # regenerate tests/_agg after adding a test file
pixi run mojo -I . tests/http/test_router.mojo   # one file on its own
```

There used to be a `tests-per-file` task holding a
hand-maintained chain of ~300 invocations. It was removed in
0.11: the aggregates replaced it, and unlike them it had no
drift gate, so it had rotted to the point of naming a test file
that did not exist. Run a single file directly, as above.

`tests/_agg/agg_<area>.mojo` is **generated** by
[`tests/tools/gen_test_aggregates.py`](../tests/tools/gen_test_aggregates.py)
and committed. It imports every module-level `def test_*` in
the area under an alias and registers each one explicitly on
a `TestSuite`.

Two consequences for anyone adding a test:

- **Every test must be a module-level `def test_<name>() raises:`.**
  A file whose tests live only inside `main()` has nothing to
  import; the generator refuses to run rather than silently
  dropping it. Keep `main()` as a thin delegator so the file
  still runs standalone.
- **Re-run `pixi run tests-gen` and commit the result.**
  `pixi run tests` re-checks the aggregates against the tree
  first and fails if they have drifted, because an aggregate
  that is out of date just stops running whatever was added
  and still exits 0.

Registration is explicit rather than via `discover_tests`
for the same reason: inside an aggregate, `discover_tests`
finds the *aggregate's* own functions -- of which there are
none -- and prints `Running 0 tests ... 0 failed`, a green
run that executed nothing.

Nine tests are excluded from the aggregates and keep their
own process: they mutate process-global state (environment
variables, named semaphores, `io_uring` registrations) or are
runtime-bound rather than compile-bound, so sharing a process
with their neighbours is either unsound or buys nothing. They
are listed in `EXCLUDE` in the generator and `STANDALONE` in
[`tests/tools/run_test_aggregates.sh`](../tests/tools/run_test_aggregates.sh);
the two lists must agree. Examples under `examples/` are
programs rather than test functions, so they also stay one
invocation each -- `pixi run tests` still runs all of them.

The aggregate builds are independent compiler invocations and
run concurrently, capped at four (`AGG_JOBS` overrides). The
cap is deliberate: each job is a full elaboration of the
source graph and the macOS runner has 7GB across 3 cores.
The examples get the same treatment -- they are built
concurrently and then run one binary at a time, so each keeps
its own process while the compile cost is shared. On
ubuntu-latest the 68 example compilations were 12.5min of a
20.5min job, all of it compilation rather than run time.

---

## Sanitizers

Two sanitizers ship with the Mojo toolchain:

- **AddressSanitizer (`--sanitize address`)** -- detects
  use-after-free, heap-buffer overflow, double-free, stack-
  buffer overflow, leak. The right tool for any change
  that touches `UnsafePointer`, `external_call`, or a
  `Pool[T]` arena.
- **ThreadSanitizer (`--sanitize thread`)** -- detects
  data races between flare workers / pthread-launched
  threads. The right tool for any change to
  `flare.runtime.scheduler` or to multi-worker server /
  WS code.

Both require `mojo build` (AOT). The JIT path
(`mojo run --sanitize address ...`) cannot resolve the
asan / tsan runtime symbols and fails with `JIT session
error: Symbols not found: [ __asan_init, ... ]`.

flare wraps the build-and-run plumbing in three pixi
tasks:

| Task | Build flag | Tests covered |
|---|---|---|
| [`tests-asserts-all`](../pixi.toml) | `-D ASSERT=all` | The same scope as `pixi run tests`, with every `debug_assert` running. |
| [`tests-asan`](../pixi.toml) | `--sanitize address -D ASSERT=all` | FFI-heavy substrate (io_uring, iovec, buffer pool, response pool, date cache, HPACK, header PHF, intern, pool, libc time, safety asserts, the H2 conn handle, the unified server, the unified client, the H2 server handler, RFC 8441 Extended CONNECT). |
| [`tests-tsan`](../pixi.toml) | `--sanitize thread -D ASSERT=all` | Multicore + reactor (test_scheduler, test_thread_ffi, test_handoff, test_ws_multicore). |

```bash
pixi run tests-asserts-all      # ~2x slower than tests; default ASSERT=all
pixi run tests-asan             # ~5-10x slower; rebuilds binaries first
pixi run tests-tsan             # ~10-20x slower; for multi-worker review
```

Per-test binaries land under `target/sanitize/`
(`.gitignore`d). Run the relevant sanitizer locally before
shipping changes that touch FFI boundaries, lifecycle
management, or multi-worker paths.

### Investigating a sanitizer failure

ASan failures come with a stack trace pointing at the
heap-buffer-overflow / use-after-free / double-free site.
Reproduce locally with `-O0 -g` for source line numbers:

```bash
mojo build -O0 -g --sanitize address -I . tests/test_X.mojo \
    -o target/sanitize/test_X_asan_dbg
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize_inlines=1 \
    ./target/sanitize/test_X_asan_dbg
```

`ASAN_OPTIONS=detect_leaks=0` is what the harness sets to
suppress LSan's exit-time chatter for one-shot test
binaries. Drop it when chasing a suspected leak.

### TSan caveat

There's a known link-time issue with the Mojo toolchain +
LLVM TSan integration: every TSan-built binary fails with
`symbol 'DW.ref.__gcc_personality_v0' is already defined`
(reproduces on every test, not specific to flare). The
test inventory is wired through `pixi run tests-tsan` so
it'll fire automatically once the upstream fix lands.

---

## Writing `debug_assert` (for contributors)

When you add a new FFI wrapper or a new `UnsafePointer`-
juggling primitive, follow this pattern:

```mojo
@always_inline
def _bind(fd: c_int, addr: UnsafePointer[UInt8, _], addrlen: c_uint) -> c_int:
    """Wrapper around bind(2)."""
    debug_assert[assert_mode="safe"](
        Int(fd) >= 0,
        "_bind: fd must be non-negative; got ", Int(fd),
    )
    debug_assert[assert_mode="safe"](
        Int(addr) != 0,
        "_bind: addr must be non-NULL",
    )
    return external_call["bind", c_int](fd, addr.bitcast[NoneType](), addrlen)
```

Rules of thumb:

1. **`assert_mode="safe"`** for any check that's `O(1)`,
   has no side effects, and would catch a memory-safety
   bug or an FFI ABI mistake. These run at the default
   `ASSERT=safe`.
2. **Default mode (no `assert_mode`)** for `O(n)` invariants
   or anything that touches allocations. These only run
   under `-D ASSERT=all`.
3. **Don't put side effects in the condition.** `String("x: ", x)`
   allocates even when the assert is compiled out. Use the
   capturing-closure overload instead:
   ```mojo
   def _check() capturing -> Bool:
       return some_o_n_invariant(self.headers)
   debug_assert[_check]("invariant violated")
   ```
4. **For wrapper structs that own a heap allocation**,
   assert non-zero in `__del__` *before* calling `.free()`.
   Catches the move-out-then-drop double-free.

Adding a new FFI-touching test? Append it to the test
inventory in [`tests/tools/run_sanitizer_tests.sh`](../tests/tools/run_sanitizer_tests.sh)
(the `ASAN_TESTS` array at the top) so `pixi run tests-asan`
picks it up.

---

## Platform support

`pixi.toml` declares three platforms. What each one actually
gives you differs, and the differences are not obvious from the
platform list alone.

| | linux-64 | linux-aarch64 | osx-arm64 |
|---|---|---|---|
| Build | yes | yes | yes |
| Test suite | yes, in CI on `ubuntu-latest` | yes, locally | yes, in CI on `macos-15` (advisory) |
| Reactor backend | io_uring, epoll fallback | io_uring, epoll fallback | kqueue |
| io_uring buffer rings | yes, opt-in | yes, opt-in | no |
| Sanitizers (ASan / TSan) | yes | yes | **no runtime shipped** |
| QUIC / HTTP/3 TLS (rustls FFI) | yes | yes | yes |
| Batch UDP (`recvmmsg` / `sendmmsg`) | yes | yes | no, falls back to one datagram per call |
| Named POSIX semaphores | yes | yes | **unavailable** |
| Benchmark harness (`wrk`, `wrk2`) | conda-provided | conda-provided | system `wrk`, build `wrk2` from source |
| Profilers (`heaptrack`, `valgrind`, `perf`) | conda-provided | partial | no |

Three of these bite often enough to state plainly.

**No ASan on Apple silicon.** The Mojo toolchain ships no
arm64 AddressSanitizer runtime, so `pixi run tests-asan` cannot
run on an M-series Mac at all -- not slowly, not at reduced
coverage. `pixi run tests-asserts-all` is the local stand-in: it
runs the same tests with every `debug_assert` armed, which
catches contract violations but not use-after-free. The real
ASan pass runs in CI on `ubuntu-latest`, and that is the only
memory-safety signal this repo has. Treat a macOS-only green
suite accordingly.

**No named POSIX semaphores on macOS.** `sem_open` is present
but the semantics flare's blocking pool needs are not, so
`_pool_try_acquire` fails open and `tests/runtime/test_block_in_pool.mojo`
fails locally on a Mac. It passes on Linux in CI. This one
failure in an otherwise green local run is expected.

**io_uring is Linux-only.** macOS runs the same reactor over
kqueue, so the code paths are shared but the buffer-ring
handler (`FLARE_BUFRING_HANDLER=1`) and the multishot-accept
paths are exercised only on Linux. `FLARE_DISABLE_IO_URING=1`
forces the epoll path on Linux when you want to compare.

---

## Cross-references

- [`docs/benchmark.md`](benchmark.md) -- the bench numbers
  this build posture produces, and the `bench-vs-baseline`
  task that drives them.
- [`docs/security.md`](security.md) -- the per-layer
  security posture the safety asserts back up.
