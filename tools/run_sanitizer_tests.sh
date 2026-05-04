#!/usr/bin/env bash
# tools/run_sanitizer_tests.sh — flare sanitizer harness.
#
# AOT-compiles a curated list of test files with `mojo build
# --sanitize <kind>` (asan or tsan) and runs the resulting
# binaries one at a time, failing fast on the first error.
#
# JIT (`mojo run --sanitize address ...`) is not supported by the
# Mojo toolchain because the JIT cannot resolve the `__asan_*` /
# `__tsan_*` runtime symbols statically. See
# `.cursor/rules/sanitizers-and-bounds-checking.mdc` §1.1.
#
# Driven by `pixi run tests-asan` / `pixi run tests-tsan` from
# `pixi.toml`. Standalone usage:
#
#   tools/run_sanitizer_tests.sh asan
#   tools/run_sanitizer_tests.sh tsan
#   tools/run_sanitizer_tests.sh asan tests/test_iovec.mojo  # single file
#
set -euo pipefail

KIND="${1:-asan}"
shift || true

case "${KIND}" in
  asan)
    SAN_FLAG="--sanitize address"
    SUFFIX="_asan"
    # detect_leaks=0 mutes LSan exit-time chatter for one-shot
    # test binaries; abort_on_error=1 turns recoverable findings
    # into hard exits so CI fails fast;
    # verify_asan_link_order=0 disables the runtime preload-order
    # check that fails when running inside `pixi run` (conda's
    # LD_LIBRARY_PATH injects libstdc++ ahead of libasan; harmless
    # in our usage because we link asan statically).
    SAN_ENV="ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize_inlines=1:verify_asan_link_order=0"
    ;;
  tsan)
    SAN_FLAG="--sanitize thread"
    SUFFIX="_tsan"
    SAN_ENV="TSAN_OPTIONS=second_deadlock_stack=1:symbolize_inlines=1:halt_on_error=1"
    ;;
  *)
    echo "usage: $0 {asan|tsan} [test_file...]" >&2
    exit 2
    ;;
esac

# ── default test inventories ────────────────────────────────────
# Curated lists — keep in sync with the `tests-asan` / `tests-tsan`
# sections in `.cursor/rules/sanitizers-and-bounds-checking.mdc`.
ASAN_TESTS=(
  # Track B substrate (FFI-heavy by construction)
  "tests/test_io_uring.mojo"          # B0 — io_uring direct-syscall FFI
  "tests/test_iovec.mojo"             # B4 — writev(2) iovec-buf
  "tests/test_buffer_pool.mojo"       # B5 — bucketed buffer pool
  "tests/test_response_pool.mojo"     # B6 — response pool
  "tests/test_date_cache.mojo"        # B7 — clock_gettime + IMF-fixdate
  "tests/test_hpack_huffman.mojo"     # B9 — RFC 7541 codec
  "tests/test_simd_parsers.mojo"      # B10 — memmem / percent-decode / cookie
  "tests/test_header_phf.mojo"        # B2 — comptime header PHF
  "tests/test_intern.mojo"            # B3 — StaticString intern table
  # Pre-existing FFI-heavy substrates
  "tests/test_pool.mojo"              # Pool[T] typed allocator
  "tests/test_libc_time.mojo"         # libc_usleep / nanosleep_ms FFI
  "tests/test_safety_asserts.mojo"    # bounds + debug_assert harness
  # Unified-HTTP/WS-over-HTTP/2 (Phase 1-7) FFI surfaces -- recv/send
  # loops on raw fds, RawSocket(_wrap=True) reconstruction during
  # PendingConnHandle -> ConnHandle/H2ConnHandle migration, Pool
  # alloc/free of the new per-conn handles.
  "tests/test_h2_conn_handle.mojo"           # H2ConnHandle + PendingConnHandle recv/send
  "tests/test_unified_http_server.mojo"      # full unified reactor over HTTP/1.1 + HTTP/2
  "tests/test_unified_http_client.mojo"      # HttpClient h2c + auth FFI
  "tests/test_h2_server_handler.mojo"        # HttpClient(prefer_h2c=True) <-> HttpServer
  "tests/test_h2_extended_connect.mojo"      # RFC 8441 SETTINGS/parse (in-memory)
)
TSAN_TESTS=(
  # Multicore + reactor (the only places we spawn pthreads)
  "tests/test_thread_ffi.mojo"
  "tests/test_scheduler.mojo"
  "tests/test_handoff.mojo"
  # Multi-worker WsServer (4-worker pthread fan-out with libc malloc'd
  # _WsWorkerCtx + UnsafePointer[ThreadHandle] storage)
  "tests/test_ws_multicore.mojo"
)

# Allow caller to override the test list.
if [[ $# -gt 0 ]]; then
  TESTS=( "$@" )
else
  if [[ "${KIND}" == "asan" ]]; then
    TESTS=( "${ASAN_TESTS[@]}" )
  else
    TESTS=( "${TSAN_TESTS[@]}" )
  fi
fi

mkdir -p target/sanitize

PASS=0
FAIL=0
START_NS=$(date +%s%N)

for test_file in "${TESTS[@]}"; do
  base=$(basename "${test_file}" .mojo)
  out="target/sanitize/${base}${SUFFIX}"

  printf '── %-44s build (%s) … ' "${base}" "${KIND}"
  # `-D ASSERT=all` ensures every debug_assert (both safe and
  # default mode) compiles in. Pair with the sanitizer for
  # maximum coverage.
  if ! pixi run mojo build ${SAN_FLAG} -D ASSERT=all -I . "${test_file}" -o "${out}" \
       > "target/sanitize/${base}${SUFFIX}.build.log" 2>&1; then
    echo "BUILD FAILED"
    cat "target/sanitize/${base}${SUFFIX}.build.log"
    FAIL=$((FAIL + 1))
    continue
  fi
  echo "ok"

  printf '   %-44s run   (%s) … ' "${base}" "${KIND}"
  if env ${SAN_ENV} "./${out}" > "target/sanitize/${base}${SUFFIX}.run.log" 2>&1; then
    summary=$(grep -E '^Summary' "target/sanitize/${base}${SUFFIX}.run.log" | tail -1 || true)
    echo "PASS — ${summary:-no summary}"
    PASS=$((PASS + 1))
  else
    echo "FAILED"
    tail -40 "target/sanitize/${base}${SUFFIX}.run.log"
    FAIL=$((FAIL + 1))
  fi
done

END_NS=$(date +%s%N)
ELAPSED_S=$(( (END_NS - START_NS) / 1000000000 ))

echo
echo "── ${KIND^^} summary: ${PASS} passed, ${FAIL} failed in ${ELAPSED_S}s"

if [[ ${FAIL} -gt 0 ]]; then
  exit 1
fi
