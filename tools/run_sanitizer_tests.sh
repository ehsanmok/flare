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
#   tools/run_sanitizer_tests.sh asan tests/runtime/test_iovec.mojo  # single file
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
  # v0.9 A3 — ByteReader/ByteWriter bounds-checked cursors (Span +
  # memcpy + sub-span borrows); ASan validates no OOB on the read path.
  "tests/io/test_byte_cursor.mojo"
  # v0.9 A1 — StreamHandler/StreamConn typed lifecycle over loopback
  # TCP (per-connection CancelCell heap alloc + owned TcpStream).
  "tests/http/test_streaming_server.mojo"
  # v0.9 A2 — serve_streaming reactor loop e2e (forked server +
  # Dict[Int, StreamConn] + EPOLLOUT drain). ASan validates the
  # parent-side client path and the connection-table teardown.
  "tests/http/test_streaming_server_reactor.mojo"
  # Track B substrate (FFI-heavy by construction)
  "tests/runtime/test_io_uring.mojo"          # B0 — io_uring direct-syscall FFI
  "tests/runtime/test_iovec.mojo"             # B4 — writev(2) iovec-buf
  "tests/runtime/test_buffer_pool.mojo"       # B5 — bucketed buffer pool
  "tests/http/test_response_pool.mojo"     # B6 — response pool
  "tests/runtime/test_date_cache.mojo"        # B7 — clock_gettime + IMF-fixdate
  "tests/http/test_hpack_huffman.mojo"     # B9 — RFC 7541 codec
  "tests/http/test_simd_parsers.mojo"      # B10 — memmem / percent-decode / cookie
  "tests/http/test_header_phf.mojo"        # B2 — comptime header PHF
  "tests/http/test_intern.mojo"            # B3 — StaticString intern table
  # Pre-existing FFI-heavy substrates
  "tests/runtime/test_pool.mojo"              # Pool[T] typed allocator
  "tests/runtime/test_libc_time.mojo"         # libc_usleep / nanosleep_ms FFI
  "tests/runtime/test_safety_asserts.mojo"    # bounds + debug_assert harness
  # Unified-HTTP/WS-over-HTTP/2 (Phase 1-7) FFI surfaces -- recv/send
  # loops on raw fds, RawSocket(_wrap=True) reconstruction during
  # PendingConnHandle -> ConnHandle/H2ConnHandle migration, Pool
  # alloc/free of the new per-conn handles.
  "tests/http2/test_h2_conn_handle.mojo"           # H2ConnHandle + PendingConnHandle recv/send
  "tests/http/test_unified_http_server.mojo"      # full unified reactor over HTTP/1.1 + HTTP/2
  "tests/http/test_unified_http_client.mojo"      # HttpClient h2c + auth FFI
  "tests/http2/test_h2_server_handler.mojo"        # HttpClient(prefer_h2c=True) <-> HttpServer
  "tests/http2/test_h2_extended_connect.mojo"      # RFC 8441 SETTINGS/parse (in-memory)
  # OwnedDLHandle borrow-helper discipline (post v0.7 b20951e). Each
  # of these tests exercises an FFI surface that was just refactored
  # to route every ``OwnedDLHandle.get_function`` + invocation through
  # a ``read lib`` borrow helper; ASan validates the lifetime fix
  # holds up under sanitizer instrumentation (no use-after-free in
  # the dlclose-on-ASAP-destruction path the legacy pattern was
  # vulnerable to). Verified clean during the b20951e gate; baking
  # them into the canonical inventory so future contributors get the
  # coverage by default.
  "tests/crypto/test_hmac.mojo"                     # crypto FFI -- HMAC-SHA256 borrow helpers
  "tests/http/test_session.mojo"                  # signed-cookie path through HMAC FFI
  "tests/tls/test_tls.mojo"                      # TLS client FFI (17 borrow helpers)
  "tests/tls/test_tls_acceptor.mojo"             # TLS server FFI (TlsAcceptor over OpenSSL)
  "tests/tls/test_tls_server_ffi.mojo"           # ServerCtx FFI (11 borrow helpers)
  "tests/tls/test_tls_resume.mojo"               # v0.7 TLS resumption: TlsSession lifetime + new_session_cb
  "tests/ws/test_ws.mojo"                       # SHA-1 FFI via compute_accept_key
  "tests/ws/test_ws_permessage_deflate.mojo"    # v0.7 — RFC 7692 codec (raw deflate / inflate FFI borrow)
  # Track Q1-W QUIC AEAD + HP mask FFI (RFC 9001 §5.3 / §5.4).
  # The OpenSslQuicCrypto carrier calls EVP_CIPHER_CTX_new/free
  # per encrypt/decrypt/mask invocation; ASan verifies the C-side
  # lifecycle is leak-free and the Mojo-side borrow helpers keep
  # libflare_tls.so live across the FFI call.
  "tests/quic/test_aead_ffi.mojo"                 # raw FFI thunks
  "tests/quic/test_hp_mask_ffi.mojo"              # raw FFI thunks
  "tests/quic/test_openssl_quic_crypto.mojo"      # Mojo trait surface
  "tests/quic/test_rfc9001_appendix_a.mojo"       # full RFC vectors
  # Track Q2-W rustls QUIC FFI smoke (Cargo cdylib over rustls::quic).
  # The Mojo binding routes every OwnedDLHandle.get_function call
  # through a `read lib` borrow helper (same pattern as the OpenSSL
  # FFI surfaces above) so ASan validates the .so stays mapped
  # across the call and the Rust-side panic = "abort" profile
  # leaves no unwind tables for ASan to trip over.
  "tests/tls/test_rustls_quic_crate_smoke.mojo"   # libflare_rustls_quic.so dlopen + abi_version + empty-PEM rejection
  # Track Q2-W full Mojo carrier surface (RustlsQuicAcceptor +
  # Session + Config + Error). Exercises every FFI thunk routed
  # through `_rustls_quic_ffi.mojo`, including the NULL-handle
  # raise paths the reactor depends on for the configuration-
  # error vs handshake-failure distinction.
  "tests/tls/test_rustls_quic.mojo"
  # Track Q2-W commit 4/4 handshake fixtures: live-fire FFI
  # against a real Ed25519 self-signed cert. Drives the full
  # acceptor_new -> accept -> feed_crypto -> take_crypto loop
  # so ASan can catch any leaks across the C ABI boundary
  # (Rust-side Box<Acceptor> / Box<Session> lifetime managed
  # by flare_rustls_quic_acceptor_free / _session_free).
  "tests/tls/test_rustls_quic_handshake.mojo"
  # Track Q3-W commit 5/5 -- QUIC server reactor over loopback
  # UDP. Drives the full QuicListener.bind -> tick ->
  # dispatch_datagram -> handle_packet -> idle-timer path with
  # real sockets so ASan validates the QuicConnection /
  # ConnectionIdTable / TimerWheel lifetime + the
  # OpenSslQuicCrypto FFI on the inbound decrypt hot path.
  "tests/quic/test_quic_loopback_integration.mojo"
  # Track Q9-W commit 1/6 -- rustls QUIC handshake bridge.
  # Drives QuicConnection.handle_packet -> CRYPTO frame ->
  # _do_feed_crypto / _do_take_crypto against a real-PEM
  # acceptor + multiple accepted sessions per listener so ASan
  # validates the Rust-side Box<Session>* lifetime: every
  # non-zero session handle freed exactly once via
  # RustlsQuicAcceptor.free_session at listener teardown.
  "tests/quic/test_quic_handshake_bridge.mojo"
)
TSAN_TESTS=(
  # Multicore + reactor (the only places we spawn pthreads)
  "tests/runtime/test_thread_ffi.mojo"
  "tests/runtime/test_scheduler.mojo"
  "tests/runtime/test_handoff.mojo"
  # Multi-worker WsServer (4-worker pthread fan-out with libc malloc'd
  # _WsWorkerCtx + UnsafePointer[ThreadHandle] storage)
  "tests/ws/test_ws_multicore.mojo"
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
