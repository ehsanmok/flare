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
  # v0.9 A4 — attach_upstream + on_upstream pump (forked server, OS
  # pipe upstream + reactor upstream-fd register/route/unregister).
  # ASan validates the parent-side client path and upstream teardown.
  "tests/http/test_streaming_upstream.mojo"
  # v0.9 B3 — FrameMux codec + FrameDemux reassembly + 1k-stream
  # loopback over one forked UnixStream. ASan validates the contiguous
  # reassembly buffer (compaction + sub-span decode) and the payload
  # copies on the parent client path.
  "tests/uds/test_frame_mux.mojo"
  # v0.9 B1 — AsyncChunkSource/ChunkPoll/UpstreamChunkSource: fork
  # loopback (framed chunks with gaps, no busy-poll) + reactor e2e
  # (serve_streaming relay). ASan validates the non-blocking recv +
  # FrameDemux drain and the per-connection source teardown.
  "tests/http/test_async_chunk_source.mojo"
  # H3C-3 -- Alt-Svc parser + per-origin cache. Pure String/Dict
  # work, but ASan validates the StringSlice byte-slicing borrows in
  # the lenient parser and the Dict record/evict churn in the cache.
  "tests/http/test_alt_svc.mojo"
  # H3C-3 -- HttpClient h3 policy surface (prefer_h3 + Alt-Svc
  # record/consult + decision). ASan validates the AltSvcCache field
  # embedded in the moved HttpClient + the clock FFI buffer.
  "tests/http/test_client_h3_policy.mojo"
  # W1 -- interior-mutable client cookie store: alloc/record/replay/free
  # churn through the pointer-backed handle. ASan validates the heap
  # CookieJar lifecycle (no leak / use-after-free on the empty handle).
  "tests/http/test_cookie_store.mojo"
  # W1 -- wired client UX (redirect policy + auto-decompress + cookie jar
  # + retry) over a forked router. ASan validates the per-hop header
  # rebuild, the gzip decode buffer, and the cookie-store teardown in
  # the moved HttpClient.
  "tests/http/test_client_ux.mojo"
  # W5 -- HTTPS (TLS h1) client pool driven with real TlsStreams. ASan
  # validates the Pool[TlsStream] heap cells (move in/out + close on
  # over-cap / disabled) and the per-origin deque + timestamp maps.
  "tests/http/test_tls_client_pool.mojo"
  # W5 -- streaming request body (chunked TE) round trip. ASan validates
  # the per-chunk frame buffers and the de-chunk decode on the forked
  # raw-TCP decoder server.
  "tests/http/test_client_stream_upload.mojo"
  # W3 -- unary gRPC client over the h2c path against a forked greeter.
  # ASan validates the LPM encode/decode buffers and the response
  # header/trailer merge on the moved HttpClient.
  "tests/grpc/test_grpc_client.mojo"
  # W6 -- streaming gRPC (server/client/bidi) over h2c. ASan validates
  # the _H2Transport heap cell (pooled TcpStream), the long-lived
  # Http2ClientConnection, and the LPM reassembly buffer across the
  # incremental drain_body / send_data path.
  "tests/grpc/test_grpc_streaming.mojo"
  # W6 -- off-reactor resolve_async. ASan validates the cross-thread
  # _ResolveCtx heap cell + the Pool[String]/Pool[List[IpAddr]] handoff
  # cells freed after pthread_join.
  "tests/dns/test_async_resolve.mojo"
  # W3 -- TTL DNS cache over the sync resolver. ASan validates the
  # Dict[String, _CachedAddrs] lifecycle and the IpAddr list copies.
  "tests/dns/test_dns_cache.mojo"
  # W4a + W7 -- server 0-RTT anti-replay window + byte budget + the
  # coalesced packet-length parser + the cross-connection strike set.
  # ASan validates the guard's value-type bookkeeping, the long-header
  # bounds reads, and the strike set's Dict[String, UInt64] lifecycle.
  "tests/quic/test_quic_0rtt_replay.mojo"
  # W7 -- client idempotent-only 0-RTT gate + outcome carrier. ASan
  # validates the H3ZeroRttOutcome move/copy of the embedded H3Response.
  "tests/h3/test_h3_0rtt_gate.mojo"
  # W4b -- server path-validation probe + anti-amplification budget +
  # PATH_CHALLENGE encoder. ASan validates the probe value type and the
  # frame buffer build.
  "tests/quic/test_quic_migration_probe.mojo"
  # v0.9 B2 — hi/lo watermark backpressure: deterministic hysteresis +
  # counter checks, plus a forked slow-client soak. ASan validates the
  # relay-buffer compaction under throttled draining and the upstream
  # interest toggle path.
  "tests/http/test_backpressure.mojo"
  # v0.9 B4 — admission cap: a forked server with max_in_flight refuses
  # the over-capacity connection with a 503 + Retry-After and recovers
  # as slots free. ASan validates the accept-edge shed path (canned
  # response build + socket teardown) and the live-conn table.
  "tests/http/test_admission.mojo"
  # v0.9 B5 — incremental inbound body: a forked client streams multi-MB
  # while the front consumes it in fixed 64 KiB read_body chunks. ASan
  # validates the non-blocking inbound recv path and the bounded reader.
  "tests/http/test_inbound_body.mojo"
  # v0.9 B6 — upstream-cancel propagation: a forked backend + relay front;
  # a client disconnect drives a CANCEL frame to the backend. ASan
  # validates the send_cancel frame write + the relay teardown path.
  "tests/http/test_upstream_cancel.mojo"
  # v0.9 B7 — write coalescing: K queued chunks flush in one send(2)
  # (syscall counter) and the peer receives them in order. ASan validates
  # the contiguous out_buf gather + drain.
  "tests/http/test_write_coalescing.mojo"
  # Ergonomic surface — send() byte-type overloads (in-process loopback)
  # + framework-owned UpstreamChunkSource attach/relay/auto-close (forked
  # backend e2e). ASan validates the Optional[UpstreamChunkSource] move
  # into StreamConn + the teardown drop closing the owned upstream.
  "tests/http/test_streaming_ergonomics.mojo"
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
  # State machine (sans-I/O) incl. connection-migration frame
  # transitions: the dispatcher routes frames through
  # _ConnFrameHandler, which holds raw Int addresses of the
  # caller's Connection / ConnectionEvents and dereferences them
  # via UnsafePointer[..., MutUntrackedOrigin]. ASan validates
  # those interior pointers stay in-bounds across the peer-CID
  # table mutations + path-validation match.
  "tests/quic/test_state.mojo"
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
  # H3C-0 -- the client-role binding (RustlsQuicConnector +
  # connect()). Drives a full client<->server loopback handshake
  # through the role-agnostic feed/take CRYPTO path so ASan
  # validates the Box<Connector> / Box<Session> client lifetimes
  # (freed via flare_rustls_quic_connector_free / _session_free)
  # and the .so stays mapped across every client-side FFI call.
  "tests/tls/test_rustls_quic_client.mojo"
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
  # H3C-1 -- the QUIC client connection driver. Drives a full
  # client handshake (QuicClientConnection.start -> poll) against
  # the real QuicListener over loopback UDP so ASan validates the
  # client-side RustlsQuicSession lifetime, the per-level egress
  # builders' Span/List borrows, and the inbound decrypt hot path
  # (header_decrypt + packet_decrypt through rustls).
  "tests/quic/test_quic_client.mojo"
  # RFC 9000 §9 client-initiated connection migration over loopback:
  # server NEW_CONNECTION_ID issuance + cid_table multi-registration,
  # client socket rebind (old fd closed, new UdpSocket bound) + DCID
  # switch + PATH_CHALLENGE, server peer-addr follow + PATH_RESPONSE
  # echo. ASan validates the rebind fd lifecycle + the per-slot
  # pending-migration buffers + the rustls 1-RTT crypto across the
  # path change.
  "tests/quic/test_quic_migration.mojo"
  # RFC 9001 sec 4.6 client session resumption / 0-RTT early-key
  # readiness over loopback: two QUIC connections on one connector,
  # the second resumes the cached ticket (stateful server resumption)
  # and installs EarlyData keys. ASan validates the cross-connection
  # rustls session reuse + the early-key install/teardown path.
  "tests/quic/test_quic_resumption.mojo"
  # H3C-2 -- HTTP/3 client request writer + response reader. Pure
  # byte codecs (no QUIC), but ASan validates the response reader's
  # inbox compaction across frame boundaries and the QPACK field-
  # section decode borrows on the client side.
  "tests/h3/test_h3_client_streams.mojo"
  # H3C-4 -- end-to-end H3 client vs the real QuicListener over
  # loopback UDP (GET + POST echo through real QUIC encryption).
  # ASan validates the full client request/response hot path:
  # uni-stream + bidi send through rustls 1-RTT, inbound STREAM
  # reassembly into the response reader, and the H3ClientConnection
  # lifetime across the poll loop.
  "tests/h3/test_h3_client_e2e.mojo"
  # W9 -- client 0-RTT (EarlyData) send flight (fork). ASan validates
  # the _build_0rtt packet build + send_stream_early flight buffer and
  # the finish_early_data replay path (reset offsets + 1-RTT resend on
  # a foreign-ticket reject) across the resumed connection lifetime.
  "tests/h3/test_h3_0rtt_e2e.mojo"
  # H3C follow-up -- offset-ordered STREAM reassembly (_StreamReasm).
  # ASan validates the pending-chunk Dict churn + the trimmed/borrowed
  # Span feeds across out-of-order / duplicate / overlapping chunks.
  "tests/h3/test_h3_client_reasm.mojo"
  # H3C follow-up -- multiplexed H3 client over one QUIC connection.
  # ASan validates the per-stream _PendingRequest Dict (reasm + owned
  # reader) pop/reinsert churn while two requests are demuxed in flight.
  "tests/h3/test_h3_client_mux.mojo"
  # H3C follow-up -- multi-packet request-body fragmentation + idle
  # keepalive reuse. ASan validates the per-chunk STREAM frame buffer
  # churn across several packets and the padded keepalive PING build.
  "tests/h3/test_h3_client_frag.mojo"
  # H3C follow-up -- live HttpClient h3 dial over loopback QUIC (fork).
  # ASan validates the AltSvcStore interior-mut heap lifetime, the
  # per-request QuicClientConnection + H3ClientConnection allocation,
  # and the H3Response -> Response lowering across the dial path.
  "tests/http/test_h3_live_dial.mojo"
  # H3C follow-up -- HttpClient h3 connection reuse (fork). ASan
  # validates the QuicConnectionPool heap-cell churn (Pool[H3Conn]
  # alloc_move / take_pointee / free) across acquire + release + the
  # graceful CONNECTION_CLOSE drain in __del__.
  "tests/http/test_h3_pool_reuse.mojo"
  # H3C follow-up -- threaded h3-vs-h2 happy-eyeballs race. ASan
  # validates the heap result/arg cells shared across the two spawned
  # workers and freed after the join barrier, plus the live h3 leg's
  # QUIC alloc path while the h2 leg fast-fails concurrently.
  "tests/http/test_h3_happy_eyeballs.mojo"
)
TSAN_TESTS=(
  # Multicore + reactor (the only places we spawn pthreads)
  "tests/runtime/test_thread_ffi.mojo"
  "tests/runtime/test_scheduler.mojo"
  "tests/runtime/test_handoff.mojo"
  # Multi-worker WsServer (4-worker pthread fan-out with libc malloc'd
  # _WsWorkerCtx + UnsafePointer[ThreadHandle] storage)
  "tests/ws/test_ws_multicore.mojo"
  # Happy-eyeballs race: two ThreadHandle workers over shared heap
  # result cells, read only after the join barrier (no atomics).
  "tests/http/test_h3_happy_eyeballs.mojo"
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
