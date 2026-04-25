# Operational guarantees

The criticism that drives the v0.5 line is plain:

> Users care more about partial reads and writes, cancellation,
> backpressure, timeout behaviour, shutdown semantics, TLS
> boundaries, and parser safety than about a narrow throughput
> benchmark.

This page is the answer, written down. Each row is one operational
concern, what flare handles for you on the current `main`, and what
remains your job. "Planned" items show the release they target so users
don't ship into a hole.

The current branch is `main`, post-v0.4.1, working toward v0.5.0 Step 1
(operational core: peer visibility, sanitised errors, `Cancel`,
deadlines, drain, SIGTERM, plus the docs reset that produced this
file). Streaming bodies, server-side TLS, and the `RequestView` /
`HeaderMapView` zero-copy refactors land in subsequent v0.5.0 steps.

| Concern | flare's guarantee | Your responsibility | Since |
|---|---|---|---|
| Partial reads | Buffered until headers complete; body reads accumulate into a per-connection buffer with a configurable max. | none | v0.3.0 |
| Partial writes | Retried on every writable edge from `kqueue` / `epoll`; the connection stays in `STATE_WRITING` until flushed. | none | v0.3.0 |
| Idle keep-alive timeout | Configurable via `ServerConfig.idle_timeout_ms`; armed and rearmed by the reactor. | tune for your traffic | v0.3.0 |
| Header injection | RFC 7230 token validation rejects CR/LF/`\0` and out-of-spec characters at parse time. | none | v0.2.0 |
| Body size limits | Enforced by the reactor against `ServerConfig.max_body_size`; oversized bodies get a 413 before any handler dispatch. | configure | v0.3.0 |
| URI / header length limits | `max_uri_length`, `max_header_size`. Defaults are 8 KB each. | configure | v0.3.0 |
| Slow-client DoS | Mitigated by `idle_timeout_ms` + (Step 1) `read_body_timeout_ms`. | tune for your traffic | partial v0.3.0, full v0.5.0 Step 1 |
| Peer visibility | `Request.peer: SocketAddr` populated by the reactor at accept. Use for logging, rate limiting, ACLs. | none | v0.5.0 Step 1 |
| Sanitised error responses | 4xx bodies do not echo extractor `raise Error(...)` messages by default — fixed reason ("Bad Request") is sent, full message is logged with a `[flare:bad-request]` prefix. Switch with `ServerConfig.expose_error_messages = True` for local dev (the reactor copies the flag to every parsed `Request`). | none in prod | v0.5.0 Step 1 |
| Cancellation | `Cancel` token plumbed through `CancelHandler.serve(req, cancel)`. The reactor flips it on peer FIN, idle timeout, deadline, or shutdown. | check `cancel.cancelled()` between expensive steps | v0.5.0 Step 1 |
| Per-handler / per-body / per-request deadlines | `ServerConfig.{handler_timeout_ms, read_body_timeout_ms, request_timeout_ms}`. Defaults 30s / 30s / 60s; `0` disables. ``request_timeout_ms`` must bound the inner deadlines (checked at compile time in ``serve_comptime``). ``read_body_timeout_ms`` is wired through the cancel-aware reactor read path; ``handler_timeout_ms`` and ``request_timeout_ms`` cooperate via ``Cancel`` (the multi-threaded "external thread flips the cell" half lands with drain in commit 6). | none in prod | v0.5.0 Step 1 |
| Graceful shutdown | `HttpServer.drain(timeout_ms)` closes the listener, signals the reactor to stop, waits up to the timeout for in-flight events to flush, returns a `ShutdownReport`. The single-threaded variant is best-effort (one report per call); the multi-worker `Scheduler.drain` returning per-worker reports lands in v0.5.0 Step 2. | call `drain(timeout_ms)` instead of `close()` when you want graceful exit | v0.5.0 Step 1 |
| SIGTERM / SIGINT | Investigated. The libc-mmap pattern (`__attribute__((constructor))` mmaps a 4 KB page; Mojo + the C signal handler both bind to the address via an FFI helper) would work in principle but runs into Mojo `MutExternalOrigin` pointer-lifetime audit ambiguity around the signal-delivery boundary. Tracked for a Mojo nightly that ships module-level mutable globals. The shape will land cleanly when that's done; deferring now avoids ripping out the libc-mmap workaround later with tests breaking on the seam. | install your own `signal(2)` handler in a `sigwait` pthread that calls `srv.drain` | investigated, queued for next Mojo nightly |
| Multicore drain coordination | `Scheduler.drain(timeout_ms) -> List[ShutdownReport]` broadcasts to every worker, closes each worker's listener, joins. Each worker walks its own conn registry on stop and flips `Cancel.SHUTDOWN` on every in-flight `ConnHandle.cancel_cell` (worker-self-walks-conns pattern, in-thread) — cancel-aware handlers (`CancelHandler`/`ViewHandler`) observe the flip at their next `cancel.cancelled()` poll and short-circuit. Plain `Handler`s run to completion as before. SIGTERM-triggered drain (`install_drain_on_sigterm(srv)`) remains blocked on Mojo "global variables not supported"; production deployments wire SIGTERM to `srv.drain` via their own `sigwait` pthread. | call `Scheduler.drain(timeout_ms)` from the main thread or your own SIGTERM-watching pthread | shipped v0.5.0 |
| Streaming response bodies | `Body` / `ChunkSource` / `InlineBody` / `ChunkedBody[Source]` plus `StreamingResponse[B: Body]` and `serialize_streaming_response[B](resp, cancel, keep_alive) -> List[UInt8]` shipped. The serializer renders `Content-Length` framing for `InlineBody` and `Transfer-Encoding: chunked` framing per RFC 7230 §4.1 for `ChunkedBody`; cancel-aware mid-stream stop emits the chunked terminator so the framing contract holds even on a cooperative abort. The reactor-loop adoption that calls the serializer per writable edge ships in a tight follow-up commit gated on Mojo's parametric-trait-method-with-origin specialisation slowness clearing. | until reactor adoption lands, large/unbounded responses go through `serialize_streaming_response` directly + `Stream.write_all`; sub-MB inline responses keep using the v0.4.x `Response` path | shipped v0.5.0 (reactor pull-loop integration follow-up) |
| Server-side TLS | `TlsAcceptor` constructor wires through to OpenSSL via `flare/tls/_server_ffi.mojo` (`ServerCtx.new(cert, key)` runs the cert + key load + min-protocol TLS 1.2 + forward-secret AEAD ciphers + check-private-key). ALPN preference flows through `TlsServerConfig.alpn` to OpenSSL's selection callback (RFC 7301 server-preference). mTLS opt-in via `require_client_cert=True` + `client_ca_bundle` triggers `SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT`. Cert reload via `acceptor.reload()` re-runs cert + key load atomically; in-flight sessions hold the old cert. `TlsAcceptor.handshake_fd(fd) raises -> (ssl_addr, TlsInfo)` drives `SSL_accept` to completion in blocking-poll mode and returns live-populated TlsInfo (negotiated ALPN + SNI). The reactor `STATE_TLS_HANDSHAKE` state and `HttpsServer` entry point ship in a focused follow-up gated on Mojo specialisation slowness for parametric trait methods with origin (the same gap that affects `serve_view`). | terminate TLS at nginx / Caddy in front of flare for high-throughput production until the reactor adoption lands; for moderate-throughput or admin-plane use, drive `TlsAcceptor.handshake_fd` directly per-accept | shipped v0.5.0 (reactor-loop integration follow-up) |
| HTTP/2 | Planned: only over TLS, with paranoid HPACK bounds and a 5M-run fuzz gate. Requires server TLS first. `h2c` (HTTP/2 cleartext) is a permanent non-goal. | none | planned, v0.6 |
| Public async / await | Planned: gated on Mojo shipping `async`. The reactor is the foundation; the public `Handler` trait gains an `async` variant when Mojo is ready. | none | planned, v1.0 |
| Half-open connection handling | Today: `recv == 0` is treated as "peer closed; close everything," which is wrong for handlers that want to keep writing after observing a peer FIN. | known gap; see `.cursor/rules/criticism.md` §2.6 | planned |
| Header storage as offsets (no per-header `String` alloc on the read path) | `HeaderMapView[origin]` shipped (`flare/http/header_view.mojo`) with RFC 7230 §3.2.4 / §3.2.6 token + field-value validation. The reactor's cancel-aware read path now goes through `parse_request_view` (which uses `HeaderMapView` internally) — per-header `String` allocation eliminated during parse. `into_owned()` materialises an owned `HeaderMap` only when handlers explicitly need it. | none | shipped v0.5.0 |
| `RequestView[origin]` for borrowed bodies (zero-copy reads) | `RequestView[origin]` + `parse_request_view` shipped (`flare/http/request_view.mojo`). The cancel-aware reactor read path now calls `parse_request_view` and materialises the owned `Request` only at the `Handler.serve` boundary — per-header `String` allocation eliminated during parse. The `ViewHandler.serve_view(req: RequestView[origin], cancel)` trait + `HttpServer.serve_view[VH](handler)` entry point ship the full zero-copy contract (body slice points directly into `ConnHandle.read_buf`); `WithViewCancel[H]` adapter lets v0.4.x `Handler` structs plug into the same entry point. RFC 7230 §3.2.4 / §3.2.6 token + field-value validation maintained through the new parser. | none | shipped v0.5.0 |
| `Pool[ConnHandle]` typed allocator (replaces `UnsafePointer.alloc[ConnHandle]` in the hot path) | Generic `Pool[T: ImplicitlyDestructible & Movable]` in `flare/runtime/pool.mojo`. ``alloc_move(value) -> Int`` / ``free(addr)`` confine the unsafe pointer plumbing; the reactor's `_conn_alloc_addr` / `_conn_free_addr` route through it. ASAN-equivalent gate (Linux soak) lands with S3.7. | none | shipped v0.5.0 Step 2 |
| `Router` accepts `Handler` structs (not just `def` functions) | `r.get[H](path, h)` accepts any `H: Handler & Copyable & Movable` (including `Extracted[H]()`, `WithCancel[H]`, app-state-bearing handlers). The `def(Request)` overload still works. Boxing uses heap allocation per route plus monomorphised serve / destroy thunks for direct (no trait-table) dispatch. | none | v0.5.0 Step 2 |

---

## What "the user owns" really means

flare deliberately does not silently retry, hide errors, or paper over
operational state. If a handler raises, the reactor maps it to a 500
(or a 400 for parser-level errors). If a deadline fires, it flips
`Cancel`; the handler decides whether to short-circuit. If shutdown
hits, the reactor flips `Cancel.SHUTDOWN`; same deal.

The reason for putting all of this in one table is that flare's
predecessors and peers (nginx, Go `net/http`, Rust `hyper`) document
their operational behaviour in a dozen scattered places. We try to
keep one canonical answer per row, version-tagged, so a serious user
can read this page and decide whether flare meets their bar.

If a row above has the wrong answer for your workload, please open an
issue. The bar is not "is it fast." The bar is: **is it hard to
misuse under load and easy to operate.**
