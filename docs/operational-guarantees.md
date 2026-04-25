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
| SIGTERM / SIGINT | Planned: `install_sigterm_handler` / `install_drain_on_sigterm[srv]`. Mojo as of `v0.26.3.0.dev2026042205` doesn't allow module-level mutable `var`s, which the C-callable signal handler needs to communicate "I fired" to the application thread. The shape will land once Mojo grows static-mutable storage or libc `mmap` cooperates with `MutExternalOrigin`-tagged pointers. | until then, install your own `signal(2)` handler that flips a flag the main thread polls before calling `srv.drain` | planned, v0.5.0 Step 2 |
| Multicore drain coordination | Planned: `Scheduler.drain(timeout_ms)` broadcasts to every worker; returns one `ShutdownReport` per worker. | none | planned, v0.5.0 Step 2 |
| Streaming response bodies | Planned: `Body` + `ChunkSource` traits with reactor-pull chunks on writable edges. Today's behaviour is "buffer the whole response before the first send" — fine for sub-MB bodies, foot-gun for sub-GB. | until streaming lands, keep response bodies bounded | planned, v0.5.0 Step 2 |
| Server-side TLS | Planned: `TlsAcceptor` integrated with the reactor as a `STATE_TLS_HANDSHAKE` connection state, ALPN advertisement, optional mTLS, cert reload via atomic swap. Client TLS already ships. | until then, terminate TLS at nginx / Caddy in front of flare | planned, v0.5.0 Step 3 |
| HTTP/2 | Planned: only over TLS, with paranoid HPACK bounds and a 5M-run fuzz gate. Requires server TLS first. `h2c` (HTTP/2 cleartext) is a permanent non-goal. | none | planned, v0.6 |
| Public async / await | Planned: gated on Mojo shipping `async`. The reactor is the foundation; the public `Handler` trait gains an `async` variant when Mojo is ready. | none | planned, v1.0 |
| Half-open connection handling | Today: `recv == 0` is treated as "peer closed; close everything," which is wrong for handlers that want to keep writing after observing a peer FIN. | known gap; see `.cursor/rules/criticism.md` §2.6 | planned |
| Header storage as offsets (no per-header `String` alloc on the read path) | `HeaderMapView[origin]` shipped (`flare/http/header_view.mojo`); offset-based lookup, case-insensitive ASCII, OWS trimming, `into_owned()` for handlers that need owned headers. The reactor's read path still constructs an owned `HeaderMap` via `_parse_http_request_bytes`; the view-into-`Request.headers` integration lands with `RequestView[origin]` (S2.5). | none | shipped v0.5.0 Step 2 (integration in S2.5) |
| `RequestView[origin]` for borrowed bodies (zero-copy reads) | Planned: handlers gain a borrowed-body variant; `Request.into_owned()` for handlers that need to keep the request beyond one event-loop iteration. | none | planned, v0.5.0 Step 2 |
| `Pool[ConnHandle]` typed allocator (replaces `UnsafePointer.alloc[ConnHandle]` in the hot path) | Planned: confines `UnsafePointer` to `flare/runtime/`. ASAN-equivalent gate in CI. | none | planned, v0.5.0 Step 2 |
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
