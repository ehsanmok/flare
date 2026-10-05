# Features

Complete inventory of what ships in [`flare/`](../flare/), generated
by walking [`flare/__init__.mojo`](../flare/__init__.mojo) plus each
submodule. Every entry here is part of the stable public surface
(see [Stability](#stability)). Internal types (anything in `_*.mojo`)
are intentionally excluded.

For runnable code, [`cookbook.md`](cookbook.md) maps "I want to..." to
an example file. For layering and the request lifecycle, see
[`architecture.md`](architecture.md).

- [What serves what](#what-serves-what)
- [HTTP server](#http-server)
- [HTTP client](#http-client)
- [Routing](#routing)
- [Handlers and extractors](#handlers-and-extractors)
- [Middleware](#middleware)
- [Cookies, sessions, auth](#cookies-sessions-auth)
- [Forms and content-encoding](#forms-and-content-encoding)
- [Body, streaming, SSE, templates, static files](#body-streaming-sse-templates-static-files)
- [Streaming proxy surface (v0.9)](#streaming-proxy-surface-v09)
- [Observability](#observability)
- [HTTP/2](#http2)
- [WebSocket](#websocket)
- [TLS](#tls)
- [TCP, UDP, Unix sockets, DNS, addressing](#tcp-udp-unix-sockets-dns-addressing)
- [Crypto](#crypto)
- [I/O primitives](#io-primitives)
- [Reactor and runtime](#reactor-and-runtime)
- [Performance internals](#performance-internals)
- [Errors](#errors)
- [Configuration knobs](#configuration-knobs)
- [Stability](#stability)

## What serves what

Which wire works over which transport, at which worker count. The
handler is the same object in every cell.

| Wire | Cleartext, 1 worker | Cleartext, N workers | TLS, 1 worker | TLS, N workers |
|---|---|---|---|---|
| HTTP/1.1 | yes | yes | yes | yes |
| HTTP/2 | yes (h2c) | yes (h2c) | yes (ALPN `h2`) | yes (ALPN `h2`) |
| HTTP/3 | n/a | n/a | yes (`serve_http3`) | not yet |
| WebSocket | yes | yes | yes (over h1 or h2) | yes |

Every HTTP/2 cell above is verified against **curl**, not just against
flare's own client. That distinction matters: flare's client emits
HPACK H=0 literals, so an h2 server that rejected Huffman-coded headers
passed the whole in-tree h2 suite while being unable to answer curl,
a browser, or h2load (fixed in v0.10 -- see
`Http2Config.allow_huffman_decode`). `pixi run interop-smoke` is the
guard against that class of bug returning.

Cleartext picks the protocol with the RFC 9113 §3.4 preface peek; TLS
picks it from the ALPN the handshake negotiated. `bind` with a list (several
distinct addresses) is single-worker only -- multi-worker uses
`SO_REUSEPORT` on one address, and the N x M cross product is not built.
The io_uring buffer-ring path is HTTP/1.1 cleartext only and stays
opt-in. Its workers wait on the ring for at most 100 ms
(`io_uring_enter` with a timeout), so an idle worker sees the stop flag
and `shutdown()` / `drain` return without traffic.

## HTTP server

**Changed in v0.11 (breaking, with shims).** The server surface went
from nineteen entry points to four names.

| Before | Now |
|---|---|
| `bind(addr, config, h2_config)` | `bind(addr, config)`; HTTP/2 settings live at `config.h2` |
| `bind_many(addrs, config)` | `bind(addrs, config)` -- `bind` takes an address or a list |
| `serve(handler, ws_handler)` | `attach_ws_h2(ws_handler)` then `serve(handler)` |
| `serve_tls(h)` / `serve_tls(h, n)` | `serve(h)` / `serve(h, n)` on a `bind_tls` server |
| `serve_ws_upgrade(h, ws_fn, ...)` | `ServerConfig.ws = WsUpgrade(ws_fn, offload)`, then `serve(h)` |
| `serve_static_multicore(resp, n)` | `serve_static(resp, n)` |
| `ServerConfig.ws_handler` / `.ws_offload` | `ServerConfig.ws.handler` / `.ws.offload` |
| asserts inside `serve_comptime` | `ServerConfig.check[cfg]()`, callable anywhere |

`bind_many`, `serve_tls`, `serve_ws_upgrade` and `serve_static_multicore`
remain as delegating shims and are removed in 0.12. `serve_cancellable`,
`serve_view` and `serve_static` now raise when a TLS context or extra
listeners are bound, instead of silently ignoring both.

**Changed in v0.11 (breaking): stricter HTTP/1.1 request parsing.**
Each of these used to be accepted and is now answered 400 (or 501),
because a front end could read the same bytes as a different request:

- `Content-Length` counts only as a header line of its own; the value
  must be 1-18 digits. `Transfer-Encoding` is read across every line,
  must end in `chunked`, and may not appear alongside `Content-Length`.
  Any coding before `chunked` is a 501, since flare does not decode
  transfer codings.
- A bare LF ending the header block, a field line without a colon, an
  empty field name, and more than one `Host` field.
- A method that is not a token, a request target with anything other
  than visible ASCII, and a control byte other than HTAB in a field
  value.
- Repeated fields are all kept: `headers.get(name)` returns the first
  value and `get_all(name)` every one. Previously the last line won.

| Surface | Where |
|---|---|
| `HttpServer.bind(addr)` / `serve(handler)` / `serve(handler, num_workers=N)` — version-aware listener that dispatches HTTP/1.1, HTTP/2 over TLS (ALPN), and h2c (RFC 9113 §3.4 preface peek, no `Upgrade` dance) to the same handler | [`http_server.mojo`](../examples/basic/http_server.mojo), [`http2.mojo`](../examples/advanced/http2.mojo), [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) |
| `HttpServer.bind(addrs: List[SocketAddr])` — single-worker listener over multiple distinct addresses; the accept loop walks every fd and demuxes onto the same handler. `bind` takes one address or a list; `bind_many` is the pre-0.11 spelling and goes away in 0.12 | [`multi_listener.mojo`](../examples/intermediate/multi_listener.mojo) |
| HTTP/1.1 trailer fields (RFC 7230 §4.1.2 / §4.4) — `StreamingResponse[B].trailers: HeaderMap` on the outbound side (buffered `Response` uses `Content-Length` and never carries trailers), automatic `Trailer:` header, smuggling guard rejects trailers when `Content-Length` is present or when forbidden trailer names are listed; `HttpClient` parses inbound trailers off the chunked decoder and lands them on `Response.trailers` (also a `HeaderMap`) | [`trailers.mojo`](../examples/intermediate/trailers.mojo), [`tests/http/test_h1_trailers.mojo`](../tests/http/test_h1_trailers.mojo) |
| `HttpServer.serve_static(StaticResponse, num_workers=1)` — pre-encoded static-response fast path that skips parsing and handler dispatch; `num_workers > 1` runs one listener per worker thread (used by `flare_mc_static` bench row) | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |
| `ServerConfig.check[config]()` — build-time invariant checks on a comptime `ServerConfig`; `serve_comptime[handler, config]()` is the deprecated pre-0.11 spelling (removed in 0.12) | `flare.http.server` |
| Per-worker `SO_REUSEPORT` listeners by default (`num_workers >= 2`); `FLARE_REUSEPORT_WORKERS=0` switches to single-listener `EPOLLEXCLUSIVE` shape | [`multicore.mojo`](../examples/intermediate/multicore.mojo) |
| `pin_cores=True` (default): worker N pinned to core `N % num_cpus()` on Linux, no-op on macOS | [`multicore.mojo`](../examples/intermediate/multicore.mojo) |
| `HttpServer.drain(timeout_ms) -> ShutdownReport` per worker: closes the listener, keeps the reactor serving for the full `timeout_ms` (in-flight responses finish), then stops it; `drain(0)` is a hard stop | [`drain.mojo`](../examples/intermediate/drain.mojo) |
| `ServerConfig` (request / handler / `read_body_timeout_ms` deadlines, `max_header_size`, `max_body_size`, `max_keepalive_requests`, `idle_timeout_ms`) | `flare.http.server` |
| Response builders: `ok(body)`, `ok_json(body)`, `bad_request(msg)`, `not_found(msg)`, `internal_error(msg)`, `redirect(url)` | `flare.http.server` |
| `Method` enum, `Status` enum, `Response` with header / body / status, `ResponsePool` for response object reuse | `flare.http.{request,response,response_pool}` |
| `Request.peer` threaded from the accept path | `flare.http.request` |
| `precompute_response(status, content_type, body) -> StaticResponse` — keep-alive + `Connection: close` wire forms both pre-encoded; a `HEAD` request is answered with the head only (no body) | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |

## HTTP client

**Added in v0.11.** `with_h2c(prior_knowledge, upgrade)` is the builder
spelling for the `prefer_h2c` / `h2c_upgrade` constructor arguments,
which still work. `pool_stats()` returns one snapshot across all three
connection pools rather than four separate accessors. The default
`User-Agent` is derived from the library version; it had been the
literal `flare/0.1.0` for nine releases.

| Surface | Where |
|---|---|
| `HttpClient(base_url, auth=...)`, `HttpClient(prefer_h2c=True)` — version-aware over TLS+ALPN; `prefer_h2c=True` opts into HTTP/2 cleartext via prior knowledge | [`http_get.mojo`](../examples/basic/http_get.mojo), [`http2_client.mojo`](../examples/advanced/http2_client.mojo) |
| `HttpClient.with_pool(...)` — connection pool keyed on `(scheme, host, port)`, idle reuse, per-origin caps, stale-conn retry. Covers cleartext HTTP/1.1 and, over TLS, a `TlsConnectionPool` for HTTPS keep-alive (the whole established `TlsStream` is pooled); `idle_count()` / `tls_idle_count()` expose pool depth | [`client_pool.mojo`](../examples/advanced/client_pool.mojo), [`tests/http/test_tls_client_pool.mojo`](../tests/http/test_tls_client_pool.mojo) |
| `HttpClient(h2c_upgrade=True)` — h2c via Upgrade (RFC 7540 §3.2): client emits `Upgrade: h2c` + `HTTP2-Settings` on the first request, reads 101, carries the peer SETTINGS forward into a fresh h2 connection | [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo), [`tests/http/test_h2c_client_upgrade.mojo`](../tests/http/test_h2c_client_upgrade.mojo) |
| `HttpClient(prefer_http3=True)` / `.with_prefer_http3()` — HTTP/3 over QUIC: per-origin `Alt-Svc` (RFC 7838) discovery + cache, happy-eyeballs race of the HTTP/3-vs-HTTP/2 connection establishment on first contact (the request is sent once on the winner, never duplicated), transparent fallback to HTTP/2/HTTP/1.1 on any QUIC failure. Idempotent requests may ride 0-RTT on a resumed connection (replaying at 1-RTT if the server rejects). HTTP/3 connections are pooled + multiplexed per origin | [`http3_client.mojo`](../examples/advanced/http3_client.mojo), [`tests/http/test_h3_live_dial.mojo`](../tests/http/test_h3_live_dial.mojo) |
| `.with_redirect_policy(...)` — `RedirectPolicy.follow_all()` / `.same_origin_only()` / `.deny()` factories; modes on `RedirectMode.FOLLOW_ALL` / `.SAME_ORIGIN_ONLY` / `.DENY`; `TooManyRedirects` error. Origins compare the host case-insensitively (RFC 6454). A `Location` is resolved per RFC 3986 §5.2: absolute, network-path (`//host/path` keeps only the base scheme), origin-relative, query-only (`?page=2` keeps the base path), fragment-only and relative paths, with `.` / `..` segments removed from the resolved path | `flare.http.{redirect_policy,error}` |
| `.with_cookies()` — pointer-backed `CookieStore` cookie jar; captures `Set-Cookie` and replays matching cookies on subsequent requests. **Changed in v0.11 (breaking)**: cookies are scoped per RFC 6265 -- host-only unless `Domain` names the setting host or a parent, `Path`-matched, `Secure` only over https -- where the jar used to replay every cookie to every origin; a `Domain` for another site is refused. `cookie_header(url)` takes the URL to match. On a redirect to another origin the caller's own `Cookie` and `Proxy-Authorization` headers are dropped, as `Authorization` already was | [`tests/http/test_cookie_store.mojo`](../tests/http/test_cookie_store.mojo) |
| `.with_retry(RetryPolicy)` — bounded retry + backoff for idempotent requests | [`tests/http/test_client_ux.mojo`](../tests/http/test_client_ux.mojo) |
| `auto_decompress=True` (default) — transparent response body decompression (gzip / deflate / brotli) driven by `Content-Encoding`, bounded by a 16 MiB decompressed-size cap (zip-bomb guard) tunable via `.with_max_decompressed_bytes(n)` | [`tests/http/test_http.mojo`](../tests/http/test_http.mojo) |
| `RequestBuilder(method, url)` — per-request method / headers / query / typed body; `MultipartFormBuilder` assembles `multipart/form-data` bodies (RFC 7578) client-side | [`tests/http/test_multipart_builder.mojo`](../tests/http/test_multipart_builder.mojo) |
| `HttpClient.send_chunked(method, url, source, content_type, body_size, cancel)` — streaming *upload* from a `ChunkSource`, one chunk in flight, body never materialised. `body_size` (v0.11) switches the framing from `Transfer-Encoding: chunked` to `Content-Length` when the producer knows its length; `cancel` (v0.11) is threaded to `source.next()` so an upload can be abandoned between chunks. A source that raises mid-body propagates *without* writing the chunked terminator, so a truncated upload is never framed as a complete one. One-shot by design: no pooling, no redirects, no retries, since a streamed body cannot be replayed | [`streaming_upload.mojo`](../examples/advanced/streaming_upload.mojo), [`test_client_stream_upload.mojo`](../tests/http/test_client_stream_upload.mojo) |
| `HttpClient.get_streaming(url)` `-> HttpStreamResponse` — streaming *download* on `http://` and `https://` alike (v0.11; replaces the cleartext-only `get_streaming` plus its `get_streaming_tls` twin). The wire is whatever negotiation settles: ALPN picks `h2` or `http/1.1` on TLS, and the matching reader is used, so an h2 response streams rather than falling back. `read_chunk()` pulls the body in bounded memory; `read_all(limit)` is for bodies known to be small. `send_streaming(req)` is the primitive and `post_streaming(url, body)` the SSE / JSON-lines convenience. Auth and the cookie jar are attached; redirects and retries apply only until the head is parsed, because a streamed body cannot be replayed. The connection is exclusive and is not pooled. HTTP/1 framing is strict: informational 1xx heads are consumed, trailers land in their own `HeaderMap`, `max_header_bytes` bounds the head *and* each chunk-size line *and* the trailer section, and the reader refuses 101, a status outside 100-599, conflicting or duplicate `Content-Length`, a `Transfer-Encoding` whose final coding is not `chunked`, whitespace in a chunk-size line, obs-fold continuation lines, whitespace before a field-name colon, framing or routing fields in a trailer section, and a truncated body. HEAD, 204, 304 and a 2xx to CONNECT are bodyless | [`http_stream_client.mojo`](../examples/advanced/http_stream_client.mojo), [`test_stream_request_headers.mojo`](../tests/http/test_stream_request_headers.mojo) |
| `.with_proxy(url)` + `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` / `ALL_PROXY` env — routes requests through an HTTP proxy via a `CONNECT` tunnel (both `http://` and `https://`; TLS runs over the tunnel via `TlsStream.connect_over_tcp`) | [`tests/http/test_client_proxy.mojo`](../tests/http/test_client_proxy.mojo) |
| Module-level helpers: `get`, `post`, `put`, `patch`, `delete`, `head` — `post` with `String` body sets `Content-Type: application/json` automatically | `flare.http.client` |
| `Auth`, `BasicAuth(user, pass)`, `BearerAuth(token)` — both wires | `flare.http.auth` |
| `Response.json()`, `.text()`, `.raise_for_status()`, `.ok()`, `.status` | `flare.http.response` |

## Routing

| Surface | Where |
|---|---|
| `Router` — runtime trie with path parameters (`:name`), wildcards (`*`), method dispatch, 404 / 405-with-`Allow`. `Handler & Copyable & Movable` so `srv.serve(router^, num_workers=N)` resolves to the multi-worker overload; boxed struct handlers shared across worker copies via an Arc-style refcount | [`router.mojo`](../examples/basic/router.mojo), [`tests/http/test_router_copy.mojo`](../tests/http/test_router_copy.mojo) |
| `ComptimeRouter[ROUTES]`, `ComptimeRoute(method, path, handler)` — segments parsed at compile time, dispatch loop unrolled per route; as in `Router`, `*` is valid only as the last segment — a pattern with a middle `*` (e.g. `/files/*/meta`) matches nothing (404) instead of capturing the tail | [`comptime_router.mojo`](../examples/advanced/comptime_router.mojo) |
| Application-scoped state via captured handlers — wrap your handler in a struct that holds shared state by value; for shared mutation, use a `flare.runtime.Pool` heap-address handle | [`state.mojo`](../examples/intermediate/state.mojo) |

## Handlers and extractors

### Handler traits

| Trait | What it gets | Where |
|---|---|---|
| `Handler` | `serve(req: Request) raises -> Response` | `flare.http.handler` |
| `CancelHandler` | `serve(req: Request, cancel: Cancel) raises -> Response`; `cancel.cancelled()` flips on peer FIN, deadline elapse, or graceful drain | [`cancel.mojo`](../examples/intermediate/cancel.mojo) |
| `ViewHandler` | Receives `RequestView[origin]` for zero-copy reads (no `String` materialisation) | `flare.http.handler` |
| `WithCancel[Inner]` | Adapt a `CancelHandler` to fit the `Handler` shape | `flare.http.handler` |
| `WithViewCancel[Inner]` | Same, for `ViewHandler` + `Cancel` | `flare.http.handler` |
| `FnHandler(fn)` / `FnHandlerCT(fn)` | Wrap a plain `def` as a `Handler` (runtime / comptime) | `flare.http.handler` |

### Extractors

Concrete typed extractors (`.value` is the parsed primitive):

| Extractor | Type | Source |
|---|---|---|
| `PathInt[name]` / `PathStr[name]` / `PathFloat[name]` / `PathBool[name]` | path parameter | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `QueryInt[name]` / `QueryStr` / `QueryFloat` / `QueryBool` | query string | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `OptionalQueryInt[name]` / `OptionalQueryStr` / `OptionalQueryFloat` / `OptionalQueryBool` | optional query | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `HeaderInt[name]` / `HeaderStr` / `HeaderFloat` / `HeaderBool` | request header | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `OptionalHeaderInt[name]` / `OptionalHeaderStr` / `OptionalHeaderFloat` / `OptionalHeaderBool` | optional header | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `Peer` | client `SocketAddr` from accept path | `flare.http.extract` |
| `BodyBytes` / `BodyText` | raw request body | `flare.http.extract` |
| `Json[T]` | JSON-decoded body | `flare.http.extract` |
| `Form[T]` | `application/x-www-form-urlencoded` body | [`forms.mojo`](../examples/intermediate/forms.mojo) |
| `Multipart` | `multipart/form-data` body | [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo) |
| `Cookies` | inbound `Cookie:` header → `CookieJar` | [`request_cookies.mojo`](../examples/intermediate/request_cookies.mojo) |

Extractor traits + reflective adapter:

| Surface | What it does | Where |
|---|---|---|
| `Extractor` trait | Anything that pulls a value from a `Request` | `flare.http.extract` |
| `Extracted[H]` | Reflects on a struct's fields, runs every extractor before `serve`; malformed input becomes a sanitised 400. Copies a registration-time prototype per request, so pre-set fields survive | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| `State[T]` | No-op extractor field carrying registration-time state (DB pool, config, cache) alongside request-derived extractors -- the analogue of axum's `State(db)`. Set it on a prototype `H`, then `Extracted[H](proto^)` | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |

Custom types are handled by writing your own `Extractor` struct
that pulls and validates the value from the request. The
extractor surface is intentionally concrete — every type is
named — so the IDE, the compiler, and the reader all see the
same shape.

## Middleware

Each layer is itself a `Handler` that holds another `Handler`. Stack
by nesting structs:

    CatchPanic(Logger(RequestId(router^)))

**Changed in v0.11 (breaking).** A layer binds its inner handler as
`Handler & Copyable`. It used to also require `Defaultable`, which
meant a handler carrying required state could not be wrapped at all
without adding a dummy field to satisfy the bound. The no-argument
form each layer offered is gone with it: write `Logger(MyHandler())`
rather than `Logger[MyHandler]()`.

| Layer | Behaviour | Where |
|---|---|---|
| `Logger[Inner]` | Space-delimited per-request line (`[flare] GET /users 200 12ms`) | [`middleware.mojo`](../examples/intermediate/middleware.mojo) |
| `RequestId[Inner]` | Generate / propagate `X-Request-Id` | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) |
| `Compress[Inner]` | gzip / brotli / identity content-encoding via q-value negotiation; small-body / already-encoded / partial-content (206, `Content-Range`) skip. Every other response carries `Vary: Accept-Encoding`, including the identity variant (no `Accept-Encoding`, identity preferred, every coding refused), so shared caches keep the variants apart; skipped responses get no `Vary` | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo), [`brotli.mojo`](../examples/intermediate/brotli.mojo) |
| `CatchPanic[Inner]` | Convert handler panic to sanitised 500 | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) |
| `Cors[Inner]` + `CorsConfig` | WHATWG Fetch CORS protocol; permissive / allowlist / preflight short-circuit / credentials echo / exposed-headers / max-age. The allowlist is a set, independent of entry order: with `allow_credentials`, a `*` entry authorises nothing (a credentialed response may not use `*`) and the listed origins are matched wherever they appear. Every response carries `Vary: Origin`, including those without an `Origin`, from a rejected origin and the 403 to a rejected preflight, so shared caches keep CORS and non-CORS responses apart | [`cors.mojo`](../examples/intermediate/cors.mojo) |
| `Conditional[Inner]` | RFC 9110 §13 preconditions: `If-Match` / `If-None-Match` (304 / 412), `If-Modified-Since` / `If-Unmodified-Since`; opt-in auto-ETag from FNV-1a body hash via `Conditional.with_auto_etag`. On unsafe methods, `Conditional.with_validators(inner, lookup)` checks preconditions *before* the handler runs, from a `ValidatorLookup` returning the resource's current `Validators`. **Changed in v0.11 (breaking)**: without a lookup, an unsafe method's preconditions are left to the handler and its response passes through unchanged (it used to run the handler and then rewrite to 412, after the write had happened); only 2xx responses to GET / HEAD are rewritten to 304 / 412 | `flare.http.conditional` |
| `FileServer.new(root)` | Static file serving with GET / HEAD + RFC 9110 §14.4 single-Range, MIME inference, path safety (`..` / NUL / absolute path rejection), `index.html` directory fall-through | [`static_files.mojo`](../examples/intermediate/static_files.mojo) |
| `Retry[Inner]` + `RetryPolicy` | Re-invoke the inner handler up to `max_attempts` times on 5xx; RFC 9110 §9.2.2 idempotent-method gate on by default (GET / HEAD / PUT / DELETE / OPTIONS retry; POST / PATCH pass through once unless `retry_only_idempotent` is `False`). Optional exponential backoff with jitter via `RetryPolicy(backoff_base_ms, backoff_max_ms, backoff_jitter_ms)` | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `PostHocDeadline[Inner]` | **Post-hoc** wall-clock guard: invokes the inner handler synchronously, then if the elapsed time exceeds `budget_ms`, replaces the response with a sanitised 504. Does **not** cancel the inner handler mid-execution -- it only refuses the response that was produced too late. `budget_ms <= 0` is the explicit "disabled" sentinel that always trips 504. The cancel-cell wiring that would let the deadline preempt the inner handler is a future addition. | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `RateLimit[Inner]` | Token-bucket admission gate: admits `rate_per_sec` req/s with a `burst` depth, rejects with `429 Too Many Requests` once the bucket is empty (inner handler never invoked on rejection). `rate_per_sec <= 0` disables it. The refill is exact for any idle time (the elapsed time is clamped to the time that fills the bucket); `burst * 1e9` and `rate_per_sec` must stay below 2^62 | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `CircuitBreaker[Inner]` | Opens after `failure_threshold` consecutive failures (5xx or raise), fast-fails with `503` for `cooldown_ms` (counted from when the failing call returned, so a slow failure does not use up the cooldown), then a single half-open probe (other calls keep fast-failing with `503` while it is in flight); success closes it. `failure_threshold <= 0` disables it | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `negotiate_encoding(Accept-Encoding) -> Encoding` | RFC 9110 §12.5.3 q-value parser exposed for direct use. A coding takes the largest weight of an entry naming it, else the weight of `*`; the highest non-zero weight wins (ties br > gzip > identity), independent of entry order, and `identity;q=0, *` never selects identity. A bare `*` therefore picks br / gzip rather than identity | `flare.http.middleware` |

## HTTP caching (RFC 9111)

Cache primitives, an in-memory store, and a wrapping `Cache[Inner, S]`
middleware that handles RFC 9111 freshness and conditional revalidation.

| Surface | Where |
|---|---|
| `Cache[Inner, S]` — wrapping middleware: on cache hit + fresh-per-RFC-9111 entry, returns the stored response without invoking `Inner`; on miss / stale, runs `Inner` and stores the response (subject to `Cache-Control` directives). Conditional revalidation forwards `If-None-Match` / `If-Modified-Since` to upstream and folds 304 into the cached entry | [`http_cache.mojo`](../examples/intermediate/http_cache.mojo) |
| `parse_cache_control(headers) -> CacheControl` — RFC 9111 §5.2 directive parser (max-age, s-maxage, no-cache, no-store, private, public, must-revalidate, proxy-revalidate, immutable, stale-while-revalidate, stale-if-error) | `flare.http.cache.control` |
| `CacheControl` — typed directive struct with the full RFC 9111 §5.2 surface | `flare.http.cache.control` |
| `parse_vary_header(headers) -> List[String]` — RFC 9111 §4.1 `Vary:` parser feeding the secondary cache-key derivation | `flare.http.cache.control` |
| Shared-cache storage rules (v0.11): one store serves every client of the process, so `private` responses are never stored, a response to a request carrying `Authorization` is stored only with `public`, `s-maxage` or `must-revalidate` (RFC 9111 §3.5), and a response to a request carrying `Cookie` only with `public` or a `Vary` naming `Cookie`. **Breaking**: these used to be stored and served to other clients | [`test_cache_middleware.mojo`](../tests/http/test_cache_middleware.mojo) |
| `derive_cache_key(request) -> CacheKey`, `CacheKey` — method + canonical URL + `Vary`-aware secondary key | `flare.http.cache.key` |
| `CacheStore` trait + `InMemoryCacheStore(capacity)` — bounded FIFO store with `get` / `put` / `remove`; freshness logic lives on `CacheEntry` (parsed `CacheControl` + `Vary` carried at insert time so the lookup path doesn't re-parse) | `flare.http.cache.store` |
| `CacheEntry.is_fresh(now_ms)` — RFC 9111 §4.2 freshness check against the entry's parsed directives and `Date:` baseline | `flare.http.cache.store` |

## Cookies, sessions, auth

| Surface | Where |
|---|---|
| `Cookie`, `CookieJar`, `SameSite`; `Cookie.session(name, value)` for a session cookie with `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax` | [`cookies.mojo`](../examples/basic/cookies.mojo) |
| `parse_cookie_header`, `parse_set_cookie_header` (RFC 6265) | [`cookies.mojo`](../examples/basic/cookies.mojo) |
| `signed_cookie_encode(value, key)` / `signed_cookie_decode(cookie, key)` — HMAC-SHA256 over base64url payload + tag | `flare.http.session` |
| `signed_cookie_decode_keys(cookie, keys)` — accept any of N keys, for graceful key rotation | `flare.http.session` |
| `Session[T]`, `SessionCodec`, `StringSessionCodec` | [`sessions.mojo`](../examples/intermediate/sessions.mojo) |
| `CookieSessionStore` (signed-cookie-backed), `InMemorySessionStore` (server-side); both satisfy the `SessionStore` read trait (`cookie_name` + `load`) | [`sessions.mojo`](../examples/intermediate/sessions.mojo) |
| `BackedSessionStore[B: SessionBackend]` — CSPRNG-id signed cookie + a pluggable `SessionBackend` (`get`/`set`/`delete`/`sweep`) with TTL expiry + `destroy` revocation; `MemorySessionBackend` reference impl; `new_session_id()` (256-bit `/dev/urandom` id) | [`tests/http/test_session.mojo`](../tests/http/test_session.mojo) |
| `Auth`, `BasicAuth`, `BearerAuth`, `AuthError` | `flare.http.{auth,auth_extract}` |
| HAProxy PROXY v1 + v2 parser, `ProxyParseError` | `flare.http.proxy_protocol` |

**Changed in v0.11 (breaking).** `Cookie.to_set_cookie_header()` raises
(and so `Response.set_cookie` does) on a name that is not a token, a value
outside RFC 6265 cookie-octets -- above all a `;`, which injected attributes
-- a `Domain` / `Path` with a control byte or `;`, or an unknown `SameSite`.
`SameSite=None` now also emits `Secure`. `parse_set_cookie_header` reads a
negative `Max-Age` as "expire now" instead of dropping the sign, and ignores
a malformed one.

**Changed in v0.11 (breaking).** Every session store now needs a key of
at least 16 bytes (`MIN_SESSION_KEY_BYTES`) and raises at construction
without one; the zero-argument constructors, and `Defaultable`, are
gone from `CookieSessionStore` and `InMemorySessionStore`.
`add_previous_key` raises on a short key too, and `signed_cookie_decode`
refuses to verify under one. A short key used to be kept as an empty
"invalid" marker that could not sign but did verify, so a store built
from an unset environment variable accepted cookies anyone could forge.

## Forms and content-encoding

| Surface | Where |
|---|---|
| `FormData`, `parse_form_urlencoded`, `urldecode`, `urlencode`, `Form` extractor (decoding raises on a malformed escape or when the decoded bytes are not valid UTF-8; the `Form` extractor then answers 400) | [`forms.mojo`](../examples/intermediate/forms.mojo) |
| `MultipartPart`, `MultipartForm`, `parse_multipart_form_data`, `Multipart` extractor (server parse); `MultipartFormBuilder` (client build) | [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo) |
| `Url`, `UrlParseError` — URL parser, percent decoding | `flare.http.url` |
| `Encoding` enum, `compress_gzip` / `decompress_gzip`, `compress_brotli` / `decompress_brotli`, `decompress_deflate` | [`encoding.mojo`](../examples/basic/encoding.mojo), [`brotli.mojo`](../examples/intermediate/brotli.mojo) |
| `decode_content("br" / "gzip" / "deflate" / "identity", ...)` | `flare.http.encoding` |

## Body, streaming, SSE, templates, static files

| Surface | Where |
|---|---|
| `Body`, `InlineBody`, `ChunkedBody`, `ChunkSource`, `drain_body` | `flare.http.body` |
| `StreamingResponse[B]`, `serialize_streaming_response` | `flare.http.streaming_response` |
| `stream_response[S: ChunkSource](source, status)` — wire-agnostic streaming from the normal `Handler.serve -> Response` contract: the returned `Response.body_stream` is pulled a bounded batch at a time per writable edge and framed as H1 chunked, H2 DATA, H3 DATA, or chunked-over-`SSL_write` (https). Batching is what keeps an N-chunk response from costing N reactor turns; a source that yields an empty chunk ends the batch, which is how a live-but-idle source (SSE) avoids being re-polled in a tight loop. The **same handler streams byte-identically on every wire** (proven by `tests/http/test_cross_wire_streaming.mojo`); the H1 head is framed by the shared `frame_h1_stream_head_into` adapter | `flare.http.response`, `flare.http._server.write` |
| `response_from_body[B: Body](body, status, reason)` — opt-in `Response[B]` ergonomics: lowers any `Body` impl into the concrete `Response` (buffered when length-known, `body_stream`-chunked otherwise) for the normal `Handler` path, no hot-path change | `flare.http.response` |
| Inbound `Transfer-Encoding: chunked` request bodies — the reactor sizes a chunked request from its chunk framing (`scan_chunked_end`) instead of the absent `Content-Length`, and decodes it before dispatch, so a streamed upload reaches `Handler.serve` whole. `max_body_size` is enforced during the framing walk, not after, so an upload cannot grow the read buffer past the limit; malformed framing is a 400. Before v0.10 a chunked request was declared complete the moment its headers landed and the handler saw an empty body | `flare.http.proto.chunked`, [`tests/http/test_chunked_request.mojo`](../tests/http/test_chunked_request.mojo) |
| `RequestView[origin]`, `parse_request_view` — zero-copy borrow over the parsed request, paired with `ViewHandler` | `flare.http.request_view` |
| `HeaderMap`, `HeaderInjectionError`, `HeaderMapView`, `parse_header_view` | `flare.http.{headers,header_view}` |
| `StaticResponse`, `precompute_response` — pre-encoded wire form for fixed-body endpoints | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |
| `SseEvent`, `SseChannel` (in-memory FIFO + cancel-aware `ChunkSource` wrapper), `format_sse_event`, `sse_response` (buffered snapshot), `stream_sse_response` (K1 streaming via the Router/Handler path over H1 chunked + H2 DATA), `SseStreamingResponse[B]` | [`sse.mojo`](../examples/intermediate/sse.mojo) |
| Askama-shape templates: `{{ name }}` (HTML-escaped, `| safe` opt-out), `{% if %}...{% endif %}`, `{% for x in name %}...{% endfor %}`, single-level inheritance via `{% block <name> %}...{% endblock %}` + `{% extends "<parent>" %}` (rendered via `Template.render_extending(ctx, parent)`), `TemplateError` | `flare.http.template`, [`template_inheritance.mojo`](../examples/intermediate/template_inheritance.mojo) |
| `ByteRange`, `parse_range`, `FileServer` (see [Middleware](#middleware)) | `flare.http.fs` |

## Streaming proxy surface (v0.9)

The shape a streaming proxy (any reverse proxy that pumps an external
producer's output to a client) needs: a typed streaming server whose
response body's chunks arrive on a reactor-registered fd, with
backpressure coupled across upstream and downstream. The front is
a `StreamHandler` plus a typed state struct — no raw reactor loop, no
`UnsafePointer` state smuggling, no per-slot `alloc` tables, no manual
byte parsing, and — for the common single-upstream relay — no file
descriptors, no byte `Span` wrapping, and no per-connection table in
front code at all. See
[`streaming_proxy.mojo`](../examples/advanced/streaming_proxy.mojo) for
the end-to-end shape; a complete relay front is `on_open` (attach a
source) + `on_upstream` (`conn.relay_upstream()`).

| Surface | Where |
|---|---|
| `StreamHandler` — typed lifecycle trait (`on_open` / `on_upstream` / `on_writable` / `on_close`); the handler struct's fields are its shared state | `flare.http.streaming_server`, `flare` |
| `StreamConn` — framework-owned per-connection handle: owns the client `TcpStream`, a per-connection `Cancel`, one optional framework-owned upstream source, and a single coalescing outbound buffer (`send` queues; the reactor drains on writable edges) | `flare.http.streaming_server`, `flare` |
| `HttpServer.serve_streaming[H](handler, max_in_flight=0, retry_after_s=1)` — the streaming entry point; `max_in_flight` admits with a 503 + `Retry-After` past the cap. A `serve_streaming[H](handler, num_workers=N)` overload fans out across N pthreads (`StreamFrontend` + shared reactor loop), each worker with its own handler copy | [`tests/http/test_streaming_multicore.mojo`](../tests/http/test_streaming_multicore.mojo), `flare.http.server` |
| `conn.attach_upstream(source)` + `conn.relay_upstream()` — hand an `UpstreamChunkSource` to the framework (it watches the fd, owns the source, closes it on teardown, and cancels upstream on client disconnect); `relay_upstream` is the whole drain loop. No descriptors, no table, no manual close | `flare.http.streaming_server` |
| `conn.send(data)` — accepts `Span[UInt8, _]` (zero-copy), `List[UInt8]`, or a `StringSlice`/string; a front sends bytes or text with no `Span[UInt8, _]` wrap at the call site | `flare.http.streaming_server` |
| `conn.attach_upstream(fd)` / `detach_upstream()` (low-level) — register a raw front-owned upstream fd (a bare pipe / eventfd, not an `UpstreamChunkSource`) so the reactor fires `on_upstream`; the front then owns the fd's close | `flare.http.streaming_server` |
| `AsyncChunkSource` trait + `ChunkPoll` tri-state (`ready(bytes)` / `pending(fd)` / `eof()`) — a body whose chunks arrive asynchronously without busy-polling | `flare.http.async_body`, `flare` |
| `UpstreamChunkSource` — concrete `AsyncChunkSource` over a framed UDS logical stream; `UpstreamChunkSource.connect(path)` dials it in one call (`request_id` defaults to `1`); `poll(cancel)` returns the tri-state, `send_cancel()` propagates a client disconnect upstream | `flare.http.async_body`, `flare` |
| Watermark backpressure: `conn.set_watermarks(hi, lo)`, `write_buffer_full()`, `apply_backpressure()` — hi/lo hysteresis gates upstream read interest so a slow client cannot force unbounded buffering | `flare.http.streaming_server` |
| Incremental inbound body: `conn.enable_inbound()`, `conn.read_body(max_bytes)` returning `ChunkPoll` — bounded-memory consumption of a large request body | `flare.http.streaming_server` |
| Write coalescing: K `send` calls in one tick flush in one `send(2)`; `conn.write_syscalls()` observes it | `flare.http.streaming_server` |
| `FrameMux` — multiplexes many logical streams over one owned `UnixStream` (`open` / `send_chunk` / `done` / `cancel` / `flush` / `pump` / `poll`); frame `\| u32 len \| u64 request_id \| u8 kind \| payload \|` via `encode_frame` / `decode_frame`, `Frame`, `FrameKind`, `FrameDemux`; fuzz-clean | `flare.uds.frame_mux` |
| `ByteReader[origin]` / `ByteWriter` — bounds-checked, endian-aware byte cursors (checked u8/u16/u32/u64 be+le, `read_utf8`); replace raw `UnsafePointer` frame parsing | `flare.io`, `flare` |

## Observability

| Surface | Where |
|---|---|
| `Logger[Inner]` — space-delimited line, grep / `jq` friendly, zero-dep | `flare.http.middleware` |
| `StructuredLogger[Inner]` — JSON-per-line additive sibling: `{"ts","method","url","status","latency_ms","request_id","peer"}`; works with Datadog / Elastic / Loki / Splunk / CloudWatch out of the box | `flare.http.structured_logger` |
| `Metrics[Inner]` — Prometheus text-exposition middleware; emits `flare_http_requests_total{method,status}`, `flare_http_request_duration_seconds_bucket{le}`, `..._sum`, `..._count`, `flare_http_requests_in_flight`, `flare_http_request_errors_total` with the canonical Prometheus default-bucket layout | `flare.http.metrics` |

## HTTP/2

`HttpServer` and `HttpClient` are HTTP-version-aware: the reactor
auto-dispatches HTTP/1.1, HTTP/2 over TLS+ALPN, and h2c per RFC 9113
§3.4 to the same handler. The low-level codec / state-machine
primitives in `flare.http2` are public for callers who want their
own dispatch loop.

| Surface | Where |
|---|---|
| `Http2Connection` synchronous driver — `take_request() -> Request`, `emit_response(...)` queues `HEADERS [+ DATA]`; strips `Connection / Transfer-Encoding / Keep-Alive / Proxy-Connection / Upgrade` per RFC 9113 §8.2.2 | [`http2.mojo`](../examples/advanced/http2.mojo) |
| Reactor wiring (one fd → one `Http2Connection`, ALPN dispatch, h2 prior-knowledge per RFC 9113 §3.4) | `flare.http._unified_reactor_impl`, [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) |
| h2c via Upgrade (mid-stream switch from h1 to h2 per RFC 7540 §3.2) | `flare.http._unified_reactor_impl._migrate_h1_to_h2`, [`tests/http/test_h2c_upgrade.mojo`](../tests/http/test_h2c_upgrade.mojo) |
| RFC 8441 Extended CONNECT dispatch + SETTINGS latch (server side); fuzz-covered (`fuzz-extended-connect`) | `flare.http2.state` |
| `Http2Config` — SETTINGS knobs validated at construction | [`http2_config.mojo`](../examples/advanced/http2_config.mojo) |
| `is_h2_alpn(...)`, `detect_h2c_upgrade(headers)` | `flare.http2.server` |
| `H2_PREFACE`, `H2_DEFAULT_FRAME_SIZE`, `H2_MAX_FRAME_SIZE`, `Http2Error`, `Http2ErrorCode` | `flare.http2` |
| Frame codec: `Frame`, `FrameFlags`, `FrameHeader`, `FrameType`, `encode_frame`, `parse_frame` (RFC 9113 §4, all 10 frame types); fuzz-clean (`fuzz-h2-frame`) | `flare.http2.frame` |
| Stream state: `Stream`, `StreamState`, `Connection.handle_frame` (RFC 9113 §5); fuzz-clean (`fuzz-h2-continuation`, `fuzz-h2-rapid-reset`) | `flare.http2.state` |
| HPACK (RFC 7541): `HpackEncoder`, `HpackDecoder`, `HpackHeader`, `encode_integer` / `decode_integer` (4/5/6/7-bit prefix codec); static + dynamic table, all four indexing modes, dynamic-table size update; fuzz-clean (`fuzz-hpack-decoder`) | `flare.http2.hpack` |
| HPACK Huffman **decode on by default** (`Http2Config.allow_huffman_decode`) — RFC 7541 §5.2 makes Huffman the encoder's choice, signalled per literal by the H bit, so a decoder must accept both forms. curl, browsers and h2load all Huffman-code by default; this defaulted to `False` through v0.9, which made the h2 server unable to complete a request from any of them. `allow_huffman_encode` stays off: what the server emits is its own choice and H=0 is side-channel-free by construction | `flare.http2.server` |
| HPACK Huffman codec — scalar-correct, H=1 wire-up + RFC 7541 §C.4 fixtures, and a 256-entry table-driven fast decoder that resolves codes of length <= 8 in one lookup (>=3x scalar across 16 B / 256 B / 4 KB / 64 KB input sizes; codes of length 9..30 fall through to the scalar bit-walker) | `flare.http.hpack_huffman`, `flare.http.hpack_huffman_simd` |
| CONTINUATION-flood / RAPID-RESET (CVE-2023-44487) state-machine fuzz coverage | `fuzz/fuzz_h2_continuation.mojo`, `fuzz/fuzz_h2_rapid_reset.mojo` |
| RFC 8441 Extended CONNECT (client side — `WsClient` over h2): `Http2ClientConnection.send_extended_connect` + `WsOverH2Stream` adapter + `bootstrap_ws_over_h2` | [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo), `flare.ws.client_h2` |
| RFC 8441 Extended CONNECT (server side — WS-over-h2 bridge): `Http2Connection.take_extended_connect_streams` / `accept_ws_over_h2` (200 without END_STREAM) / `drain_stream_data` + `WsOverH2ServerStream` (unmasked server frames, unmasks client frames); full paired-driver round-trip | [`tests/ws/test_ws_h2_roundtrip.mojo`](../tests/ws/test_ws_h2_roundtrip.mojo), `flare.ws.server_h2` |
| RFC 8441 Extended CONNECT (server side — reactor sidecar dispatch): edge-driven `WsH2Handler` (`on_open`/`on_message`/`on_close`) + `HttpServer.attach_ws_h2(ws_handler)` then `serve(handler)` route a live CONNECT stream to the handler over the unified reactor (boxed `WsH2Hooks`, zero-cost when none is attached; the `serve[H, W]` overload this replaces went away in v0.11); forked h2c e2e | [`tests/ws/test_ws_h2_reactor.mojo`](../tests/ws/test_ws_h2_reactor.mojo), `flare.ws.server_h2`, `flare.http.server` |
| HTTP/2 concurrent multiplexed server streaming (K1): a handler returning `stream_response` / `stream_sse_response` ships a bounded batch of DATA frames per writable edge; **many** streaming responses run concurrently on one connection with a fair per-stream pump, `min(conn, stream)` send-window bounding, and WINDOW_UPDATE re-pump (no single-active-stream ceiling); trailers close each stream — the same body-stream path as H1 chunked | [`tests/http2/test_h2_conn_handle.mojo`](../tests/http2/test_h2_conn_handle.mojo), [`tests/http2/test_h2_server_handler.mojo`](../tests/http2/test_h2_server_handler.mojo), `flare.http._h2_conn_handle`, `flare.http2.server` |
| Per-stream `Cancel` propagation (peer RST_STREAM → handler `cancel.cancelled()`): `Http2ConnHandle` carries a `Dict[StreamId, Cancel]`, RST_STREAM / GOAWAY / drain all signal the matching cell | `flare.http._h2_conn_handle`, [`tests/http2/test_h2_per_stream_cancel.mojo`](../tests/http2/test_h2_per_stream_cancel.mojo) |
| h1.1 client connection pool: `HttpClient.with_pool(...)` keyed on `(scheme, host, port)`, idle reuse + per-origin caps + stale-conn retry | [`client_pool.mojo`](../examples/advanced/client_pool.mojo), `flare.http.client_pool` |
| h2c via Upgrade (client side — `Upgrade` + `HTTP2-Settings` + 101 carry-forward) | [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo), [`tests/http/test_h2c_client_upgrade.mojo`](../tests/http/test_h2c_client_upgrade.mojo) |
| Incremental response streaming (v0.11): `Http2ClientConnection.enable_response_streaming(sid)` defers a stream's flow-control credit so it is returned by `drain_body` rather than on receipt, which is what keeps a large body bounded instead of buffered. `initial_response_headers` / `response_trailers` expose the head before the body completes | [`test_h2_streaming_state.mojo`](../tests/http2/test_h2_streaming_state.mojo) |
| Request-body bound (v0.11): `Http2Config.max_body_size` resets an over-large stream with `ENHANCE_YOUR_CALM` and drops both its body and its header list. A malformed response is a stream error per RFC 9113 §8.1.1, never a connection error, so one bad stream cannot take its siblings down | [`test_h2_streaming_state.mojo`](../tests/http2/test_h2_streaming_state.mojo) |

## HTTP/3 + QUIC

End-to-end QUIC v1 (RFC 9000) + HTTP/3 (RFC 9114) server: the
sans-I/O codecs, the pure state machines, the OpenSSL AEAD
backend behind `QuicCrypto`, the rustls binding behind
`RustlsQuicAcceptor`, the QUIC UDP reactor (live
`recv -> dispatch -> handle -> drain -> protect -> sendto`
cycle), the per-stream HTTP/3 dispatch
(`Http3Connection` slab on `QuicListener`), the
Handler-mounted serve loop (`HttpServer.bind_with_http3 +
serve_http3[H]`), and the ALPN router on top of
`HttpServer.bind` are all wired. The same `Handler` instance
reaches HTTP/1.1 + h2c + HTTP/2 + HTTP/3 simultaneously.

**Live wire status (gate met).** The QUIC reactor I/O cycle is
live, the rustls FFI wrapper surfaces the per-level
`KeyChange` Handshake / 1-RTT keys back to
`QuicConnection.install_handshake_keys` /
`install_1rtt_keys`, and the Handler dispatch chain carries
requests end-to-end over the wire. The bench gate
(`flare_h3 >= 72,571 req/s vs quiche`) closed: flare HTTP/3 leads
at `74,653 req/s` (median, `+2.9 %` over `quiche 0.22`) on the
1-client x 100-stream workload. The win came from the reactor
rewrite -- eliminating per-packet whole-connection deep copies
(in-place `ref` mutation), a cached-table QPACK decode path,
and coalesced 1-RTT egress with capacity-reserved packet
builders. See the `docs/benchmark.md` HTTP/3 row for the full
table and baselines.

The codec layer is byte-clean and covered by `fuzz-quic-varint`,
`fuzz-quic-long-header`, `fuzz-quic-frame-decode`,
`fuzz-quic-transport-params`, `fuzz-h3-frame`,
`fuzz-qpack-decode`, `fuzz-quic-packet-decrypt`,
`fuzz-quic-initial-handshake`, `fuzz-quic-connection-id`, and
`fuzz-h3-server` (200 K runs each, zero crashes); see the
[fuzz coverage table](#testing-and-fuzz-coverage). The codec
demo at [`quic_codec_demo.mojo`](../examples/advanced/quic_codec_demo.mojo)
exercises varint, frame codec, transport parameters, state
machine, and congestion controller round-trips end-to-end. The
runnable server example at [`http3_server.mojo`](../examples/advanced/http3_server.mojo)
serves a single `Handler` over HTTP/1.1 + HTTP/2 + HTTP/3 simultaneously.

**Limits and checks the server now enforces.** These came in with the
v0.11 audit fixes; before them the server accepted what follows.

- A handler that raises, or a request the h3 layer cannot build, now
  ends only that stream: `400` for a malformed request, `500` for a
  handler error (its text only with `expose_errors`). It used to stop
  `serve_http3` for every connection.
- Requests are validated like h2 ones. A missing or duplicated pseudo
  header, or a connection-specific field (`Connection`, `TE` other than
  `trailers`, ...), is refused instead of defaulting to `GET /`.
  Connection-specific fields are no longer emitted in responses.
- An Initial in a datagram under 1200 bytes is dropped (RFC 9000 sec
  14.1). Until the client's address is validated, the server sends at
  most three times what it received, and the handshake flight goes out
  in packets that fit a 1200-byte datagram.
- The server picks its own connection ID rather than adopting the
  client's, sets `retry_source_connection_id` after a Retry, and keeps
  `active_connection_id_limit` at 2. The flare client validates the
  connection IDs in the server's transport parameters, and the server
  validates the client's once the handshake reaches 1-RTT keys: a blob
  that does not decode, carries a server-only parameter, or lacks the
  client's `initial_source_connection_id` closes the connection with
  TRANSPORT_PARAMETER_ERROR (RFC 9000 sec 7.3, 18.2).
- Only CRYPTO, ACK, PADDING, PING and CONNECTION_CLOSE are accepted in
  Initial and Handshake packets, Initial keys are dropped once the
  handshake moves on, and HTTP/3 is dispatched only on 1-RTT or 0-RTT
  data.
- Stream ids, the bidi stream count and connection flow control are
  enforced, and credit is granted as the application consumes data
  rather than as the peer sends it. A request body is capped at
  10 MiB (`Http3RequestReader.max_body_bytes`); the QPACK encoder stream
  may not set a table capacity beyond what was advertised, and an
  instruction that names a missing or evicted entry (Insert With Name
  Reference, Duplicate) is `QPACK_ENCODER_STREAM_ERROR` (0x201) at once
  rather than a stalled stream.
- A request field section that cannot be decoded (a Required Insert
  Count the table cannot satisfy, a reference outside it, or a truncated
  prefix) is a connection error: the server closes the connection with
  `QPACK_DECOMPRESSION_FAILED` (0x200) instead of leaving the request
  unanswered. It advertises 0 blocked streams, so nothing waits for
  inserts. Any other HTTP/3 or QPACK error the driver raises closes the
  connection with its H3 code (`flare.http3.server.h3_error_code`) and
  no longer stops `serve_http3`.
- The HTTP/2-reserved frame types 0x02, 0x06, 0x08 and 0x09 (PRIORITY,
  PING, WINDOW_UPDATE, CONTINUATION) on a request stream are a connection
  error of type `H3_FRAME_UNEXPECTED` (0x105), not ignored as unknown
  frames.
- A peer SETTINGS frame carrying an HTTP/2-reserved identifier
  (0x02 to 0x05) is `H3_SETTINGS_ERROR` (RFC 9114 §7.2.4.1); other unknown
  identifiers are ignored.
- DATA, HEADERS, PUSH_PROMISE and the HTTP/2-reserved types on the
  peer's control stream are `H3_FRAME_UNEXPECTED` (RFC 9114 §7.2); CANCEL_PUSH,
  MAX_PUSH_ID and unknown types stay accepted.
- A client-initiated push stream (type 0x01) and a second QPACK encoder
  or decoder stream are `H3_STREAM_CREATION_ERROR` (RFC 9114 §6.2.2,
  RFC 9204 §4.2), like a second control stream.
- A request-stream frame other than HEADERS and DATA (an unknown or
  grease type) that declares more than `max_field_section_size` bytes
  (default 8192) is refused from its header with `H3_EXCESSIVE_LOAD`
  rather than buffered up to the QUIC flow-control window.
- A GOAWAY frame must carry exactly one varint: bytes after the stream id,
  an empty payload or a truncated id are `H3_FRAME_ERROR` (RFC 9114 §7.2.6,
  §7.1), not ignored.
- CRYPTO reassembly holds at most 64 KiB ahead of the next expected
  byte, and a request stream at most 2 MiB ahead of a gap.
- Duplicate packets are dropped, ACKs for packet numbers never sent
  close the connection with `PROTOCOL_VIOLATION`, and a connection's
  slot is reclaimed when it dies. `QuicServerConfig.max_connections`
  (10,000 by default) caps live connections; an Initial past it is
  dropped.

The bench figure above predates these checks and has not been re-run.

| Surface | Where |
|---|---|
| QUIC variable-length integer codec (RFC 9000 §16): `QuicVarint`, `quic_encode_varint`, `quic_decode_varint`, `quic_varint_encoded_length`, `QUIC_VARINT_MAX` | `flare.quic.varint` |
| QUIC long / short packet header codec (RFC 9000 §17): `QuicLongHeader`, `QuicShortHeader`, `QuicConnectionId`, `QuicInitialExtras`, `quic_encode_long_header`, `quic_encode_short_header`, `quic_parse_long_header`, `quic_parse_short_header`, `quic_parse_initial_extras` | `flare.quic.packet` |
| QUIC packet-type constants: `QUIC_PACKET_TYPE_INITIAL` / `_ZERO_RTT` / `_HANDSHAKE` / `_RETRY`, `QUIC_VERSION_1`, `QUIC_VERSION_NEGOTIATION`, `QUIC_MAX_CID_LENGTH` | `flare.quic` |
| QUIC transport-frame codec (RFC 9000 §19 — all 22 frame types: PADDING, PING, ACK / ACK_ECN, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI / _UNI, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED_BIDI / _UNI, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport + application), HANDSHAKE_DONE, plus RFC 9221 DATAGRAM with / without length): typed payload structs (`AckFrame`, `StreamFrame`, `CryptoFrame`, `DatagramFrame`, ...) plus the `FrameHandler` trait + `parse_frame_into[H](buf, handler)` (MAX_STREAMS / STREAMS_BLOCKED above 2^60 and ACK ranges reaching below packet number 0 are a FRAME_ENCODING_ERROR) zero-carrier dispatcher (the parser walks one wire frame and fires the matching `on_*` callback on the caller's handler -- no intermediate union allocation), the per-type `encode_*(payload, mut out: List[UInt8])` writers that append to a caller-owned buffer, and the `FRAME_TYPE_*` constants | `flare.quic.frame` |
| QUIC transport parameters (RFC 9000 §18): `TransportParameters`, `encode_transport_parameters`, `decode_transport_parameters`, `empty_transport_parameters`, `check_client_transport_params` / `check_server_transport_params` (RFC 9000 §7.3 / §18.2 connection-ID authentication: an absent `initial_source_connection_id` differs from a zero-length one, `retry_source_connection_id` needs a Retry, no `preferred_address` with a zero-length CID); `initial_max_streams_bidi` / `_uni` above 2^60 and a `preferred_address` that breaks its RFC 9000 §18.2 layout (1..20-byte CID, 41 + CID-length bytes) are a TRANSPORT_PARAMETER_ERROR on decode; all `TP_ID_*` identifiers and defaults (`DEFAULT_MAX_UDP_PAYLOAD_SIZE`, `DEFAULT_ACK_DELAY_EXPONENT`, `DEFAULT_MAX_ACK_DELAY`, `DEFAULT_ACTIVE_CONNECTION_ID_LIMIT`) | `flare.quic.transport_params` |
| QUIC connection + stream state machines (RFC 9000 §3, §10, §13): `Connection`, `Stream`, `ConnectionEvents`, `handle_frame`, `mark_handshake_complete`, `is_idle_timeout_expired`, `connection_close`, `new_connection`, `new_stream`, `empty_events`; `CONN_STATE_*` and `STREAM_STATE_*` enums | `flare.quic.state` |
| QUIC congestion control (RFC 9002 §7): the `CongestionController` trait + `RenoController` (RFC 9002 NewReno) + `CubicController` (RFC 9438 CUBIC with RFC 9406 HyStart++ slow-start exit), selected by `CcChoice`. The 1-RTT loss-recovery path (`flare.quic._loss_recovery`) now runs an RTT estimator (RFC 9002 §5), ACK-based loss detection (§6.1 packet-number + time thresholds), the §6.2 PTO formula, and drives a CUBIC controller on every ACK / loss. Both peers use it: the client since v0.9 and the server since v0.11. RFC 9002 §7.7 send pacing is still not wired (the window gates burst size; there is no inter-packet timer) -- deferred to v0.12 | `flare.quic.cc` |
| QUIC initial-secret + AEAD key schedule (RFC 9001 §5 + RFC 5869 HKDF): `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label`, `derive_initial_secrets`, `QuicAead` enum, `QuicCrypto` trait, `OpenSslQuicCrypto`. OpenSSL AEAD backend (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) + AES-ECB / ChaCha20 header-protection mask per RFC 9001 §5.3 / §5.4; key schedule is RFC 9001 Appendix A.1 byte-exact, AEAD vectors are RFC 9001 Appendix A byte-exact, both pinned by `tests/quic/test_crypto.mojo` + `tests/quic/test_openssl_quic_crypto.mojo` + `tests/quic/test_rfc9001_appendix_a.mojo`; fuzz-covered (`fuzz-quic-packet-decrypt`) | `flare.quic.crypto` |
| Batched UDP I/O (`flare.udp.batch`, Linux): `BatchReceiver` (one `recvmmsg(2)` drains a whole inbound burst), `send_batch` (one `sendmmsg(2)` for a vector of datagrams), `send_segmented` (GSO `UDP_SEGMENT` one-`sendmsg` egress), all behind `udp_batch_supported()` + an `ENOSYS`-latched fallback to per-datagram `recvfrom` / `sendto`. The QUIC reactor's per-tick drain uses `BatchReceiver` by default (disable with `FLARE_QUIC_NO_BATCH=1`); loopback A/B shows no throughput regression on the single-client HTTP/3 bench and tighter run-to-run variance | `flare.udp.batch` |
| HTTP/3 server driver: `Http3Connection` (per-connection driver mounted on `Handler`), `Http3Config` (SETTINGS carrier -- max field section size, QPACK table caps, CONNECT-Protocol toggle, GOAWAY soft cap), `Http3StreamType` (RFC 9114 §6.2 codepoints). `feed_stream_chunk` drives `Http3RequestReader` -> `Handler` -> response writer; `take_response_frames` drains encoded bytes; the server opens its own control stream (stream 3: type 0x00 + SETTINGS) with the first 1-RTT flight (`take_control_stream_start`); CONTROL + QPACK uni-stream dispatch consumes SETTINGS / GOAWAY / MAX_PUSH_ID and replays peer QPACK encoder-stream inserts into a per-connection dynamic table (`take_qpack_decoder_frames` drains the owed Insert Count Increment); fuzz-covered (`fuzz-h3-server`) | `flare.http3.server` |
| QUIC server reactor: `QuicServerConfig`, `QuicListener`, `QuicConnection`, `ConnectionIdTable` (RFC 9000 §5 -- multiple connection IDs per peer). UDP bind + a blocking `recv_from` wake followed by a batched `recvmmsg` burst drain (per-datagram `try_recv_from` fallback) + per-datagram dispatch with coalesced 1-RTT egress, ECN echo per RFC 9002 §A.4. Idle-timeout dispatch follows RFC 9000 §10.1 (the timer uses the minimum of the server's and the client's non-zero `max_idle_timeout`, at least 3×PTO, is disabled when both are 0, and is restarted only by a successfully processed packet or the first ack-eliciting packet sent after one), plus stateless reset on unknown short-header DCIDs (RFC 9000 §10.3) and ack-delay timer dispatch, PROTOCOL_VIOLATION for a HANDSHAKE_DONE frame received by a server (RFC 9000 §19.20), STREAM_STATE_ERROR / STREAM_LIMIT_ERROR for a RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA or STREAM_DATA_BLOCKED that names a stream half that does not exist or a stream above the advertised limit (RFC 9000 §4.6, §19.4-§19.13), the advertised unidirectional stream limit enforced on STREAM frames too, and RFC 9002 loss recovery: inbound ACK ranges drive a per-slot `LossRecovery`, lost frames are re-sent under fresh packet numbers, and a real PTO probes the oldest unacked packet, bounded by `QuicServerConfig.max_pto_count`. A connection error closes the connection with a 1-RTT CONNECTION_CLOSE carrying the error code, then the slot stays in the closing state for three PTOs (at most 10 s), answering incoming packets with CONNECTION_CLOSE (rate limited) before it is reclaimed (RFC 9000 §10.2). After the peer's CONNECTION_CLOSE a connection is draining and the server sends no packet at all (§10.2.2). Received packet numbers are tracked as at most 32 ACK ranges plus a floor, so a replayed packet from a range dropped at the cap is still recognised as a duplicate. Send pacing is deferred to v0.12; fuzz-covered (`fuzz-quic-initial-handshake`, `fuzz-quic-connection-id`) | `flare.quic.server` |
| HTTP/3 incremental server streaming (K1): a handler returning `stream_response` / `stream_sse_response` emits HEADERS first, then pumps one DATA frame per tick from the stashed (boxed) `ChunkSource` with a persistent per-stream send offset, MTU-bounded by datagram fragmentation, deferring FIN + trailers to end-of-stream — the same wire-agnostic body-stream path as H1 chunked / H2 DATA (buffered path stays byte-identical) | [`tests/h3/test_h3_end_to_end.mojo`](../tests/h3/test_h3_end_to_end.mojo), `flare.quic.server` |
| ALPN -> wire-protocol dispatcher: `WireProtocol` codepoints (UNKNOWN / HTTP_1_1 / H2C / HTTP_2 / HTTP_3), `ALPN_HTTP_1_1` / `ALPN_HTTP_2` / `ALPN_HTTP_3` identifiers, `dispatch_alpn`, `dispatch_h2c_upgrade`, `negotiate_alpn`, `wire_protocol_name`. The pure decision function the reactor consults after a TLS handshake completes | `flare.http.alpn_dispatch` |
| QUIC Retry address validation (RFC 9000 §8.1), server **and** client wired: `QuicServerConfig.require_address_validation` answers a token-less Initial with a Retry (HMAC token bound to peer addr + original DCID, amplification-safe) and only accepts a validated token; the client detects an inbound Retry, captures the token + server-chosen DCID, and re-sends its Initial. Codecs (`encode_retry_packet` / `verify_retry_integrity` RFC 9001 §5.8 + Appendix A.4, `mint_retry_token` / `validate_retry_token`, `encode_version_negotiation`) are spec-validated + fuzz-clean; a full loopback handshake-through-Retry e2e passes | `flare.quic.retry`, `flare.quic.server`, `flare.quic.client` |
| QUIC DATAGRAM transport (RFC 9221): `DatagramFrame` + `encode_datagram` / `FrameHandler.on_datagram`, the `max_datagram_frame_size` transport parameter (`TP_ID_MAX_DATAGRAM_FRAME_SIZE`), and received datagrams surfaced on `ConnectionEvents.datagrams` | `flare.quic.frame`, `flare.quic.transport_params` |
| rustls QUIC binding: `RustlsQuicConfig`, `RustlsQuicAcceptor`, `RustlsQuicSession`, `RustlsQuicError`, `QuicEncryptionLevel`. C ABI shim over `rustls::quic::ServerConnection` (rustls 0.23); per-level CRYPTO frames feed / drain through `flare_rustls_quic_feed_crypto` / `_take_crypto`, negotiated ALPN via `flare_rustls_quic_alpn` | `flare.tls.rustls_quic` |
| HTTP/3 frame codec (RFC 9114 §7): `Http3Frame`, `Http3FrameType`, `encode_http3_frame`, `decode_http3_frame`; frame-type constants `H3_FRAME_TYPE_{DATA,HEADERS,CANCEL_PUSH,SETTINGS,PUSH_PROMISE,GOAWAY,MAX_PUSH_ID}` | `flare.http3.frame` |
| HTTP/3 SETTINGS payload (RFC 9114 §7.2.4): `Http3Setting`, `encode_http3_settings`, `decode_http3_settings`; standard identifiers `H3_SETTINGS_{QPACK_MAX_TABLE_CAPACITY,MAX_FIELD_SECTION_SIZE,QPACK_BLOCKED_STREAMS,ENABLE_CONNECT_PROTOCOL}` | `flare.http3.frame` |
| HTTP/3 request-stream state machine (RFC 9114 §4 + §7): `Http3RequestReader`, `Http3RequestEventHandler`, `feed_into[H]`; fires `on_headers` / `on_data` / `on_trailers` / `on_unknown_frame` / `on_protocol_error` callbacks on a caller-supplied handler, returns the byte count consumed (`0` == NEEDS_MORE), and tracks the INIT / BODY / TRAILERS / DONE phases via the `H3_REQUEST_STATE_*` tags | `flare.http3.request_reader` |
| HTTP/3 client response reading (v0.11): `Http3ResponseReader` consumes a response incrementally -- head available before the body completes, DATA yielded as it arrives, final-size checked against `content-length`, 1xx sections discarded and their field-section budget released (the budget is per-section per RFC 9114 §4.2). A stream that fails is isolated: `QuicClientConnection.cancel_stream` sends STOP_SENDING and RESET_STREAM once, marks the send half reset (`Stream.send_reset`) so no further STREAM frame can be emitted on it (RFC 9000 §3.1), and leaves sibling streams on the connection running; the two halves of a stream reset independently (`Stream.peer_reset` for a received RESET_STREAM, `Stream.send_reset` for STOP_SENDING or our own reset), so one never hides the other. `QuicClientConnection.poll` closes a connection that has been idle for the RFC 9000 §10.1 effective timeout (minimum of both advertised `max_idle_timeout` values, at least 3×PTO) and reports it through `ConnectionEvents.connection_closed`. A STOP_SENDING for a stream whose send half is not yet reset is answered with one RESET_STREAM carrying the same error code and the final size (RFC 9000 §3.5; `ConnectionEvents.stop_sending_resets`). A stream frame the server sends for a stream half that does not exist, a stream the client has not opened, or a stream above the 16 the client advertises ends the connection with a CONNECTION_CLOSE (STREAM_STATE_ERROR / STREAM_LIMIT_ERROR, RFC 9000 §4.6, §19) | [`test_h3_response_reader.mojo`](../tests/h3/test_h3_response_reader.mojo), [`test_h3_client_mux.mojo`](../tests/h3/test_h3_client_mux.mojo) |
| HTTP/3 response-stream writer (RFC 9114 §4 + §7): `encode_response_headers`, `encode_response_data`, `encode_response_trailers`; lowercases header names, rejects pseudo-headers in application + trailer sections, validates status in 100..599; QPACK-encodes field sections via `flare.qpack` | `flare.http3.response_writer` |
| QPACK encoder + decoder (RFC 9204 — static table per Appendix A, literal field lines with literal names, Huffman shared with HPACK; literals that are not valid UTF-8 are refused): `QpackHeader`, `encode_field_section`, `decode_field_section`, `static_table_lookup`, `static_table_find`, `static_table_find_name`, `QPACK_STATIC_TABLE_SIZE` | `flare.qpack` |
| QPACK dynamic table (RFC 9204 §3-4; `QpackEncoder` tracks no acknowledgments yet, so it references no dynamic entry in `encode` and refuses an `insert` that would evict): `QpackDynamicTable` (capacity-bounded eviction, absolute / relative indexing), encoder-stream instruction codec (Set Capacity, Insert With Name Reference, Insert With Literal Name, Duplicate) via `apply_encoder_instructions` / `apply_encoder_instructions_partial`, decoder-stream instructions (Section Ack, Stream Cancel, Insert Count Increment), dynamic field-section codec `encode_field_section_dynamic` / `decode_field_section_dynamic`, owners `QpackEncoder` / `QpackDecoder`; fuzz-clean (`fuzz-qpack-dynamic`) | `flare.qpack.dynamic` |

## gRPC

**Changed in v0.11.** The seventeen status codes are namespaced on the
struct: `GrpcStatus.NOT_FOUND` rather than `GRPC_STATUS_NOT_FOUND`. The
module-level names remain as aliases.

gRPC primitives on top of HTTP/2. The bottom two wire layers (LPM
framing, canonical Status codes, Metadata carrier) ship as sans-I/O
codecs. The **unary server** ships both the sans-I/O adapter
(`GrpcUnary` trait + `run_unary_call`) and the reactor-mounted
`GrpcService` over `HttpServer` H2, with `grpc-timeout` deadline
enforcement, gzip message-compression negotiation
(`grpc-accept-encoding` / `grpc-encoding`, request decompress + response
compress), and chainable interceptors (`Intercepted[I, H]`). A proto3
wire codec (`ProtoWriter` / `ProtoReader`) is the serializer handlers
target, and `tests/tools/proto_gen.py` generates Mojo message structs
(encode/decode) from a `.proto` for the supported subset (messages,
nested messages, enums, scalars, repeated, singular message fields).
The standard `grpc.health.v1.Health` ships both `Check` (unary) and
`Watch` (`HealthWatchHandler`, server-streaming status transitions), and
server reflection (`grpc.reflection.v1alpha`) answers `list_services`
**plus** `file_by_filename` / `file_containing_symbol` from a registered
`FileDescriptorProto` registry (mountable over the bidi
`ReflectionBidiHandler`). The **client** ships unary (`GrpcClient`,
including base64 binary `-bin` metadata) plus server-streaming /
client-streaming / bidirectional. All four **server** shapes ship as
reactor-mounted adapters: `GrpcService` (unary), `GrpcStreamingService`
(server-streaming, now **incrementally flushed** -- one DATA frame per
message via the K1 body-stream path), `GrpcClientStreamingService`, and
`GrpcBidiService`. `tests/tools/proto_gen.py` now also emits **`service`-block
codegen**: `PATH_*` consts, a typed `<Service>Server` trait, per-RPC byte
adapters, a typed `<Service>Client` stub, and a serialized
`FileDescriptorProto`. Still deferred: maps / oneof in the message
codegen.

A handler that raises now ends its call with `INTERNAL` and the fixed
message `handler raised`. The raise text used to be sent to the client
as `grpc-message`. To give the client a reason, return
`GrpcUnaryReply.err(GrpcStatus.err(code, reason))`. `grpc-message` is
percent-encoded on the way out and decoded by both clients
(`grpc_message_encode` / `grpc_message_decode`). Compressed request
frames share one 16 MiB inflate budget per call instead of 16 MiB
each.

| Surface | Where |
|---|---|
| Length-prefixed message framing (gRPC wire format): `GrpcMessage`, `GrpcDecodeResult`, `GrpcCompressionFlag`, `encode_grpc_message`, `decode_grpc_message`, `GRPC_COMPRESSION_NONE`, `GRPC_COMPRESSION_COMPRESSED` | `flare.grpc.framing` |
| Canonical status codes (`GrpcStatus`): `GRPC_STATUS_OK`, `_CANCELLED`, `_UNKNOWN`, `_INVALID_ARGUMENT`, `_DEADLINE_EXCEEDED`, `_NOT_FOUND`, `_ALREADY_EXISTS`, `_PERMISSION_DENIED`, `_RESOURCE_EXHAUSTED`, `_FAILED_PRECONDITION`, `_ABORTED`, `_OUT_OF_RANGE`, `_UNIMPLEMENTED`, `_INTERNAL`, `_UNAVAILABLE`, `_DATA_LOSS`, `_UNAUTHENTICATED` | `flare.grpc.status` |
| Metadata carrier with binary / text key discipline (`-bin` suffix for binary keys, base64 transport): `GrpcMetadata`, `GrpcMetadataEntry` | `flare.grpc.metadata` |
| Unary server adapter: `GrpcUnary` per-method handler trait, `GrpcUnaryReply` typed handler return (`ok(body, metadata)` / `err(status, metadata)` factories), `GrpcRequestHeaders` typed request-HEADERS carrier (`Optional[String]` for `grpc-timeout` / `grpc-accept-encoding`), `GrpcCallContext` (parsed deadline + accept-encoding + initial metadata), `GrpcCallOutcome` (response bytes + final `GrpcStatus` + trailing `GrpcMetadata`), `parse_request_headers` (validates POST + `content-type: application/grpc[+proto]` + `te: trailers` case-insensitively), `stitch_request_data` (concatenates LPM frames from HTTP/2 DATA, rejects compressed-flag set), `encode_unary_response` (wraps reply in uncompressed LPM), `emit_trailing_headers_status` (framework-controlled trailer entries: `grpc-status`, optional `grpc-message`, optional base64 `grpc-status-details-bin`), `run_unary_call` (sans-I/O orchestration that threads the call through the handler; never raises -- header / LPM / handler failures fold into typed `INVALID_ARGUMENT` / `INTERNAL` outcomes) | `flare.grpc.server` |
| Optional binary status details: `GrpcStatus.with_details(payload: List[UInt8])` attaches an opaque payload that the trailer emitter base64-encodes as `grpc-status-details-bin` per gRPC PROTOCOL-HTTP2 | `flare.grpc.status` |

## OpenAPI

OpenAPI 3.1 spec model + deterministic JSON emitter, plus
`spec_from_router` which derives a spec (paths, methods, path
parameters) by walking a runtime `Router`. Request/response body schemas
from the typed `Extracted[H]` handler remain a comptime follow-up (the
Router erases the handler type at registration).

| Surface | Where |
|---|---|
| Spec model: `OpenApiSpec`, `OpenApiInfo`, `OpenApiPath`, `OpenApiOperation`, `OpenApiParameter`, `OpenApiResponse` | `flare.openapi.spec` |
| Deterministic JSON emitter (stable key order — diffable specs in CI): `emit_openapi_json(spec) -> String` | `flare.openapi.spec` |
| Router derivation: `spec_from_router(router, title, version)` — route-table walk, `:id` → `{id}` templates, path params, one operation per method | [`tests/openapi/test_openapi.mojo`](../tests/openapi/test_openapi.mojo) |

## WebSocket

| Surface | Where |
|---|---|
| `WsClient.connect(url)` — handshake + frame loop, `WsHandshakeError` | [`websocket_echo.mojo`](../examples/basic/websocket_echo.mojo) |
| `WsServer` — server-side handshake + frame loop | [`ws_server.mojo`](../examples/basic/ws_server.mojo) |
| `WsHandler` trait + `WsServer.serve[H]` — stateful struct handler (per-connection state via `mut self`), the struct-handler twin of the `def(mut WsConnection)` callback | [`tests/ws/test_ws_stateful_handler.mojo`](../tests/ws/test_ws_stateful_handler.mojo) |
| `WsMessage` — high-level text / binary message wrapper | [`ergonomics.mojo`](../examples/basic/ergonomics.mojo) |
| `WsFrame`, `WsOpcode`, `WsCloseCode`, `WsProtocolError` — low-level frame surface | `flare.ws.frame` |
| Mandatory client-mask validation, UTF-8 validation on text frames (RFC 6455) | `flare.ws.frame` |
| WS-over-HTTP/2 (RFC 8441), client + server — `WsOverH2Stream` + `bootstrap_ws_over_h2` (client) and `WsOverH2ServerStream` + `Http2Connection.{take_extended_connect_streams,accept_ws_over_h2,drain_stream_data}` (server); CONNECT + `:protocol=websocket` over one h2 stream, mask discipline both directions; full paired round-trip | [`tests/ws/test_ws_h2_roundtrip.mojo`](../tests/ws/test_ws_h2_roundtrip.mojo), `flare.ws.client_h2`, `flare.ws.server_h2` |
| `permessage-deflate` (RFC 7692) — `PermessageDeflateConfig`, `compress_message` / `decompress_message`, `Sec-WebSocket-Extensions` parser + emitter, `negotiate_permessage_deflate`; default invariant: `no_context_takeover` on both sides + 16 MiB per-message decompressed cap | [`ws_permessage_deflate.mojo`](../examples/advanced/ws_permessage_deflate.mojo), `flare.ws.permessage_deflate` |
| `permessage-deflate` context-takeover (RFC 7692 §7.1 default mode) — `PermessageDeflateContext`: persistent compressor + decompressor pair, LZ77 sliding window carries between messages, fuzz-covered lifecycle (`fuzz-pmd-context` × 3 targets, 350K runs) | `flare.ws.permessage_deflate.PermessageDeflateContext` |
| `WsAutoClient.connect()` — runtime ALPN-aware dispatcher: on `wss://` with `prefer_h2=True` it handshakes advertising `["h2", "http/1.1"]`, and if the peer selects `h2` drives the WS-over-HTTP/2 tunnel (`bootstrap_ws_over_h2`, RFC 8441 Extended CONNECT); otherwise it opens a fresh HTTP/1.1 `WsClient`. `chosen_wire` reports the outcome | [`tests/ws/test_ws_autoclient.mojo`](../tests/ws/test_ws_autoclient.mojo), `flare.ws.auto_client` |
| `WsAutoClient` + `WsAutoClientConfig` + `WsWireChoice` + `decide_wire` — the pure decision function behind the dispatcher: consults URL scheme, `prefer_h2`, negotiated ALPN, and the peer's `ENABLE_CONNECT_PROTOCOL` SETTINGS flag (RFC 8441 §3); routes to HTTP/1.1, HTTP/2 (RFC 8441 Extended CONNECT), or FAILED. Folding this into a single `WsClient` `prefer_h2` knob (so callers don't pick between the two client types) is the remaining polish | [`tests/ws/test_ws_autoclient.mojo`](../tests/ws/test_ws_autoclient.mojo), `flare.ws.auto_client` |

## TLS

| Surface | Where |
|---|---|
| `TlsStream.connect(host, port, TlsConfig)` — client | [`tls.mojo`](../examples/basic/tls.mojo) |
| `TlsConfig`, `TlsVerify` — verification mode (`TlsVerify.REQUIRED` (default) or `TlsVerify.NONE`) | `flare.tls.config` |
| `TlsAcceptor`, `TlsServerConfig`, `TlsInfo` — server side over OpenSSL | `flare.tls.acceptor` |
| `HttpServer.bind_tls(addr, cert, key, alpn)` + `serve[H](handler, num_workers)` — in-process HTTPS server; no reverse proxy needed. The handshake runs on the reactor as a `KIND_TLS` connection, then ALPN dispatches to HTTP/1.1 or HTTP/2; many TLS connections are concurrent and `num_workers > 1` scales across cores. Buffered **and** `stream_response` chunked bodies both ride ciphertext | [`https_server.mojo`](../examples/advanced/https_server.mojo), `flare.http.server`, `flare.http._reactor.tls_conn_handle` |
| `TlsConnHandle` — non-blocking server-TLS state machine: owns the fd, drives `SSL_accept`/`SSL_read`/`SSL_write` mapping `WANT_READ`/`WANT_WRITE` onto the reactor `StepResult`; reads ALPN + SNI on completion (`flare_ssl_read_ex`/`write_ex` return explicit `FLARE_SSL_IO_*` sentinels) | `flare.http._reactor.tls_conn_handle`, `flare.tls._server_ffi` |
| `TlsAcceptor.reload()` — ACME / Let's Encrypt cert rotation without restart | [`cert_reload.mojo`](../examples/advanced/cert_reload.mojo) |
| mTLS — construction-time validation of CA chain + client cert | [`mtls.mojo`](../examples/advanced/mtls.mojo) |
| ALPN advertised + parsed on both sides; refusal-to-downgrade enforced | `flare.tls` |
| `TLS_PROTOCOL_TLS12`, `TLS_PROTOCOL_TLS13` (1.0 / 1.1 refused) | `flare.tls.acceptor` |
| Session resumption (RFC 5077 / RFC 8446 §4.6.1) — server-side ticket cache (opt-in via `TlsServerConfig.enable_session_tickets`) + client-side reconnect (opt-in via `TlsConfig.enable_session_resumption`) | [`tests/tls/test_tls_resume.mojo`](../tests/tls/test_tls_resume.mojo), `flare.tls.acceptor`, `flare.tls.config` |
| Errors: `TlsHandshakeError`, `CertificateExpired`, `CertificateHostnameMismatch`, `CertificateUntrusted`, `TlsServerError`, `TlsServerNotImplemented` | `flare.tls.error` |

The first TLS context or connection flare creates sets `SIGPIPE` to
`SIG_IGN`, if its disposition is still the default. OpenSSL writes to
the socket without `MSG_NOSIGNAL`, so writing to a peer that had
disconnected raised `SIGPIPE` and ended the process. With the signal
ignored, the write fails with `EPIPE` and raises `NetworkError`. A
handler or `SIG_IGN` that the application installed itself is left
alone.

A `TlsSession` records the `host:port` it came from (`TlsSession.origin`),
and `connect_resumed` offers it only to that origin. For any other host
it runs a full handshake. It used to offer the session to whatever host
it was given. Sessions from `connect_over_tcp` carry no origin and are
never offered.

Breaking: an HTTPS response whose body runs to the end of the stream
(no `Content-Length`, not chunked) now raises `NetworkError` if the
server closes without a TLS `close_notify`, because nothing else shows
whether the body arrived whole. It used to be returned as complete.
Responses framed by length or chunking are unaffected.
`TlsStream.eof_was_unclean()` exposes the signal to other readers.

Breaking: the HTTP/1.1 client now raises `NetworkError` when a chunked
response ends before its last chunk and the empty line after the
trailers, on TCP and on TLS. It used to return the bytes read so far as
the whole body.

An inbound chunked request now gets the same verdict however TCP splits
it. A chunk-size line of exactly `CHUNK_LINE_MAX` (4096) bytes is accepted
whether or not the first read ends after its CR, and a complete trailer
line over 4096 bytes is refused with 400 like a partial one (it used to
pass when it arrived whole).

The HTTP/1.1 request parser keeps header values as `String`s, so a value
that is not valid UTF-8 is now refused (400) even with
`accept_obs_text_in_field_value` on; valid UTF-8 obs-text is still
accepted. The same check covers obs-fold continuation lines.

With `allow_obs_fold` on, an obs-fold continuation line now gets the same
byte check as a field's first line (RFC 9110 sec 5.5, RFC 9112 sec 5.2):
control bytes other than HTAB, and obs-text unless
`accept_obs_text_in_field_value` is set, are refused with 400. They used
to reach the handler through a fold.

HTTP/1.1 client: a response head that contains a bare LF (a line not
ended by CRLF), or an empty line before its end, is now refused with
`NetworkError` by the buffered and the streaming readers. The head used
to run to the first CRLFCRLF with empty lines skipped, so an
LF-recognising cache in front of the client could see header-shaped bytes
as body.

HTTP/1.1 client: a status line whose code is longer than three digits
(`HTTP/1.1 2041 OK`) is refused. It used to be read as its first three
digits, so a 2041 became a bodyless 204.

HTTP/1.1 client pool: a connection is returned to the pool only after an
`HTTP/1.1` response that did not say `Connection: close`. An `HTTP/1.0`
response (even with `Connection: keep-alive`) now closes the connection,
so the next request opens a new one instead of writing to a socket the
server is closing.

Breaking: the streaming download (`get_streaming` over HTTPS) now applies
the same close_notify rule to a close-delimited body: if the server resets
the connection without `close_notify`, the read raises `NetworkError`
instead of reporting the end of the body.

## TCP, UDP, Unix sockets, DNS, addressing

| Surface | Where |
|---|---|
| `TcpStream.connect(host, port)`, `TcpListener.bind(addr)`, IPv4 + IPv6, TCP options | [`tcp_echo.mojo`](../examples/basic/tcp_echo.mojo) |
| `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` | [`udp.mojo`](../examples/basic/udp.mojo) |
| `UnixListener`, `UnixStream`, `accept_uds_fd` — AF_UNIX sidecar IPC | [`uds_sidecar.mojo`](../examples/advanced/uds_sidecar.mojo) |
| `IpAddr.parse(...)`, `IpAddr.is_v4()`/`is_v6()`, `is_private()`, `is_loopback()`, `SocketAddr.parse(...)`, `SocketAddr.localhost(port)`, `RawSocket` | [`addresses.mojo`](../examples/basic/addresses.mojo) |
| `resolve()`, `resolve_v4()`, `resolve_v6()` — getaddrinfo, dual-stack, numeric-IP passthrough | [`dns_resolution.mojo`](../examples/basic/dns_resolution.mojo) |

`UnixListener.bind` removes only a stale socket file, one whose probe
`connect(2)` is refused (nothing is listening on it). A path with a live
listener raises `AddressInUse`, and so does a socket the probe cannot
judge (for example one the caller may not write, `EACCES`, or a socket of
another type). A path that is not a socket raises `NetworkError`. None of
them is touched. It used to unlink whatever was at the path, and later
every socket whose probe failed for any reason. On destruction a listener
removes its socket file only if the file is still the one it created.

## Crypto

| Surface | Where |
|---|---|
| `hmac_sha256(key, message) -> List[UInt8]` | `flare.crypto.hmac` |
| `hmac_sha256_verify(key, message, tag) -> Bool` (constant-time compare) | `flare.crypto.hmac` |
| `base64url_encode` / `base64url_decode` (RFC 4648 §5, no padding) | `flare.crypto` |

## I/O primitives

| Surface | Where |
|---|---|
| `Readable` trait | `flare.io.buf_reader` |
| `BufReader` over any `Readable` | [`ergonomics.mojo`](../examples/basic/ergonomics.mojo) |

## Reactor and runtime

| Surface | Where |
|---|---|
| `Reactor` — `kqueue` (macOS), `epoll` (Linux); register / deregister fds, run one tick or until shutdown | [`reactor.mojo`](../examples/advanced/reactor.mojo) |
| `Event`, `INTEREST_READ`, `INTEREST_WRITE`, `EVENT_READABLE`, `EVENT_WRITABLE`, `EVENT_ERROR`, `EVENT_HUP`, `WAKEUP_TOKEN`, `LISTENER_TOKEN` | `flare.runtime.event` |
| `TimerWheel` — hashed timing wheel for idle / deadline timeouts | `flare.runtime.timer_wheel` |
| `default_worker_count()`, `num_cpus()` | `flare.runtime` |
| Experimental AsyncRT thread engine (`-D FLARE_ASYNCRT`) — runs server workers on Mojo's AsyncRT pool instead of pthreads; `num_workers <= parallelism_level() - 1`; throughput matches pthreads on the 1-worker and 4-worker benchmarks | [`asyncrt.md`](asyncrt.md) |
| `HandoffPolicy.from_env()`, `HandoffQueue` (bounded MPSC FIFO of fd tokens), `WorkerHandoffPool.peek_idle_worker(exclude)` — cross-worker steering, gated on `FLARE_SOAK_WORKERS=on` | [`work_stealing.mojo`](../examples/advanced/work_stealing.mojo) |
| `IoUringRing`, `IoUringParams`, `is_io_uring_available()` — opt-in `io_uring` reactor on Linux ≥ 6.0 (`FLARE_BUFRING_HANDLER=1`); auto-fallback to `epoll` | `flare.runtime.io_uring` |
| `Cancel`, `CancelCell`, `CancelReason` (peer FIN / deadline / drain) plumbed to `CancelHandler` | [`cancel.mojo`](../examples/intermediate/cancel.mojo) |

## Performance internals

These are public but most users won't touch them directly; the
HTTP server already wires them in. Listed for completeness.

| Surface | Where |
|---|---|
| SIMD parsers: `simd_memmem`, `simd_percent_decode`, `simd_cookie_scan` (fuzzed against scalar oracle: `fuzz-header-scan`, 500K runs) | `flare.http.simd_parsers` |
| Header PHF: `StandardHeader`, `standard_header_count`, `standard_header_name`, `lookup_standard_header_bytes` / `_string`, `is_standard_header` — perfect-hash lookup over the 70 IANA standard headers | `flare.http.header_phf` |
| Method / value interning: `MethodIntern`, `ValueIntern`, `intern_method_bytes` / `_string`, `intern_common_value` / `_string` | `flare.http.intern` |
| HPACK Huffman codec (see [HTTP/2](#http2)) | `flare.http.hpack_huffman` |
| `BufferPool`, `BufferHandle` — pooled output buffers for the response writer | `flare.runtime.buffer_pool` |
| `IoVecBuf`, `writev_buf`, `writev_buf_all` — vectored I/O | `flare.runtime.iovec` |
| `DateCache` — once-per-second cached `Date:` header to avoid re-formatting | `flare.runtime.date_cache` |
| `ResponsePool` — per-worker `Response` object reuse | `flare.http.response_pool` |

## Errors

Typed error hierarchy. Each error carries enough context that a
caller can distinguish recoverable from terminal cases.

| Family | Errors |
|---|---|
| Top-level | `IoError`, `ValidationError` |
| HTTP | `HttpError`, `TooManyRedirects`, `HttpParseError` |
| Auth / proxy / template | `AuthError`, `ProxyParseError`, `TemplateError` |
| Headers / URL | `HeaderInjectionError`, `UrlParseError` |
| Network | `NetworkError`, `ConnectionRefused`, `ConnectionTimeout`, `ConnectionReset`, `AddressInUse`, `AddressParseError`, `BrokenPipe`, `DnsError`, `Timeout` |
| TLS | `TlsHandshakeError`, `CertificateExpired`, `CertificateHostnameMismatch`, `CertificateUntrusted`, `TlsServerError`, `TlsServerNotImplemented` |
| HTTP/2 | `Http2Error`, `Http2ErrorCode`, `HuffmanError` |
| WebSocket | `WsHandshakeError`, `WsProtocolError` |
| UDP | `DatagramTooLarge` |

Sanitised 4xx / 5xx bodies: extractor messages are logged with the
request id but never echoed to the client. See
[`security.md`](security.md) for the full policy.

## Configuration knobs

| Env var | Effect |
|---|---|
| `FLARE_REUSEPORT_WORKERS=0` | Switch from per-worker `SO_REUSEPORT` to shared-listener `EPOLLEXCLUSIVE` shape (7–22 % less req/s depending on path, uniformly tighter p99.99 σ under sustained load) |
| `FLARE_BUFRING_HANDLER=1` | Opt into `io_uring` reactor on Linux ≥ 6.0; auto-fallback to `epoll` |
| `FLARE_SOAK_WORKERS=on` | Enable cross-worker `WorkerHandoffPool` for skewed-keepalive workloads |
| `FLARE_QUIC_NO_BATCH=1` | Force the QUIC reactor's per-datagram `recvfrom` drain instead of the default batched `recvmmsg` burst drain (Linux); use to A/B the syscall-batching win |
| `SOAK_DURATION_SECS=<n>` | Override default soak harness duration (`pixi run --environment bench bench-soak-*`) |
| `FLARE_LIB_DIR=<abs path>` | Directory holding the `libflare_*.so` FFI shims when running outside pixi. Checked before `$CONDA_PREFIX/lib`; ignored unless absolute |

**Changed (breaking).** With neither `FLARE_LIB_DIR` nor `CONDA_PREFIX`
set, the FFI shims are looked up by bare name on the system library
path. They used to be loaded from `build/` under the working directory,
so a program started in a directory someone else could write to ran
their `libflare_tls.so`. A bare checkout run outside pixi now needs
`FLARE_LIB_DIR=$PWD/build`.

`ServerConfig` defaults (override per-server): `max_header_size` (8192 B),
`max_body_size` (10 MiB), `max_keepalive_requests` (100), `idle_timeout_ms`
(500), `read_body_timeout_ms` (30_000), `request_timeout_ms` (60_000),
and `handler_timeout_ms`.

`max_body_size` may be as large as `Int.MAX` (effectively unlimited): the read-buffer
cap is compared as `len(read_buf) - max_header_size > max_body_size`, so the sum of
the two limits is never formed and cannot wrap.

The reactor's static and short-request fast paths decide `Connection: close`
by scanning the raw header block. The scan only matches `Connection:` at the
start of a header line (an `X-Connection:` header is ignored) and combines
every `Connection` line, so a later `Connection: close` is honoured. The value
is read as a comma-separated option list (RFC 9110 §7.6.1), so
`Connection: keep-alive, close` and `Connection: TE, close` close the
connection; HTTP/1.0 stays open only when a `keep-alive` option is present.

An error response the reactor generates itself (400, 408, 413, 431, 500, ...) for a
`HEAD` request carries the headers only, like any other response to HEAD (RFC 9110
§9.3.2).

**Changed in v0.11 (breaking).** `idle_timeout_ms` now also applies to
a connection that has not sent its first byte: it is armed at accept,
where before a silent connection was never timed out. `request_timeout_ms`
is enforced: reading one request, head and body, may take at most that
long from its first byte, and the answer to a peer that trickles bytes
just inside the idle timeout is a 408. `handler_timeout_ms` is still not
enforced -- handlers run synchronously on the worker thread -- and its
docstring now says so. The streaming (`serve_streaming`) and io_uring
loops are unchanged.

WebSocket on the same port: set `ServerConfig.ws` to a
`WsUpgrade(ws_fn)` and any request that arrives with a valid RFC 6455
upgrade is handed to `ws_fn`, while everything else goes to the
ordinary `Handler`. Each upgraded socket runs on its own detached
thread; `WsUpgrade(ws_fn, offload=False)` runs the handler on the
reactor thread instead, which blocks every other connection on that
worker until the WebSocket closes. The upgrade is cleartext only: on a
TLS-terminated listener (`bind_tls`) the `WsUpgrade` hook is ignored and a
`wss://` handshake is served as an ordinary HTTP/1.1 request inside TLS,
because the upgrade path writes on the raw socket. Use a separate
`WsServer` for `wss://`.

**Changed in v0.11 (breaking).** `offload` defaults to `True`; it was
`False`, so one WebSocket client stalled its whole worker by default. A
handshake whose `Sec-WebSocket-Version` is not 13 is answered 426 with
`Sec-WebSocket-Version: 13` (RFC 6455 sec 4.4) and `Connection: close`; the
connection is closed after that response and a pipelined request behind it is
not served. The version used to go
unchecked, so any draft was upgraded. There is still no cap on offload threads.

**Changed in v0.11.** These were two loose fields, `ws_handler` and
`ws_offload`, which made it easy to set the handler and never learn
the offload flag existed. `serve_ws_upgrade(fn, ws_fn)` wired both and
is now a shim that goes away in 0.12.

```mojo
var cfg = ServerConfig()
cfg.ws = WsUpgrade(ws_fn)                  # was: cfg.ws_handler = ws_fn
var srv = HttpServer.bind(addr, cfg.copy())
srv.serve(http_fn)                         # was: srv.serve_ws_upgrade(http_fn, ws_fn)
```

Client-side timeouts: `HttpClient(timeout_ms=...)` bounds the TCP
connect and, on `https://`, the TLS handshake. `with_read_timeout(ms)`
arms `SO_RCVTIMEO` so a peer that goes silent mid-body cannot park the
caller. Both are per-phase bounds; there is no whole-request deadline
yet. Cleartext pooled sockets are re-armed on checkout, pooled TLS
connections keep whatever was armed when they were dialled, and
lowering the value to `0` clears neither. Build-time invariants (e.g. `max_body_size >=
max_header_size`) are checked by Mojo `comptime assert` when used with
`serve_comptime[handler, config]`.

## Known gaps

Caveats that would otherwise be buried inside a table cell. Nothing
here is a bug; each is a place where the shipped surface stops short
of what you might reasonably assume from the surrounding feature.

**HTTP client**

- Streaming over HTTP/3 is not reachable. `Http3Download` exists and is
  tested, but no entry point wires to it, so `get_streaming` settles on
  HTTP/1.1 or h2. Buffered h3 requests are unaffected.
- The streaming calls do not take the `Upgrade: h2c` path. They use
  prior knowledge when `with_h2c` asks for it and HTTP/1.1 otherwise. A
  streaming response cannot be re-read if the origin declines the
  upgrade, so the handshake is not attempted rather than guessed at.
- `send_chunked` skips the connection pool, redirects and retries. The
  body comes from a `ChunkSource` and cannot be replayed, so none of
  the three is safe. It does apply auth and the cookie jar.
- A streaming download owns its connection and does not return it to a
  pool. h2-negotiated TLS connections are not pooled at all.
- `with_read_timeout` bounds each read, not the whole request. There is
  no end-to-end deadline.
- `Expect: 100-continue` is rejected on the streaming path rather than
  handled.
- Request HEADERS are not split into CONTINUATION frames, so a header
  block larger than the peer's maximum frame size fails rather than
  spanning frames.

**HTTP server**

- `bind_tls` takes a certificate, a key and an ALPN list. mTLS, a
  minimum protocol version and session tickets are configurable on
  `TlsAcceptor` but are not reachable through `HttpServer`; the reactor
  builds its own context.
- HTTP/3 serves single-worker only. The other three wires serve at any
  worker count, cleartext or TLS.
- `bind_many` is single-worker only for its address cross product.
- The io_uring buffer-ring handler path (`FLARE_BUFRING_HANDLER=1`) is
  HTTP/1.1 cleartext only and cannot stream.

**QUIC and HTTP/3**

- Send pacing is built but not wired, and the congestion window is not
  gated on the HTTP/3 DATA pump. Loss recovery, the window itself and
  the ack-eliciting accounting are live and correct; nothing reads the
  window on that one path. Deferred to 0.12 together with pacing.
- The QPACK dynamic table is dormant. Both ends work, statically.
- The h3 client rejects a request body larger than one packet.

**gRPC**

- The code generator covers messages, nested messages, enums, scalars,
  repeated and singular message fields. Maps and `oneof` are not
  generated.
- `deflate` egress compression is not wired; gzip is.

**Elsewhere**

- `flare.openapi` emits a spec from a router but derives no body
  schemas from extractors. Treat it as experimental.
- WebSocket frames are capped at `max_frame_size`, 16 MiB by default,
  on `WsConnection`, `WsClient` and both h2 carriers. A frame whose
  header declares more is answered with CLOSE 1009 and the receive
  raises; it used to be buffered towards any size up to 4 GiB. Raise
  the field before the first receive to accept larger frames.
  `recv()` delivers frame by frame, so the limit bounds a message there.
  `WsClient.recv_message()` reassembles fragmented messages (and skips
  PONG, validating UTF-8 over the whole text message) and applies the same
  limit to the reassembled payload: a longer message is answered with
  CLOSE 1009 and the call raises. It used to return each fragment as a
  message of its own.
- `WsConnection` now takes part in the closing handshake (RFC 6455
  sec 5.5.1). `recv()` answers a received CLOSE before returning it: it
  echoes the status code, sends an empty CLOSE for an empty body, and
  sends 1002 for a 1-byte body, a code that may not appear on the wire or
  a reason that is not UTF-8. `close()` sends one CLOSE, no longer claims
  to wait for the reply, and does nothing if a CLOSE went out already.
  After a CLOSE, `send_text`, `send_binary` and `send_frame` raise
  `NetworkError` instead of putting data frames on the wire; `send_frame`
  now takes `mut self`. Clients used to see EOF (1006) instead of the
  close code.
- `WsFrame.decode_one` now raises `WsProtocolError` for a reserved opcode
  (0x3-0x7, 0xB-0xF), as RFC 6455 sec 5.2 requires of a receiver. It used
  to return the frame, so `recv()` handed it to the application. The
  server, client and h2 receive paths all decode through it.
- `WsClient.recv()` and `recv_message()` now raise `WsProtocolError` when
  the server sends a masked frame (RFC 6455 sec 5.1: a client MUST close
  the connection on one). They used to unmask it and return the payload.
- `WsClient.connect` now checks the whole `101` response (RFC 6455 sec
  4.1), not only `Sec-WebSocket-Accept`: it raises `WsHandshakeError`
  unless the response has `Upgrade: websocket` and a `Connection` field
  with the `upgrade` token, and it refuses one that names a
  `Sec-WebSocket-Protocol` or `Sec-WebSocket-Extensions` (the client
  offers neither). A server that skipped those fields used to connect.
- The standalone `WsServer` now checks the whole opening handshake (RFC
  6455 sec 4.2.1): a `GET` over HTTP/1.1, `Upgrade` and `Connection`
  matched as comma-separated tokens (`Connection: noupgrade` no longer
  counts), exactly one `Sec-WebSocket-Key` that is base64 of 16 bytes,
  and exactly one `Sec-WebSocket-Version` of 13. A refused handshake gets
  an HTTP answer before the close: 426 with `Sec-WebSocket-Version: 13`
  when only the version is wrong, 400 otherwise. All of these used to be
  upgraded. The shared-listener upgrade (`ServerConfig.ws`) applies the
  same rule.
- **The server side of WebSocket is not RFC 6455 conformant yet.** The
  Autobahn suite ran against flare for the first time in v0.11 and 63
  of roughly 450 cases fail. Three gaps account for nearly all of
  them. `WsConnection` has no fragment reassembly and no
  `recv_message`, which the client side does have, so a CONTINUATION
  sequence reaches the handler as separate frames. A reserved opcode
  or reserved bit is handed to the handler instead of failing the
  connection with 1002. And a TEXT payload that is not valid UTF-8, or
  a reserved close code, is not rejected with the status the RFC asks
  for. The measured baseline is recorded case by case in
  [`tests/tools/conformance/autobahn-known-fail.txt`](../tests/tools/conformance/autobahn-known-fail.txt),
  so CI catches a regression against it; closing the gaps is 0.12
  work. Sections 12 and 13 are excluded rather than failing: the
  standalone handshake does not negotiate permessage-deflate, so they
  would measure the test fixture.
- Batch UDP is Linux-only, and the `sendmmsg` / GSO egress path is
  built and measured but not wired into QUIC.
- `is_private()` does not recognise IPv6 unique local addresses.
- A crashed worker still reports `is_running() == True`.

**Platform**

- io_uring is Linux-only; macOS runs the same reactor over kqueue.
- Sanitizer builds are Linux-only. The Mojo toolchain ships no arm64
  ASan runtime, so `tests-asserts-all` is the local stand-in on Apple
  silicon and the real thing runs in CI.
- Named POSIX semaphores are unavailable on macOS, so `block_in_pool`
  fails open there.

## Stability

The public Mojo API is stable within a minor version: patch releases
never break source for the same minor. Breaking changes only land at
minor bumps. Internal types (anything in `_*.mojo`, or anything in
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.

## Testing and fuzz coverage

Test code reaches for two cross-cutting helper modules that the
Mojo stdlib doesn't ship: `flare.testing` and `flare.utils`.

`flare.testing` ships two shapes:

- `TestClient[H]` — FastAPI-style in-process handler exerciser.
  Drives `Handler.serve` directly without binding a port, so
  the same `Request` builder + assertions used in production
  code paths work in unit tests. The compiler monomorphises
  the parametric `H` so a `TestClient[MyHandler]` invocation
  is a direct call, not a virtual dispatch.
- `fork_server(handler, addr)` / `kill_forked_server(pid)` —
  fork-and-serve so a single-process example or integration
  test can both serve and connect to itself, with the parent
  process retaining the handle.

`flare.utils` exposes the POSIX FFI thunks Mojo stdlib doesn't:
`fork` / `waitpid` / `kill` / `usleep` / `exit` / `getpid` +
`SIGKILL` / `SIGTERM` / `SIGINT`.

Tests under [`tests/`](../tests/) mirror the package layout:
`tests/{crypto,dns,http,http2,net,runtime,tcp,testing,tls,udp,uds,ws}/`.

| | Count |
|---|---|
| Unit + integration tests | 2499 across `tests/`, run as 20 per-area aggregate binaries |
| Examples (each part of `pixi run tests`) | 73 under [`examples/`](../examples/); `check-example-tasks` keeps the files, the `example-*` tasks and the `examples` aggregate in step |
| Fuzz harnesses | 63 under [`fuzz/`](../fuzz/), 9M+ runs combined, zero known crashes; all 63 run nightly since v0.11 |
| Sanitizer harnesses | `tests-asan` / `tests-tsan` on Linux, `tests-asserts-all` everywhere. The Mojo toolchain ships no arm64 sanitizer runtime, so the first two exit 0 with an explanation on macOS (see [`build.md`](build.md)) |
| Conformance corpora | RFC 7230 HTTP/1 wire shapes under [`tests/conformance/h1/`](../tests/conformance/h1/) (runner: `test-conformance-h1`); RFC 6455 WebSocket frames under [`tests/conformance/ws/`](../tests/conformance/ws/) (runner: `test-conformance-ws`, 13 fixtures; Autobahn-anchored case ids 1.x / 2.x / 3.x / 5.x / 7.x). External suites run through `pixi run conformance`: h2spec, and since v0.11 the full Autobahn fuzzing client against [`websocket_echo_server.mojo`](../examples/basic/websocket_echo_server.mojo), each gated against a documented known-fail list |

Per-harness breakdown (input → fuzzer):

| Target | Harness |
|---|---|
| WebSocket frames | `fuzz-ws`, `prop-ws` |
| WebSocket server | `fuzz-ws-server` |
| URL / percent-decode | `fuzz-url` |
| HTTP headers (parser) | `fuzz-headers`, `prop-headers` |
| HTTP responses | `fuzz-http-response` |
| HTTP server pipeline | `fuzz-http-server`, `fuzz-server-reactor-chunks` |
| Encoding (gzip / brotli / deflate) | `fuzz-encoding` |
| Cookies | `fuzz-cookie` |
| Reactor churn | `fuzz-reactor-churn` |
| Timer wheel | `prop-timer-wheel` |
| Auth | `prop-auth` |
| Router paths | `fuzz-router-paths` |
| Scheduler shutdown | `fuzz-scheduler-shutdown` |
| Typed extractors | `fuzz-extractors` |
| Comptime router (oracle vs runtime) | `fuzz-routes-comptime` |
| SIMD scanners (oracle vs scalar) | `fuzz-header-scan` |
| Forms (urlencoded) | `fuzz-form` |
| Multipart forms | `fuzz-multipart` |
| Signed cookie / session decode | `fuzz-session-decode` |
| Range header | `fuzz-fs-range` |
| HTTP/2 frame codec | `fuzz-h2-frame` |
| HPACK decoder | `fuzz-hpack-decoder` |
| HPACK Huffman codec (oracle vs SIMD shim) | `fuzz-huffman-simd` |
| HTTP/2 CONTINUATION flood (CVE-2023-44487 shape) | `fuzz-h2-continuation` |
| HTTP/2 RAPID RESET (CVE-2023-44487 shape) | `fuzz-h2-rapid-reset` |
| RFC 8441 Extended CONNECT | `fuzz-extended-connect` |
| HTTP/2 preface peek | `fuzz-h2-preface-peek` |
| WebSocket `permessage-deflate` | `fuzz-ws-deflate` |
| WebSocket `permessage-deflate` context-takeover (persistent z_stream lifecycle) | `fuzz-pmd-context` |
| HAProxy PROXY v1 + v2 | `fuzz-proxy-protocol` |
| io_uring SQE / CQE codec | `fuzz-io-uring-sqe` |
| io_uring reactor cancel-surface | `fuzz-uring-reactor` |
| gRPC LPM message decoder | `fuzz-grpc-lpm-decoder` |
| QUIC varint codec (canonical round-trip + non-shortest policy) | `fuzz-quic-varint` |
| QUIC long header parser (consumed-bytes invariant) | `fuzz-quic-long-header` |
| QUIC transport-frame codec (RFC 9000 §19 — safety + idempotence on arbitrary bytes) | `fuzz-quic-frame-decode` |
| QUIC Retry token + integrity verify (RFC 9000 §8.1 / RFC 9001 §5.8 — arbitrary-byte token validation + integrity verify never panic) | `fuzz-quic-retry` |
| QUIC transport-parameter codec (RFC 9000 §18 — typed-value stability across encode / decode / re-encode) | `fuzz-quic-transport-params` |
| HTTP/3 frame codec (multi-byte varint frame types) | `fuzz-h3-frame` |
| QPACK static-only decoder + round-trip (RFC 9204 — header stability across encode / decode) | `fuzz-qpack-decode` |
| QPACK dynamic-table encoder/decoder streams (RFC 9204 §3-4 — arbitrary-byte insert replay + field-section decode never panic) | `fuzz-qpack-dynamic` |
| QUIC packet AEAD (decrypt → re-encrypt round-trip; RFC 9001 §5) | `fuzz-quic-packet-decrypt` |
| QUIC Initial handshake parser (RFC 9000 §17.2.2 long header + CRYPTO frame extraction) | `fuzz-quic-initial-handshake` |
| QUIC Connection ID dispatch (`ConnectionIdTable.lookup` on arbitrary bytes) | `fuzz-quic-connection-id` |
| HTTP/3 server end-to-end (request stream feed → handler → response writer) | `fuzz-h3-server` |
| Cache-Control header parser (idempotent re-parse) | `fuzz-cache-control-parser` |
| Alt-Svc response-header parser (RFC 7838, idempotent re-parse) | `fuzz-alt-svc-parser` |
| ALPN -> wire-protocol dispatch (decision function on arbitrary bytes) | `fuzz-alpn-dispatch` |
| `ByteReader` / `ByteWriter` bounds-checked cursor (reads past end raise; `read_utf8` validates) | `fuzz-byte-cursor` |
| HTTP/1.1 chunked transfer-decoder (standalone) | `fuzz-chunked-decoder` |
| Conditional-request preconditions (ETag / date parse; RFC 9110 §13) | `fuzz-conditional` |
| UDS `FrameMux` frame codec (split-invariance encode / decode) | `fuzz-frame-mux` |
| HTTP/3 client response-stream reader (whole / byte-at-a-time / split feed) | `fuzz-h3-response-reader` |
| proto3 `ProtoReader` (varint / zigzag / wire-type decode) | `fuzz-proto-reader` |
| Template engine parser + renderer | `fuzz-template` |
| QUIC 0-RTT EarlyData length framing | `fuzz-quic-early-data-len` |
| QUIC 0-RTT cross-connection replay strike set | `fuzz-quic-early-data-strike` |
| QUIC connection migration (CID switch / PATH_CHALLENGE parse) | `fuzz-quic-migration` |
| QUIC migration anti-amplification byte accounting | `fuzz-quic-migration-amplification` |
