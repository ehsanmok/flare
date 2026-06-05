# Features

Complete inventory of what ships in [`flare/`](../flare/), generated
by walking [`flare/__init__.mojo`](../flare/__init__.mojo) plus each
submodule. Every entry here is part of the stable public surface
(see [Stability](#stability)). Internal types (anything in `_*.mojo`)
are intentionally excluded.

For runnable code, [`cookbook.md`](cookbook.md) maps "I want to..." to
an example file. For layering and the request lifecycle, see
[`architecture.md`](architecture.md).

- [HTTP server](#http-server)
- [HTTP client](#http-client)
- [Routing](#routing)
- [Handlers and extractors](#handlers-and-extractors)
- [Middleware](#middleware)
- [Cookies, sessions, auth](#cookies-sessions-auth)
- [Forms and content-encoding](#forms-and-content-encoding)
- [Body, streaming, SSE, templates, static files](#body-streaming-sse-templates-static-files)
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

## HTTP server

| Surface | Where |
|---|---|
| `HttpServer.bind(addr)` / `serve(handler)` / `serve(handler, num_workers=N)` — version-aware listener that dispatches HTTP/1.1, HTTP/2 over TLS (ALPN), and h2c (RFC 9113 §3.4 preface peek, no `Upgrade` dance) to the same handler | [`http_server.mojo`](../examples/basic/http_server.mojo), [`http2.mojo`](../examples/advanced/http2.mojo), [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) |
| `HttpServer.bind_many(addrs: List[SocketAddr])` — single-worker listener over multiple distinct addresses; the accept loop walks every fd and demuxes onto the same handler | [`multi_listener.mojo`](../examples/intermediate/multi_listener.mojo) |
| HTTP/1.1 trailer fields (RFC 7230 §4.1.2 / §4.4) — `StreamingResponse[B].trailers: HeaderMap` on the outbound side (buffered `Response` uses `Content-Length` and never carries trailers), automatic `Trailer:` header, smuggling guard rejects trailers when `Content-Length` is present or when forbidden trailer names are listed; `HttpClient` parses inbound trailers off the chunked decoder and lands them on `Response.trailers` (also a `HeaderMap`) | [`trailers.mojo`](../examples/intermediate/trailers.mojo), [`tests/http/test_h1_trailers.mojo`](../tests/http/test_h1_trailers.mojo) |
| `HttpServer.serve_static(StaticResponse)` — pre-encoded static-response fast path that skips parsing and handler dispatch (used by `flare_mc_static` bench row) | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |
| `HttpServer.serve_comptime[handler, config]()` — comptime-specialised reactor with build-time invariant checks on `ServerConfig` | `flare.http.server` |
| Per-worker `SO_REUSEPORT` listeners by default (`num_workers >= 2`); `FLARE_REUSEPORT_WORKERS=0` switches to single-listener `EPOLLEXCLUSIVE` shape | [`multicore.mojo`](../examples/intermediate/multicore.mojo) |
| `pin_cores=True` (default): worker N pinned to core `N % num_cpus()` on Linux, no-op on macOS | [`multicore.mojo`](../examples/intermediate/multicore.mojo) |
| `HttpServer.drain(timeout_ms) -> ShutdownReport` per worker | [`drain.mojo`](../examples/intermediate/drain.mojo) |
| `ServerConfig` (request / handler / `read_body_timeout_ms` deadlines, `max_header_size`, `max_body_size`, `max_keepalive_requests`, `idle_timeout_ms`) | `flare.http.server` |
| Response builders: `ok(body)`, `ok_json(body)`, `bad_request(msg)`, `not_found(msg)`, `internal_error(msg)`, `redirect(url)` | `flare.http.server` |
| `Method` enum, `Status` enum, `Response` with header / body / status, `ResponsePool` for response object reuse | `flare.http.{request,response,response_pool}` |
| `Request.peer` threaded from the accept path | `flare.http.request` |
| `precompute_response(status, content_type, body) -> StaticResponse` — keep-alive + `Connection: close` wire forms both pre-encoded | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |

## HTTP client

| Surface | Where |
|---|---|
| `HttpClient(base_url, auth=...)`, `HttpClient(prefer_h2c=True)` — version-aware over TLS+ALPN; `prefer_h2c=True` opts into HTTP/2 cleartext via prior knowledge | [`http_get.mojo`](../examples/basic/http_get.mojo), [`http2_client.mojo`](../examples/advanced/http2_client.mojo) |
| `HttpClient.with_pool(...)` — HTTP/1.1 connection pool keyed on `(scheme, host, port)`, idle reuse, per-origin caps, stale-conn retry; opt-in via the builder | [`client_pool.mojo`](../examples/advanced/client_pool.mojo) |
| `HttpClient(h2c_upgrade=True)` — h2c via Upgrade (RFC 7540 §3.2): client emits `Upgrade: h2c` + `HTTP2-Settings` on the first request, reads 101, carries the peer SETTINGS forward into a fresh h2 connection | [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo), [`tests/http/test_h2c_client_upgrade.mojo`](../tests/http/test_h2c_client_upgrade.mojo) |
| Module-level helpers: `get`, `post`, `put`, `patch`, `delete`, `head` — `post` with `String` body sets `Content-Type: application/json` automatically | `flare.http.client` |
| `RedirectPolicy.follow_all()` / `.same_origin_only()` / `.deny()` (default) factories; modes live on `RedirectMode.FOLLOW_ALL` / `.SAME_ORIGIN_ONLY` / `.DENY`; `TooManyRedirects` error | `flare.http.{redirect_policy,error}` |
| `Auth`, `BasicAuth(user, pass)`, `BearerAuth(token)` — both wires | `flare.http.auth` |
| `Response.json()`, `.text()`, `.raise_for_status()`, `.ok()`, `.status` | `flare.http.response` |

## Routing

| Surface | Where |
|---|---|
| `Router` — runtime trie with path parameters (`:name`), wildcards (`*`), method dispatch, 404 / 405-with-`Allow`. `Handler & Copyable & Movable` so `srv.serve(router^, num_workers=N)` resolves to the multi-worker overload; boxed struct handlers shared across worker copies via an Arc-style refcount | [`router.mojo`](../examples/basic/router.mojo), [`tests/http/test_router_copy.mojo`](../tests/http/test_router_copy.mojo) |
| `ComptimeRouter[ROUTES]`, `ComptimeRoute(method, path, handler)` — segments parsed at compile time, dispatch loop unrolled per route | [`comptime_router.mojo`](../examples/advanced/comptime_router.mojo) |
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
| `Extracted[H]` | Reflects on a struct's fields, runs every extractor before `serve`; malformed input becomes a sanitised 400 | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |

Custom types are handled by writing your own `Extractor` struct
that pulls and validates the value from the request. The
extractor surface is intentionally concrete — every type is
named — so the IDE, the compiler, and the reader all see the
same shape.

## Middleware

Each layer is itself a `Handler` that holds another `Handler`. Stack
by nesting structs:

| Layer | Behaviour | Where |
|---|---|---|
| `Logger[Inner]` | Space-delimited per-request line (`[flare] GET /users 200 12ms`) | [`middleware.mojo`](../examples/intermediate/middleware.mojo) |
| `RequestId[Inner]` | Generate / propagate `X-Request-Id` | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) |
| `Compress[Inner]` | gzip / brotli / identity content-encoding via q-value negotiation; small-body / already-encoded skip | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo), [`brotli.mojo`](../examples/intermediate/brotli.mojo) |
| `CatchPanic[Inner]` | Convert handler panic to sanitised 500 | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) |
| `Cors[Inner]` + `CorsConfig` | WHATWG Fetch CORS protocol; permissive / allowlist / preflight short-circuit / credentials echo / exposed-headers / max-age | [`cors.mojo`](../examples/intermediate/cors.mojo) |
| `Conditional[Inner]` | RFC 9110 §13 preconditions: `If-Match` / `If-None-Match` (304 / 412), `If-Modified-Since` / `If-Unmodified-Since`; opt-in auto-ETag from FNV-1a body hash via `Conditional.with_auto_etag` | `flare.http.conditional` |
| `FileServer.new(root)` | Static file serving with GET / HEAD + RFC 9110 §14.4 single-Range, MIME inference, path safety (`..` / NUL / absolute path rejection), `index.html` directory fall-through | [`static_files.mojo`](../examples/intermediate/static_files.mojo) |
| `Retry[Inner]` + `RetryPolicy` | Re-invoke the inner handler up to `max_attempts` times on 5xx; RFC 9110 §9.2.2 idempotent-method gate on by default (GET / HEAD / PUT / DELETE / OPTIONS retry; POST / PATCH pass through once unless `retry_only_idempotent` is `False`). Optional exponential backoff with jitter via `RetryPolicy(backoff_base_ms, backoff_max_ms, backoff_jitter_ms)` | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `PostHocDeadline[Inner]` | **Post-hoc** wall-clock guard: invokes the inner handler synchronously, then if the elapsed time exceeds `budget_ms`, replaces the response with a sanitised 504. Does **not** cancel the inner handler mid-execution -- it only refuses the response that was produced too late. `budget_ms <= 0` is the explicit "disabled" sentinel that always trips 504. The cancel-cell wiring that would let the deadline preempt the inner handler is a future addition. | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `negotiate_encoding(Accept-Encoding) -> Encoding` | RFC 9110 §12.5.3 q-value parser exposed for direct use | `flare.http.middleware` |

## HTTP caching (RFC 9111)

Cache primitives, an in-memory store, and a wrapping `Cache[Inner, S]`
middleware that handles RFC 9111 freshness and conditional revalidation.

| Surface | Where |
|---|---|
| `Cache[Inner, S]` — wrapping middleware: on cache hit + fresh-per-RFC-9111 entry, returns the stored response without invoking `Inner`; on miss / stale, runs `Inner` and stores the response (subject to `Cache-Control` directives). Conditional revalidation forwards `If-None-Match` / `If-Modified-Since` to upstream and folds 304 into the cached entry | [`http_cache.mojo`](../examples/intermediate/http_cache.mojo) |
| `parse_cache_control(headers) -> CacheControl` — RFC 9111 §5.2 directive parser (max-age, s-maxage, no-cache, no-store, private, public, must-revalidate, proxy-revalidate, immutable, stale-while-revalidate, stale-if-error) | `flare.http.cache.control` |
| `CacheControl` — typed directive struct with the full RFC 9111 §5.2 surface | `flare.http.cache.control` |
| `parse_vary_header(headers) -> List[String]` — RFC 9111 §4.1 `Vary:` parser feeding the secondary cache-key derivation | `flare.http.cache.control` |
| `derive_cache_key(request) -> CacheKey`, `CacheKey` — method + canonical URL + `Vary`-aware secondary key | `flare.http.cache.key` |
| `CacheStore` trait + `InMemoryCacheStore(capacity)` — bounded FIFO store with `get` / `put` / `remove`; freshness logic lives on `CacheEntry` (parsed `CacheControl` + `Vary` carried at insert time so the lookup path doesn't re-parse) | `flare.http.cache.store` |
| `CacheEntry.is_fresh(now_ms)` — RFC 9111 §4.2 freshness check against the entry's parsed directives and `Date:` baseline | `flare.http.cache.store` |

## Cookies, sessions, auth

| Surface | Where |
|---|---|
| `Cookie`, `CookieJar`, `SameSite` | [`cookies.mojo`](../examples/basic/cookies.mojo) |
| `parse_cookie_header`, `parse_set_cookie_header` (RFC 6265) | [`cookies.mojo`](../examples/basic/cookies.mojo) |
| `signed_cookie_encode(value, key)` / `signed_cookie_decode(cookie, key)` — HMAC-SHA256 over base64url payload + tag | `flare.http.session` |
| `signed_cookie_decode_keys(cookie, keys)` — accept any of N keys, for graceful key rotation | `flare.http.session` |
| `Session[T]`, `SessionCodec`, `StringSessionCodec` | [`sessions.mojo`](../examples/intermediate/sessions.mojo) |
| `CookieSessionStore[T]` (signed-cookie-backed), `InMemorySessionStore[T]` (server-side) | [`sessions.mojo`](../examples/intermediate/sessions.mojo) |
| `Auth`, `BasicAuth`, `BearerAuth`, `AuthError` | `flare.http.{auth,auth_extract}` |
| HAProxy PROXY v1 + v2 parser, `ProxyParseError` | `flare.http.proxy_protocol` |

## Forms and content-encoding

| Surface | Where |
|---|---|
| `FormData`, `parse_form_urlencoded`, `urldecode`, `urlencode`, `Form` extractor | [`forms.mojo`](../examples/intermediate/forms.mojo) |
| `MultipartPart`, `MultipartForm`, `parse_multipart_form_data`, `Multipart` extractor | [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo) |
| `Url`, `UrlParseError` — URL parser, percent decoding | `flare.http.url` |
| `Encoding` enum, `compress_gzip` / `decompress_gzip`, `compress_brotli` / `decompress_brotli`, `decompress_deflate` | [`encoding.mojo`](../examples/basic/encoding.mojo), [`brotli.mojo`](../examples/intermediate/brotli.mojo) |
| `decode_content("br" / "gzip" / "deflate" / "identity", ...)` | `flare.http.encoding` |

## Body, streaming, SSE, templates, static files

| Surface | Where |
|---|---|
| `Body`, `InlineBody`, `ChunkedBody`, `ChunkSource`, `drain_body` | `flare.http.body` |
| `StreamingResponse[B]`, `serialize_streaming_response` | `flare.http.streaming_response` |
| `RequestView[origin]`, `parse_request_view` — zero-copy borrow over the parsed request, paired with `ViewHandler` | `flare.http.request_view` |
| `HeaderMap`, `HeaderInjectionError`, `HeaderMapView`, `parse_header_view` | `flare.http.{headers,header_view}` |
| `StaticResponse`, `precompute_response` — pre-encoded wire form for fixed-body endpoints | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |
| `SseEvent`, `SseChannel` (in-memory FIFO + cancel-aware `ChunkSource` wrapper), `format_sse_event`, `sse_response`, `SseStreamingResponse[B]` | [`sse.mojo`](../examples/intermediate/sse.mojo) |
| Askama-shape templates: `{{ name }}` (HTML-escaped, `| safe` opt-out), `{% if %}...{% endif %}`, `{% for x in name %}...{% endfor %}`, single-level inheritance via `{% block <name> %}...{% endblock %}` + `{% extends "<parent>" %}` (rendered via `Template.render_extending(ctx, parent)`), `TemplateError` | `flare.http.template`, [`template_inheritance.mojo`](../examples/intermediate/template_inheritance.mojo) |
| `ByteRange`, `parse_range`, `FileServer` (see [Middleware](#middleware)) | `flare.http.fs` |

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
| `H2Connection` synchronous driver — `take_request() -> Request`, `emit_response(...)` queues `HEADERS [+ DATA]`; strips `Connection / Transfer-Encoding / Keep-Alive / Proxy-Connection / Upgrade` per RFC 9113 §8.2.2 | [`http2.mojo`](../examples/advanced/http2.mojo) |
| Reactor wiring (one fd → one `H2Connection`, ALPN dispatch, h2 prior-knowledge per RFC 9113 §3.4) | `flare.http._unified_reactor_impl`, [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) |
| h2c via Upgrade (mid-stream switch from h1 to h2 per RFC 7540 §3.2) | `flare.http._unified_reactor_impl._migrate_h1_to_h2`, [`tests/http/test_h2c_upgrade.mojo`](../tests/http/test_h2c_upgrade.mojo) |
| RFC 8441 Extended CONNECT dispatch + SETTINGS latch (server side); fuzz-covered (`fuzz-extended-connect`) | `flare.http2.state` |
| `Http2Config` — SETTINGS knobs validated at construction | [`http2_config.mojo`](../examples/advanced/http2_config.mojo) |
| `is_h2_alpn(...)`, `detect_h2c_upgrade(headers)` | `flare.http2.server` |
| `H2_PREFACE`, `H2_DEFAULT_FRAME_SIZE`, `H2_MAX_FRAME_SIZE`, `H2Error`, `H2ErrorCode` | `flare.http2` |
| Frame codec: `Frame`, `FrameFlags`, `FrameHeader`, `FrameType`, `encode_frame`, `parse_frame` (RFC 9113 §4, all 10 frame types); fuzz-clean (`fuzz-h2-frame`) | `flare.http2.frame` |
| Stream state: `Stream`, `StreamState`, `Connection.handle_frame` (RFC 9113 §5); fuzz-clean (`fuzz-h2-continuation`, `fuzz-h2-rapid-reset`) | `flare.http2.state` |
| HPACK (RFC 7541): `HpackEncoder`, `HpackDecoder`, `HpackHeader`, `encode_integer` / `decode_integer` (4/5/6/7-bit prefix codec); static + dynamic table, all four indexing modes, dynamic-table size update; fuzz-clean (`fuzz-hpack-decoder`) | `flare.http2.hpack` |
| HPACK Huffman codec — scalar-correct, H=1 wire-up + RFC 7541 §C.4 fixtures, and a 256-entry table-driven fast decoder that resolves codes of length <= 8 in one lookup (>=3x scalar across 16 B / 256 B / 4 KB / 64 KB input sizes; codes of length 9..30 fall through to the scalar bit-walker) | `flare.http.hpack_huffman`, `flare.http.hpack_huffman_simd` |
| CONTINUATION-flood / RAPID-RESET (CVE-2023-44487) state-machine fuzz coverage | `fuzz/fuzz_h2_continuation.mojo`, `fuzz/fuzz_h2_rapid_reset.mojo` |
| RFC 8441 Extended CONNECT (client side — `WsClient` over h2): `Http2ClientConnection.send_extended_connect` + `WsOverH2Stream` adapter + `bootstrap_ws_over_h2` | [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo), `flare.ws.client_h2` |
| Per-stream `Cancel` propagation (peer RST_STREAM → handler `cancel.cancelled()`): `H2ConnHandle` carries a `Dict[StreamId, Cancel]`, RST_STREAM / GOAWAY / drain all signal the matching cell | `flare.http._h2_conn_handle`, [`tests/http2/test_h2_per_stream_cancel.mojo`](../tests/http2/test_h2_per_stream_cancel.mojo) |
| h1.1 client connection pool: `HttpClient.with_pool(...)` keyed on `(scheme, host, port)`, idle reuse + per-origin caps + stale-conn retry | [`client_pool.mojo`](../examples/advanced/client_pool.mojo), `flare.http.client_pool` |
| h2c via Upgrade (client side — `Upgrade` + `HTTP2-Settings` + 101 carry-forward) | [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo), [`tests/http/test_h2c_client_upgrade.mojo`](../tests/http/test_h2c_client_upgrade.mojo) |

## HTTP/3 + QUIC

End-to-end QUIC v1 (RFC 9000) + HTTP/3 (RFC 9114) server: the
sans-I/O codecs, the pure state machines, the OpenSSL AEAD
backend behind `QuicCrypto`, the rustls binding behind
`RustlsQuicAcceptor`, the QUIC UDP reactor (live
`recv -> dispatch -> handle -> drain -> protect -> sendto`
cycle per Phase E Track Q11-W), the per-stream H3 dispatch
(`H3Connection` slab on `QuicListener` per Track Q12-W), the
Handler-mounted serve loop (`HttpServer.bind_with_h3 +
serve_h3[H]` per Track Q12-W), and the ALPN router on top of
`HttpServer.bind` are all wired. The same `Handler` instance
reaches h1 + h2c + h2 + h3 simultaneously.

**Live wire status (gate met).** The QUIC reactor I/O cycle is
live, the rustls FFI wrapper surfaces the per-level
`KeyChange` Handshake / 1-RTT keys back to
`QuicConnection.install_handshake_keys` /
`install_1rtt_keys`, and the Handler dispatch chain carries
requests end-to-end over the wire. The bench gate
(`flare_h3 >= 72,571 req/s vs quiche`) closed: flare h3 leads
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
serves a single `Handler` over h1 + h2 + h3 simultaneously.

| Surface | Where |
|---|---|
| QUIC variable-length integer codec (RFC 9000 §16): `QuicVarint`, `quic_encode_varint`, `quic_decode_varint`, `quic_varint_encoded_length`, `QUIC_VARINT_MAX` | `flare.quic.varint` |
| QUIC long / short packet header codec (RFC 9000 §17): `QuicLongHeader`, `QuicShortHeader`, `QuicConnectionId`, `QuicInitialExtras`, `quic_encode_long_header`, `quic_encode_short_header`, `quic_parse_long_header`, `quic_parse_short_header`, `quic_parse_initial_extras` | `flare.quic.packet` |
| QUIC packet-type constants: `QUIC_PACKET_TYPE_INITIAL` / `_ZERO_RTT` / `_HANDSHAKE` / `_RETRY`, `QUIC_VERSION_1`, `QUIC_VERSION_NEGOTIATION`, `QUIC_MAX_CID_LENGTH` | `flare.quic` |
| QUIC transport-frame codec (RFC 9000 §19 — all 22 frame types: PADDING, PING, ACK / ACK_ECN, RESET_STREAM, STOP_SENDING, CRYPTO, NEW_TOKEN, STREAM, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS_BIDI / _UNI, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED_BIDI / _UNI, NEW_CONNECTION_ID, RETIRE_CONNECTION_ID, PATH_CHALLENGE, PATH_RESPONSE, CONNECTION_CLOSE (transport + application), HANDSHAKE_DONE): typed payload structs (`AckFrame`, `StreamFrame`, `CryptoFrame`, ...) plus the `FrameHandler` trait + `parse_frame_into[H](buf, handler)` zero-carrier dispatcher (the parser walks one wire frame and fires the matching `on_*` callback on the caller's handler -- no intermediate union allocation), the per-type `encode_*(payload, mut out: List[UInt8])` writers that append to a caller-owned buffer, and the `FRAME_TYPE_*` constants | `flare.quic.frame` |
| QUIC transport parameters (RFC 9000 §18): `TransportParameters`, `encode_transport_parameters`, `decode_transport_parameters`, `empty_transport_parameters`; all `TP_ID_*` identifiers and defaults (`DEFAULT_MAX_UDP_PAYLOAD_SIZE`, `DEFAULT_ACK_DELAY_EXPONENT`, `DEFAULT_MAX_ACK_DELAY`, `DEFAULT_ACTIVE_CONNECTION_ID_LIMIT`) | `flare.quic.transport_params` |
| QUIC connection + stream state machines (RFC 9000 §3, §10, §13): `Connection`, `Stream`, `ConnectionEvents`, `handle_frame`, `mark_handshake_complete`, `is_idle_timeout_expired`, `connection_close`, `new_connection`, `new_stream`, `empty_events`; `CONN_STATE_*` and `STREAM_STATE_*` enums | `flare.quic.state` |
| QUIC congestion control (RFC 9438 CUBIC + RFC 9406 HyStart++ + RFC 9002 §7.7 pacing) as pure functions over a `CcState` value: `cc_init`, `on_packet_sent`, `on_ack_received`, `on_packets_lost`, `on_round_start`, `pacing_budget`, `pacing_rate_bytes_per_second`, `can_send` | `flare.quic.cc` |
| QUIC congestion controller trait (RFC 9438 CUBIC default + RFC 9002 Appendix B Reno fallback): `CongestionController` trait, `CubicController`, `RenoController`, `CcChoice` carrier. Picks deterministic Reno for tests and CUBIC for production via a single config field | `flare.quic.cc` |
| QUIC initial-secret + AEAD key schedule (RFC 9001 §5 + RFC 5869 HKDF): `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label`, `derive_initial_secrets`, `QuicAead` enum, `QuicCrypto` trait, `OpenSslQuicCrypto`. OpenSSL AEAD backend (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) + AES-ECB / ChaCha20 header-protection mask per RFC 9001 §5.3 / §5.4; key schedule is RFC 9001 Appendix A.1 byte-exact, AEAD vectors are RFC 9001 Appendix A byte-exact, both pinned by `tests/quic/test_crypto.mojo` + `tests/quic/test_openssl_quic_crypto.mojo` + `tests/quic/test_rfc9001_appendix_a.mojo`; fuzz-covered (`fuzz-quic-packet-decrypt`) | `flare.quic.crypto` |
| QUIC server reactor: `QuicServerConfig`, `QuicListener`, `QuicConnection`, `ConnectionIdTable` (RFC 9000 §5 -- multiple connection IDs per peer). UDP bind + non-blocking `recv_from` drain + per-datagram dispatch with coalesced 1-RTT egress, ECN echo per RFC 9002 §A.4, PTO + idle + ack-delay timers on the shared TimerWheel, CC + pacing driven from the egress path; fuzz-covered (`fuzz-quic-initial-handshake`, `fuzz-quic-connection-id`) | `flare.quic.server` |
| HTTP/3 server driver: `H3Connection` (per-connection driver mounted on `Handler`), `H3ConnectionConfig` (SETTINGS carrier -- max field section size, QPACK table caps, CONNECT-Protocol toggle, GOAWAY soft cap), `H3StreamType` (RFC 9114 §6.2 codepoints). `feed_stream_chunk` drives `H3RequestReader` -> `Handler` -> response writer; `take_response_frames` drains encoded bytes; CONTROL + QPACK uni-stream dispatch consumes SETTINGS / GOAWAY / MAX_PUSH_ID; fuzz-covered (`fuzz-h3-server`) | `flare.h3.server` |
| ALPN -> wire-protocol dispatcher: `WireProtocol` codepoints (UNKNOWN / HTTP_1_1 / H2C / HTTP_2 / HTTP_3), `ALPN_HTTP_1_1` / `ALPN_HTTP_2` / `ALPN_HTTP_3` identifiers, `dispatch_alpn`, `dispatch_h2c_upgrade`, `negotiate_alpn`, `wire_protocol_name`. The pure decision function the reactor consults after a TLS handshake completes | `flare.http.alpn_dispatch` |
| rustls QUIC binding: `RustlsQuicConfig`, `RustlsQuicAcceptor`, `RustlsQuicSession`, `RustlsQuicError`, `QuicEncryptionLevel`. C ABI shim over `rustls::quic::ServerConnection` (rustls 0.23); per-level CRYPTO frames feed / drain through `flare_rustls_quic_feed_crypto` / `_take_crypto`, negotiated ALPN via `flare_rustls_quic_alpn` | `flare.tls.rustls_quic` |
| HTTP/3 frame codec (RFC 9114 §7): `H3Frame`, `H3FrameType`, `encode_h3_frame`, `decode_h3_frame`; frame-type constants `H3_FRAME_TYPE_{DATA,HEADERS,CANCEL_PUSH,SETTINGS,PUSH_PROMISE,GOAWAY,MAX_PUSH_ID}` | `flare.h3.frame` |
| HTTP/3 SETTINGS payload (RFC 9114 §7.2.4): `H3Setting`, `encode_h3_settings`, `decode_h3_settings`; standard identifiers `H3_SETTINGS_{QPACK_MAX_TABLE_CAPACITY,MAX_FIELD_SECTION_SIZE,QPACK_BLOCKED_STREAMS,ENABLE_CONNECT_PROTOCOL}` | `flare.h3.frame` |
| HTTP/3 request-stream state machine (RFC 9114 §4 + §7): `H3RequestReader`, `H3RequestEventHandler`, `feed_into[H]`; fires `on_headers` / `on_data` / `on_trailers` / `on_unknown_frame` / `on_protocol_error` callbacks on a caller-supplied handler, returns the byte count consumed (`0` == NEEDS_MORE), and tracks the INIT / BODY / TRAILERS / DONE phases via the `H3_REQUEST_STATE_*` tags | `flare.h3.request_reader` |
| HTTP/3 response-stream writer (RFC 9114 §4 + §7): `encode_response_headers`, `encode_response_data`, `encode_response_trailers`; lowercases header names, rejects pseudo-headers in application + trailer sections, validates status in 100..599; QPACK-encodes field sections via `flare.qpack` | `flare.h3.response_writer` |
| QPACK static-only encoder + decoder (RFC 9204 — static table per Appendix A, literal field lines with literal names, Huffman shared with HPACK; dynamic table deferred): `QpackHeader`, `encode_field_section`, `decode_field_section`, `static_table_lookup`, `static_table_find`, `static_table_find_name`, `QPACK_STATIC_TABLE_SIZE` | `flare.qpack` |

## gRPC

gRPC primitives on top of the HTTP/2 reactor. The bottom two
wire layers (LPM framing, canonical Status codes, Metadata
carrier) ship as sans-I/O codecs; the unary call shape ships
as a server adapter that maps an HTTP/2 stream to a typed
`GrpcUnary` handler. Server-streaming, client-streaming,
bidirectional, the client side, and proto3 codegen are
deferred to follow-up cycles.

| Surface | Where |
|---|---|
| Length-prefixed message framing (gRPC wire format): `GrpcMessage`, `GrpcDecodeResult`, `GrpcCompressionFlag`, `encode_grpc_message`, `decode_grpc_message`, `GRPC_COMPRESSION_NONE`, `GRPC_COMPRESSION_COMPRESSED` | `flare.grpc.framing` |
| Canonical status codes (`GrpcStatus`): `GRPC_STATUS_OK`, `_CANCELLED`, `_UNKNOWN`, `_INVALID_ARGUMENT`, `_DEADLINE_EXCEEDED`, `_NOT_FOUND`, `_ALREADY_EXISTS`, `_PERMISSION_DENIED`, `_RESOURCE_EXHAUSTED`, `_FAILED_PRECONDITION`, `_ABORTED`, `_OUT_OF_RANGE`, `_UNIMPLEMENTED`, `_INTERNAL`, `_UNAVAILABLE`, `_DATA_LOSS`, `_UNAUTHENTICATED` | `flare.grpc.status` |
| Metadata carrier with binary / text key discipline (`-bin` suffix for binary keys, base64 transport): `GrpcMetadata`, `GrpcMetadataEntry` | `flare.grpc.metadata` |
| Unary server adapter: `GrpcUnary` per-method handler trait, `GrpcUnaryReply` typed handler return (`ok(body, metadata)` / `err(status, metadata)` factories), `GrpcRequestHeaders` typed request-HEADERS carrier (`Optional[String]` for `grpc-timeout` / `grpc-accept-encoding`), `GrpcCallContext` (parsed deadline + accept-encoding + initial metadata), `GrpcCallOutcome` (response bytes + final `GrpcStatus` + trailing `GrpcMetadata`), `parse_request_headers` (validates POST + `content-type: application/grpc[+proto]` + `te: trailers` case-insensitively), `stitch_request_data` (concatenates LPM frames from HTTP/2 DATA, rejects compressed-flag set), `encode_unary_response` (wraps reply in uncompressed LPM), `emit_trailing_headers_status` (framework-controlled trailer entries: `grpc-status`, optional `grpc-message`, optional base64 `grpc-status-details-bin`), `run_unary_call` (sans-I/O orchestration that threads the call through the handler; never raises -- header / LPM / handler failures fold into typed `INVALID_ARGUMENT` / `INTERNAL` outcomes) | `flare.grpc.server` |
| Optional binary status details: `GrpcStatus.with_details(payload: List[UInt8])` attaches an opaque payload that the trailer emitter base64-encodes as `grpc-status-details-bin` per gRPC PROTOCOL-HTTP2 | `flare.grpc.status` |

## OpenAPI

OpenAPI 3.1 spec model + deterministic JSON emitter. The
model is hand-built today (manual `OpenApiSpec` construction
+ `emit_openapi_json`); auto-derivation from `ComptimeRouter`
is the next iteration.

| Surface | Where |
|---|---|
| Spec model: `OpenApiSpec`, `OpenApiInfo`, `OpenApiPath`, `OpenApiOperation`, `OpenApiParameter`, `OpenApiResponse` | `flare.openapi.spec` |
| Deterministic JSON emitter (stable key order — diffable specs in CI): `emit_openapi_json(spec) -> String` | `flare.openapi.spec` |

## WebSocket

| Surface | Where |
|---|---|
| `WsClient.connect(url)` — handshake + frame loop, `WsHandshakeError` | [`websocket_echo.mojo`](../examples/basic/websocket_echo.mojo) |
| `WsServer` — server-side handshake + frame loop | [`ws_server.mojo`](../examples/basic/ws_server.mojo) |
| `WsMessage` — high-level text / binary message wrapper | [`ergonomics.mojo`](../examples/basic/ergonomics.mojo) |
| `WsFrame`, `WsOpcode`, `WsCloseCode`, `WsProtocolError` — low-level frame surface | `flare.ws.frame` |
| Mandatory client-mask validation, UTF-8 validation on text frames (RFC 6455) | `flare.ws.frame` |
| WS-over-HTTP/2 (RFC 8441) — `WsOverH2Stream` + `bootstrap_ws_over_h2`; CONNECT + `:protocol=websocket` over a single h2 stream, frame masking preserved | [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo), `flare.ws.client_h2` |
| `permessage-deflate` (RFC 7692) — `PermessageDeflateConfig`, `compress_message` / `decompress_message`, `Sec-WebSocket-Extensions` parser + emitter, `negotiate_permessage_deflate`; default invariant: `no_context_takeover` on both sides + 16 MiB per-message decompressed cap | [`ws_permessage_deflate.mojo`](../examples/advanced/ws_permessage_deflate.mojo), `flare.ws.permessage_deflate` |
| `permessage-deflate` context-takeover (RFC 7692 §7.1 default mode) — `PermessageDeflateContext`: persistent compressor + decompressor pair, LZ77 sliding window carries between messages, fuzz-covered lifecycle (`fuzz-pmd-context` × 3 targets, 350K runs) | `flare.ws.permessage_deflate.PermessageDeflateContext` |
| `WsClient.connect_prefer_h2(url, tls_config)` — ALPN-aware factory: advertises `["h2", "http/1.1"]`; if peer selects `http/1.1` (or none), delegates to the existing H1 Upgrade handshake; if peer selects `h2`, raises pointing at the (in-flight) full H2-tunnel runtime | [`tests/ws/test_ws_prefer_h2.mojo`](../tests/ws/test_ws_prefer_h2.mojo), `flare.ws.client` |
| `WsAutoClient` + `WsAutoClientConfig` + `WsWireChoice` + `decide_wire` — high-level dispatcher that picks the carrying wire after the TLS handshake completes. Pure decision function consults URL scheme, `prefer_h2`, negotiated ALPN, and the peer's `ENABLE_CONNECT_PROTOCOL` SETTINGS flag (RFC 8441 §3); routes to HTTP/1.1, HTTP/2 (RFC 8441 Extended CONNECT), or FAILED. Runtime hand-off to `WsClient` / `WsOverH2Stream` is the focused follow-up | [`tests/ws/test_ws_autoclient.mojo`](../tests/ws/test_ws_autoclient.mojo), `flare.ws.auto_client` |

## TLS

| Surface | Where |
|---|---|
| `TlsStream.connect(host, port, TlsConfig)` — client | [`tls.mojo`](../examples/basic/tls.mojo) |
| `TlsConfig`, `TlsVerify` — verification mode (`TlsVerify.REQUIRED` (default) or `TlsVerify.NONE`) | `flare.tls.config` |
| `TlsAcceptor`, `TlsServerConfig`, `TlsInfo` — server side over OpenSSL | `flare.tls.acceptor` |
| `TlsAcceptor.reload()` — ACME / Let's Encrypt cert rotation without restart | [`cert_reload.mojo`](../examples/advanced/cert_reload.mojo) |
| mTLS — construction-time validation of CA chain + client cert | [`mtls.mojo`](../examples/advanced/mtls.mojo) |
| ALPN advertised + parsed on both sides; refusal-to-downgrade enforced | `flare.tls` |
| `TLS_PROTOCOL_TLS12`, `TLS_PROTOCOL_TLS13` (1.0 / 1.1 refused) | `flare.tls.acceptor` |
| Session resumption (RFC 5077 / RFC 8446 §4.6.1) — server-side ticket cache (opt-in via `TlsServerConfig.enable_session_tickets`) + client-side reconnect (opt-in via `TlsConfig.enable_session_resumption`) | [`tests/tls/test_tls_resume.mojo`](../tests/tls/test_tls_resume.mojo), `flare.tls.acceptor`, `flare.tls.config` |
| Errors: `TlsHandshakeError`, `CertificateExpired`, `CertificateHostnameMismatch`, `CertificateUntrusted`, `TlsServerError`, `TlsServerNotImplemented` | `flare.tls.error` |

## TCP, UDP, Unix sockets, DNS, addressing

| Surface | Where |
|---|---|
| `TcpStream.connect(host, port)`, `TcpListener.bind(addr)`, IPv4 + IPv6, TCP options | [`tcp_echo.mojo`](../examples/basic/tcp_echo.mojo) |
| `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` | [`udp.mojo`](../examples/basic/udp.mojo) |
| `UnixListener`, `UnixStream`, `accept_uds_fd` — AF_UNIX sidecar IPC | [`uds_sidecar.mojo`](../examples/advanced/uds_sidecar.mojo) |
| `IpAddr.parse(...)`, `IpAddr.is_v4()`/`is_v6()`, `is_private()`, `is_loopback()`, `SocketAddr.parse(...)`, `SocketAddr.localhost(port)`, `RawSocket` | [`addresses.mojo`](../examples/basic/addresses.mojo) |
| `resolve()`, `resolve_v4()`, `resolve_v6()` — getaddrinfo, dual-stack, numeric-IP passthrough | [`dns_resolution.mojo`](../examples/basic/dns_resolution.mojo) |

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
| `Event`, `INTEREST_READ`, `INTEREST_WRITE`, `EVENT_READABLE`, `EVENT_WRITABLE`, `EVENT_ERROR`, `EVENT_HUP`, `WAKEUP_TOKEN` | `flare.runtime.event` |
| `TimerWheel` — hashed timing wheel for idle / deadline timeouts | `flare.runtime.timer_wheel` |
| `default_worker_count()`, `num_cpus()` | `flare.runtime` |
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
| HTTP/2 | `H2Error`, `H2ErrorCode`, `HuffmanError` |
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
| `SOAK_DURATION_SECS=<n>` | Override default soak harness duration (`pixi run --environment bench bench-soak-*`) |

`ServerConfig` defaults (override per-server): `max_header_size` (8192 B),
`max_body_size` (10 MiB), `max_keepalive_requests` (100), `idle_timeout_ms`
(500), `read_body_timeout_ms` (30_000), plus `request_timeout_ms` /
`handler_timeout_ms`. Build-time invariants (e.g. `max_body_size >=
max_header_size`) are checked by Mojo `comptime assert` when used with
`serve_comptime[handler, config]`.

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
| Unit + integration tests | 600+ across `tests/` |
| Examples (each part of `pixi run tests`) | 40+ under [`examples/`](../examples/) |
| Fuzz harnesses | 40 under [`fuzz/`](../fuzz/), 9M+ runs combined, zero known crashes |
| Sanitizer harnesses | `tests-asan` / `tests-tsan` / `tests-asserts-all` (see [`build.md`](build.md)) |
| Conformance corpora | RFC 7230 HTTP/1 wire shapes under [`conformance/h1/`](../conformance/h1/) (runner: `test-conformance-h1`); RFC 6455 WebSocket frames under [`conformance/ws/`](../conformance/ws/) (runner: `test-conformance-ws`, 13 fixtures; Autobahn-anchored case ids 1.x / 2.x / 3.x / 5.x / 7.x) |

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
| QUIC transport-parameter codec (RFC 9000 §18 — typed-value stability across encode / decode / re-encode) | `fuzz-quic-transport-params` |
| HTTP/3 frame codec (multi-byte varint frame types) | `fuzz-h3-frame` |
| QPACK static-only decoder + round-trip (RFC 9204 — header stability across encode / decode) | `fuzz-qpack-decode` |
| QUIC packet AEAD (decrypt → re-encrypt round-trip; RFC 9001 §5) | `fuzz-quic-packet-decrypt` |
| QUIC Initial handshake parser (RFC 9000 §17.2.2 long header + CRYPTO frame extraction) | `fuzz-quic-initial-handshake` |
| QUIC Connection ID dispatch (`ConnectionIdTable.lookup` on arbitrary bytes) | `fuzz-quic-connection-id` |
| HTTP/3 server end-to-end (request stream feed → handler → response writer) | `fuzz-h3-server` |
| Cache-Control header parser (idempotent re-parse) | `fuzz-cache-control-parser` |
