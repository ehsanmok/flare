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
| `App[S, H]` — application-scoped state bundled with a handler; `state_view()` hands out a `State[S]` borrow that middleware can read or mutate | [`state.mojo`](../examples/intermediate/state.mojo) |
| `State[S]` typed handle, `state.get()` borrow | [`state.mojo`](../examples/intermediate/state.mojo) |

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

Parametric / pluggable forms:

| Surface | What it does | Where |
|---|---|---|
| `Path[T: ParamParser, name]`, `Query[T, name]`, `OptionalQuery[T, name]`, `Header[T, name]`, `OptionalHeader[T, name]` | Plug in a custom `ParamParser` for non-standard primitives | `flare.http.extract` |
| `ParamParser` trait + `ParamInt` / `ParamFloat64` / `ParamBool` / `ParamString` | Stock parser implementations | `flare.http.extract` |
| `Extractor` trait | Anything that pulls a value from a `Request` | `flare.http.extract` |
| `Extracted[H]` | Reflects on a struct's fields, runs every extractor before `serve`; malformed input becomes a sanitised 400 | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |

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
| `Retry[Inner]` + `RetryPolicy` | Re-invoke the inner handler up to `max_attempts` times on 5xx; idempotent-method gate on by default (GET / HEAD / PUT / DELETE / OPTIONS retry; POST / PATCH pass through once unless `retry_only_idempotent` is `False`) | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `TimeoutMiddleware[Inner]` (`flare.http.Timeout`) | Bound the inner handler's wall-clock time; on overrun, the response is replaced with a sanitised 504; `budget_ms <= 0` is the explicit "disabled" sentinel that always trips 504 | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| `negotiate_encoding(Accept-Encoding) -> Encoding` | RFC 9110 §12.5.3 q-value parser exposed for direct use | `flare.http.middleware` |

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
| Askama-shape templates: `{{ name }}` (HTML-escaped, `| safe` opt-out), `{% if %}...{% endif %}`, `{% for x in name %}...{% endfor %}`, `TemplateError` | `flare.http.template` |
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

## WebSocket

| Surface | Where |
|---|---|
| `WsClient.connect(url)` — handshake + frame loop, `WsHandshakeError` | [`websocket_echo.mojo`](../examples/basic/websocket_echo.mojo) |
| `WsServer` — server-side handshake + frame loop | [`ws_server.mojo`](../examples/basic/ws_server.mojo) |
| `WsMessage` — high-level text / binary message wrapper | [`ergonomics.mojo`](../examples/basic/ergonomics.mojo) |
| `WsFrame`, `WsOpcode`, `WsCloseCode`, `WsProtocolError` — low-level frame surface | `flare.ws.frame` |
| Mandatory client-mask validation, UTF-8 validation on text frames (RFC 6455) | `flare.ws.frame` |
| WS-over-HTTP/2 (RFC 8441) — `WsOverH2Stream` + `bootstrap_ws_over_h2`; CONNECT + `:protocol=websocket` over a single h2 stream, frame masking preserved | [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo), `flare.ws.client_h2` |
| `permessage-deflate` (RFC 7692) — `PermessageDeflateConfig`, `compress_message` / `decompress_message`, `Sec-WebSocket-Extensions` parser + emitter, `negotiate_permessage_deflate`; invariant: `no_context_takeover` on both sides + 16 MiB per-message decompressed cap | [`ws_permessage_deflate.mojo`](../examples/advanced/ws_permessage_deflate.mojo), `flare.ws.permessage_deflate` |

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
Mojo stdlib doesn't ship: `flare.testing` (`fork_server` /
`kill_forked_server` — fork-and-serve so a single-process
example can both serve and connect to itself) and `flare.utils`
(POSIX FFI thunks: `fork` / `waitpid` / `kill` / `usleep` /
`exit` / `getpid` plus `SIGKILL` / `SIGTERM` / `SIGINT`).
Tests under [`tests/`](../tests/) mirror the package layout:
`tests/{crypto,dns,http,http2,net,runtime,tcp,testing,tls,udp,uds,ws}/`.

| | Count |
|---|---|
| Unit + integration tests | 600+ across `tests/` |
| Examples (each part of `pixi run tests`) | 40+ under [`examples/`](../examples/) |
| Fuzz harnesses | 34 under [`fuzz/`](../fuzz/), 8M+ runs combined, zero known crashes |
| Sanitizer harnesses | `tests-asan` / `tests-tsan` / `tests-asserts-all` (see [`build.md`](build.md)) |

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
| HAProxy PROXY v1 + v2 | `fuzz-proxy-protocol` |
| io_uring SQE / CQE codec | `fuzz-io-uring-sqe` |
| io_uring reactor cancel-surface | `fuzz-uring-reactor` |
