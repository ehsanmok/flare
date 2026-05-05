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
| `HttpServer.bind(addr)` / `serve(handler)` / `serve(handler, num_workers=N)` — version-aware listener that dispatches HTTP/1.1, HTTP/2 over TLS (ALPN), and h2c (RFC 9113 §3.4 preface peek, no `Upgrade` dance) to the same handler | [`08_http_server.mojo`](../examples/08_http_server.mojo), [`35_http2.mojo`](../examples/35_http2.mojo), [`41_http2_server_router.mojo`](../examples/41_http2_server_router.mojo) |
| `HttpServer.serve_static(StaticResponse)` — pre-encoded static-response fast path that skips parsing and handler dispatch (used by `flare_mc_static` bench row) | [`21_static_response.mojo`](../examples/21_static_response.mojo) |
| `HttpServer.serve_comptime[handler, config]()` — comptime-specialised reactor with build-time invariant checks on `ServerConfig` | `flare.http.server` |
| Per-worker `SO_REUSEPORT` listeners by default (`num_workers >= 2`); `FLARE_REUSEPORT_WORKERS=0` switches to single-listener `EPOLLEXCLUSIVE` shape | [`17_multicore.mojo`](../examples/17_multicore.mojo) |
| `pin_cores=True` (default): worker N pinned to core `N % num_cpus()` on Linux, no-op on macOS | [`17_multicore.mojo`](../examples/17_multicore.mojo) |
| `HttpServer.drain(timeout_ms) -> ShutdownReport` per worker, `install_drain_on_sigterm` | [`23_drain.mojo`](../examples/23_drain.mojo) |
| `ServerConfig` (request / handler / body-read deadlines, `max_header_size`, `max_body_size`, `max_keepalive_requests`, `idle_timeout_ms`) | `flare.http.server` |
| Response builders: `ok(body)`, `ok_json(body)`, `bad_request(msg)`, `not_found(msg)`, `internal_error(msg)`, `redirect(url)` | `flare.http.server` |
| `Method` enum, `Status` enum, `Response` with header / body / status, `ResponsePool` for response object reuse | `flare.http.{request,response,response_pool}` |
| `Request.peer` threaded from the accept path | `flare.http.request` |
| `precompute_response(status, content_type, body) -> StaticResponse` — keep-alive + `Connection: close` wire forms both pre-encoded | [`21_static_response.mojo`](../examples/21_static_response.mojo) |

## HTTP client

| Surface | Where |
|---|---|
| `HttpClient(base_url, auth=...)`, `HttpClient(prefer_h2c=True)` — version-aware over TLS+ALPN; `prefer_h2c=True` opts into HTTP/2 cleartext via prior knowledge | [`05_http_get.mojo`](../examples/05_http_get.mojo), [`40_http2_client.mojo`](../examples/40_http2_client.mojo) |
| Module-level helpers: `get`, `post`, `put`, `patch`, `delete`, `head` — `post` with `String` body sets `Content-Type: application/json` automatically | `flare.http.client` |
| `RedirectPolicy.FOLLOW_ALL` / `SAME_ORIGIN_ONLY` / `DENY` (default), `TooManyRedirects` error | `flare.http.{redirect_policy,error}` |
| `Auth`, `BasicAuth(user, pass)`, `BearerAuth(token)` — both wires | `flare.http.auth` |
| `Response.json()`, `.text()`, `.raise_for_status()`, `.ok()`, `.status` | `flare.http.response` |

## Routing

| Surface | Where |
|---|---|
| `Router` — runtime trie with path parameters (`:name`), wildcards (`*`), method dispatch, 404 / 405-with-`Allow` | [`15_router.mojo`](../examples/15_router.mojo) |
| `ComptimeRouter[ROUTES]`, `ComptimeRoute(method, path, handler)` — segments parsed at compile time, dispatch loop unrolled per route | [`20_comptime_router.mojo`](../examples/20_comptime_router.mojo) |
| `App[S, H]` — application-scoped state bundled with a handler; `state_view()` hands out a `State[S]` borrow that middleware can read or mutate | [`16_state.mojo`](../examples/16_state.mojo) |
| `State[S]` typed handle, `state.get()` borrow | [`16_state.mojo`](../examples/16_state.mojo) |

## Handlers and extractors

### Handler traits

| Trait | What it gets | Where |
|---|---|---|
| `Handler` | `serve(req: Request) raises -> Response` | `flare.http.handler` |
| `CancelHandler` | `serve(req: Request, cancel: Cancel) raises -> Response`; `cancel.cancelled()` flips on peer FIN, deadline elapse, or graceful drain | [`22_cancel.mojo`](../examples/22_cancel.mojo) |
| `ViewHandler` | Receives `RequestView[origin]` for zero-copy reads (no `String` materialisation) | `flare.http.handler` |
| `WithCancel[Inner]` | Adapt a `CancelHandler` to fit the `Handler` shape | `flare.http.handler` |
| `WithViewCancel[Inner]` | Same, for `ViewHandler` + `Cancel` | `flare.http.handler` |
| `FnHandler(fn)` / `FnHandlerCT(fn)` | Wrap a plain `def` as a `Handler` (runtime / comptime) | `flare.http.handler` |

### Extractors

Concrete typed extractors (`.value` is the parsed primitive):

| Extractor | Type | Source |
|---|---|---|
| `PathInt[name]` / `PathStr[name]` / `PathFloat[name]` / `PathBool[name]` | path parameter | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| `QueryInt[name]` / `QueryStr` / `QueryFloat` / `QueryBool` | query string | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| `OptionalQueryInt[name]` / `OptionalQueryStr` / `OptionalQueryFloat` / `OptionalQueryBool` | optional query | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| `HeaderInt[name]` / `HeaderStr` / `HeaderFloat` / `HeaderBool` | request header | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| `OptionalHeaderInt[name]` / `OptionalHeaderStr` / `OptionalHeaderFloat` / `OptionalHeaderBool` | optional header | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| `Peer` | client `SocketAddr` from accept path | `flare.http.extract` |
| `BodyBytes` / `BodyText` | raw request body | `flare.http.extract` |
| `Json[T]` | JSON-decoded body | `flare.http.extract` |
| `Form[T]` | `application/x-www-form-urlencoded` body | [`28_forms.mojo`](../examples/28_forms.mojo) |
| `Multipart` | `multipart/form-data` body | [`29_multipart_upload.mojo`](../examples/29_multipart_upload.mojo) |
| `Cookies` | inbound `Cookie:` header → `CookieJar` | [`27_request_cookies.mojo`](../examples/27_request_cookies.mojo) |

Parametric / pluggable forms:

| Surface | What it does | Where |
|---|---|---|
| `Path[T: ParamParser, name]`, `Query[T, name]`, `OptionalQuery[T, name]`, `Header[T, name]`, `OptionalHeader[T, name]` | Plug in a custom `ParamParser` for non-standard primitives | `flare.http.extract` |
| `ParamParser` trait + `ParamInt` / `ParamFloat64` / `ParamBool` / `ParamString` | Stock parser implementations | `flare.http.extract` |
| `Extractor` trait | Anything that pulls a value from a `Request` | `flare.http.extract` |
| `Extracted[H]` | Reflects on a struct's fields, runs every extractor before `serve`; malformed input becomes a sanitised 400 | [`19_extractors.mojo`](../examples/19_extractors.mojo) |

## Middleware

Each layer is itself a `Handler` that holds another `Handler`. Stack
by nesting structs:

| Layer | Behaviour | Where |
|---|---|---|
| `Logger[Inner]` | Space-delimited per-request line (`[flare] GET /users 200 12ms`) | [`18_middleware.mojo`](../examples/18_middleware.mojo) |
| `RequestId[Inner]` | Generate / propagate `X-Request-Id` | [`31_middleware_stack.mojo`](../examples/31_middleware_stack.mojo) |
| `Compress[Inner]` | gzip / brotli / identity content-encoding via q-value negotiation; small-body / already-encoded skip | [`31_middleware_stack.mojo`](../examples/31_middleware_stack.mojo), [`34_brotli.mojo`](../examples/34_brotli.mojo) |
| `CatchPanic[Inner]` | Convert handler panic to sanitised 500 | [`31_middleware_stack.mojo`](../examples/31_middleware_stack.mojo) |
| `Cors[Inner]` + `CorsConfig` | RFC 6454 + Fetch CORS protocol; permissive / allowlist / preflight short-circuit / credentials echo / exposed-headers / max-age | [`32_cors.mojo`](../examples/32_cors.mojo) |
| `Conditional[Inner]` | RFC 9110 §13 preconditions: `If-Match` / `If-None-Match` (304 / 412), `If-Modified-Since` / `If-Unmodified-Since`; opt-in auto-ETag from FNV-1a body hash via `Conditional.with_auto_etag` | `flare.http.conditional` |
| `FileServer.new(root)` | Static file serving with GET / HEAD + RFC 9110 §14.4 single-Range, MIME inference, path safety (`..` / NUL / absolute path rejection), `index.html` directory fall-through | [`33_static_files.mojo`](../examples/33_static_files.mojo) |
| `negotiate_encoding(Accept-Encoding) -> Encoding` | RFC 9110 §12.5.3 q-value parser exposed for direct use | `flare.http.middleware` |

## Cookies, sessions, auth

| Surface | Where |
|---|---|
| `Cookie`, `CookieJar`, `SameSite` | [`13_cookies.mojo`](../examples/13_cookies.mojo) |
| `parse_cookie_header`, `parse_set_cookie_header` (RFC 6265) | [`13_cookies.mojo`](../examples/13_cookies.mojo) |
| `signed_cookie_encode(value, key)` / `signed_cookie_decode(cookie, key)` — HMAC-SHA256 over base64url payload + tag | `flare.http.session` |
| `signed_cookie_decode_keys(cookie, keys)` — accept any of N keys, for graceful key rotation | `flare.http.session` |
| `Session[T]`, `SessionCodec`, `StringSessionCodec` | [`30_sessions.mojo`](../examples/30_sessions.mojo) |
| `CookieSessionStore[T]` (signed-cookie-backed), `InMemorySessionStore[T]` (server-side) | [`30_sessions.mojo`](../examples/30_sessions.mojo) |
| `Auth`, `BasicAuth`, `BearerAuth`, `AuthError` | `flare.http.{auth,auth_extract}` |
| HAProxy PROXY v1 + v2 parser, `ProxyParseError` | `flare.http.proxy_protocol` |

## Forms and content-encoding

| Surface | Where |
|---|---|
| `FormData`, `parse_form_urlencoded`, `urldecode`, `urlencode`, `Form` extractor | [`28_forms.mojo`](../examples/28_forms.mojo) |
| `MultipartPart`, `MultipartForm`, `parse_multipart_form_data`, `Multipart` extractor | [`29_multipart_upload.mojo`](../examples/29_multipart_upload.mojo) |
| `Url`, `UrlParseError` — URL parser, percent decoding | `flare.http.url` |
| `Encoding` enum, `compress_gzip` / `decompress_gzip`, `compress_brotli` / `decompress_brotli`, `decompress_deflate` | [`10_encoding.mojo`](../examples/10_encoding.mojo), [`34_brotli.mojo`](../examples/34_brotli.mojo) |
| `decode_content("br" / "gzip" / "deflate" / "identity", ...)` | `flare.http.encoding` |

## Body, streaming, SSE, templates, static files

| Surface | Where |
|---|---|
| `Body`, `InlineBody`, `ChunkedBody`, `ChunkSource`, `drain_body` | `flare.http.body` |
| `StreamingResponse[B]`, `serialize_streaming_response` | `flare.http.streaming_response` |
| `RequestView[origin]`, `parse_request_view` — zero-copy borrow over the parsed request, paired with `ViewHandler` | `flare.http.request_view` |
| `HeaderMap`, `HeaderInjectionError`, `HeaderMapView`, `parse_header_view` | `flare.http.{headers,header_view}` |
| `StaticResponse`, `precompute_response` — pre-encoded wire form for fixed-body endpoints | [`21_static_response.mojo`](../examples/21_static_response.mojo) |
| `SseEvent`, `SseChannel` (in-memory FIFO + cancel-aware `ChunkSource` wrapper), `format_sse_event`, `sse_response`, `SseStreamingResponse[B]` | [`24_sse.mojo`](../examples/24_sse.mojo) |
| Askama-shape templates: `{{ name }}` (HTML-escaped, `| safe` opt-out), `{% if %}...{% endif %}`, `{% for x in name %}...{% endfor %}`, `TemplateError` | `flare.http.template` |
| `ByteRange`, `parse_range`, `FileServer` (see [Middleware](#middleware)) | `flare.http.fs` |

## Observability

| Surface | Where |
|---|---|
| `Logger[Inner]` — space-delimited line, grep / `jq` friendly, zero-dep | `flare.http.middleware` |
| `StructuredLogger[Inner]` — JSON-per-line additive sibling: `{"ts","method","url","status","latency_ms","request_id","peer"}`; works with Datadog / Elastic / Loki / Splunk / CloudWatch out of the box | `flare.http.structured_logger` |
| `Metrics[Inner]` — Prometheus text-exposition middleware (v0.0.4 spec); emits `flare_http_requests_total{method,status}`, `flare_http_request_duration_seconds_bucket{le}`, `..._sum`, `..._count`, `flare_http_requests_in_flight`, `flare_http_request_errors_total` with the canonical Prometheus default-bucket layout | `flare.http.metrics` |

## HTTP/2

| Surface | Where |
|---|---|
| `H2Connection` — synchronous, buffer-driven driver; `take_request() -> Request`, `emit_response(...)` queues `HEADERS [+ DATA]`; strips `Connection / Transfer-Encoding / Keep-Alive / Proxy-Connection / Upgrade` per RFC 9113 §8.2.2 | [`35_http2.mojo`](../examples/35_http2.mojo) |
| `Http2Config` — SETTINGS knobs validated at construction | [`37_http2_config.mojo`](../examples/37_http2_config.mojo) |
| `is_h2_alpn(...)`, `detect_h2c_upgrade(headers)` | `flare.http2.server` |
| `H2_PREFACE`, `H2_DEFAULT_FRAME_SIZE`, `H2_MAX_FRAME_SIZE`, `H2Error`, `H2ErrorCode` | `flare.http2` |
| Frame codec: `Frame`, `FrameFlags`, `FrameHeader`, `FrameType`, `encode_frame`, `parse_frame` (RFC 9113 §4, all 10 frame types) | `flare.http2.frame` |
| Stream state: `Stream`, `StreamState`, `Connection.handle_frame` (RFC 9113 §5) | `flare.http2.state` |
| HPACK (RFC 7541): `HpackEncoder`, `HpackDecoder`, `HpackHeader`, `encode_integer` / `decode_integer` (4/5/6/7-bit prefix codec); static + dynamic table, all four indexing modes, dynamic-table size update | `flare.http2.hpack` |
| HPACK Huffman: `HuffmanError`, `huffman_encode`, `huffman_decode`, `huffman_encoded_length`, `huffman_decoded_length` | `flare.http.hpack_huffman` |
| RFC 8441 Extended CONNECT dispatch + SETTINGS latch (fuzz-covered: `fuzz-extended-connect`) | `flare.http2.state` |

## WebSocket

| Surface | Where |
|---|---|
| `WsClient.connect(url)` — handshake + frame loop, `WsHandshakeError` | [`06_websocket_echo.mojo`](../examples/06_websocket_echo.mojo) |
| `WsServer` — server-side handshake + frame loop | [`09_ws_server.mojo`](../examples/09_ws_server.mojo) |
| `WsMessage` — high-level text / binary message wrapper | [`07_ergonomics.mojo`](../examples/07_ergonomics.mojo) |
| `WsFrame`, `WsOpcode`, `WsCloseCode`, `WsProtocolError` — low-level frame surface | `flare.ws.frame` |
| Mandatory client-mask validation, UTF-8 validation on text frames (RFC 6455) | `flare.ws.frame` |

## TLS

| Surface | Where |
|---|---|
| `TlsStream.connect(host, port, TlsConfig)` — client | [`12_tls.mojo`](../examples/12_tls.mojo) |
| `TlsConfig`, `TlsVerify` — verification mode (full / hostname / none) | `flare.tls.config` |
| `TlsAcceptor`, `TlsServerConfig`, `TlsInfo` — server side over OpenSSL | `flare.tls.acceptor` |
| `TlsAcceptor.reload()` — ACME / Let's Encrypt cert rotation without restart | [`25_cert_reload.mojo`](../examples/25_cert_reload.mojo) |
| mTLS — construction-time validation of CA chain + client cert | [`26_mtls.mojo`](../examples/26_mtls.mojo) |
| ALPN advertised + parsed on both sides; refusal-to-downgrade enforced | `flare.tls` |
| `TLS_PROTOCOL_TLS12`, `TLS_PROTOCOL_TLS13` (1.0 / 1.1 refused) | `flare.tls.acceptor` |
| Errors: `TlsHandshakeError`, `CertificateExpired`, `CertificateHostnameMismatch`, `CertificateUntrusted`, `TlsServerError`, `TlsServerNotImplemented` | `flare.tls.error` |

## TCP, UDP, Unix sockets, DNS, addressing

| Surface | Where |
|---|---|
| `TcpStream.connect(host, port)`, `TcpListener.bind(addr)`, IPv4 + IPv6, TCP options | [`04_tcp_echo.mojo`](../examples/04_tcp_echo.mojo) |
| `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` | [`11_udp.mojo`](../examples/11_udp.mojo) |
| `UnixListener`, `UnixStream`, `accept_uds_fd` — AF_UNIX sidecar IPC | [`38_uds_sidecar.mojo`](../examples/38_uds_sidecar.mojo) |
| `IpAddr.parse(...)`, `IpAddr.is_v4/v6`, `is_private`, `is_loopback`, `SocketAddr.parse(...)`, `SocketAddr.localhost(port)`, `RawSocket` | [`01_addresses.mojo`](../examples/01_addresses.mojo) |
| `resolve()`, `resolve_v4()`, `resolve_v6()` — getaddrinfo, dual-stack, numeric-IP passthrough | [`02_dns_resolution.mojo`](../examples/02_dns_resolution.mojo) |

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
| `BufReader` over any `Readable` | [`07_ergonomics.mojo`](../examples/07_ergonomics.mojo) |

## Reactor and runtime

| Surface | Where |
|---|---|
| `Reactor` — `kqueue` (macOS), `epoll` (Linux); register / deregister fds, run one tick or until shutdown | [`14_reactor.mojo`](../examples/14_reactor.mojo) |
| `Event`, `INTEREST_READ`, `INTEREST_WRITE`, `EVENT_READABLE`, `EVENT_WRITABLE`, `EVENT_ERROR`, `EVENT_HUP`, `WAKEUP_TOKEN` | `flare.runtime.event` |
| `TimerWheel` — hashed timing wheel for idle / deadline timeouts | `flare.runtime.timer_wheel` |
| `default_worker_count()`, `num_cpus()` | `flare.runtime` |
| `HandoffPolicy.from_env()`, `HandoffQueue` (bounded MPSC FIFO of fd tokens), `WorkerHandoffPool.peek_idle_worker(exclude)` — cross-worker steering, gated on `FLARE_SOAK_WORKERS=on` | [`36_work_stealing.mojo`](../examples/36_work_stealing.mojo) |
| `IoUringRing`, `IoUringParams`, `is_io_uring_available()` — opt-in `io_uring` reactor on Linux ≥ 6.0 (`FLARE_BUFRING_HANDLER=1`); auto-fallback to `epoll` | [`39_iouring_plaintext.mojo`](../examples/39_iouring_plaintext.mojo) |
| `Cancel`, `CancelCell`, `CancelReason` (peer FIN / deadline / drain) plumbed to `CancelHandler` | [`22_cancel.mojo`](../examples/22_cancel.mojo) |

## Performance internals

These are public but most users won't touch them directly; the
HTTP server already wires them in. Listed for completeness.

| Surface | Where |
|---|---|
| SIMD parsers: `simd_memmem`, `simd_percent_decode`, `simd_cookie_scan` (fuzzed against scalar oracle: `fuzz-header-scan`, 500K runs) | `flare.http.simd_parsers` |
| Header PHF: `StandardHeader`, `standard_header_count`, `standard_header_name`, `lookup_standard_header_bytes` / `_string`, `is_standard_header` — perfect-hash lookup over the 80 IANA standard headers | `flare.http.header_phf` |
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
| `FLARE_REUSEPORT_WORKERS=0` | Switch from per-worker `SO_REUSEPORT` to shared-listener `EPOLLEXCLUSIVE` shape (~17 % less req/s, ~0.25 ms tighter p99.99) |
| `FLARE_BUFRING_HANDLER=1` | Opt into `io_uring` reactor on Linux ≥ 6.0; auto-fallback to `epoll` |
| `FLARE_SOAK_WORKERS=on` | Enable cross-worker `WorkerHandoffPool` for skewed-keepalive workloads |
| `SOAK_DURATION_SECS=<n>` | Override default soak harness duration (`pixi run --environment bench bench-soak-*`) |

`ServerConfig` constants (compile-time defaults, override per-server):
`max_header_size` (16 KiB), `max_body_size` (1 MiB), `max_keepalive_requests`
(1000), `idle_timeout_ms` (30_000), `request_timeout_ms`,
`handler_timeout_ms`, `body_read_timeout_ms`. Build-time invariants
(e.g. `max_body_size >= max_header_size`) are checked by Mojo
`comptime assert` when used with `serve_comptime[handler, config]`.

## Stability

The public Mojo API is stable within a minor version: patch releases
never break source for the same minor. Breaking changes only land at
minor bumps. Internal types (anything in `_*.mojo`, or anything in
`flare.runtime.*` not re-exported from the package barrel) carry no
stability guarantee.

## Testing and fuzz coverage

| | Count |
|---|---|
| Unit + integration tests | 600+ across `tests/` |
| Examples (each part of `pixi run tests`) | 40+ under [`examples/`](../examples/) |
| Fuzz harnesses | 24 under [`fuzz/`](../fuzz/), 5.4M+ runs combined, zero known crashes |
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
| RFC 8441 Extended CONNECT | `fuzz-extended-connect` |
| HTTP/2 preface peek | `fuzz-h2-preface-peek` |
| HAProxy PROXY v1 + v2 | `fuzz-proxy-protocol` |
| io_uring SQE / CQE codec | `fuzz-io-uring-sqe` |
| io_uring reactor cancel-surface | `fuzz-uring-reactor` |
