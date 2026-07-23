# Cookbook

Examples are organised under [`examples/`](../examples/) into three
tiers — **basic**, **intermediate**, and **advanced**. Each example
is a single self-contained file: clone, run, see what changes when
you tweak it. Every example is part of `pixi run tests` and runs on
CI, so they stay green with the code. Run any single example with
`pixi run example-<name>` (see [`pixi.toml`](../pixi.toml) for the
full task list).

## Basic — networking primitives, hello-world HTTP, simple WS

The "first ten minutes with flare" surface. Plain functions, no
typed extractors, no middleware composition. If you're skimming to
see whether the framework feels right, start here.

| File | What it shows |
|---|---|
| [`addresses.mojo`](../examples/basic/addresses.mojo) | `IpAddr`, `SocketAddr`, v4 / v6 classification |
| [`dns_resolution.mojo`](../examples/basic/dns_resolution.mojo) | `resolve()`, `resolve_v4()`, `resolve_v6()`, numeric-IP passthrough |
| [`error_handling.mojo`](../examples/basic/error_handling.mojo) | typed error hierarchy and the context each error carries |
| [`tcp_echo.mojo`](../examples/basic/tcp_echo.mojo) | `TcpListener` + `TcpStream` round-trip, TCP options |
| [`udp.mojo`](../examples/basic/udp.mojo) | `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` |
| [`encoding.mojo`](../examples/basic/encoding.mojo) | gzip / deflate compress and decompress |
| [`tls.mojo`](../examples/basic/tls.mojo) | `TlsConfig`, `TlsStream.connect`, raw TLS handshake + GET |
| [`http_get.mojo`](../examples/basic/http_get.mojo) | `HttpClient` GET / POST / PUT / PATCH / DELETE / HEAD |
| [`websocket_echo.mojo`](../examples/basic/websocket_echo.mojo) | `WsClient` connect, send, receive |
| [`ergonomics.mojo`](../examples/basic/ergonomics.mojo) | high-level requests-style API (`BufReader`, `WsMessage`, `Auth`) |
| [`http_server.mojo`](../examples/basic/http_server.mojo) | `HttpServer` with routing, JSON responses, response helpers |
| [`router.mojo`](../examples/basic/router.mojo) | `Router` with path parameters, method dispatch, 404 / 405 |
| [`ws_server.mojo`](../examples/basic/ws_server.mojo) | `WsServer` handshake + frame loop |
| [`cookies.mojo`](../examples/basic/cookies.mojo) | `Cookie`, `CookieJar`, `parse_cookie_header`, `parse_set_cookie_header` |

## Intermediate — building a real app

Typed extractors, shared state, middleware composition, sessions,
forms, multipart uploads, content-encoding negotiation, CORS,
static files, Server-Sent Events. The next 30 minutes after the
basics.

| File | What it shows |
|---|---|
| [`extractors.mojo`](../examples/intermediate/extractors.mojo) | Typed extractors (`PathInt`, `QueryStr`, `HeaderStr`, ...), reflective `Extracted[H]` auto-injection, and `State[T]` registration-time injection alongside request extractors |
| [`typed_extractors.mojo`](../examples/intermediate/typed_extractors.mojo) | `OptionalPath{Int,Str,Float,Bool}` optional path params + `JsonAs[T: FromJson]` typed-body deserialization |
| [`state.mojo`](../examples/intermediate/state.mojo) | Shared application state via a captured wrapping `Handler` (a `Counters` snapshot tagged onto responses) -- the no-injection pattern; for injected state beside extractors see `State[T]` in `extractors.mojo` |
| [`middleware.mojo`](../examples/intermediate/middleware.mojo) | Middleware composition (outside-in): `RequestID` → `Logger` → `Timing` → `Recover` → `RequireAuth` → `Router` |
| [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) | `Logger` + `RequestId` + `Compress` + `CatchPanic` chain |
| [`multicore.mojo`](../examples/intermediate/multicore.mojo) | `HttpServer.serve(..., num_workers=default_worker_count())` |
| [`static_response.mojo`](../examples/intermediate/static_response.mojo) | Pre-encoded `StaticResponse` + `HttpServer.serve_static` fast path |
| [`cancel.mojo`](../examples/intermediate/cancel.mojo) | `CancelHandler` polling `cancel.cancelled()` between expensive steps |
| [`drain.mojo`](../examples/intermediate/drain.mojo) | `HttpServer.drain(timeout_ms)` per-worker (caller wires SIGTERM today) |
| [`sse.mojo`](../examples/intermediate/sse.mojo) | Streaming response body via `ChunkSource` (Server-Sent Events shape) |
| [`response_from_body.mojo`](../examples/intermediate/response_from_body.mojo) | Opt-in `Response[B: Body]` ergonomics via `response_from_body` (buffered `InlineBody` + chunk-streamed `ChunkedBody` over a forked server) |
| [`request_cookies.mojo`](../examples/intermediate/request_cookies.mojo) | Reading inbound `Cookie:` headers + the `Cookies` extractor |
| [`forms.mojo`](../examples/intermediate/forms.mojo) | `application/x-www-form-urlencoded` parsing + the `Form` extractor |
| [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo) | `multipart/form-data` (file uploads) + the `Multipart` extractor |
| [`sessions.mojo`](../examples/intermediate/sessions.mojo) | Typed `Session[T]` over `CookieSessionStore` (HMAC-SHA256 signed) |
| [`cors.mojo`](../examples/intermediate/cors.mojo) | `Cors` permissive vs allowlist + preflight + credentials |
| [`static_files.mojo`](../examples/intermediate/static_files.mojo) | `FileServer` with HEAD + Range + path safety |
| [`brotli.mojo`](../examples/intermediate/brotli.mojo) | `compress_brotli` / `decompress_brotli` + `Compress` middleware emitting `br` |
| [`ok_json_typed.mojo`](../examples/intermediate/ok_json_typed.mojo) | Typed JSON request → typed JSON response via `ok_json_value` |
| [`infallible_handler.mojo`](../examples/intermediate/infallible_handler.mojo) | `HandlerInfallible` + `WithRaises` adapter for provably no-`raises` paths |
| [`trailers.mojo`](../examples/intermediate/trailers.mojo) | HTTP/1.1 trailer fields (gRPC-style status trailer): `Response.trailers`, `Trailer:` header, smuggling guard |
| [`multi_listener.mojo`](../examples/intermediate/multi_listener.mojo) | `HttpServer.bind_many` over multiple distinct addresses, single accept loop |
| [`reliability.mojo`](../examples/intermediate/reliability.mojo) | `Retry[Inner]` + `PostHocDeadline[Inner]` + `RetryPolicy` -- RFC 9110 §9.2.2 idempotent-method gate (GET / HEAD / PUT / DELETE / OPTIONS), opt-in exponential backoff with jitter (`backoff_base_ms` / `backoff_max_ms` / `backoff_jitter_ms`), post-hoc 504 wall-clock guard |
| [`http_cache.mojo`](../examples/intermediate/http_cache.mojo) | `Cache[Inner, S]` middleware over an `InMemoryCacheStore` -- RFC 9111 freshness check on `CacheEntry.is_fresh`, `Vary`-aware secondary key, conditional revalidation (`If-None-Match` / `If-Modified-Since` + 304 folding back into the cached entry) |
| [`template_inheritance.mojo`](../examples/intermediate/template_inheritance.mojo) | Single-level template inheritance: parent layout + child overrides via `{% block %}` / `{% extends %}` / `Template.render_extending` |

## Advanced — comptime, low-level reactor, HTTP/2, mTLS, work-stealing

The Mojo-unique surfaces (compile-time route tables, direct
reactor primitives, `io_uring`), HTTP/2-specific dispatch, mTLS,
ACME-style cert reload, AF_UNIX sidecar IPC, multi-worker
handoff. Don't reach for these until the intermediate tier feels
natural.

| File | What it shows |
|---|---|
| [`comptime_router.mojo`](../examples/advanced/comptime_router.mojo) | `ComptimeRouter[routes]` with comptime segment parsing and per-route dispatch unroll |
| [`reactor.mojo`](../examples/advanced/reactor.mojo) | direct `flare.runtime.Reactor` usage for custom protocols |
| [`work_stealing.mojo`](../examples/advanced/work_stealing.mojo) | `HandoffQueue` + `WorkerHandoffPool` + `FLARE_SOAK_WORKERS` knob |
| [`uds_sidecar.mojo`](../examples/advanced/uds_sidecar.mojo) | `UnixListener` / `UnixStream` AF_UNIX sidecar IPC |
| [`streaming_proxy.mojo`](../examples/advanced/streaming_proxy.mojo) | streaming-proxy surface: `StreamHandler` + `attach_upstream(UpstreamChunkSource)` + `relay_upstream()` over `serve_streaming`, relaying a `FrameMux` backend with watermark backpressure, no fd, no `Span`, no per-connection table in front code |
| [`cert_reload.mojo`](../examples/advanced/cert_reload.mojo) | `TlsAcceptor.reload()` for ACME / Let's Encrypt cert rotation without restart |
| [`mtls.mojo`](../examples/advanced/mtls.mojo) | mTLS configuration + construction-time validation |
| [`https_server.mojo`](../examples/advanced/https_server.mojo) | In-process HTTPS server: `HttpServer.bind_tls` / `serve_tls` (TLS-terminated HTTP/1.1) with a buffered handler and a `stream_response` chunked body over `SSL_write` |
| [`http2.mojo`](../examples/advanced/http2.mojo) | `Http2Connection` driver, ALPN dispatch, h2c upgrade detection |
| [`http2_config.mojo`](../examples/advanced/http2_config.mojo) | `Http2Config` SETTINGS knobs + validation |
| [`http2_client.mojo`](../examples/advanced/http2_client.mojo) | `HttpClient(prefer_h2c=True)` GET + POST over h2c (cleartext HTTP/2 via prior knowledge) |
| [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) | Path-dispatching handler served over HTTP/2 via the unified `HttpServer.serve(handler)` (auto-dispatches HTTP/1.1 + HTTP/2 on the same port) |
| [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo) | HTTP/2 cleartext client via the `Upgrade: h2c` + `HTTP2-Settings` dance (RFC 7540 §3.2): first request flows over h1 then carries forward to h2 |
| [`client_pool.mojo`](../examples/advanced/client_pool.mojo) | `HttpClient.with_pool` — keyed idle reuse, per-origin caps, stale-conn retry |
| [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo) | RFC 8441 WebSockets-over-HTTP/2 (Extended CONNECT + `:protocol=websocket`) |
| [`ws_permessage_deflate.mojo`](../examples/advanced/ws_permessage_deflate.mojo) | RFC 7692 `permessage-deflate` extension: offer / negotiate / compress / decompress |
| [`alpn_dispatch_demo.mojo`](../examples/advanced/alpn_dispatch_demo.mojo) | ALPN -> wire-protocol dispatcher decisions: h1 / h2c / h2 / h3, including RFC 7301 §3.2 server-preference negotiation |
| [`http3_server.mojo`](../examples/advanced/http3_server.mojo) | Serve the same `Handler` over HTTP/1.1 + HTTP/2 + HTTP/3 simultaneously: TCP listener for h1 / h2c / h2 alongside a UDP listener for h3 |
| [`http3_client.mojo`](../examples/advanced/http3_client.mojo) | `HttpClient(prefer_http3=True)` live HTTP/3 GET over QUIC: Alt-Svc discovery, happy-eyeballs race vs h2 / h1, transparent fallback |
| [`http3_server_walkthrough.mojo`](../examples/advanced/http3_server_walkthrough.mojo) | `Http3Connection` driver lifecycle walkthrough (pure state-machine surface; pairs with `http3_server.mojo`) |
| [`quic_codec_demo.mojo`](../examples/advanced/quic_codec_demo.mojo) | QUIC varint / frame codec / transport params / state machine / congestion controller round-trips |
| [`h3_codec_demo.mojo`](../examples/advanced/h3_codec_demo.mojo) | HTTP/3 codec round-trip without a QUIC stream: QPACK field sections + RFC 9114 §7 frame codec + request reader |
| [`quic_handler_dispatch.mojo`](../examples/advanced/quic_handler_dispatch.mojo) | RFC 9000 §19 transport-frame dispatch via `FrameHandler` + `parse_frame_into` (per-type callbacks, no union carrier) |
| [`grpc_unary_server.mojo`](../examples/advanced/grpc_unary_server.mojo) | Reactor-mounted gRPC unary server: a `GrpcService` served over the unified `HttpServer` H2 reactor, `grpc-status` in H2 trailers |
| [`grpc_unary_demo.mojo`](../examples/advanced/grpc_unary_demo.mojo) | Sans-I/O gRPC unary adapter (no socket): LPM framing + metadata + status + `run_unary_call` orchestration |
| [`grpc_client_demo.mojo`](../examples/advanced/grpc_client_demo.mojo) | `GrpcClient` unary RPC over the `HttpClient` HTTP/2 path (h2c), against a forked gRPC-speaking server |
| [`openai_sse_front.mojo`](../examples/advanced/openai_sse_front.mojo) | OpenAI-shaped `chat.completion.chunk` SSE front relaying an upstream token stream over `UpstreamChunkSource` / `FrameMux` with watermark backpressure |
| [`unified_middleware.mojo`](../examples/advanced/unified_middleware.mojo) | One `Logger(RequestId(Router))` middleware stack shared across both a `Handler` control plane and a `StreamHandler` streaming endpoint |
| [`production_setup.mojo`](../examples/advanced/production_setup.mojo) | Production-shaped server: `RequestId` + `StructuredLogger` + `CatchPanic` + graceful shutdown + healthz |

---

## "I want to..." quick links

| Goal | Start here |
|---|---|
| Serve hello-world | [`http_server.mojo`](../examples/basic/http_server.mojo) |
| Add a route with a parameter | [`router.mojo`](../examples/basic/router.mojo) |
| Make HTTP requests | [`http_get.mojo`](../examples/basic/http_get.mojo) |
| Talk WebSocket | [`websocket_echo.mojo`](../examples/basic/websocket_echo.mojo) |
| Use TLS as a client | [`tls.mojo`](../examples/basic/tls.mojo) |
| Manage cookies | [`cookies.mojo`](../examples/basic/cookies.mojo) |
| Pass typed inputs to a handler | [`extractors.mojo`](../examples/intermediate/extractors.mojo) |
| Share state across handlers | [`state.mojo`](../examples/intermediate/state.mojo) |
| Stack middleware | [`middleware.mojo`](../examples/intermediate/middleware.mojo) |
| Stack `Logger` / `RequestId` / `Compress` / `CatchPanic` | [`middleware_stack.mojo`](../examples/intermediate/middleware_stack.mojo) |
| Scale to all cores | [`multicore.mojo`](../examples/intermediate/multicore.mojo) |
| Skip the parser entirely | [`static_response.mojo`](../examples/intermediate/static_response.mojo) |
| Detect mid-handler client disconnect | [`cancel.mojo`](../examples/intermediate/cancel.mojo) |
| Drain on SIGTERM | [`drain.mojo`](../examples/intermediate/drain.mojo) |
| Stream a response body / SSE | [`sse.mojo`](../examples/intermediate/sse.mojo) |
| Read inbound cookies | [`request_cookies.mojo`](../examples/intermediate/request_cookies.mojo) |
| Parse a form POST | [`forms.mojo`](../examples/intermediate/forms.mojo) |
| Accept file uploads | [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo) |
| Use signed-cookie sessions | [`sessions.mojo`](../examples/intermediate/sessions.mojo) |
| Configure CORS | [`cors.mojo`](../examples/intermediate/cors.mojo) |
| Serve static files (with `Range`) | [`static_files.mojo`](../examples/intermediate/static_files.mojo) |
| Send `Content-Encoding: br` | [`brotli.mojo`](../examples/intermediate/brotli.mojo) |
| Return a typed JSON response | [`ok_json_typed.mojo`](../examples/intermediate/ok_json_typed.mojo) |
| Use a no-`raises` handler | [`infallible_handler.mojo`](../examples/intermediate/infallible_handler.mojo) |
| Compile-time route table | [`comptime_router.mojo`](../examples/advanced/comptime_router.mojo) |
| Drive the reactor directly | [`reactor.mojo`](../examples/advanced/reactor.mojo) |
| Reload a TLS cert without restart | [`cert_reload.mojo`](../examples/advanced/cert_reload.mojo) |
| Configure mTLS | [`mtls.mojo`](../examples/advanced/mtls.mojo) |
| Drive HTTP/2 directly | [`http2.mojo`](../examples/advanced/http2.mojo) |
| Tune HTTP/2 SETTINGS | [`http2_config.mojo`](../examples/advanced/http2_config.mojo) |
| Make HTTP/2 client requests (h2c via prior knowledge; `https://` auto-negotiates h2 vs h1.1 via ALPN) | [`http2_client.mojo`](../examples/advanced/http2_client.mojo) |
| Serve HTTP/1.1 + HTTP/2 from one port | [`http2_server_router.mojo`](../examples/advanced/http2_server_router.mojo) |
| AF_UNIX sidecar IPC | [`uds_sidecar.mojo`](../examples/advanced/uds_sidecar.mojo) |
| Proxy an external producer's stream with end-to-end backpressure | [`streaming_proxy.mojo`](../examples/advanced/streaming_proxy.mojo) |
| Even out skewed-keepalive load | [`work_stealing.mojo`](../examples/advanced/work_stealing.mojo) |
| Emit gRPC-style HTTP/1.1 trailers | [`trailers.mojo`](../examples/intermediate/trailers.mojo) |
| Bind a single worker on multiple addresses | [`multi_listener.mojo`](../examples/intermediate/multi_listener.mojo) |
| Speak h2c via the `Upgrade` dance from a client | [`h2c_client.mojo`](../examples/advanced/h2c_client.mojo) |
| Reuse h1.1 connections via `HttpClient.with_pool` | [`client_pool.mojo`](../examples/advanced/client_pool.mojo) |
| Tunnel WebSockets over HTTP/2 (RFC 8441) | [`ws_over_h2.mojo`](../examples/advanced/ws_over_h2.mojo) |
| Compress WebSocket payloads with `permessage-deflate` | [`ws_permessage_deflate.mojo`](../examples/advanced/ws_permessage_deflate.mojo) |
| Stand up a production-shaped server (RequestId + structured logs + graceful shutdown + healthz) | [`production_setup.mojo`](../examples/advanced/production_setup.mojo) |
| Reuse markup via template inheritance (`{% block %}` / `{% extends %}`) | [`template_inheritance.mojo`](../examples/intermediate/template_inheritance.mojo) |
| Retry idempotent requests + bound handler latency | [`reliability.mojo`](../examples/intermediate/reliability.mojo) |
| Cache GET responses with RFC 9111 freshness + revalidation | [`http_cache.mojo`](../examples/intermediate/http_cache.mojo) |
| Route inbound TLS connections to h1 / h2 / h3 by ALPN | [`alpn_dispatch_demo.mojo`](../examples/advanced/alpn_dispatch_demo.mojo) |
| Serve HTTP/3 alongside HTTP/1.1 + HTTP/2 on the same Handler | [`http3_server.mojo`](../examples/advanced/http3_server.mojo) |
| Pick the WebSocket carrier wire by negotiated ALPN | `flare.ws.WsAutoClient` + `flare.ws.decide_wire` (`tests/ws/test_ws_autoclient.mojo`) |

## Reading data from a `Request`

flare exposes inbound request data through a layered surface — the
right shape depends on whether you want a plain field, a parsed
primitive, or a typed struct populated by the request as a whole.
The table below is the canonical reference; pick the cheapest shape
that gets you the value you need.

| Shape | What you get | Example | When to reach for it |
|---|---|---|---|
| **Plain field access** | The raw string / bytes / list / `HeaderMap` directly off `Request` | `req.method`, `req.url`, `req.body`, `req.headers`, `req.peer`, `req.version` | You want the wire-level value as the parser saw it. No copying, no extraction. |
| **Path params** | Value matched by a Router path segment (`:name`) | `req.param("id") raises -> String`, `req.has_param`, `req.params_mut()["id"] = ...` | The URL path itself carries the value. `param` raises if the segment didn't match (use `has_param` to peek). |
| **Query params** | Single value from the URL's query string | `req.query_param("k") -> String` (returns `""` if missing), `req.has_query_param` | Querystring `?k=v` style data; return-value-on-miss makes one-line reads natural. |
| **Cookies** | Inbound `Cookie` header parsed into name/value pairs | `req.cookies() -> CookieJar`, `req.cookie("name") -> String` (returns `""` if missing), `req.has_cookie` | Inspecting an inbound `Cookie` header directly. For typed extraction prefer the `Cookies` extractor. |
| **Body decoding** | Body interpreted as text / JSON / raw bytes | `req.text() -> String`, `req.json() raises -> json.Value`, `req.body: List[UInt8]` | Reading the body opportunistically inside a handler without an extractor. |
| **`*.extract(req)` extractors** | Typed value from the body or a header set | `Form.extract(req) -> Form`, `Multipart.extract(req) -> MultipartForm`, `Cookies.extract(req) -> Cookies` | Hand-written extractor pipeline; reach for this when the auto-injection adapter is overkill but you still want typed parsing. |
| **Comptime-keyed extractors** | Single typed primitive keyed at compile time | `PathInt["id"]`, `QueryStr["q"]`, `OptionalQueryInt["page"]`, `HeaderStr["Authorization"]`, `Json[T]` | Building blocks for the auto-injection shape (next row); each one is a `Defaultable` struct with a `value` field. |
| **`Extracted[H]` auto-injection** | A handler struct whose fields are the extractor set; the adapter walks the field list per request and populates each | `r.get("/users/:id", Extracted[GetUser]())` where `GetUser(HandlerExtractor)` declares `id: PathInt["id"]` etc. | Production handler shape: declarative, typed, monomorphised. The adapter raises 400 with the parser error on extractor failure; `serve` raises propagate to 500. |

Examples that exercise each shape, in order: the [`router.mojo`](../examples/basic/router.mojo)
example covers plain field + path param shapes; [`request_cookies.mojo`](../examples/intermediate/request_cookies.mojo)
walks the cookie surface; [`forms.mojo`](../examples/intermediate/forms.mojo)
and [`multipart_upload.mojo`](../examples/intermediate/multipart_upload.mojo)
use the `*.extract(req)` extractors; [`extractors.mojo`](../examples/intermediate/extractors.mojo)
and [`ok_json_typed.mojo`](../examples/intermediate/ok_json_typed.mojo)
show comptime-keyed extractors and the `Extracted[H]` auto-injection
adapter.
