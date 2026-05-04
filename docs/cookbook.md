# Cookbook

One-line index of `examples/NN_*.mojo`. Each example is run as part
of `pixi run tests` and on CI, so they stay green with the code.
Every example is a single self-contained file: clone, run, see what
changes when you tweak it.

| File | What it shows |
|---|---|
| [`01_addresses.mojo`](../examples/01_addresses.mojo) | `IpAddr`, `SocketAddr`, v4 / v6 classification |
| [`02_dns_resolution.mojo`](../examples/02_dns_resolution.mojo) | `resolve()`, `resolve_v4()`, `resolve_v6()`, numeric-IP passthrough |
| [`03_error_handling.mojo`](../examples/03_error_handling.mojo) | typed error hierarchy and the context each error carries |
| [`04_tcp_echo.mojo`](../examples/04_tcp_echo.mojo) | `TcpListener` + `TcpStream` round-trip, TCP options |
| [`05_http_get.mojo`](../examples/05_http_get.mojo) | `HttpClient` GET / POST / PUT / PATCH / DELETE / HEAD |
| [`06_websocket_echo.mojo`](../examples/06_websocket_echo.mojo) | `WsClient` connect, send, receive |
| [`07_ergonomics.mojo`](../examples/07_ergonomics.mojo) | high-level requests-style API (`BufReader`, `WsMessage`, `Auth`) |
| [`08_http_server.mojo`](../examples/08_http_server.mojo) | `HttpServer` with routing, JSON responses, response helpers |
| [`09_ws_server.mojo`](../examples/09_ws_server.mojo) | `WsServer` handshake + frame loop |
| [`10_encoding.mojo`](../examples/10_encoding.mojo) | gzip / deflate compress and decompress |
| [`11_udp.mojo`](../examples/11_udp.mojo) | `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` |
| [`12_tls.mojo`](../examples/12_tls.mojo) | `TlsConfig`, `TlsStream.connect`, raw TLS handshake + GET |
| [`13_cookies.mojo`](../examples/13_cookies.mojo) | `Cookie`, `CookieJar`, `parse_cookie_header`, `parse_set_cookie_header` |
| [`14_reactor.mojo`](../examples/14_reactor.mojo) | direct `flare.runtime.Reactor` usage for custom protocols |
| [`15_router.mojo`](../examples/15_router.mojo) | `Router` with path parameters, method dispatch, 404 / 405 |
| [`16_state.mojo`](../examples/16_state.mojo) | `App[Counters]` + typed `State[T]` injected into a middleware handler |
| [`17_multicore.mojo`](../examples/17_multicore.mojo) | `HttpServer.serve(..., num_workers=default_worker_count())` |
| [`18_middleware.mojo`](../examples/18_middleware.mojo) | Middleware composition: `Logger` wraps `RequireAuth` wraps `Router` |
| [`19_extractors.mojo`](../examples/19_extractors.mojo) | Typed extractors: `Path[T, name]`, `Query`, `Header`, `Json`, and reflective `Extracted[H]` auto-injection |
| [`20_comptime_router.mojo`](../examples/20_comptime_router.mojo) | `ComptimeRouter[routes]` with comptime segment parsing and per-route dispatch unroll |
| [`21_static_response.mojo`](../examples/21_static_response.mojo) | Pre-encoded `StaticResponse` + `HttpServer.serve_static` fast path |
| [`22_cancel.mojo`](../examples/22_cancel.mojo) | `CancelHandler` polling `cancel.cancelled()` between expensive steps |
| [`23_drain.mojo`](../examples/23_drain.mojo) | `HttpServer.drain(timeout_ms)` + `install_drain_on_sigterm` |
| [`24_sse.mojo`](../examples/24_sse.mojo) | Streaming response body via `ChunkSource` (Server-Sent Events shape) |
| [`25_cert_reload.mojo`](../examples/25_cert_reload.mojo) | `TlsAcceptor.reload()` for ACME / Let's Encrypt cert rotation without restart |
| [`26_mtls.mojo`](../examples/26_mtls.mojo) | mTLS configuration + construction-time validation |
| [`27_request_cookies.mojo`](../examples/27_request_cookies.mojo) | Reading inbound `Cookie:` headers + the `Cookies` extractor |
| [`28_forms.mojo`](../examples/28_forms.mojo) | `application/x-www-form-urlencoded` parsing + the `Form` extractor |
| [`29_multipart_upload.mojo`](../examples/29_multipart_upload.mojo) | `multipart/form-data` (file uploads) + the `Multipart` extractor |
| [`30_sessions.mojo`](../examples/30_sessions.mojo) | Typed `Session[T]` over `CookieSessionStore` (HMAC-SHA256 signed) |
| [`31_middleware_stack.mojo`](../examples/31_middleware_stack.mojo) | `Logger` + `RequestId` + `Compress` + `CatchPanic` chain |
| [`32_cors.mojo`](../examples/32_cors.mojo) | `Cors` permissive vs allowlist + preflight + credentials |
| [`33_static_files.mojo`](../examples/33_static_files.mojo) | `FileServer` with HEAD + Range + path safety |
| [`34_brotli.mojo`](../examples/34_brotli.mojo) | `compress_brotli` / `decompress_brotli` + `Compress` middleware emitting `br` |
| [`35_http2.mojo`](../examples/35_http2.mojo) | `H2Connection` driver, ALPN dispatch, h2c upgrade detection |
| [`36_work_stealing.mojo`](../examples/36_work_stealing.mojo) | `HandoffQueue` + `WorkerHandoffPool` + `FLARE_SOAK_WORKERS` knob |
| [`37_http2_config.mojo`](../examples/37_http2_config.mojo) | `Http2Config` SETTINGS knobs + validation |
| [`38_uds_sidecar.mojo`](../examples/38_uds_sidecar.mojo) | `UnixListener` / `UnixStream` AF_UNIX sidecar IPC |
| [`39_iouring_plaintext.mojo`](../examples/39_iouring_plaintext.mojo) | `io_uring` reactor backend (Linux ≥ 5.10) |
| [`40_http2_client.mojo`](../examples/40_http2_client.mojo) | `HttpClient(prefer_h2c=True)` GET + POST over h2c (cleartext HTTP/2 via prior knowledge) |
| [`41_http2_server_router.mojo`](../examples/41_http2_server_router.mojo) | Path-dispatching handler served over HTTP/2 via the unified `HttpServer.serve(handler)` (auto-dispatches HTTP/1.1 + HTTP/2 on the same port) |

Run any single example with `pixi run example-<name>`; see the full
list in [`pixi.toml`](../pixi.toml).

---

## "I want to..." quick links

| Goal | Start here |
|---|---|
| Serve hello-world | [`08_http_server.mojo`](../examples/08_http_server.mojo) |
| Add a route with a parameter | [`15_router.mojo`](../examples/15_router.mojo) |
| Pass typed inputs to a handler | [`19_extractors.mojo`](../examples/19_extractors.mojo) |
| Share state across handlers | [`16_state.mojo`](../examples/16_state.mojo) |
| Stack middleware | [`18_middleware.mojo`](../examples/18_middleware.mojo) |
| Scale to all cores | [`17_multicore.mojo`](../examples/17_multicore.mojo) |
| Skip the parser entirely | [`21_static_response.mojo`](../examples/21_static_response.mojo) |
| Compile-time route table | [`20_comptime_router.mojo`](../examples/20_comptime_router.mojo) |
| Detect mid-handler client disconnect | [`22_cancel.mojo`](../examples/22_cancel.mojo) |
| Drain on SIGTERM | [`23_drain.mojo`](../examples/23_drain.mojo) |
| Stream a response body / SSE | [`24_sse.mojo`](../examples/24_sse.mojo) |
| Reload a TLS cert without restart | [`25_cert_reload.mojo`](../examples/25_cert_reload.mojo) |
| Configure mTLS | [`26_mtls.mojo`](../examples/26_mtls.mojo) |
| Make HTTP requests | [`05_http_get.mojo`](../examples/05_http_get.mojo) |
| Talk WebSocket | [`06_websocket_echo.mojo`](../examples/06_websocket_echo.mojo) |
| Manage cookies | [`13_cookies.mojo`](../examples/13_cookies.mojo) |
| Drive the reactor directly | [`14_reactor.mojo`](../examples/14_reactor.mojo) |
| Use TLS as a client | [`12_tls.mojo`](../examples/12_tls.mojo) |
| Read inbound cookies | [`27_request_cookies.mojo`](../examples/27_request_cookies.mojo) |
| Parse a form POST | [`28_forms.mojo`](../examples/28_forms.mojo) |
| Accept file uploads | [`29_multipart_upload.mojo`](../examples/29_multipart_upload.mojo) |
| Use signed-cookie sessions | [`30_sessions.mojo`](../examples/30_sessions.mojo) |
| Stack `Logger` / `RequestId` / `Compress` / `CatchPanic` | [`31_middleware_stack.mojo`](../examples/31_middleware_stack.mojo) |
| Configure CORS | [`32_cors.mojo`](../examples/32_cors.mojo) |
| Serve static files (with `Range`) | [`33_static_files.mojo`](../examples/33_static_files.mojo) |
| Send `Content-Encoding: br` | [`34_brotli.mojo`](../examples/34_brotli.mojo) |
| Drive HTTP/2 directly | [`35_http2.mojo`](../examples/35_http2.mojo) |
| Tune HTTP/2 SETTINGS | [`37_http2_config.mojo`](../examples/37_http2_config.mojo) |
| Make HTTP/2 client requests (h2c + h2-over-TLS) | [`40_http2_client.mojo`](../examples/40_http2_client.mojo) |
| Serve a Router over HTTP/2 | [`41_http2_server_router.mojo`](../examples/41_http2_server_router.mojo) |
| AF_UNIX sidecar IPC | [`38_uds_sidecar.mojo`](../examples/38_uds_sidecar.mojo) |
| io_uring reactor backend | [`39_iouring_plaintext.mojo`](../examples/39_iouring_plaintext.mojo) |
| Even out skewed-keepalive load | [`36_work_stealing.mojo`](../examples/36_work_stealing.mojo) |
