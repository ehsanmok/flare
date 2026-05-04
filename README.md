<p align="center">
  <img src="./logo.png" alt="flare" width="280">
</p>

<h1 align="center">flare</h1>

<p align="center">
  <a href="https://github.com/ehsanmok/flare/actions/workflows/ci.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml/badge.svg?branch=main&event=workflow_dispatch" alt="Fuzz"></a>
  <a href="https://ehsanmok.github.io/flare/"><img src="https://github.com/ehsanmok/flare/actions/workflows/docs.yaml/badge.svg?branch=main" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

A Mojo HTTP server (HTTP/1.1 + HTTP/2) you can put in front of users, an HTTP client (HTTP/1.1 + HTTP/2 over h2c or TLS-ALPN h2), and the raw TCP, UDP, TLS, DNS, and WebSocket (server + client) primitives it's all built on. One reactor per worker (`kqueue` on macOS, `epoll` on Linux with `EPOLLEXCLUSIVE` shared listener for multi-worker), a per-connection state machine, an RFC 7230 parser with extensive fuzz coverage, and a `Handler` trait that takes plain `def` functions or compiled-down structs.

```mojo
from flare import HttpServer, Router, Request, Response, ok, SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=4)
```

The bar isn't "is it fast", it's *is it hard to misuse under load and easy to operate*.

## Features

- **Full networking stack — one `HttpClient`, one `HttpServer`, version-aware**: a single `flare.http.HttpServer.serve(handler, num_workers=N)` accept loop auto-dispatches HTTP/1.1 and HTTP/2 per accepted connection (cleartext preface peek + ALPN `h2` for TLS), and a single `flare.http.HttpClient` advertises ALPN `["h2", "http/1.1"]` for `https://` URLs (or speaks h2c via prior knowledge with `prefer_h2c=True`). Same `Router` / `App[S]` / middleware / typed extractors / `Auth` work unchanged on both wires. WebSocket (RFC 6455, client + server), TLS 1.2/1.3 (client + server, OpenSSL with ALPN both directions), TCP, UDP, DNS, all layered so each module imports only from below.
- **One reactor per worker** (`kqueue` on macOS, `epoll` on Linux + `EPOLLEXCLUSIVE` shared listener) with a per-connection state machine + timer wheel; **thread-per-core** via `HttpServer.serve(handler, num_workers=N)`. Optional cross-worker `WorkerHandoffPool` (`FLARE_SOAK_WORKERS=on`) for skewed-keepalive workloads.
- **Composable handlers**: `Handler` trait, `Router` with path params, `App[S]` for shared state, typed extractors (`PathInt` / `QueryInt` / `HeaderStr` / `Form` / `Multipart` / `Cookies` / ...), middleware stack (`Logger`, `RequestId`, `Compress`, `CatchPanic`), `Cors`, `FileServer` with HEAD + Range; `ComptimeRouter[ROUTES]` unrolls dispatch at compile time.
- **Same handler runs on HTTP/1.1 + HTTP/2**: every higher-level construct (Router, middleware, extractors, sessions, content negotiation) operates on `Request` / `Response`, so the unified `HttpServer.serve(handler)` loop dispatches both wires through the same handler with no protocol-aware code in the application.
- **Sessions + signed cookies**: HMAC-SHA256 (`flare.crypto`) under typed `Session[T]` with `CookieSessionStore` + `InMemorySessionStore` and the `signed_cookie_*` lower-level codec.
- **Content negotiation**: gzip + brotli content-encoding (RFC 9110 §12.5.3 q-value parser), urlencoded + multipart form parsing, RFC 6265 cookie jars, RFC 9110 Range support.
- **Streaming + push**: first-class Server-Sent Events (`SseChannel` / `SseEvent` / `sse_response` / `SseStreamingResponse`), inbound streaming bodies via `RequestChunkSource`, outbound `StreamingResponse[B]` with backpressure.
- **Edge / proxy ready**: HAProxy PROXY protocol v1 + v2 parser (`flare.http.parse_proxy_protocol`, fuzz-clean over 200K runs); `UnixListener` / `UnixStream` AF_UNIX subsystem under `flare.uds` for sidecar IPC; RFC 9110 §13 `Conditional[Inner]` middleware (`If-Match` / `If-None-Match` / `If-Modified-Since` / `If-Unmodified-Since` → 304/412); client-side `RedirectPolicy` (`FOLLOW_ALL` / `SAME_ORIGIN_ONLY` / `DENY`).
- **Auth + CSRF batteries**: client-side `BasicAuth` / `BearerAuth` (`HttpClient(BasicAuth(...))` works on both wires); server-side `BearerExtract` / `BasicExtract` typed extractors; double-submit-cookie `CsrfToken` with constant-time comparator.
- **Observability**: JSON-per-line `StructuredLogger[Inner]` for Datadog / Loki / Splunk; `Metrics[Inner]` + Prometheus text exposition (counter / histogram / gauge); askama-shape `Template` engine (`{{ var }}`, `{% if %}`, `{% for %}`, OWASP HTML escape) for human-facing pages.
- **Production hygiene**: per-request `Cancel` token (peer FIN, timeout, drain unified), server-side TLS with cert reload + mTLS + ALPN, sanitised 4xx/5xx, graceful drain with per-worker `ShutdownReport`s, 24 h soak harness, **24 fuzz harnesses (5.4M+ runs, zero known crashes)** including the new RFC 8441 Extended CONNECT dispatch and the unified server's preface-peek classifier.

## Numbers

TFB plaintext (`GET /plaintext` → 13-byte `Hello, World!`), `wrk2 -t8 -c256 -d12s --latency` (coordinated-omission corrected), Linux EPYC 7R32. Each row's `R=` is the highest sustained rate that holds p99.99 ≤ 5 ms (one step below the queue-overflow cliff).

| Server | Workers | Req/s (peak-sustainable) | p99 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **258,292** | **2.77** | **3.54** |
| actix_web (tokio) | 4 | 248,361 | 2.72 | 3.43 |
| **flare_mc** (handler) [^reuse] | **4** | **238,431** | **2.76** | **3.47** |
| hyper (tokio multi-thread) | 4 | 208,624 | 2.79 | 3.70 |
| axum (tokio multi-thread) | 4 | 189,953 | 2.69 | 3.74 |
| nginx (`worker_processes 1`) | 1 | 68,875 | 2.95 | 3.59 |
| **flare** (reactor) | **1** | **52,147** | **2.79** | **3.46** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 34,439 | 2.98 | 4.70 |

- **flare_mc_static beats actix_web** (+4 % req/s, **fastest** of the five 4-worker frameworks).
- **flare_mc handler beats hyper** (+14 %) **and axum** (+25 %) and is within 4 % of actix_web.
- **flare keeps a tight tail** at peak: 3.47 ms / 3.54 ms p99.99 vs actix_web 3.43, hyper 3.70, axum 3.74.
- **flare 1w** keeps the tightest p99.99 of the single-worker pack (3.46 ms vs nginx 3.59 / Go 4.70). Throughput: 76 % of nginx 1w and 1.51x Go 1w on this unpinned dev-box (88 % / 1.56x on the historical CPU-pinned reference).

Full methodology, the rate-sweep that locates each cliff, the historical CPU-pinned reference run, and reproducibility instructions are in [`docs/benchmark.md`](docs/benchmark.md).

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web's listener strategy). Set `FLARE_REUSEPORT_WORKERS=0` to opt back into the single-listener `EPOLLEXCLUSIVE` shape, which trades ~10 % req/s for an even tighter p99.99 (3.23 ms in the historical CPU-pinned reference). See [`docs/benchmark.md`](docs/benchmark.md) for both modes. Numbers above are from `mojo build -D ASSERT=none` (matches what production users should pass; see [Production build](#production-build)).

## Install

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "<latest-release>" }
```

```bash
pixi install
```

Requires [pixi](https://pixi.sh) (pulls Mojo nightly automatically). Released tags are listed on [GitHub Releases](https://github.com/ehsanmok/flare/releases). Pin to one for reproducible builds.

To track unreleased work (breaking changes possible between tags):

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## Quick start

The tour below grows the snippet at the top of this README out, one persona at a time. Each level adds roughly one concept; everything compiles, and the runnable equivalents live under [`examples/`](examples/) (every one is part of `pixi run tests`). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example, and the rendered package docstring is at <https://ehsanmok.github.io/flare/>.

### Beginner: your first router

Two routes, one with a path parameter, a JSON-shaped response. This is where most apps start: `def` handlers, a `Router`, `HttpServer.bind`, `num_workers`. No traits, no generics, no extractors yet.

```mojo
from flare import HttpServer, Router, Request, Response, ok, SocketAddr

def home(req: Request) raises -> Response:
    return ok("flare is up")

def greet(req: Request) raises -> Response:
    return ok("hello, " + req.param("name"))

def health(req: Request) raises -> Response:
    var resp = ok('{"status":"ok"}')
    resp.headers.set("Content-Type", "application/json")
    return resp^

def main() raises:
    var r = Router()
    r.get("/",           home)
    r.get("/hi/:name",   greet)
    r.get("/health",     health)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=4)
```

What you get for free: 404 on unknown paths, 405 with `Allow` on wrong method, sanitised 4xx / 5xx bodies, peer-FIN cancellation, RFC 7230 size limits, the per-worker reactor with `kqueue` / `epoll`.

For request bodies, query strings, cookies, sessions, multipart forms, gzip / brotli, TLS, HTTP/2, and WebSocket: all under [`examples/`](examples/) (`05_http_get`, `13_cookies`, `28_forms`, `29_multipart_upload`, `30_sessions`, `34_brotli`, `12_tls`, `35_http2`, `06_websocket_echo`).

### Intermediate: typed extractors

Once your handlers need to read structured input (path params as integers, query strings as bools, headers as strings), promote each `Handler` from a `def` into a struct whose fields *are* the inputs. `PathInt["id"]` / `PathStr` / `QueryInt` / `HeaderStr` / `Form[T]` / `Multipart` / `Cookies` / ... parse and validate at extraction time; `Extracted[H]` reflects on the struct's fields and pulls each one in before `serve` runs. Missing or malformed values become a 400 with a sanitised body, so your `serve` only sees well-typed values.

```mojo
from flare.http import (
    Router, ok, Request, Response, HttpServer,
    Extracted, PathInt, Handler,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]

    def __init__(out self):
        self.id = PathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user=" + String(self.id.value))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get[Extracted[GetUser]]("/users/:id", Extracted[GetUser]())
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

Middleware is the same shape: a `Handler` that wraps another `Handler`. The stock layers (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`, `FileServer`) all compose by nesting structs, no callback chain. `examples/18_middleware.mojo` walks through the production-shaped pipeline (`RequestID → Logger → Timing → Recover → RequireAuth → Router`).

### Advanced: compile-time dispatch, shared state, cancel awareness

Three patterns the production server leans on. Each is independent; pick the one your workload needs.

**Cancel-aware handlers.** `CancelHandler.serve(req, cancel)` gets a token the reactor flips on peer FIN, deadline elapse, or graceful drain. Long-running handlers poll between expensive steps and return early; plain `Handler`s ignore the token and run to completion. The reactor still tears down the connection if the peer goes away; the token just lets your handler do partial work cleanly.

```mojo
from flare.http import CancelHandler, Cancel, Request, Response, ok

@fieldwise_init
struct SlowHandler(CancelHandler, Copyable, Movable):
    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(100):
            if cancel.cancelled():
                return ok("partial: " + String(i))
            # ...one expensive step...
        return ok("done")
```

**Compile-time route tables.** When the route table is known at build time, `ComptimeRouter[ROUTES]` parses the path patterns at compile time and unrolls the dispatch loop per route. No runtime trie walk, no per-request handler-table indirection. Same path-param + wildcard syntax as the runtime `Router`, same 404 / 405-with-`Allow` semantics; the only difference is *when* the dispatch is decided.

```mojo
from flare.http import (
    ComptimeRoute, ComptimeRouter, HttpServer,
    Request, Response, Method, ok,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))

def files(req: Request) raises -> Response:
    return ok("files=" + req.param("*"))

comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET,  "/",            home),
    ComptimeRoute(Method.GET,  "/users/:id",   get_user),
    ComptimeRoute(Method.GET,  "/files/*",     files),
]

def main() raises:
    var r = ComptimeRouter[ROUTES]()
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

**App state + middleware composition.** `App[S]` carries shared state alongside an inner handler; `state_view()` hands out a borrow that middleware can read or mutate. The compiler monomorphises the whole nested chain into one direct call sequence per request type, with no virtual dispatch and no per-request allocation.

```mojo
from flare.http import App, Router, Request, Response, Handler, State, ok, HttpServer
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct WithHits[Inner: Handler](Handler):
    var inner:    Self.Inner
    var snapshot: State[Counters]

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.snapshot.get().hits))
        return resp^

def main() raises:
    var router = Router()
    router.get("/", home)
    var app  = App(state=Counters(hits=0), handler=router^)
    var view = app.state_view()

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(WithHits(inner=app^, snapshot=view^))
```

For the static-response fast path (`serve_static`), `serve_comptime[handler, config]` with build-time invariant checks, the multi-worker shared-listener mode (`HttpServer.serve(handler, num_workers=N)`), and the cross-worker `WorkerHandoffPool` (`FLARE_SOAK_WORKERS=on`), see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

## Low-level API

flare ships the primitives the HTTP server is built on, so you can drop down a layer when HTTP isn't the right shape: custom binary protocols, raw TLS, UDP, or running the reactor directly.

```mojo
from flare.tcp import TcpStream
from flare.tls import TlsStream, TlsConfig
from flare.udp import UdpSocket
from flare.ws  import WsClient
from flare.dns import resolve
from flare.runtime import Reactor, INTEREST_READ
```

Round-trip examples for each (`04_tcp_echo`, `06_websocket_echo`, `11_udp`, `12_tls`, `14_reactor`) live under [`examples/`](examples/) and the rendered package docstring at <https://ehsanmok.github.io/flare/> walks the layered API top-down. Use cases: a custom protocol over TLS, a UDP client / server, a WebSocket client driven from a CLI tool, or a hand-rolled non-HTTP server on top of the same reactor that powers `HttpServer`.

## Architecture

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455)
flare.http     HTTP/1.1 client + reactor server + Cancel + Handler / Router / App
flare.tls      TLS 1.2/1.3 (OpenSSL, both client and server; reactor-loop integration follow-up)
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll), TimerWheel, Scheduler, Pool[T]
```

Each layer imports only from layers below it. No circular dependencies. The full request lifecycle, including the `Cancel` injection point and the per-connection state machine, lives in [`docs/architecture.md`](docs/architecture.md).

## Performance

Headline numbers live in the [Numbers](#numbers) block above; full single/multi-worker tables, tail percentiles, methodology, and the soak harness for long-running operational gates live in [`docs/benchmark.md`](docs/benchmark.md). Multi-worker cross-server ratios are gated on matched-worker baselines (Go `GOMAXPROCS=N`, nginx `worker_processes N`, Rust hyper / axum N-worker); flare publishes its own scaling claim and does not publish a "vs Go" multicore ratio against single-worker baselines.

We do not lead on speed. The position is plain: *speed claims in networking are mostly architecture and kernel, not language*. flare's job is to be operationally honest under load. Numbers are a corollary, not the headline.

### Production build

flare ships dev-grade safety asserts on every FFI / unsafe-pointer boundary (`debug_assert[assert_mode="safe"]` per [`.cursor/rules/sanitizers-and-bounds-checking.mdc`](.cursor/rules/sanitizers-and-bounds-checking.mdc)). The Mojo stdlib default `ASSERT=safe` keeps them in the binary — great for development (catches use-after-free, EBADF, EFAULT before they become silent kernel-mode UB), but each one costs one cmp+je on the reactor hot path.

For production deployments and apples-to-apples benchmarks, build with asserts compiled out:

```bash
mojo build -D ASSERT=none -I . examples/08_http_server.mojo -o myserver
./myserver
```

This matches what the bench harness uses for the `flare_mc_static` / `flare_mc` numbers above (so they're directly comparable to Rust's `cargo build --release --locked` posture). `mojo build` defaults to `-O3`; no extra flag needed.

The full assert hierarchy (`none` / `safe` / `all` / `warn`) and when to use each is documented in [`.cursor/rules/sanitizers-and-bounds-checking.mdc`](.cursor/rules/sanitizers-and-bounds-checking.mdc) §2.

## Security

Per-layer security posture and the sanitised-error-response policy live in [`docs/security.md`](docs/security.md). Highlights: RFC 7230 token validation, configurable size limits, sanitised 4xx/5xx bodies, TLS 1.2+ only, WebSocket frame masking + UTF-8 validation, 19 fuzz harnesses with 4M+ runs and zero known crashes.

For security issues, please open a private security advisory on GitHub or email the maintainer directly.

## Develop

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install                  # lean: tests, examples, microbench, format-check
pixi install -e dev           # adds mojodoc + pre-commit
```

flare uses four pixi environments, layered:

| Env | Adds | What it unlocks |
|---|---|---|
| `default` | nothing | `tests`, `examples`, microbenchmarks, `format-check` |
| `dev` | `mojodoc`, `pre-commit` | `docs`, `docs-build`, `format` (with hook install) |
| `fuzz` | `dev` + `mozz` | `fuzz-*` / `prop-*` |
| `bench` | `dev` + `go`, `nginx`, `wrk`, `wrk2` | `bench-vs-baseline*`, `bench-tail-quick`, `bench-mixed-keepalive` |

```bash
pixi run tests                                     # full suite + 21+ examples
pixi run --environment fuzz fuzz-all               # 19 harnesses
pixi run --environment bench bench-vs-baseline-quick   # ~7 min
```

Per-component task list lives in [`pixi.toml`](pixi.toml). The full architecture / benchmark / security / cookbook tour is under [`docs/`](docs/).

## License

[MIT](./LICENSE)
