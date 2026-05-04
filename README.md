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

**Full networking stack for Mojo**🔥: HTTP/1.1 + HTTP/2 server and client, WebSocket server and client, TLS 1.2/1.3 (OpenSSL with ALPN), TCP, UDP, DNS. The HTTP server and client are version-aware. `HttpServer.serve(handler)` dispatches HTTP/1.1 and HTTP/2 to the same handler from a per-connection preface peek for cleartext, or from TLS ALPN. `HttpClient.get("https://...")` negotiates the same way. One reactor per worker: `kqueue` on macOS, `epoll` on Linux, with an opt-in `io_uring` backend on Linux ≥ 6.0 (`FLARE_BUFRING_HANDLER=1`) that falls back to `epoll` automatically when the kernel is older or the flag is unset. Per-connection state machine, an RFC 7230 parser fuzzed across 24 harnesses, and a `Handler` trait that takes plain `def` functions or compiled-down structs.

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

- **Everything you need for a network app, in one library.** HTTP/1.1 + HTTP/2 server and client, WebSocket server and client (RFC 6455), TLS 1.2/1.3 over OpenSSL with ALPN, TCP, UDP, DNS. No external HTTP framework, no separate WebSocket library, no add-on for sessions or sanitised errors. The full layer stack lives in [`flare/`](flare/); each module imports only from layers below it.
- **One `HttpServer`, one `HttpClient`, version-aware.** `HttpServer.serve(handler)` peeks the first 24 bytes of every accepted connection. If they match the RFC 9113 §3.4 preface, the connection is HTTP/2; otherwise it's HTTP/1.1. Same handler is invoked either way. `HttpClient.get("https://...")` advertises ALPN `["h2", "http/1.1"]` and switches wires from what the server picks. `Router`, `App[S]`, middleware, typed extractors, `Auth` — none of them know which wire is talking to them.
- **Thread-per-core reactor.** `kqueue` on macOS, `epoll` on Linux. `HttpServer.serve(handler, num_workers=N)` runs N pthread workers behind per-worker `SO_REUSEPORT` listeners by default; set `FLARE_REUSEPORT_WORKERS=0` for the shared-listener `EPOLLEXCLUSIVE` shape with tighter p99.99. Optional cross-worker `WorkerHandoffPool` (`FLARE_SOAK_WORKERS=on`) for skewed-keepalive workloads.
- **Handlers compose by nesting structs, not callbacks.** `Handler` is a trait. `Router` with path params, `App[S]` for shared state, `ComptimeRouter[ROUTES]` for compile-time dispatch tables, typed extractors that turn malformed input into a sanitised 400 before your `serve` runs (`PathInt` / `QueryInt` / `HeaderStr` / `Form` / `Multipart` / `Cookies` / `Json` / ...). Middleware (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`, `Conditional[Inner]`, `FileServer` with HEAD + Range) wraps another `Handler` by holding it in a field.
- **The plumbing that's usually a separate dependency.** Signed cookies (HMAC-SHA256), typed `Session[T]` with cookie + in-memory stores. gzip + brotli + identity content-encoding. Multipart + urlencoded forms. RFC 6265 cookie jars and RFC 9110 Range. HAProxy PROXY v1 + v2 parser. AF_UNIX sockets for sidecar IPC. Server-Sent Events with backpressure. Client `RedirectPolicy` (`FOLLOW_ALL` / `SAME_ORIGIN_ONLY` / `DENY`). `BasicAuth` / `BearerAuth` on both HTTP wires. CSRF double-submit-cookie. Observability: JSON-per-line `StructuredLogger`, `Metrics` + Prometheus text exposition, askama-shape templates with HTML escaping.
- **Operational discipline.** Per-request `Cancel` token (peer FIN, deadline, graceful drain) plumbed to `CancelHandler`. TLS cert reload + mTLS. Sanitised 4xx/5xx (extractor messages logged with request id, never echoed to the client). `drain(timeout_ms)` returns a `ShutdownReport` per worker. 24h soak harness. **24 fuzz harnesses, 5.4M+ runs, zero known crashes**, including the RFC 8441 Extended CONNECT dispatch and the unified server's preface-peek classifier. ASan + assert-mode coverage on every FFI boundary.

## Numbers

TFB plaintext (`GET /plaintext` returning 13 bytes of `Hello, World!`), `wrk2 -t8 -c256 -d30s --latency` (coordinated-omission corrected), Linux EPYC 7R32 dev-box. Each row is the highest sustained rate that holds `p99 ≤ 50 ms` from the bench harness's calibrated peak-finder, with the latency distribution measured at 90% of that peak across five 30s rounds. Both flare and the Rust baselines are AOT-built with no debug asserts (`mojo build -D ASSERT=none` for flare, `cargo build --release --locked` for actix_web / hyper / axum), so the comparison is on the same compiler posture both sides.

**4-worker comparison** (the four frameworks that ship a multi-worker mode):

| Server | Workers | Req/s | p50 (ms) | p99 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|
| actix_web (tokio) | 4 | 259,950 | 1.23 | 2.74 | 3.88 |
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **259,125** | **1.17** | **2.74** | **3.38** |
| **flare_mc** (handler) [^reuse] | **4** | **222,755** | **1.25** | **2.70** | **3.38** |
| hyper (tokio multi-thread) | 4 | 219,966 | 1.25 | 2.85 | 3.63 |
| axum (tokio multi-thread) | 4 | 204,439 | 1.28 | 2.82 | 3.65 |

**Single-worker** (per-core request-processing cost):

| Server | Workers | Req/s | p50 (ms) | p99 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|
| nginx (`worker_processes 1`) | 1 | 80,040 | 1.16 | 3.20 | 4.39 |
| **flare** (reactor) | **1** | **74,489** | **1.24** | **3.05** | **3.36** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 39,644 | 1.38 | 3.22 | 4.40 |

What jumps out:

- **flare_mc_static essentially ties actix_web for #1 throughput** (within 0.3%) and posts the **best p99.99 of the four 4-worker frameworks** (3.38 ms vs actix_web's 3.88, hyper 3.63, axum 3.65).
- **flare_mc (the handler path)** beats hyper by 1.3% and axum by 9% on throughput, and **leads on every tail metric** (best p99 *and* best p99.99 of the four). It's 14% behind actix_web on raw req/s, which is the honest residual handler-path gap to actix's `Bytes::from_static` path.
- **flare 1w**: 93% of nginx 1w throughput (74,489 vs 80,040) but with the **tightest tail of the single-worker pack** -- p99 3.05 vs nginx 3.20, p99.99 3.36 vs nginx 4.39. 1.88x Go `net/http` at the same worker count, again with a tighter tail (p99.99 3.36 vs 4.40 ms).

Full methodology, the rate-sweep that locates each cliff, the historical CPU-pinned reference run, and reproducibility instructions are in [`docs/benchmark.md`](docs/benchmark.md). The matching nginx / hyper / actix_web / axum baselines built from-source by the harness live under [`benchmark/baselines/`](benchmark/baselines/).

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web). Set `FLARE_REUSEPORT_WORKERS=0` to opt into the single-listener `EPOLLEXCLUSIVE` shape, which trades ~17% req/s for ~0.25 ms tighter p99.99. See [`docs/benchmark.md`](docs/benchmark.md) for the listener-mode A/B and [Production build](#production-build) for the `mojo build -D ASSERT=none` shape these numbers use.

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

flare ships safety asserts on every FFI / unsafe-pointer boundary (`debug_assert[assert_mode="safe"]`). The Mojo stdlib default `ASSERT=safe` keeps them in the binary, which is what you want in development -- they catch use-after-free, EBADF, EFAULT in the FFI layer before they become silent kernel-mode UB. Each one costs roughly one cmp+je on the reactor hot path.

For production deployments and apples-to-apples benchmarks, build with asserts compiled out:

```bash
mojo build -D ASSERT=none -I . examples/08_http_server.mojo -o myserver
./myserver
```

This matches what the bench harness uses for the `flare_mc_static` / `flare_mc` numbers above (directly comparable to Rust's `cargo build --release --locked` posture). `mojo build` defaults to `-O3`; no extra flag needed.

Full assert-mode hierarchy (`none` / `safe` / `all` / `warn`), the sanitizer harness, and contributor guidance for adding `debug_assert` to new FFI wrappers all live in [`docs/build.md`](docs/build.md).

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
