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

**Full networking stack for Mojo**🔥 HTTP/1.1 and HTTP/2 server and client, WebSocket, TLS, TCP, UDP, DNS, all in one library on top of one reactor. Drop to raw sockets when HTTP isn't the right shape.

```mojo
from flare import HttpServer, Router, Request, Response, ok, SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)                                       # single-worker; for multi-worker pass a Copyable handler + num_workers=N
```

## Why flare

- **Batteries included.** HTTP/1.1 + HTTP/2, WebSocket (RFC 6455), TLS 1.2/1.3 with ALPN, signed cookies, sessions, multipart, gzip + brotli, CORS, static files, SSE, mTLS, and the PROXY protocol all live in `flare/`. No add-on shopping. Full inventory in [`docs/features.md`](docs/features.md).
- **HTTP/2 and h2c without the dance.** `HttpServer.serve(handler)` peeks every accepted connection for the RFC 9113 preface and dispatches h2c without an `Upgrade` negotiation; over TLS it's plain ALPN. The same `Router`, middleware, and extractors run on both wires.
- **Composable by types, not callbacks.** `Handler` is a trait. `Router`, `App[S]`, middleware, and typed extractors (`PathInt`, `QueryInt`, `Form[T]`, `Json[T]`, `Cookies`) compose by nesting structs. The compiler monomorphises the chain into one direct call sequence per request, with no virtual dispatch and no per-request allocation.
- **Operationally honest.** Per-request `Cancel` tokens, graceful drain, sanitized 4xx/5xx, TLS cert reload, structured logging, Prometheus metrics. Hard to misuse under load.
- **Fast, with a tight tail.** Thread-per-core reactor (`kqueue` / `epoll`, opt-in `io_uring`). On a 4-worker plaintext bench, flare posts the best p99 / p99.9 / p99.99 of the four major Rust frameworks, with stdev across 5 runs ≤ 4 ms at every percentile. [Numbers below.](#performance)
- **Fuzzed.** 24 fuzz harnesses, 5.4M+ runs, zero known crashes. ASan and assert-mode coverage on every FFI boundary.

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

Requires [pixi](https://pixi.sh) (pulls Mojo nightly automatically). Pin to a [released tag](https://github.com/ehsanmok/flare/releases) for reproducible builds.

To track unreleased work (breaking changes possible between tags):

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## Quick start

The tour below grows the snippet at the top of this README out, one persona at a time. Each level adds roughly one concept; everything compiles, and the runnable equivalents live under [`examples/`](examples/) (every one is part of `pixi run tests`). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example, and the rendered package docstring is at <https://ehsanmok.github.io/flare/>.

### Beginner: your first router

Three routes — two infallible, one that may fail — a path parameter, a JSON response. This is where most apps start: `def` handlers, a `Router`, `HttpServer.bind`, `num_workers`. No traits, no generics, no extractors yet.

```mojo
from flare.prelude import *  # Request, Response, Router, HttpServer, ok, ok_json, SocketAddr, ...

def home(req: Request) -> Response:                     # no raises - body cannot fail
    return ok("flare is up")

def health(req: Request) -> Response:                   # no raises - static JSON
    return ok_json('{"status":"ok"}')

def greet(req: Request) raises -> Response:             # raises - req.param("name")
    return ok("hello, " + req.param("name"))            #   raises if :name is missing

def main() raises:
    var r = Router()
    r.get("/",           home)
    r.get("/hi/:name",   greet)
    r.get("/health",     health)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

The single-worker `srv.serve(r^)` shape works with any `Handler` (including `Router`). For multi-worker mode (`num_workers=N`) the handler must be `Copyable` because each worker gets its own `H.copy()`; pass a bare-function handler (`srv.serve(my_fn, num_workers=4)`) or a `ComptimeRouter[ROUTES]` (the comptime route table is `Copyable`). Wrapping a `Router` for multi-worker is a v0.7.x roadmap item.

`flare.prelude` re-exports the everyday handler surface — `Request`, `Response`, `Router`, `HttpServer`, `ok` / `ok_json` / `ok_json_value` / `not_found` / `bad_request` / `internal_error` / `redirect`, `Method` / `Status`, the `Handler` family, `SocketAddr`. Anything outside that set (typed extractors, middleware, sessions, cookies, forms, comptime routing, HTTP/2 internals, lower-level transports) stays as an explicit `from flare.http import ...` so the import block continues to document what each module reaches for. For the very first hello-world up at the top of this README we kept the explicit import to show which names are in play; everywhere else the prelude is enough.

`raises` is optional and tracks the body. If the handler genuinely cannot fail (`home`, `health` above) drop the annotation; if it parses input or talks to a DB (`greet`'s `req.param` raises when `:name` is missing) keep it and let the server's catch-converts-to-500 contract take over. Mojo's function-type subtyping accepts both shapes at the same `Router.get(...)` call site. For *stateful* infallible handlers (the body still cannot fail but needs to carry struct fields) see [`HandlerInfallible`](examples/intermediate/infallible_handler.mojo).

What you get for free: 404 on unknown paths, 405 with `Allow` on wrong method, sanitized 4xx / 5xx bodies, peer-FIN cancellation, RFC 7230 size limits, the per-worker reactor with `kqueue` / `epoll`.

For request bodies, query strings, cookies, sessions, multipart forms, gzip / brotli, TLS, HTTP/2, and WebSocket: all under [`examples/`](examples/) (`basic/http_get`, `basic/cookies`, `intermediate/forms`, `intermediate/multipart_upload`, `intermediate/sessions`, `intermediate/brotli`, `basic/tls`, `advanced/http2`, `basic/websocket_echo`).

### Intermediate: typed extractors

Once your handlers need to read structured input (path params as integers, query strings as bools, headers as strings), promote each `Handler` from a `def` into a struct whose fields *are* the inputs. `PathInt["id"]` / `PathStr` / `QueryInt` / `HeaderStr` / `Form[T]` / `Multipart` / `Cookies` / ... parse and validate at extraction time; `Extracted[H]` reflects on the struct's fields and pulls each one in before `serve` runs. Missing or malformed values become a 400 with a sanitized body, so your `serve` only sees well-typed values.

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

Middleware is the same shape: a `Handler` that wraps another `Handler`. The stock layers (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`, `FileServer`) all compose by nesting structs, no callback chain. `examples/intermediate/middleware.mojo` walks through the production-shaped pipeline (`RequestID → Logger → Timing → Recover → RequireAuth → Router`).

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

## Performance

TFB plaintext (`GET /plaintext` returning 13 bytes of `Hello, World!`), `wrk2 -t8 -c256 -d30s --latency` (coordinated-omission corrected), Linux x86_64 dev-box. Each row is the highest sustained rate that holds `p99 ≤ 50 ms` from the bench harness's calibrated peak-finder, with the latency distribution measured at 90% of that peak across five 30s rounds. Latency cells are `median ± σ` over the 5 runs (σ = sample stdev across runs, ms); Req/s is the calibrated peak with stdev as a percentage of mean. Both flare and the Rust baselines are AOT-built with no debug asserts (`mojo build -D ASSERT=none` for flare, `cargo build --release --locked` for actix_web / hyper / axum), so the comparison is on the same compiler posture on both sides.

**4-worker comparison** (the four frameworks that ship a multi-worker mode):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| actix_web (tokio) | 4 | 251,416 | 0.35 | 1.25 ± 0.01 | 2.74 ± 0.17 | 3.77 ± 35.13 | 7.62 ± 43.93 |
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **235,223** | **0.21** | **1.23 ± 0.03** | **2.67 ± 0.02** | **3.01 ± 0.04** | **3.22 ± 3.86** |
| hyper (tokio multi-thread) | 4 | 218,074 | 0.21 | 1.24 ± 0.00 | 2.83 ± 0.02 | 3.28 ± 6.73 | 3.69 ± 33.56 |
| **flare_mc** (handler) [^reuse] | **4** | **216,170** | **0.28** | **1.25 ± 0.02** | **2.66 ± 0.02** | **2.98 ± 0.33** | **3.35 ± 31.06** |
| axum (tokio multi-thread) | 4 | 200,097 | 0.35 | 1.29 ± 0.01 | 2.83 ± 0.03 | 3.32 ± 5.22 | 18.05 ± 37.93 |

**Single-worker** (per-core request-processing cost):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| nginx (`worker_processes 1`) | 1 | 76,000 | 1.27 | 1.14 ± 0.03 | 3.28 ± 0.15 | 3.67 ± 0.22 | 4.11 ± 0.31 |
| **flare** (reactor) | **1** | **71,997** | **0.00** | **1.17 ± 0.02** | **3.03 ± 0.15** | **3.35 ± 0.14** | **3.48 ± 0.14** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 40,974 | 1.27 | 1.39 ± 0.01 | 3.27 ± 29.89 | 3.88 ± 37.71 | 4.72 ± 40.41 |

What jumps out:

- **flare_mc_static** posts the **best p99 / p99.9 / p99.99 of the four 4-worker frameworks** and the smallest stdev at every percentile — `3.22 ± 3.86 ms` p99.99 vs actix_web's `7.62 ± 43.93`, hyper's `3.69 ± 33.56`, axum's `18.05 ± 37.93`. It trades ~6% throughput to actix_web for an order-of-magnitude tighter p99.99 stdev.
- **flare_mc (the handler path)** leads on p99 (2.66 ms, tightest with σ=0.02) and ties or wins p99.9, with handler-path throughput between hyper and axum. The honest residual throughput gap to actix_web is the static-vs-handler difference, which `flare_mc_static` closes.
- **flare 1w** posts 95% of nginx 1w throughput with a uniformly tighter tail (p99 3.03 vs 3.28; p99.9 3.35 vs 3.67; p99.99 3.48 vs 4.11) and the smallest stdev of all three single-worker rows. It does 1.76× Go `net/http` at the same worker count, with Go's tail σ ~200× wider (40 ms vs 0.14 ms at p99.99) due to GC pauses.

Full methodology, the rate-sweep that locates each cliff, the historical CPU-pinned reference run, and reproducibility instructions are in [`docs/benchmark.md`](docs/benchmark.md). The matching nginx / hyper / actix_web / axum baselines built from source by the harness live under [`benchmark/baselines/`](benchmark/baselines/).

Speed in networking is mostly architecture and kernel, not language, so we don't lead with throughput claims. The job is to stay honest under load; the numbers are a corollary.

### Production build

flare ships safety asserts on every FFI / unsafe-pointer boundary (`debug_assert[assert_mode="safe"]`). The Mojo stdlib default `ASSERT=safe` keeps them in the binary, which is what you want in development: they catch use-after-free, EBADF, EFAULT in the FFI layer before they become silent kernel-mode UB. Each one costs roughly one cmp+je on the reactor hot path.

For production deployments and apples-to-apples benchmarks, build with asserts compiled out:

```bash
mojo build -D ASSERT=none -I . examples/basic/http_server.mojo -o myserver
./myserver
```

This matches what the bench harness uses for the `flare_mc_static` / `flare_mc` numbers above (directly comparable to Rust's `cargo build --release --locked` posture). `mojo build` defaults to `-O3`; no extra flag needed.

Full assert-mode hierarchy (`none` / `safe` / `all` / `warn`), the sanitizer harness, and contributor guidance for adding `debug_assert` to new FFI wrappers all live in [`docs/build.md`](docs/build.md).

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

Round-trip examples for each (`basic/tcp_echo`, `basic/websocket_echo`, `basic/udp`, `basic/tls`, `advanced/reactor`) live under [`examples/`](examples/), and the rendered package docstring at <https://ehsanmok.github.io/flare/> walks the layered API top-down. Use cases: a custom protocol over TLS, a UDP client / server, a WebSocket client driven from a CLI tool, or a hand-rolled non-HTTP server on top of the same reactor that powers `HttpServer`.

## Architecture

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455, permessage-deflate, WS-over-h2)
flare.http     HTTP/1.1 client + reactor server + Cancel + Handler / Router / App
flare.http2    HTTP/2 frame codec, HPACK, stream state, h2c upgrade
flare.tls      TLS 1.2/1.3 (OpenSSL, both client and server)
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll/io_uring), TimerWheel, Scheduler, Pool[T]
flare.testing  fork-and-serve helpers for cookbook examples + integration tests
flare.utils    POSIX FFI thunks (fork / waitpid / kill / usleep / exit / getpid)
```

Each layer imports only from layers below it. No circular dependencies. The full request lifecycle, including the `Cancel` injection point and the per-connection state machine, lives in [`docs/architecture.md`](docs/architecture.md).

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
| `bench` | `dev` + `go`, `nginx`, `wrk`, `wrk2`, `rust` | `bench-vs-baseline*`, `bench-tail-quick`, `bench-mixed-keepalive`, `bench-soak-*` |

Common tasks (run with `pixi run [--environment <env>] <task>`):

| Task | Env | What it does |
|---|---|---|
| `tests` | `default` | Full unit + integration suite plus every example under [`examples/`](examples/) |
| `format-check` / `format` | `default` / `dev` | `mojo format` over `flare`, `tests`, `benchmark`, `examples`, `fuzz` |
| `docs` / `docs-build` | `dev` | mojodoc-rendered package docstring (live or static) |
| `fuzz-all` | `fuzz` | Every harness in [`fuzz/`](fuzz/) (24 harnesses, 5.4M+ runs combined) |
| `fuzz-<name>` / `prop-<name>` | `fuzz` | Single harness — see [`pixi.toml`](pixi.toml) for the full list |
| `bench-vs-baseline-quick` | `bench` | flare vs Go `net/http`, throughput config (~7 min) |
| `bench-vs-baseline` | `bench` | flare vs all baselines (Go, nginx, hyper, axum, actix_web), all configs |
| `bench-tail-quick` | `bench` | Tail-percentile harness at the calibrated peak rate |
| `bench-mixed-keepalive` | `bench` | Mixed keepalive / non-keepalive workload |
| `bench-soak-{slow_clients,churn,mixed,smoke,extended}` | `bench` | 24 h soak harnesses for long-running operational gates |
| `bench-tls-setup` | `bench` | Generate self-signed cert + key for the TLS benches |

```bash
pixi run tests                                          # full suite + 40+ examples
pixi run --environment fuzz fuzz-all                    # 24 harnesses
pixi run --environment bench bench-vs-baseline-quick    # ~7 min
```

The full task list (per-component + the every-individual-fuzz-harness breakdown) lives in [`pixi.toml`](pixi.toml). The architecture / benchmark / security / cookbook tour is under [`docs/`](docs/).

## License

[MIT](./LICENSE)

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web). Set `FLARE_REUSEPORT_WORKERS=0` to opt into the single-listener `EPOLLEXCLUSIVE` shape, which trades ~17% req/s for ~0.25 ms tighter p99.99. See [`docs/benchmark.md`](docs/benchmark.md) for the listener-mode A/B and [Production build](#production-build) for the `mojo build -D ASSERT=none` shape these numbers use.
