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

A Mojo HTTP/1.1 server you can put in front of users, plus the raw TCP, UDP, TLS, DNS, and WebSocket primitives it's built on. One reactor per worker (`kqueue` on macOS, `epoll` on Linux), shared-nothing thread-per-core via `SO_REUSEPORT`, RFC 7230 parser with 19 fuzz harnesses, and a `Handler` trait that takes plain `def` functions or compiled-down structs.

```mojo
from flare.http import HttpServer, Router, Request, Response, ok
from flare.net import SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=4)
```

flare is **pre-1.0**. The bar isn't "is it fast", it's *is it hard to misuse under load and easy to operate*.

## Features

- **Full networking stack**: HTTP/1.1 (client + server), WebSocket (RFC 6455), TLS 1.2/1.3 (client + server, OpenSSL), TCP, UDP, DNS — layered, each module importing only from below.
- **One reactor per worker** (`kqueue` on macOS, `epoll` on Linux) with a per-connection state machine + timer wheel; **thread-per-core** via `SO_REUSEPORT` (`HttpServer.serve(handler, num_workers=N)`).
- **Composable handlers**: `Handler` trait, `Router` with path params, `App[S]` for shared state, typed extractors (`PathInt` / `QueryInt` / `HeaderStr` / ...), middleware as value composition; `ComptimeRouter[ROUTES]` unrolls dispatch at compile time.
- **Production hygiene**: per-request `Cancel` token (peer FIN, timeout, drain unified), server-side TLS with cert reload + mTLS + ALPN, streaming bodies with backpressure, sanitised 4xx/5xx, graceful drain with per-worker `ShutdownReport`s, 24 h soak harness, **19 fuzz harnesses (4M+ runs, zero known crashes)**.

## Numbers

TFB plaintext, single-worker except where noted, `wrk2` two-phase (find-peak, then sustain at 90 % of peak). Full methodology + tables in [`docs/benchmark.md`](docs/benchmark.md).

- **Linux EPYC 7R32, single-worker**: ~80K req/s, **on par with nginx (`worker_processes 1`), ~1.96x Go `net/http` (`GOMAXPROCS=1`)**.
- **Multi-worker scaling**: **4.38x from 1 to 4 workers** (flare's `SO_REUSEPORT` thread-per-core scheduler).
- **Tail latencies under sustained 90%-of-peak load** (`wrk2 --latency`, coordinated-omission corrected): p50 ≈ 1.2 ms, p99 ≈ 3.1 ms, **p99.99 ≈ 3.8 ms**.
- **Apple M-series, single-worker**: ~157K req/s, ~1.10× Go `net/http`.

## Install

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "v0.5.0" }
```

```bash
pixi install
```

Requires [pixi](https://pixi.sh) (pulls Mojo nightly automatically). Released tags are listed on [GitHub Releases](https://github.com/ehsanmok/flare/releases); `main` always targets the next unreleased version.

To track unreleased work (breaking changes possible between tags):

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## Quick start

The full walk-through, gradually-disclosed, used to live here. It now lives in the package docstring on rendered at <https://ehsanmok.github.io/flare/> and in the runnable examples under [`examples/`](examples/). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example.

### Typed extractors

`PathInt["id"]` / `PathStr` / `QueryInt` / `HeaderStr` / etc. parse the request value at extraction time; `Extracted[H]` reflects on a handler struct's fields and pulls each one in before calling `serve`. Missing or malformed values become a 400 with a sanitised body.

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

### Cancel-aware handlers

`CancelHandler.serve(req, cancel)` gets a token the reactor flips on peer FIN, deadline elapse, or graceful drain. Handlers poll it between expensive steps and return early; plain `Handler`s ignore it and run to completion.

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

### App state and middleware

`App[S]` carries shared state alongside an inner handler; `state_view()` hands out a borrow that middleware can read or mutate. Middleware is just a `Handler` that wraps another `Handler`, so composition is value composition, with no callback chain to thread through.

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

### Static route tables (`ComptimeRouter`)

When the route table is known at build time, `ComptimeRouter[ROUTES]` parses the path patterns at compile time and unrolls the dispatch loop per route. No runtime trie walk, no per-request handler-table indirection. The route table is a single `comptime` list of `(method, pattern, handler)` triples; the handler is bound in the same place as the pattern, no separate `r.get(path, fn)` step.

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

Same path-param + wildcard syntax as the runtime `Router`; same 404 / 405-with-`Allow` semantics. For the static-response fast path (`serve_static`), `serve_comptime[handler, config]` with build-time invariant checks, and the `num_workers` scale knob, see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

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

We do not lead on speed. The position is plain: *speed claims in networking are mostly architecture and kernel, not language*. flare's job is to be operationally honest under load — numbers are a corollary, not the headline.

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
