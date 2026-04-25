<p align="center">
  <img src="./logo.png" alt="flare" width="280">
</p>

<h1 align="center">flare</h1>

<p align="center">
  <a href="https://github.com/ehsanmok/flare/actions/workflows/ci.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml"><img src="https://github.com/ehsanmok/flare/actions/workflows/fuzz.yml/badge.svg" alt="Fuzz"></a>
  <a href="https://ehsanmok.github.io/flare/"><img src="https://github.com/ehsanmok/flare/actions/workflows/docs.yaml/badge.svg" alt="Docs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

A Mojo HTTP/1.1 server you can put in front of users — plus the raw TCP, UDP, TLS, DNS, and WebSocket primitives it's built on. One reactor per worker (`kqueue` on macOS, `epoll` on Linux), shared-nothing thread-per-core via `SO_REUSEPORT`, RFC 7230 parser with 19 fuzz harnesses, and a `Handler` trait that takes plain `def` functions or compiled-down structs.

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

flare is **pre-1.0**. The bar isn't "is it fast" — it's *is it hard to misuse under load and easy to operate*. The v0.5 work is about exactly that. See [`docs/operational-guarantees.md`](docs/operational-guarantees.md) for the concern-by-concern table of what flare handles for you (partial reads/writes, cancellation, graceful shutdown, sanitised error bodies, per-request deadlines, header/body limits, RFC 7230 validation) versus what's still your job, and what's still missing — streaming response bodies (v0.5.0 Step 2), server-side TLS (v0.5.0 Step 3), HTTP/2 (v0.6), public `async`/`await` (v1.0, gated on Mojo). HTTP/3, WebTransport, and `h2c` are permanent non-goals.

## Quick start

The full walk-through, gradually-disclosed, used to live here. It now lives in the package docstring on [`flare/__init__.mojo`](flare/__init__.mojo) (rendered at <https://ehsanmok.github.io/flare/>) and in the runnable examples under [`examples/`](examples/). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example.

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

```mojo
from flare.http import CancelHandler, Cancel, Request, Response, ok

@fieldwise_init
struct SlowHandler(CancelHandler, Copyable, Movable):
    fn serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(100):
            if cancel.cancelled():
                return ok("partial: " + String(i))
            # ...one expensive step...
        return ok("done")
```

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

For the comptime route table (`ComptimeRouter[ROUTES]`), the static-response fast path (`serve_static`), `serve_comptime[handler, config]` with build-time invariant checks, and the `num_workers` scale knob — see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

## Low-level API

flare ships the primitives the HTTP server is built on, so you can drop down a layer when HTTP isn't the right shape — custom binary protocols, raw TLS, UDP, or running the reactor directly:

```mojo
from flare.tcp import TcpStream
from flare.tls import TlsStream, TlsConfig
from flare.udp import UdpSocket
from flare.ws  import WsClient
from flare.dns import resolve
from flare.runtime import Reactor, INTEREST_READ
```

Round-trip examples for each — `04_tcp_echo`, `06_websocket_echo`, `11_udp`, `12_tls`, `14_reactor` — live under [`examples/`](examples/) and the rendered package docstring at <https://ehsanmok.github.io/flare/> walks the layered API top-down. Use cases: a custom protocol over TLS, a UDP client / server, a WebSocket client driven from a CLI tool, or a hand-rolled non-HTTP server on top of the same reactor that powers `HttpServer`.

## Architecture

```
flare.io       BufReader (Readable trait, generic buffered reader)
flare.ws       WebSocket client + server (RFC 6455)
flare.http     HTTP/1.1 client + reactor server + Cancel + Handler / Router / App
flare.tls      TLS 1.2/1.3 (OpenSSL, client today; server in v0.5.0 Step 3)
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll), TimerWheel, Scheduler, install_drain_on_sigterm
```

Each layer imports only from layers below it. No circular dependencies. The full request lifecycle (with the v0.5 `Cancel` injection point and the per-connection state machine) lives in [`docs/architecture.md`](docs/architecture.md).

## Performance

Disciplined: pinned toolchains, response-body integrity check before measurement, 5-run median with stdev ≤ 3 % gate. The headline v0.4.1 number on Linux EPYC is **flare_mc at 4 pinned workers ≈ 257K req/s on TFB plaintext, 4.38x single-worker flare and 7.03x Go `net/http`**. v0.5 swaps `wrk` for `wrk2` and adds tail percentiles (p99.9 / p99.99) and a mixed-keepalive workload — methodology and tables in [`docs/benchmark.md`](docs/benchmark.md).

We do not lead on speed. The criticism that drove v0.5 is plain: *speed claims in networking are mostly architecture and kernel, not language*. flare's job in the next release is to be operationally honest under load. Numbers are a corollary, not the headline.

## Security

Per-layer security posture and the v0.5.0 Step 1 sanitised-error-response policy live in [`docs/security.md`](docs/security.md). Highlights:

- RFC 7230 token validation, configurable header / URI / body size limits.
- 19 fuzz harnesses, 4M+ runs, zero known crashes.
- Sanitised 4xx / 5xx response bodies by default (extractor messages logged with request id, not echoed). Switch with `ServerConfig.expose_error_messages = True` for local dev only.
- TLS 1.2+ only, weak ciphers disabled, SNI always sent.
- WebSocket: client frames masked per RFC 6455, CSPRNG handshake nonce, UTF-8 validation on TEXT frames.

For security issues, please open a private security advisory on GitHub or email the maintainer directly.

## Install

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "v0.4.1" }
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
