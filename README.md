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

**Full networking stack for Mojo** 🔥 HTTP/1.1, HTTP/2, and HTTP/3 server and client (HTTP/3 over QUIC), WebSocket, TLS, TCP, UDP, Unix sockets, DNS, all in one library on top of one non-blocking reactor. Drop to raw sockets when HTTP isn't the right shape. The codecs and protocol state machines are [proved against the RFCs in Lean 4](#formal-verification).

```mojo
from flare.prelude import *

def hello(req: Request) -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=2)
```

And a version-aware client (negotiates HTTP/2 via ALPN, opt into HTTP/3):

```mojo
from flare.prelude import *

def main() raises:
    with HttpClient("https://example.com", prefer_http3=True) as c:
        var r = c.get("/")
        print(r.status, r.text())
```

## Why flare

- **Batteries included:** HTTP/1.1, HTTP/2 and HTTP/3 (server and client), WebSocket, gRPC, TLS and mTLS, streaming, sessions, compression, CORS, static files, SSE, templates, caching and an OpenAPI emitter. Full inventory in [`docs/features.md`](docs/features.md).
- **Composable by types, not callbacks:** `Handler` is a trait; `Router`, middleware and typed extractors compose by nesting structs, monomorphised into one direct call sequence per request type.
- **Hard to misuse under load:** per-request `Cancel` tokens, graceful drain, sanitized 4xx/5xx, TLS cert reload, structured logging, Prometheus metrics and an in-process `TestClient[H]`.
- **Fast, with a tight tail:** thread-per-core reactor (`kqueue` / `epoll`, opt-in `io_uring`). At 4 workers the handler path reaches `0.96-1.00x` of `actix_web` and the static path `1.08-1.16x`, with p99 about 3 ms at the peak; see [Performance](#performance).
- **Fuzzed and formally modelled:** 63 fuzz harnesses (9M+ runs, zero known crashes) and Lean 4 models of the codecs, state machines and scheduler, proved against the RFCs; see [Formal verification](#formal-verification).

## Install

```toml
[workspace]
channels = ["https://conda.modular.com/max", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "<latest-release>" }
```

```bash
pixi install
```

Requires [pixi](https://pixi.sh) (pulls Mojo automatically). Pin to a [released tag](https://github.com/ehsanmok/flare/releases) for reproducible builds.

To track unreleased work (breaking changes possible between tags):

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## Quick start

### Simplest

```mojo
from flare.prelude import *

def home(req: Request) -> Response:
    return ok("flare is up")

def health(req: Request) -> Response:
    return ok_json('{"status":"ok"}')

def greet(req: Request) raises -> Response:        # raises: req.param() can
    return ok("hello, " + req.param("name"))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get("/hi/:name", greet)
    r.get("/health", health)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

### Intermediate: typed extractors

Handler fields are the inputs; a bad value becomes a sanitized 400 before your code runs.

```mojo
from flare.prelude import *

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler):
    var id: PathInt["id"]

    def __init__(out self):
        self.id = PathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user=" + String(self.id.value))

def main() raises:
    var r = Router()
    r.get("/users/:id", Extracted[GetUser]())
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=4)
```

### Advanced

Cancel-aware handlers get a token the reactor flips on peer FIN, deadline or drain:

```mojo
@fieldwise_init
struct SlowHandler(CancelHandler, Copyable):
    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(100):
            if cancel.cancelled():
                return ok("partial: " + String(i))
            # ...one expensive step...
        return ok("done")
```

Compile-time route tables unroll dispatch per route, with no runtime trie walk:

```mojo
comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/",          home),
    ComptimeRoute(Method.GET, "/users/:id", get_user),
    ComptimeRoute(Method.GET, "/files/*",   files),
]

var r = ComptimeRouter[ROUTES]()
```

Middleware and shared state are structs wrapping a `Handler`, monomorphised into one call sequence per request type:

```mojo
@fieldwise_init
struct WithHits[Inner: Handler](Handler):
    var inner: Self.Inner
    var hits: Int

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req).lower()
        resp.headers.set("X-Hits", String(self.hits))
        return resp^

srv.serve(WithHits(inner=router^, hits=37))
```

Every tier has runnable, tested equivalents:

| I want to... | Go to |
|---|---|
| Start with routing, JSON, a client, raw TCP/UDP/TLS/WebSocket | [`examples/basic/`](examples/basic/) |
| Add middleware, state, sessions, forms, SSE, caching, CORS, static files | [`examples/intermediate/`](examples/intermediate/) |
| Go to HTTP/2, HTTP/3, gRPC, mTLS, compile-time routing, streaming proxies, the raw reactor | [`examples/advanced/`](examples/advanced/) |
| Find the example for a use case | [`docs/cookbook.md`](docs/cookbook.md) |
| Browse the API | <https://ehsanmok.github.io/flare/> |

## Performance

TFB plaintext, `wrk2 -t8 -c256 -d30s`, 48-vCPU Xeon Platinum 8488C, Linux 6.12, one run for all rows, flare workers pinned, all servers built without debug asserts (`mojo build -D ASSERT=none`, `cargo build --release --locked`). Each row is the highest rate that survives the harness's sustainable-peak finder.

| Server (4 workers) | Req/s | p99 (ms) |
|---|---:|---:|
| **flare_mc_static** (fixed-response path) | **705,569** | **2.82** |
| actix_web | 610,408 | 2.78 |
| **flare_mc** (handler path) | **607,940** | **3.00** |
| hyper | 556,619 | 2.67 |
| axum | 489,422 | 2.71 |

On one worker flare does `168k req/s` against nginx's `212k` and Go `net/http`'s `99k`, with the lowest p50 and p99 of the three. Absolute numbers move by about 5 % between runs on this shared box, so compare rows within one run. Methodology, every workload, HTTP/2 and HTTP/3 results, and how to reproduce are in [`docs/benchmark.md`](docs/benchmark.md). Production builds use `-D ASSERT=none`; see [`docs/build.md`](docs/build.md).

## Low-level API

The primitives the HTTP server is built on are public, for when HTTP isn't the right shape: `flare.tcp`, `flare.tls`, `flare.udp`, `flare.uds`, `flare.ws`, `flare.dns` and the `flare.runtime.Reactor`. Runnable examples are in [`examples/basic/`](examples/basic/) and [`examples/advanced/reactor.mojo`](examples/advanced/reactor.mojo).

## Architecture

```
flare.http / http2 / http3   servers, clients, Router, middleware, extractors
flare.ws  grpc  openapi      WebSocket, gRPC, OpenAPI
flare.quic                   QUIC v1 (sans-I/O codec + live UDP reactor)
flare.tls  crypto            TLS 1.2/1.3 (OpenSSL, rustls for QUIC), HMAC, base64url
flare.tcp  udp  uds  dns     sockets
flare.net  io                addresses, buffered readers
flare.runtime                reactor (kqueue / epoll / io_uring), scheduler, timers
```

Each layer imports only from layers below it. The per-module inventory, the request lifecycle and the per-connection state machine are in [`docs/architecture.md`](docs/architecture.md).

## Formal verification

[`formal/`](formal/) holds Lean 4 models of flare, from the byte codecs up through HTTP/1.1, HTTP/2, QUIC and HTTP/3 to the scheduler, each proved against a separate spec written from the RFC (core Lean only, no `sorry`, no extra axioms). Anchors, a spec lock and differential tests keep the models in sync with the Mojo code, and the 0.12 audit found 138 issues, all fixed. The design is in [`formal/README.md`](formal/README.md#design), the audit in [`formal/REPORT.md`](formal/REPORT.md).

## Security

Per-layer posture, limits and the sanitized-error policy are in [`docs/security.md`](docs/security.md), the threat model in [`docs/threat-model.md`](docs/threat-model.md). To report a vulnerability, open a private security advisory on GitHub or email the maintainer.

## Develop

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install
pixi run tests                  # full suite plus every example
pixi run tests-gen              # after adding a test file
pixi run format                 # mojo format (needs `pixi install -e dev`)
```

Environments, the task list and the structural lints are in [`docs/development.md`](docs/development.md); every task is defined in [`pixi.toml`](pixi.toml).

## License

[MIT](./LICENSE)
