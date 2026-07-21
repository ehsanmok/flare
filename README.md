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

**Full networking stack for Mojo** 🔥 HTTP/1.1, HTTP/2, and HTTP/3 server and client (HTTP/3 over QUIC), WebSocket, TLS, TCP, UDP, Unix sockets, DNS, all in one library on top of one non-blocking reactor. Drop to raw sockets when HTTP isn't the right shape.

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

- **Batteries included:** HTTP/1.1, HTTP/2, and HTTP/3 over QUIC (server + client), WebSocket (RFC 6455 + permessage-deflate), gRPC, TLS 1.2/1.3 + mTLS, sessions, gzip + brotli, CORS, static files, SSE, templates, RFC 9111 caching, and an OpenAPI 3.1 emitter. Full inventory in [`docs/features.md`](docs/features.md).
- **Composable by types, not callbacks:** `Handler` is a trait; `Router`, middleware, and typed extractors (`PathInt`, `Json[T]`, `Cookies`, ...) compose by nesting structs, monomorphised into one direct call sequence per request type with no virtual dispatch.
- **Hard to misuse under load:** Per-request `Cancel` tokens, graceful drain, sanitized 4xx/5xx, TLS cert reload, structured logging, Prometheus metrics, and an in-process `TestClient[H]`.
- **Fast, with a tight tail:** Thread-per-core reactor (`kqueue` / `epoll`, opt-in `io_uring`); top-of-pack throughput with a p99 median that ties `actix_web` and beats `hyper` / `axum`, plus [match-or-beat-quiche on HTTP/3](#performance).
- **Fuzzed:** 62 fuzz harnesses, 9M+ runs, zero known crashes; ASan + assert-mode coverage on every FFI boundary.

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

Beginner to advanced, roughly one concept per level. Everything compiles; runnable equivalents live under [`examples/`](examples/) (all part of `pixi run tests`). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to an example; rendered docs at <https://ehsanmok.github.io/flare/>.

### Beginner: your first router

Three routes (one fallible), a path param, a JSON response. Plain `def` handlers, no traits or generics yet.

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

`srv.serve(r^)` accepts any `Handler`. Multi-worker (`num_workers=N`) needs a `Copyable` handler (each worker gets its own `H.copy()`); `Router` qualifies because its routes sit behind an Arc-style refcount. Bare functions and `ComptimeRouter[ROUTES]` work the same.

`flare.prelude` re-exports the everyday surface (`Request`, `Response`, `Router`, `HttpServer`, the `ok` / `ok_json` / `not_found` / ... builders, `Method` / `Status`, the `Handler` family, `SocketAddr`). Everything else (extractors, middleware, sessions, transports) stays an explicit `from flare.http import ...` so imports document intent, which is why the Intermediate example below spells them out.

`raises` is optional and tracks the body: drop it when the handler cannot fail, keep it when it parses input or does I/O (the server converts a raise to a sanitized 500). Both shapes bind at the same `Router.get(...)` call. For stateful infallible handlers see [`HandlerInfallible`](examples/intermediate/infallible_handler.mojo).

Free: 404 on unknown paths, 405 with `Allow`, sanitized 4xx/5xx, peer-FIN cancellation, RFC 7230 size limits, per-worker `kqueue` / `epoll` (opt-in `io_uring`). Bodies, query strings, cookies, sessions, multipart, gzip/brotli, TLS, HTTP/2, WebSocket: see [`examples/`](examples/) (indexed in [`docs/cookbook.md`](docs/cookbook.md)).

### Intermediate: typed extractors

When handlers need structured input, make each `Handler` a struct whose fields *are* the inputs. `PathInt["id"]` / `QueryInt` / `HeaderStr` / `Form[T]` / `Multipart` / `Cookies` / ... parse and validate at extraction; `Extracted[H]` pulls them in before `serve`. Bad values become a sanitized 400, so `serve` only sees well-typed values.

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

Middleware is the same shape: a `Handler` wrapping a `Handler`. Stock middleware (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`) and leaf handlers (`FileServer`) all nest as structs, no callback chain. [`examples/intermediate/middleware.mojo`](examples/intermediate/middleware.mojo) walks a production stack (RequestID -> Logger -> Timing -> Recover -> RequireAuth -> Router).

### Advanced: compile-time dispatch, shared state, cancel awareness

Three independent patterns. Pick the ones your workload needs.

**Cancel-aware handlers:** `CancelHandler.serve(req, cancel)` gets a token the reactor flips on peer FIN, deadline, or drain. Poll it between expensive steps to return partial work early; plain `Handler`s ignore it and run to completion.

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

**Compile-time route tables:** `ComptimeRouter[ROUTES]` parses path patterns at compile time and unrolls dispatch per route, no runtime trie walk. Same path-param + wildcard syntax and 404 / 405-with-`Allow` semantics as `Router`; only *when* dispatch is decided differs.

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

**Shared state + middleware composition:** capture app-scoped state by value in a `Handler` struct; layers stack by nesting constructors. The compiler monomorphises the chain into one direct call sequence per request type, no virtual dispatch, no per-request allocation. For cross-worker mutation, hold state behind a `flare.runtime.Pool` heap address.

```mojo
from flare.http import Router, Request, Response, Handler, ok, HttpServer
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct WithHits[Inner: Handler](Handler):
    var inner: Self.Inner
    var counters: Counters

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.counters.hits))
        return resp^

def main() raises:
    var router = Router()
    router.get("/", home)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(WithHits(inner=router^, counters=Counters(hits=37)))
```

For `serve_static`, `serve_comptime[handler, config]` (build-time invariant checks), shared-listener multi-worker mode, and the cross-worker `WorkerHandoffPool`, see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

### Streaming proxy: relay an upstream with backpressure

When the body is produced elsewhere (e.g. a backend streaming chunks over a Unix socket), a `StreamHandler` relays it with end-to-end backpressure. The framework owns the per-connection upstream: hand it the source, it watches, drains, and closes the fd. Front code touches no file descriptors, byte `Span`, or per-connection table.

```mojo
from flare import HttpServer, StreamHandler, StreamConn, UpstreamChunkSource
from flare.net import SocketAddr

struct Proxy(Movable, StreamHandler):
    var backend: String

    def __init__(out self, backend: String):
        self.backend = backend

    def on_open(mut self, mut conn: StreamConn) raises:
        conn.attach_upstream(UpstreamChunkSource.connect(self.backend))
        conn.set_watermarks(hi=64 * 1024, lo=16 * 1024)

    def on_upstream(mut self, mut conn: StreamConn) raises:
        conn.relay_upstream()

    def on_writable(mut self, mut conn: StreamConn) raises: pass
    def on_close(mut self, mut conn: StreamConn) raises: pass

def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_streaming(Proxy("/run/backend.sock"))
```

`set_watermarks` couples the two pipes: when the relay buffer crosses the high mark the reactor stops reading upstream until it drains to the low mark, so a slow consumer cannot force unbounded buffering. A client disconnect propagates a `CANCEL` upstream. Runnable version: [`examples/advanced/streaming_proxy.mojo`](examples/advanced/streaming_proxy.mojo).

## Performance

TFB plaintext (`GET /plaintext` returning 13 bytes of `Hello, World!`), `wrk2 -t8 -c256 -d30s --latency` (coordinated-omission corrected), Linux x86_64 dev-box. Each row is the highest rate that survives the bench harness's sustainable-peak finder; latency cells are `median ± σ` over five 30 s measurement rounds at that rate. Both flare and the Rust baselines are AOT-built with no debug asserts (`mojo build -D ASSERT=none` / `cargo build --release --locked`). Full methodology in [`docs/benchmark.md`](docs/benchmark.md#methodology).

The σ on the tail percentiles is the **honesty meter**: a small σ means all 5 runs landed inside the working envelope; a σ in the tens or hundreds of ms means at least one run brushed the saturation cliff and the headline rate is sitting at the limit, not comfortably inside it.

**4-worker comparison** (the four frameworks that ship a multi-worker mode):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **242,384** | **0.21** | **1.18 ± 0.02** | **2.67 ± 0.02** | **3.03 ± 0.02** | **3.34 ± 0.16** |
| actix_web (tokio) | 4 | 239,108 | 0.33 | 1.26 ± 0.00 | 2.73 ± 0.04 | 3.25 ± 11.28 | 5.21 ± 12.05 |
| **flare_mc** (handler) [^reuse] | **4** | **237,761** | **0.34** | **1.20 ± 0.02** | **2.74 ± 320.65** | **5.99 ± 359.05** | **64.86 ± 350.97** |
| hyper (tokio multi-thread) | 4 | 217,036 | 0.21 | 1.24 ± 0.01 | 2.83 ± 0.02 | 3.28 ± 0.08 | 3.66 ± 2.72 |
| axum (tokio multi-thread) | 4 | 201,216 | 0.35 | 1.29 ± 0.00 | 2.82 ± 0.03 | 3.25 ± 2.50 | 3.64 ± 29.52 |

**Single-worker** (per-core request-processing cost):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| **flare** (reactor) | **1** | **79,028** | **1.57** | **1.13 ± 0.03** | **3.23 ± 0.12** | **3.84 ± 0.37** | **4.30 ± 0.51** |
| nginx (`worker_processes 1`) | 1 | 76,883 | 1.27 | 1.12 ± 0.01 | 3.23 ± 0.09 | 3.62 ± 0.15 | 4.05 ± 0.48 |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 40,343 | 0.00 | 1.35 ± 0.01 | 3.21 ± 0.01 | 3.60 ± 0.04 | 4.40 ± 0.17 |

What jumps out:

- **flare_mc_static** (fixed-response fast path) leads the 4-worker pack on throughput at `242,384 req/s` and holds a uniformly tight tail (σ `<= 0.16 ms` at every percentile) - all five runs landed inside the working envelope this round.
- **flare_mc** (the handler path) is third at `237,761 req/s`, within `~2 %` of the leader, and its p99 *median* of `2.74 ms` is essentially tied with actix (`2.73`) and ahead of hyper (`2.83`) and axum (`2.82`). The large `+/- 320-359 ms` σ on its tail is the **honesty meter** firing, not an error rate: every request succeeded, but one of the five 30 s runs tipped over the saturation cliff and its tail spiked into the hundreds of ms while the other four stayed tight, so the median held and the run-to-run tail did not. The handler headline here is the edge of the envelope, not its comfortable interior - back the rate off slightly for a uniformly tight tail.
- **actix_web** is second at `239,108 req/s` with a near-flat tail (σ `<= 12 ms` at p99.9 / p99.99) - a mild cliff brush rather than a steady-state blowup.
- **hyper** is the reference baseline at `217,036 req/s` with the tightest tail of the Rust pack (σ `<= 2.72 ms`); the same binary returns the same throughput run-over-run.
- **axum** is steady by design but the lowest headline of the four at `201,216 req/s`, tight everywhere except a `29.5 ms` σ at p99.99.
- **flare 1w** edges nginx 1w by `2.8 %` (`79.0k` vs `76.9k req/s`) with an identical `3.23 ms` p99 median - on par at single-core load. Against Go `net/http` at the same worker count flare does `1.96x` the throughput with comparable tail medians.

**HTTP/3 throughput (match-or-beat-quiche gate met):** The full flare HTTP/3 wire path landed in v0.8 - codec, AEAD, rustls QUIC binding, state machine, HTTP/3 dispatch, and the live UDP reactor I/O loop. On the 1-client × 100-stream gate workload (5×30 s runs), **flare HTTP/3 leads at `74,653 req/s`** (median, σ `0.50 %`, p99 `1.45 ms`, p99.9 `2.45 ms`), `+2.9 %` over `quiche 0.22`'s `72,571 req/s` at a tighter σ; `quinn 0.11 + h3 0.0.8` errors at the 100-stream workload and needs calibration. The win came from the reactor rewrite - eliminating per-packet whole-connection deep copies (in-place `ref` mutation), a cached-table QPACK decode path, and coalesced 1-RTT egress with capacity-reserved packet builders - not from egress syscall batching (ingress `recvmmsg` is built and default-on; egress `sendmmsg`/GSO are built in `flare.udp.batch` but not yet wired into QUIC egress - the gate closed without them). `quinn 0.11 + h3 0.0.8` is not a valid comparison at this workload shape (98% errored streams) and is excluded pending recalibration. Full table, baselines, and h2load+H3 build recipe in [`docs/benchmark.md#http3-throughput`](docs/benchmark.md#http3-throughput).

The matching nginx / hyper / actix_web / axum baselines built from source by the harness live under [`benchmark/baselines/`](benchmark/baselines/).

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
flare.ws       WebSocket client + server (RFC 6455, permessage-deflate
               with context-takeover, WS-over-h2 incl. server-side
               RFC 8441 reactor dispatch via HttpServer.serve[H, W])
flare.http     HTTP/1.1 client + reactor server + Cancel + Handler /
               Router + middleware (Logger / RequestId / Compress
               / Cors / Retry / PostHocDeadline / Conditional / Cache)
               + sans-I/O parser sublayer under flare.http.proto.*
               + template engine with {% block %} / {% extends %}
flare.http2    HTTP/2 frame codec, HPACK (with table-driven Huffman
               fast decoder), stream state, h2c upgrade, RFC 8441
               Extended CONNECT, per-stream RST_STREAM Cancel propagation
flare.http.cache  RFC 9111 cache: CacheControl directive parser,
               CacheKey + Vary-aware secondary key, bounded
               InMemoryCacheStore, Cache[Inner, S] wrapping
               middleware (freshness check, conditional revalidation)
flare.grpc     Sans-I/O gRPC codec primitives: LPM framing, canonical
               Status codes, Metadata carrier, plus the unary
               server adapter (`GrpcUnary` trait + `run_unary_call`)
               that maps an HTTP/2 stream to a typed handler. All
               four server shapes ship (unary, incremental server-
               streaming, client-streaming, bidi), plus proto3
               `service` codegen, server reflection (list + file
               lookups), and `grpc.health.v1.Health` Check + Watch;
               the client ships (`GrpcClient`: unary + server-/
               client-streaming + bidi). Maps / oneof in the
               message codegen are the remaining deferral.
flare.openapi  OpenAPI 3.1 spec model + deterministic JSON emitter
flare.quic     Sans-I/O QUIC v1 codec primitives: varint + long/short
               packet headers, all 22 transport frames driven through
               a `FrameHandler` trait, transport-parameter codec, the
               RFC 9000 §3+§10+§13 state machine, the RFC 9001 §5 +
               RFC 5869 HKDF key schedule behind a `QuicCrypto` trait,
               and the `CongestionController` trait (CUBIC default +
               Reno fallback). The `QuicListener` + `QuicConnection` +
               `ConnectionIdTable` run the live UDP reactor; the
               `RustlsQuicAcceptor` binding drives the QUIC TLS
               handshake and per-level keys end-to-end.
flare.http3       Sans-I/O HTTP/3 frame codec + SETTINGS payload + the
               `Http3RequestReader` state machine + response writer. The
               `Http3Connection` driver mounts on the same `Handler` trait
               the h1 / h2 paths use and is driven per-stream by the
               QUIC reactor over the wire.
flare.crypto   HMAC-SHA256, base64url (signed cookies, sessions)
flare.tls      TLS 1.2/1.3 (OpenSSL, both client and server, session
               resumption via RFC 5077 tickets + RFC 8446 §4.6.1)
flare.tcp      TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      UdpSocket (IPv4 + IPv6)
flare.uds      UnixListener + UnixStream (AF_UNIX sidecar IPC)
flare.dns      getaddrinfo (dual-stack)
flare.net      IpAddr, SocketAddr, RawSocket
flare.runtime  Reactor (kqueue/epoll/io_uring), TimerWheel, Scheduler,
               HandoffQueue + WorkerHandoffPool, BufferPool, DateCache,
               vectored I/O
flare.testing  TestClient[H] (FastAPI-shape in-process handler tester)
               + fork_server / kill_forked_server for integration tests
flare.utils    POSIX FFI thunks (fork / waitpid / kill / usleep / exit / getpid)
```

Each layer imports only from layers below it. No circular dependencies. The full request lifecycle, including the `Cancel` injection point and the per-connection state machine, lives in [`docs/architecture.md`](docs/architecture.md).

## Security

Per-layer security posture and the sanitised-error-response policy live in [`docs/security.md`](docs/security.md). Highlights: RFC 7230 token validation, configurable size limits, sanitised 4xx/5xx bodies, TLS 1.2+ only, WebSocket frame masking + UTF-8 validation, enforced HTTP/2 DoS caps (header-list / CONTINUATION / rapid-reset), client decompression-bomb cap, 62 fuzz harnesses with 9M+ runs and zero known crashes.

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
| `fuzz-all` | `fuzz` | Every harness in [`fuzz/`](fuzz/) (62 harnesses, 9M+ runs combined) |
| `fuzz-<name>` / `prop-<name>` | `fuzz` | Single harness - see [`pixi.toml`](pixi.toml) for the full list |
| `bench-vs-baseline-quick` | `bench` | flare vs Go `net/http`, throughput config (~7 min) |
| `bench-vs-baseline` | `bench` | flare vs all baselines (Go, nginx, hyper, axum, actix_web), all configs |
| `bench-tail-quick` | `bench` | Tail-percentile harness at the calibrated peak rate |
| `bench-mixed-keepalive` | `bench` | Mixed keepalive / non-keepalive workload |
| `bench-soak-{slow_clients,churn,mixed,smoke,extended}` | `bench` | 24 h soak harnesses for long-running operational gates |
| `bench-tls-setup` | `bench` | Generate self-signed cert + key for the TLS benches |
| `perf-server-alloc` | `dev` (Linux) | Repeatable allocation + CPU profile of the bench server (heaptrack + `strace -c` + `perf record`) - outputs land under `build/perf-profile/` |

```bash
pixi run tests                                          # full suite + every example under examples/
pixi run --environment fuzz fuzz-all                    # 62 harnesses
pixi run --environment bench bench-vs-baseline-quick    # ~7 min
```

The full task list (per-component + the every-individual-fuzz-harness breakdown) lives in [`pixi.toml`](pixi.toml). The architecture / benchmark / security / cookbook tour is under [`docs/`](docs/).

## License

[MIT](./LICENSE)

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web). Set `FLARE_REUSEPORT_WORKERS=0` to opt into the single-listener `EPOLLEXCLUSIVE` shape, which trades 7-22 % req/s (handler vs static fast path respectively) for a uniformly tight p99.99 across both paths. See [`docs/benchmark.md`](docs/benchmark.md) for the listener-mode A/B and [Production build](#production-build) for the `mojo build -D ASSERT=none` shape these numbers use.
