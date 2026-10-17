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

- **Batteries included:** HTTP/1.1, HTTP/2, and HTTP/3 over QUIC (server + client), WebSocket (RFC 6455 + permessage-deflate), gRPC, TLS 1.2/1.3 + mTLS + in-process HTTPS termination (`bind_tls` + `serve`), streaming responses on every wire (one handler streams byte-identically over h1 / h2 / h3 / https), sessions, gzip + brotli, CORS, static files, SSE, templates, RFC 9111 caching, and an OpenAPI 3.1 emitter. Full inventory in [`docs/features.md`](docs/features.md).
- **Composable by types, not callbacks:** `Handler` is a trait; `Router`, middleware, and typed extractors (`PathInt`, `JsonAs[T]`, `Cookies`, ...) compose by nesting structs, monomorphised into one direct call sequence per request type with no virtual dispatch.
- **Hard to misuse under load:** Per-request `Cancel` tokens, graceful drain, sanitized 4xx/5xx, TLS cert reload, structured logging, Prometheus metrics, and an in-process `TestClient[H]`.
- **Fast, with a tight tail:** Thread-per-core reactor (`kqueue` / `epoll`, opt-in `io_uring`) on Mojo's AsyncRT thread pool. At 4 workers the handler path reaches `0.90-0.93x` of `actix_web` and the static path `0.89-0.98x` (pinned or unpinned workers), all with p99 under 3 ms at the peak; see [Performance](#performance).
- **Fuzzed:** 63 fuzz harnesses, 9M+ runs, zero known crashes; ASan + assert-mode coverage on every FFI boundary.
- **Formally modelled:** Lean 4 models of the codecs, protocol state machines and concurrency, proved against the RFCs. The 0.12 audit found 138 issues with them, all fixed. Anchors keep the models in sync with the Mojo code, and differential tests run the two side by side. See [Formal verification](#formal-verification).

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

`flare.prelude` and the root `flare` package export the same list: `Request`, `Response`, `Router`, `HttpServer`, the `ok` / `ok_json` / `not_found` / ... builders, `Method` / `Status`, the `Handler` family, `SocketAddr`, the extractors, the stock middleware, sessions, and the TCP / TLS / Unix / WebSocket types. A symbol is on it if another exported symbol's signature names it, or if the examples below need it. Wire-format codecs, runtime primitives and anything in a `_`-prefixed module are not, and keep their own import: `from flare.http2 import Http2Connection`. The Intermediate example spells its imports out because naming the module you took something from is the better habit in code meant to last, not because the prelude lacks them.

`raises` is optional and tracks the body: drop it when the handler cannot fail, keep it when it parses input or does I/O (the server converts a raise to a sanitized 500). Both shapes bind at the same `Router.get(...)` call. For stateful infallible handlers see [`HandlerInfallible`](examples/intermediate/infallible_handler.mojo).

Free: 404 on unknown paths, 405 with `Allow`, sanitized 4xx/5xx, peer-FIN cancellation, RFC 7230 size limits, per-worker `kqueue` / `epoll` (opt-in `io_uring`). Bodies, query strings, cookies, sessions, multipart, gzip/brotli, TLS, HTTP/2, WebSocket: see [`examples/`](examples/) (indexed in [`docs/cookbook.md`](docs/cookbook.md)).

### Intermediate: typed extractors

When handlers need structured input, make each `Handler` a struct whose fields *are* the inputs. `PathInt["id"]` / `QueryInt` / `HeaderStr` / `Form` / `JsonAs[T]` / `Multipart` / `Cookies` / ... parse and validate at extraction; `Extracted[H]` pulls them in before `serve`. Bad values become a sanitized 400, so `serve` only sees well-typed values.

```mojo
from flare.http import (
    Router, ok, Request, Response, HttpServer,
    Extracted, PathInt, Handler,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler):
    var id: PathInt["id"]

    def __init__(out self):
        self.id = PathInt["id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user=" + String(self.id.value))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get("/users/:id", Extracted[GetUser]())
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

Middleware is the same shape: a `Handler` wrapping a `Handler`. Stock middleware (`Logger`, `RequestId`, `Compress`, `CatchPanic`, `Cors`) and leaf handlers (`FileServer`) all nest as structs, no callback chain. [`examples/intermediate/middleware.mojo`](examples/intermediate/middleware.mojo) walks a production stack (RequestID -> Logger -> Timing -> Recover -> RequireAuth -> Router).

### Advanced: compile-time dispatch, shared state, cancel awareness

Three independent patterns. Pick the ones your workload needs.

**Cancel-aware handlers:** `CancelHandler.serve(req, cancel)` gets a token the reactor flips on peer FIN, deadline, or drain. Poll it between expensive steps to return partial work early; plain `Handler`s ignore it and run to completion.

```mojo
from flare.http import CancelHandler, Cancel, Request, Response, ok

@fieldwise_init
struct SlowHandler(CancelHandler, Copyable):
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
struct Counters(Copyable):
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

For `serve_static`, `ServerConfig.check[config]()` (build-time invariant checks), shared-listener multi-worker mode, and the cross-worker `WorkerHandoffPool`, see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

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

def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_streaming(Proxy("/run/backend.sock"))
```

`set_watermarks` couples the two pipes: when the relay buffer crosses the high mark the reactor stops reading upstream until it drains to the low mark, so a slow consumer cannot force unbounded buffering. A client disconnect propagates a `CANCEL` upstream. Runnable version: [`examples/advanced/streaming_proxy.mojo`](examples/advanced/streaming_proxy.mojo).

### Streaming client: a body larger than memory, in one call

The client side of the same idea, new in v0.11. One entry point covers every wire: ALPN settles HTTP/2 against HTTP/1.1 on `https://`, and `http://` speaks HTTP/1.1, or prior-knowledge h2c when asked. Nothing buffers the body.

```mojo
from flare.http import HttpClient

def main() raises:
    var c = HttpClient()
    var r = c.get_streaming("https://example.com/big.bin")
    r.raise_for_status()
    print(r.status, "on", r.protocol())

    var total = 0
    while True:
        var chunk = r.read_chunk(65536)
        if len(chunk) == 0:
            break
        total += len(chunk)
    r.close()
    print("read", total, "bytes")
```

Uploads go the other way through `send_chunked`, pulling from a `ChunkSource` with an optional known `body_size` and a real `Cancel`. Runnable: [`examples/advanced/http_stream_client.mojo`](examples/advanced/http_stream_client.mojo) and [`examples/advanced/streaming_upload.mojo`](examples/advanced/streaming_upload.mojo). HTTP/3 has a reader but no entry point wires to it yet; see the known gaps in [`docs/features.md`](docs/features.md).

## Performance

TFB plaintext (`GET /plaintext` returning 13 bytes of `Hello, World!`), `wrk2 -t8 -c256 -d30s --latency` (coordinated-omission corrected), on a 48-vCPU AWS Xeon Platinum 8488C running Linux 6.12. Each row is the highest rate that survives the bench harness's sustainable-peak finder; latency cells are `median ± σ` over five 30 s measurement rounds at that rate. Both flare and the Rust baselines are AOT-built with no debug asserts (`mojo build -D ASSERT=none` / `cargo build --release --locked`). Full methodology in [`docs/benchmark.md`](docs/benchmark.md#methodology).

The σ on the tail percentiles is the **honesty meter**: a small σ means all 5 runs landed inside the working envelope; a σ in the tens or hundreds of ms means at least one run brushed the saturation cliff and the headline rate is sitting at the limit, not comfortably inside it.

**4-worker comparison** (the servers that ship a multi-worker mode):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| actix_web (tokio) | 4 | 594,048 | 0.20 | 1.05 ± 0.00 | 2.74 ± 0.09 | 3.28 ± 8.35 | 3.63 ± 14.30 |
| hyper (tokio multi-thread) | 4 | 545,338 | 0.20 | 1.06 ± 0.01 | 2.67 ± 0.02 | 3.19 ± 0.02 | 3.61 ± 0.04 |
| **flare_mc** (handler) [^reuse] | **4** | **533,640** | **0.02** | **1.12 ± 0.01** | **2.77 ± 0.04** | **3.30 ± 3.27** | **3.66 ± 7.36** |
| **flare_mc_static** (fixed-response fast path) [^reuse] | **4** | **530,615** | **0.45** | **1.14 ± 0.01** | **2.62 ± 0.03** | **3.11 ± 0.03** | **3.45 ± 1.72** |
| axum (tokio multi-thread) | 4 | 499,529 | 0.32 | 1.06 ± 0.01 | 2.77 ± 2.01 | 3.31 ± 10.64 | 3.74 ± 12.36 |

Same box, same harness, one run for all five rows, flare workers pinned (the benchmark default). Absolute numbers move by about 5 % between runs on this shared box, so compare rows within one run. In a second run with `FLARE_BENCH_PIN=0` and actix in the same run, actix read `628,895`, flare_mc `584,691` and flare_mc_static `616,960 req/s`.

**Single-worker** (per-core request-processing cost):

| Server | Workers | Req/s | σ%  | p50 (ms) | p99 (ms) | p99.9 (ms) | p99.99 (ms) |
|---|---:|---:|---:|---:|---:|---:|---:|
| nginx (`worker_processes 1`) | 1 | 211,873 | 0.28 | 1.17 ± 0.02 | 7.43 ± 4.62 | 16.66 ± 10.11 | 18.70 ± 11.11 |
| **flare** (reactor) | **1** | **168,128** | **0.16** | **1.01 ± 0.02** | **2.28 ± 0.10** | **4.67 ± 3.45** | **6.45 ± 4.04** |
| Go `net/http` (`GOMAXPROCS=1`) | 1 | 98,691 | 0.21 | 1.10 ± 0.02 | 3.82 ± 7.60 | 14.98 ± 11.41 | 17.38 ± 12.61 |

What jumps out:

- **flare_mc** (the handler path) reads `0.90x` actix with pinned workers and `0.93x` with unpinned ones; raw capacity is `746k` against actix's `782k req/s` ([profile and details](docs/benchmark.md#handler-path-against-actix_web-profile)). In the pinned run it is level with `flare_mc_static`, `-2 %` against hyper and `+7 %` against axum.
- **flare_mc_static** (fixed-response fast path) reads `0.89x` actix pinned and `0.98x` unpinned, with the most raw capacity of any server (`845k`). On this VM unpinned workers were faster than pinned ones by about `5-10 %`; the default stays pinned.
- **Every 4-worker row is stable:** all five runs of every server stayed inside the envelope, σ `<= 0.45 %` on throughput.
- **flare 1w** has the lowest p50 and p99 of the single-worker servers and does `1.7x` Go `net/http`, while nginx does `1.26x` flare at 256 connections. At 64 connections (one wrk2 thread) nginx leads flare by `5 %` (`203k` against `193k req/s`), so the single reactor loses ground as the connection count grows.
- **Threads:** AsyncRT matched the old pthread engine within `±1 %` in paired runs at 1-48 workers, and spawns a task in `6.3 µs` against `57 µs` for an OS thread.

**HTTP/3 throughput:** The full flare HTTP/3 wire path landed in v0.8 - codec, AEAD, rustls QUIC binding, state machine, HTTP/3 dispatch, and the live UDP reactor I/O loop. On the 1-client × 100-stream workload (5×30 s runs, h2load with `--log-file`), flare does `129,635 req/s` (σ `0.61 %`, p99 `1.03 ms`, p99.99 `1.40 ms`) against quiche's `153,494 req/s` (σ `2.95 %`, p99 `0.86 ms`, p99.99 `3.28 ms`): `0.84x` the throughput with the tighter extreme tail. On the older EPYC box flare led quiche by `2.9 %` with `--log-file` off and read the same `0.85x` with it on. The HTTP/3 path got fast through the reactor rewrite - eliminating per-packet whole-connection deep copies (in-place `ref` mutation), a cached-table QPACK decode path, and coalesced 1-RTT egress with capacity-reserved packet builders - not from egress syscall batching (ingress `recvmmsg` is built and default-on; egress `sendmmsg`/GSO are built in `flare.udp.batch` but not yet wired into QUIC egress, which leaves room against quiche). `quinn 0.11 + h3 0.0.8` is not a valid comparison at this workload shape (98% errored streams) and is excluded pending recalibration. Full table, baselines, and h2load+H3 build recipe in [`docs/benchmark.md#http3-throughput`](docs/benchmark.md#http3-throughput).

All of these numbers, the single-load-thread configs, the pthread-against-AsyncRT paired runs and the setup notes for a fresh box are in [`docs/benchmark.md`](docs/benchmark.md#xeon-8488c-re-baseline-asyncrt-thread-engine).

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
flare.tls      TLS 1.2/1.3 (OpenSSL, both client and server, opt-in
               session resumption via RFC 5077 tickets + RFC 8446 §4.6.1)
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

## Formal verification

[`formal/`](formal/) holds Lean 4 models of flare, from the byte codecs up through HTTP/1.1, HTTP/2, QUIC and HTTP/3 to the scheduler. Each implementation model is a transliteration of a Mojo function and is proved against a separate spec written from the RFC. The HTTP/2 connection, for example, refines the RFC 9113 §5.1 stream-state machine. The proofs use core Lean only (no `sorry`, no `native_decide`, no extra axioms). The 0.12 audit, [`formal/REPORT.md`](formal/REPORT.md), found 138 issues this way, all of them now fixed.

The models don't rot as the code moves:
- Every model carries an anchor (`mirrors flare/x.mojo#Symbol sha=…`) that goes stale when the Mojo it mirrors changes. A pre-commit hook blocks a commit that leaves a pinned model behind.
- A spec lock fingerprints every theorem statement, so a proof can't be passed by weakening its claim. Only a human re-locks.
- Differential tests run the Lean models and the Mojo code on the same generated inputs.
- A large change can ship a small Lean-verified sans-I/O kernel, like the io_uring buffer-ring ledger.

Cursor skills and hooks in `.cursor/` let an agent do the model upkeep within those rules. The design, with diagrams, is in [`formal/README.md`](formal/README.md#design).

## Security

Per-layer security posture and the sanitised-error-response policy live in [`docs/security.md`](docs/security.md). Highlights: RFC 7230 token validation, configurable size limits, sanitised 4xx/5xx bodies, TLS 1.2+ only, WebSocket frame masking + UTF-8 validation, enforced HTTP/2 DoS caps (header-list / CONTINUATION / rapid-reset), client decompression-bomb cap, 62 fuzz harnesses with 9M+ runs and zero known crashes.

For security issues, please open a private security advisory on GitHub or email the maintainer directly.

## Develop

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install                  # lean: tests, examples, microbench, format-check
pixi install -e dev           # adds mojodoc + pre-commit
```

flare uses six pixi environments:

| Env | Adds | What it unlocks |
|---|---|---|
| `default` | nothing | `tests`, `examples`, microbenchmarks, `format-check` |
| `dev` | `mojodoc`, `pre-commit` | `docs`, `docs-build`, `format` (with hook install) |
| `fuzz` | `dev` + `mozz` | `fuzz-*` / `prop-*` |
| `bench` | `dev` + `go`, `nginx`, `wrk`, `wrk2`, `rust` | `bench-vs-baseline*`, `bench-tail-quick`, `bench-mixed-keepalive`, `bench-soak-*` |
| `metrics` | `lizard` | `complexity`, `coverage`, `metrics` |
| `formal` | `lean4` | `formal-build`, `formal-check`, `formal-status`, `difftest*` (see [`formal/`](formal/)) |

Common tasks (run with `pixi run [--environment <env>] <task>`):

| Task | Env | What it does |
|---|---|---|
| `tests` | `default` | Full unit + integration suite plus every example under [`examples/`](examples/) |
| `format-check` / `format` | `default` / `dev` | `mojo format` over `flare`, `tests`, `benchmark`, `examples`, `fuzz` |
| `check-sans-io` / `check-no-http-http2-cycle` / `check-reactor-size` / `check-example-tasks` | `default` | The four structural lints CI runs on a bare checkout: the sans-io core imports no I/O, `flare.http` and `flare.http2` stay acyclic, per-file size caps with a dated allowlist, and every example is run by something. A few seconds each, no toolchain needed |
| `interop-smoke` | `default` | Talk to flare with software we did not write: curl and h2load on every wire, plus flare's own streaming client pulling a megabyte on each |
| `conformance` | `default` | h2spec and the Autobahn WebSocket suite, each gated against a documented known-fail list; a leg whose binary is not provisioned skips rather than passing |
| `formal-check` / `difftest` / `formal-status` | `formal` | Build the Lean models and audit their axioms; run them against the Mojo code on generated inputs; show stale anchors, unlocked specs and verified kernels on one screen |
| `docs` / `docs-build` | `dev` | mojodoc-rendered package docstring (live or static) |
| `fuzz-all` | `fuzz` | Every harness in [`fuzz/`](fuzz/) (63 harnesses, 9M+ runs combined) |
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
pixi run tests-gen                                      # regenerate tests/_agg after adding a test file
pixi run mojo -I . tests/http/test_router.mojo          # one test file on its own
pixi run --environment fuzz fuzz-all                    # 63 harnesses
pixi run --environment bench bench-vs-baseline-quick    # ~7 min
```

The full task list (per-component + the every-individual-fuzz-harness breakdown) lives in [`pixi.toml`](pixi.toml). The architecture / benchmark / security / cookbook tour is under [`docs/`](docs/).

## License

[MIT](./LICENSE)

[^reuse]: Multi-worker flare uses per-worker `SO_REUSEPORT` listeners by default for `num_workers >= 2` (matching actix_web). Set `FLARE_REUSEPORT_WORKERS=0` to opt into the single-listener `EPOLLEXCLUSIVE` shape, which trades 7-22 % req/s (handler vs static fast path respectively) for a uniformly tight p99.99 across both paths. See [`docs/benchmark.md`](docs/benchmark.md) for the listener-mode A/B and [Production build](#production-build) for the `mojo build -D ASSERT=none` shape these numbers use.
