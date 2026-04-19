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

**The fastest networking library for Mojo🔥**, from raw sockets up to HTTP/1.1 servers and WebSocket clients. Written in Mojo with a small FFI footprint (libc, plus OpenSSL for TLS).

**What you get:**

- Single-threaded reactor HTTP server (kqueue / epoll). On Linux AWS EPYC: on par with single-worker nginx and ~2x Go's `net/http`. On Apple M-series: ~1.1x Go's `net/http`. See [benchmarks](#server-throughput-tfb-plaintext).
- HTTP request and response parsing is 7 to 9x faster than the next-fastest Mojo HTTP library on the same microbenchmarks.
- WebSocket XOR masking uses SIMD and reaches 112 GB/s on 1KB payloads, 14 to 35x the scalar path.
- TCP, UDP, TLS, HTTP, WebSocket, and DNS in one package with IPv4 and IPv6 out of the box, and dual-stack DNS with automatic fallback.
- 375 tests and 15 fuzz harnesses. Over a million fuzz runs and zero known crashes.

## Quick start

### HTTP requests

```mojo
from flare.http import get, post

def main() raises:
    var resp = get("https://httpbin.org/get")
    print(resp.status, resp.ok())          # 200 True

    var r = post("https://httpbin.org/post", '{"hello": "flare"}')
    r.raise_for_status()
    var data = r.json()
    print(data["json"]["hello"].string_value())
```

`post` with a String body sets `Content-Type: application/json` automatically.

### HTTP server

```mojo
from flare.http import HttpServer, Request, Response, ok, ok_json, not_found
from flare.net import SocketAddr

def handler(req: Request) raises -> Response:
    if req.url == "/":
        return ok("hello")
    if req.url == "/data":
        var body = req.json()
        return ok_json('{"received": true}')
    return not_found(req.url)

def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(handler)
```

Under the hood the server is one event loop (kqueue on macOS, epoll on Linux), non-blocking sockets, a per-connection state machine, and a hashed timing wheel for idle timeouts. This is the nginx-style model, no thread per connection. HTTP/1.1 keep-alive, RFC 7230 header validation, and configurable limits on header, body, and URI size plus per-connection idle and write timeouts are all handled for you.

### HTTP client with auth

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth

def main() raises:
    var client = HttpClient("https://api.example.com", BearerAuth("tok_abc"))
    var items = client.get("/items").json()
    client.post("/items", '{"name": "new"}').raise_for_status()
```

### WebSocket

```mojo
from flare.ws import WsClient

def main() raises:
    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello")
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())
```

### Cookies

```mojo
from flare.http import Cookie, CookieJar, parse_set_cookie_header

def main() raises:
    var jar = CookieJar()
    jar.set(Cookie("session", "abc123", secure=True, http_only=True))
    print(jar.to_request_header())  # session=abc123

    var c = parse_set_cookie_header("id=42; Path=/; Max-Age=3600")
    print(c.name, c.value, c.max_age)  # id 42 3600
```

## Installation

Add flare to your project's `pixi.toml`:

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "v0.3.0" }
```

Then run:

```bash
pixi install
```

Requires [pixi](https://pixi.sh) (pulls Mojo nightly automatically).

For the latest development version:

```toml
[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

## What's inside

```
flare.io       ─ BufReader
    │
flare.ws       ─ WebSocket client + server (RFC 6455)
flare.http     ─ HTTP/1.1 client + reactor-backed server + cookies
    │
flare.tls      ─ TLS 1.2/1.3 (OpenSSL)
    │
flare.tcp      ─ TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      ─ UdpSocket (IPv4 + IPv6)
    │
flare.dns      ─ getaddrinfo (dual-stack)
    │
flare.net      ─ IpAddr, SocketAddr, RawSocket
flare.runtime  ─ Reactor (kqueue/epoll), TimerWheel, Event
```

Each layer only imports from layers below it. No circular dependencies.

## Low-level API

For direct socket control, custom framing, or protocols beyond HTTP:

### IP addresses and DNS

```mojo
from flare.net import IpAddr, SocketAddr
from flare.dns import resolve

def main() raises:
    var ip = IpAddr.parse("192.168.1.100")
    print(ip.is_private())                 # True

    var addr = SocketAddr.parse("[::1]:8080")
    print(addr.ip.is_v6(), addr.port)      # True 8080

    var addrs = resolve("example.com")     # returns both IPv4 and IPv6
    print(addrs[0])
```

### TCP

```mojo
from flare.tcp import TcpStream

def main() raises:
    var conn = TcpStream.connect("localhost", 8080)
    _ = conn.write("Hello\n".as_bytes())

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = conn.read(buf.unsafe_ptr(), len(buf))
    conn.close()
```

### TLS

```mojo
from flare.tls import TlsStream, TlsConfig

def main() raises:
    var tls = TlsStream.connect("example.com", 443, TlsConfig())
    _ = tls.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".as_bytes())
    tls.close()
```

### WebSocket frames

```mojo
from flare.ws import WsClient, WsFrame

def main() raises:
    var ws = WsClient.connect("ws://echo.websocket.events")
    ws.send_text("ping")
    var frame = ws.recv()
    print(frame.text_payload())
    ws.close()
```

## Security

| Layer | What it does |
|-------|-------------|
| `flare.net` | Rejects null bytes, CRLF, `@` in IP strings before they reach libc |
| `flare.dns` | Blocks injection in hostnames (null/CRLF/`@`, length limits) |
| `flare.tls` | TLS 1.2+ only, weak ciphers disabled, SNI always sent |
| `flare.http` | Header injection prevention, RFC 7230 token validation |
| `flare.http` | Configurable limits on headers (8KB), body (10MB), URI (8KB) |
| `flare.ws` | Client frames masked per RFC 6455, `Sec-WebSocket-Accept` verified |
| `flare.ws` | CSPRNG nonce for handshake key, UTF-8 validation on TEXT frames |

## Performance

Measured on Apple M-series, Mojo 0.26.3.0.dev2026041805 nightly.

### Server throughput (TFB plaintext)

macOS, Apple M-series, Mojo 0.26.3.0.dev2026041805 nightly.

| Server | Req/s (median) | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|
| **flare (reactor)** | **157,459** | 0.39 ms | 0.80 ms | **1.10x** |
| Go `net/http` (1 thread) | 143,500 | 0.44 ms | 0.86 ms | 1.00x |

flare is about 1.10x faster than Go's stdlib `net/http` at the same thread count, a roughly 3x jump over the v0.2.0 blocking server.

Linux, AWS EPYC 7R32 (64 vCPU), Linux 6.8.0-1027-aws, Mojo 0.26.3.0.dev2026041805, Go 1.24.13, nginx 1.25.3, `wrk` d40fce9. Same harness, same 5-run median with stdev ≤ 3% stability gate, different machine. Absolute req/s is not comparable across the two tables (different OS, scheduler, CPU), only the intra-platform ratios are. conda-forge ships an `nginx` binary on `linux-64`, so the Linux sweep adds nginx as an extra reference point.

| Server | Req/s (median) | p50 | p99 | vs Go `net/http` |
|---|---:|---:|---:|---:|
| nginx (1 worker) | 81,612 | 0.40 ms | 0.79 ms | 2.00x |
| **flare (reactor)** | **79,965** | 0.78 ms | 1.53 ms | **1.96x** |
| Go `net/http` (1 thread) | 40,739 | 1.59 ms | 3.10 ms | 1.00x |

On Linux flare sits within 2% of nginx's single-worker throughput and is about 1.96x Go `net/http`. The flare-vs-Go ratio is actually wider on Linux (1.96x vs 1.10x) because Go's scheduler and `netpoll` overhead is a bigger share of each request on the slower EPYC core than on an Apple M-series P-core. Absolute req/s is lower on EPYC for reasons independent of flare, see [^bench-platform].

[^bench-platform]: Three things about the Linux column are deliberate, not "flare can only hit 77K/s in production":
    1. **`GOMAXPROCS=1`, `worker_processes 1`, and single-thread flare.** Every baseline runs on one logical core so the comparison is apples-to-apples about per-core request-processing cost. This models the cheapest hosting tier (one vCPU) rather than peak throughput on the box. Production deployments on either platform should scale with worker count (nginx, Go) or with `SO_REUSEPORT` sharding.
    2. **`wrk` and the server are not CPU-pinned.** On a 64-vCPU AWS instance the Linux scheduler migrates both processes across cores between slices, causing L1/L2 misses and occasional SMT-sibling contention. Pinning `wrk` and the server to two different physical cores on the same NUMA node typically recovers 15 to 30% for Go on EPYC (a known `net/http` behaviour on shared-scheduler Linux, which is also where the flare-vs-Go ratio shift between the two platforms comes from). The harness intentionally does not pin so the numbers match an un-tuned deployment.
    3. **c5-class EC2 does not turbo like M-series.** Single-thread throughput on EPYC 7R32 is roughly half of an Apple M-series P-core for HTTP plaintext. That is microarchitecture, not a scheduler or runtime property. flare and nginx both drop by about 2x between the two tables; Go drops by about 3.5x because its goroutine plus `netpoll` overhead is a bigger percentage of each request on the slower core.

Reproduce locally (on either platform):

```bash
pixi run --environment bench bench-vs-baseline-quick   # flare vs Go only, ~7 min
pixi run --environment bench bench-vs-baseline         # + nginx + latency_floor, ~20 min
```

#### Methodology

The workload is the [TechEmpower Framework Benchmarks plaintext test (type #6)](https://github.com/TechEmpower/FrameworkBenchmarks/wiki/Project-Information-Framework-Tests-Overview#test-type-6-plaintext): `GET /plaintext` returning the 13-byte body `Hello, World!` with `Content-Type: text/plain`, HTTP/1.1 keep-alive on, no gzip, no logging. The workload spec lives at [`benchmark/workloads/plaintext.yaml`](benchmark/workloads/plaintext.yaml). Plaintext measures the cost of request routing and response serialisation on its own, without any database, template, or JSON work.

Measurement rules:

- Response-byte integrity: before any measurement round, each baseline is probed once and its response bytes are diffed against the workload spec. A target producing a different status, body length, or non-whitelisted header is rejected. Headers allowed to vary per target: `Date`, `Server`, `Connection`, `Keep-Alive`.
- Pinned toolchains: Go and `wrk` versions are pinned in `pixi.toml` under `[feature.bench.dependencies]` so the comparison does not silently drift across machines.
- Warmup and 5-run measurement: each (target, config) tuple runs one 10 s warmup followed by five 30 s measurement rounds. The median of the middle three is reported. The run fails the stability gate if stdev exceeds 3%.
- Load generator: `wrk -t1 -c64 -d30s`, one `wrk` thread, 64 keep-alive connections, 30 seconds per round. Server and `wrk` run on the same host over loopback. The load generator is always `wrk`, never `ab` or `h2load`, for consistency with published TFB-style numbers.
- Per-run provenance: every run writes its own directory under `benchmark/results/<yyyy-mm-ddTHHMM>-<host>-<git-sha>/` containing `env.json` (CPU model, OS, kernel tunables, exact toolchain versions), `integrity.md`, per-tuple result JSONs, `summary.md`, and raw `wrk` stdout under `RAW/`.

This protocol (integrity check, pinned toolchains, 5-run median with stdev gate) is stricter than TFB's own single 15 s round on shared hardware. It is closer to the reproducibility setups in [simdjson](https://github.com/simdjson/simdjson/blob/master/doc/performance.md) and [rapidjson](https://rapidjson.org/md_doc_performance.html).

### HTTP parsing

| Operation | Latency |
|-----------|---------|
| Parse HTTP request (headers + body) | 1.7 us |
| Parse HTTP response | 2.2 us |
| Encode HTTP request | 0.7 us |
| Encode HTTP response | 0.9 us |
| Header serialization | 0.12 us |

### WebSocket SIMD masking

RFC 6455 requires XOR-masking every client-to-server byte. SIMD gives a 14-35x speedup for payloads above 128 bytes:

| Payload | Scalar | SIMD-32 |
|---------|--------|---------|
| 1 KB | 3.2 GB/s | 112.6 GB/s |
| 64 KB | 3.4 GB/s | 47.8 GB/s |
| 1 MB | 3.4 GB/s | 54.8 GB/s |

## Development

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare

# Option A, users and CI (lean): runtime deps, tests, examples,
# microbenchmarks, and format-check.
pixi install

# Option B, contributors: adds mojodoc and pre-commit for docs and the
# formatting hook. Use this if you plan to run `pixi run format` or
# `pixi run docs`.
pixi install -e dev
```

flare uses four pixi environments, layered:

| Environment | Adds on top of `default` | What it unlocks |
|---|---|---|
| `default` | nothing (lean runtime only) | `tests`, `examples`, microbenchmarks (`bench-*`), `format-check` |
| `dev` | `mojodoc`, `pre-commit` | `docs`, `docs-build`, `format` (with pre-commit hook install) |
| `fuzz` | `dev` + `mozz` | `fuzz-*` / `prop-*` harnesses |
| `bench` | `dev` + `go`, `nginx`, `wrk` | `bench-vs-baseline*`, TFB-style server benchmarks |

Tasks always run under `default` unless you pass `-e <env>`, e.g. `pixi run -e dev docs-build`, `pixi run -e fuzz fuzz-all`, `pixi run -e bench bench-vs-baseline-quick`.

### Tests

```bash
pixi run tests             # 375 tests + 14 examples

# Individual layers
pixi run test-net                    # IpAddr, SocketAddr, errors
pixi run test-dns                    # hostname resolution
pixi run test-tcp                    # TcpStream, TcpListener, IPv6 loopback
pixi run test-udp                    # UdpSocket
pixi run test-tls                    # TlsConfig, TlsStream
pixi run test-http                   # HeaderMap, Url, HttpClient, Response
pixi run test-ws                     # WsFrame, WsClient, WsServer
pixi run test-server                 # HTTP server (93 tests)
pixi run test-server-reactor-state   # Reactor connection state machine
pixi run test-reactor                # Reactor (kqueue/epoll) abstraction
pixi run test-reactor-shutdown       # HttpServer graceful shutdown
pixi run test-timer-wheel            # TimerWheel
pixi run test-syscall-ffi            # Low-level epoll/kqueue/eventfd FFI
pixi run test-ergonomics             # high-level API
```

### Examples

Fourteen runnable examples under [`examples/`](examples/), each an end-to-end walk-through of one slice of the public API. Every example is executed as part of `pixi run tests` and on CI, so they stay green with the code.

| File | What it shows |
|---|---|
| [`01_addresses.mojo`](examples/01_addresses.mojo) | `IpAddr`, `SocketAddr`, v4/v6 classification |
| [`02_dns_resolution.mojo`](examples/02_dns_resolution.mojo) | `resolve()`, `resolve_v4()`, `resolve_v6()`, numeric-IP passthrough |
| [`03_error_handling.mojo`](examples/03_error_handling.mojo) | typed error hierarchy and the context each error carries |
| [`04_tcp_echo.mojo`](examples/04_tcp_echo.mojo) | `TcpListener` + `TcpStream` round-trip, TCP options |
| [`05_http_get.mojo`](examples/05_http_get.mojo) | `HttpClient` GET / POST / PUT / PATCH / DELETE / HEAD |
| [`06_websocket_echo.mojo`](examples/06_websocket_echo.mojo) | `WsClient` connect, send, receive |
| [`07_ergonomics.mojo`](examples/07_ergonomics.mojo) | high-level requests-style API (`BufReader`, `WsMessage`, `Auth`) |
| [`08_http_server.mojo`](examples/08_http_server.mojo) | `HttpServer` with routing, JSON responses, response helpers |
| [`09_ws_server.mojo`](examples/09_ws_server.mojo) | `WsServer` handshake + frame loop |
| [`10_encoding.mojo`](examples/10_encoding.mojo) | gzip / deflate compress and decompress |
| [`11_udp.mojo`](examples/11_udp.mojo) | `UdpSocket.bind`, `send_to`, `recv_from`, `DatagramTooLarge` |
| [`12_tls.mojo`](examples/12_tls.mojo) | `TlsConfig`, `TlsStream.connect`, raw TLS handshake + GET |
| [`13_cookies.mojo`](examples/13_cookies.mojo) | `Cookie`, `CookieJar`, `parse_cookie_header`, `parse_set_cookie_header` |
| [`14_reactor.mojo`](examples/14_reactor.mojo) | direct `flare.runtime.Reactor` usage (kqueue/epoll) for custom protocols |

Run any single example with `pixi run example-<name>` (see the full list in [`pixi.toml`](pixi.toml)).

### Benchmarks

See the [Methodology](#methodology) section above for the TFB plaintext workload definition, integrity check, and run protocol.

```bash
pixi run --environment bench bench-vs-baseline-quick
# flare vs Go net/http, throughput config only (~7 min total)

pixi run --environment bench bench-vs-baseline
# flare vs all baselines, throughput + latency_floor configs
```

Results and `env.json` are written under `benchmark/results/<timestamp>-<host>-<commit>/`.

#### Microbenchmarks

```bash
pixi run bench             # all microbenchmarks in sequence
pixi run bench-compare     # HTTP encode/parse throughput
pixi run bench-http        # HeaderMap, Url.parse, Response construction
pixi run bench-ws-mask     # WebSocket XOR masking: scalar vs SIMD
pixi run bench-parse       # IP parsing + DNS resolution
```

### Fuzzing

Powered by [mozz](https://github.com/ehsanmok/mozz). 15 harnesses covering HTTP parsing, WebSocket frames, URL parsing, cookies, headers, auth, encoding, and the reactor / connection state machine.

```bash
pixi run --environment fuzz fuzz-http-server             # 500K runs
pixi run --environment fuzz fuzz-reactor-churn           # 200K runs
pixi run --environment fuzz fuzz-server-reactor-chunks   # 30K runs
pixi run --environment fuzz prop-timer-wheel             # 100K runs
pixi run --environment fuzz fuzz-all                     # everything
```

### Formatting

```bash
pixi run -e dev format     # format all source (also installs pre-commit hook)
pixi run format-check      # read-only CI check (runs under lean default env)
```

`format` lives in the `dev` feature because it also wires up the git
`pre-commit` hook, which needs the `pre-commit` package. `format-check`
shells out to `mojo format` (shipped with the base compiler), so it
runs under the lean `default` env and doesn't drag in any contributor
tooling.

## License

[MIT](./LICENSE)
