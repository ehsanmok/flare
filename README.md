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

flare is **pre-1.0**. The bar isn't "is it fast" — it's *is it hard to misuse under load and easy to operate*. The v0.5 work is about exactly that. See [`docs/operational-guarantees.md`](docs/operational-guarantees.md) for the concern-by-concern table.

## Operational guarantees (a teaser)

| Concern | flare guarantees | Since |
|---|---|---|
| Partial reads / writes | reactor buffers and retries on writable edges | v0.3.0 |
| Cancellation (peer disconnect, deadlines, shutdown) | `Cancel` token plumbed to handlers via `CancelHandler.serve(req, cancel)` | v0.5.0 Step 1 |
| Graceful shutdown | `HttpServer.drain(timeout_ms)` + `install_drain_on_sigterm` | v0.5.0 Step 1 |
| Sanitised 4xx / 5xx error bodies | extractor messages logged with request id, never echoed by default | v0.5.0 Step 1 |
| Per-request / handler / body-read deadlines | `ServerConfig.{request,handler,read_body}_timeout_ms`, all default non-zero | v0.5.0 Step 1 |
| Header / URI / body size limits | configurable; defaults: 8 KB / 8 KB / 10 MB | v0.3.0 |
| RFC 7230 header validation | rejected at parse time | v0.2.0 |

The full table — partial-read semantics, half-open handling, planned items, what version each row targets — lives in [`docs/operational-guarantees.md`](docs/operational-guarantees.md).

## What flare doesn't do yet

Explicit non-goals so you don't ship into a hole:

- **No streaming response bodies** until v0.5.0 Step 2. `Response` materialises before the first `send`. Keep response bodies bounded for now.
- **No server-side TLS** until v0.5.0 Step 3. Client TLS works. Today's deployment story is "terminate TLS at nginx / Caddy in front of flare." (Don't read more into the README than that.)
- **No public `async` / `await`** — Mojo doesn't ship async yet. The reactor is the foundation; the public API gains an `async` variant when the language is ready (target v1.0).
- **No HTTP/2** until v0.6. Requires server TLS first. HPACK lives on the v0.6 roadmap with a 5M-run fuzz gate before tag.
- **No HTTP/3 / QUIC, no WebTransport, no h2c.** Permanent non-goals for the v0.x line.

## Quick start

The full walk-through, gradually-disclosed, used to live here. It now lives in the package docstring on [`flare/__init__.mojo`](flare/__init__.mojo) (rendered at <https://ehsanmok.github.io/flare/>) and in the runnable examples under [`examples/`](examples/). [`docs/cookbook.md`](docs/cookbook.md) maps "I want to..." to the right example.

```mojo
# Path parameters
from flare.http import Router, ok, Request, Response, HttpServer
from flare.net import SocketAddr

def get_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))

def main() raises:
    var r = Router()
    r.get("/users/:id", get_user)
    HttpServer.bind(SocketAddr.localhost(8080)).serve(r^, num_workers=4)
```

```mojo
# Cancel-aware handler (v0.5.0 Step 1) — short-circuits on peer disconnect,
# deadline, or drain.
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

For path params + query + header in one struct (`Extracted[H]`), comptime route tables, app state, middleware composition, multicore knob, static-response fast path, comptime config — see [`docs/cookbook.md`](docs/cookbook.md) and the linked examples.

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
