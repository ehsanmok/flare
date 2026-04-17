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

A fast networking library for Mojo🔥, covering everything from raw sockets to HTTP/1.1 servers and WebSocket clients. Written in Mojo with minimal FFI (just libc and OpenSSL for TLS).

**What you get:**

- TCP, UDP, TLS, HTTP, and WebSocket in one package
- IPv4 and IPv6 out of the box (dual-stack DNS resolution)
- 336 tests and 11 fuzz harnesses, zero known crashes
- HTTP parsing 7-9x faster than other Mojo HTTP libraries
- Server handles ~50K req/s on a single thread

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

The server reads in 8KB chunks, supports HTTP/1.1 keep-alive, validates headers per RFC 7230, and sets recv/send timeouts to prevent stalled clients from blocking other connections.

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
flare = { git = "https://github.com/ehsanmok/flare.git", tag = "v0.1.0" }
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
flare.io    ─ BufReader
    │
flare.ws    ─ WebSocket client + server (RFC 6455)
flare.http  ─ HTTP/1.1 client + server + cookies
    │
flare.tls   ─ TLS 1.2/1.3 (OpenSSL)
    │
flare.tcp   ─ TcpStream + TcpListener (IPv4 + IPv6)
flare.udp   ─ UdpSocket (IPv4 + IPv6)
    │
flare.dns   ─ getaddrinfo (dual-stack)
    │
flare.net   ─ IpAddr, SocketAddr, RawSocket
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

Measured on Apple M-series, Mojo 0.26.3 nightly.

### HTTP parsing

| Operation | Latency |
|-----------|---------|
| Parse HTTP request (headers + body) | 1.7 us |
| Parse HTTP response | 2.2 us |
| Encode HTTP request | 0.7 us |
| Encode HTTP response | 0.9 us |
| Header serialization | 0.12 us |

### Server throughput

| Scenario | Requests/sec | Avg latency |
|----------|-------------|-------------|
| 1 thread, 1 connection | 50,035 | 22 us |
| 4 threads, 100 connections | 50,847 | 49 ms |

Zero socket timeouts under concurrent load.

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
pixi install
```

### Tests

```bash
pixi run tests             # 336 tests + 10 examples

# Individual layers
pixi run test-net          # IpAddr, SocketAddr, errors
pixi run test-dns          # hostname resolution
pixi run test-tcp          # TcpStream, TcpListener, IPv6 loopback
pixi run test-udp          # UdpSocket
pixi run test-tls          # TlsConfig, TlsStream
pixi run test-http         # HeaderMap, Url, HttpClient, Response
pixi run test-ws           # WsFrame, WsClient, WsServer
pixi run test-server       # HTTP server (93 tests)
pixi run test-ergonomics   # high-level API
```

### Benchmarks

```bash
pixi run bench             # all microbenchmarks
pixi run bench-compare     # HTTP encode/parse throughput
pixi run bench-server      # start server, then use wrk against it
```

### Fuzzing

Powered by [mozz](https://github.com/ehsanmok/mozz). 11 harnesses covering HTTP parsing, WebSocket frames, URL parsing, cookies, headers, auth, and encoding.

```bash
pixi run --environment fuzz fuzz-http-server   # 500K runs
pixi run --environment fuzz fuzz-cookie        # 200K runs
pixi run --environment fuzz fuzz-all           # everything
```

### Formatting

```bash
pixi run format            # format all source
pixi run format-check      # CI check (no modifications)
```

## License

[MIT](./LICENSE)
