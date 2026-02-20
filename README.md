# flare 🔥

> [!WARNING]
> **Under development** — APIs may change.

A **foundational networking library for Mojo🔥** — from raw socket primitives up
to HTTP/1.1 and WebSockets, written entirely in Mojo with minimal FFI surface.

- **Correctness above all** — typed errors everywhere; no silent failures
- **Security by default** — TLS 1.2+, injection-safe parsing, DoS limits baked in
- **Zero unnecessary C deps** — only libc (always present) and OpenSSL for TLS
- **Layered architecture** — each layer imports only from layers below it

## Requirements

[pixi](https://pixi.sh) package manager (wraps Mojo nightly automatically)

## Installation

Add flare to your project's `pixi.toml`:

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

---

## Quick Start — High-Level API

The high-level API mirrors the ergonomics of Python's `requests`/`httpx`
and the `websockets` library. It builds on the low-level primitives and adds:
authentication, `raise_for_status`, module-level one-shot helpers, context
managers, typed `WsMessage`, and buffered I/O.

### One-shot HTTP helpers

No client object needed for simple requests. `post` with a `String` body sets
`Content-Type: application/json` automatically — no format parameter needed:

```mojo
from flare.http import get, post

fn main() raises:
    var resp = get("https://httpbin.org/get")
    print(resp.status, resp.ok())          # 200 True
    print(resp.text()[:80])                # raw body

    # String body → Content-Type: application/json automatically
    var r = post("https://httpbin.org/post", '{"hello": "flare"}')
    r.raise_for_status()                   # raises HttpError on non-2xx
    var data = r.json()                    # mojson.Value
    print(data["json"]["hello"].string_value())
```

### HttpClient — base URL, authentication, JSON

`HttpClient` takes base URL and auth as positional arguments — the most
natural call-site syntax:

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth, HttpError

fn main() raises:
    # Base URL as first positional arg — relative paths resolved automatically
    var client = HttpClient("https://api.example.com")
    client.post("/items", '{"name": "flare"}').raise_for_status()

    # HTTP Basic authentication (RFC 7617) — auth as first positional
    var auth_client = HttpClient(BasicAuth("alice", "s3cr3t"))
    var r = auth_client.get("https://httpbin.org/basic-auth/alice/s3cr3t")
    r.raise_for_status()                   # HttpError on 401 / 403
    print(r.json()["authenticated"].bool_value())

    # Base URL + Bearer token — both positional
    with HttpClient("https://api.example.com", BearerAuth("tok_abc123")) as c:
        var items = c.get("/items").json()  # mojson.Value
        c.post("/items", '{"name": "new"}').raise_for_status()
```

### Context managers

All connection types implement `__enter__` / `__exit__` for automatic cleanup:

```mojo
from flare.http import HttpClient
from flare.tcp  import TcpStream
from flare.tls  import TlsStream, TlsConfig
from flare.ws   import WsClient

fn main() raises:
    with HttpClient() as c:
        print(c.get("https://httpbin.org/get").status)

    with TcpStream.connect("localhost", 9000) as stream:
        _ = stream.write("hello\n".as_bytes())

    with TlsStream.connect("example.com", 443, TlsConfig()) as tls:
        _ = tls.write("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".as_bytes())

    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello!")
        print(ws.recv().text_payload())
```

### WebSocket with WsMessage

`recv_message()` returns a typed `WsMessage` wrapper — no raw opcode checks:

```mojo
from flare.ws import WsClient, WsMessage

fn main() raises:
    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello, flare!")
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())           # hello, flare!
```

### Streaming response body

```mojo
from flare.http import get

fn main() raises:
    var resp = get("https://httpbin.org/bytes/8192")
    var total = 0
    for chunk in resp.iter_bytes(4096):
        total += len(chunk)
    print("downloaded", total, "bytes")
```

### Buffered I/O — BufReader

`BufReader[S: Readable]` wraps any readable stream with an internal buffer,
enabling efficient line-by-line or arbitrary-sized reads:

```mojo
from flare.tls import TlsStream, TlsConfig
from flare.io  import BufReader

fn main() raises:
    var stream = TlsStream.connect("example.com", 443, TlsConfig())
    _ = stream.write(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        .as_bytes()
    )
    var reader = BufReader[TlsStream](stream^, capacity=4096)
    # readline() reads up to and including "\n"
    while True:
        var line = reader.readline()
        if line == "":
            break
        print(line, end="")
        if line == "\r\n":
            break                          # blank line = end of headers
```

---

## Quick Start — Low-Level API

Use the low-level API when you need direct control over socket options,
custom framing, or protocols beyond HTTP and WebSocket.

### IP addresses and DNS

```mojo
from flare.net import IpAddr, SocketAddr
from flare.dns import resolve_v4

fn main() raises:
    var ip = IpAddr.parse("192.168.1.100")
    print(ip.is_private())                 # True

    var addr = SocketAddr.parse("127.0.0.1:8080")
    print(addr.port)                       # 8080

    var addrs = resolve_v4("example.com")
    print(addrs[0])                        # 93.184.216.34
```

### TCP

```mojo
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr

fn main() raises:
    # String-based connect overload
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

fn main() raises:
    # TLS 1.2/1.3 — cert verified against pixi CA bundle by default
    var tls = TlsStream.connect("example.com", 443, TlsConfig())
    _ = tls.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".as_bytes())

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    _ = tls.read(buf.unsafe_ptr(), len(buf))
    tls.close()

    # Skip cert verification (testing only)
    var insecure = TlsStream.connect("localhost", 8443, TlsConfig.insecure())
```

### HTTP/1.1 — response details

```mojo
from flare.http import HttpClient, Status, Url
from mojson import Value

fn main() raises:
    var client = HttpClient()

    var resp = client.get("http://httpbin.org/get")
    if resp.status == Status.OK:
        print(resp.text()[:80])               # raw UTF-8 body
    var ct = resp.headers.get("content-type") # case-insensitive lookup

    # Parse JSON body (returns mojson.Value)
    var json_resp = client.get("https://httpbin.org/json")
    var data: Value = json_resp.json()
    print(data["slideshow"]["title"].string_value())

    # URL parsing
    var u = Url.parse("https://api.example.com:8443/v1/users?page=2")
    print(u.host, u.port, u.path)             # api.example.com 8443 /v1/users
```

### WebSocket — raw frame API

```mojo
from flare.ws import WsClient, WsFrame, WsOpcode

fn main() raises:
    var ws = WsClient.connect("ws://echo.websocket.events")

    ws.send_text("Hello, flare WebSocket!")
    var frame = ws.recv()                       # ping/pong handled automatically
    print(frame.text_payload())                 # Hello, flare WebSocket!

    # Manual frame construction
    var f = WsFrame.binary(List[UInt8]([1, 2, 3, 4]))
    var wire = f.encode(mask=True)              # RFC 6455 masked client→server

    ws.close()
```

---

## Development Setup

```bash
git clone https://github.com/ehsanmok/flare.git && cd flare
pixi install        # installs Mojo nightly + OpenSSL + builds TLS FFI wrapper
```

### Tests

```bash
pixi run tests             # full CI suite — all tests + all 7 examples

# Individual layers
pixi run test-net          # IpAddr, SocketAddr, error types
pixi run test-dns          # hostname resolution
pixi run test-tcp          # TcpStream, TcpListener
pixi run test-udp          # UdpSocket
pixi run test-tls          # TlsConfig, TlsStream
pixi run test-http         # HeaderMap, Url, HttpClient, Response
pixi run test-ws           # WsFrame codec, WsClient
pixi run test-ergonomics   # high-level API (Auth, BufReader, WsMessage, …)
```

### Examples

```bash
pixi run examples            # run all 7 examples in sequence

pixi run example-addresses   # IpAddr / SocketAddr construction
pixi run example-dns         # DNS resolve with error handling
pixi run example-errors      # typed error hierarchy
pixi run example-tcp         # TCP bind/accept/ping-pong/64 KiB payload
pixi run example-http        # HTTP GET + POST JSON (plain + TLS)
pixi run example-ws          # WebSocket frame encode/decode + echo
pixi run example-ergonomics  # high-level API (HttpClient, Auth, iter_bytes, BufReader)
```

### Benchmarks

```bash
pixi run bench               # all three benchmarks in sequence

pixi run bench-parse         # IP parsing + DNS throughput (SIMD not useful here)
pixi run bench-ws-mask       # WebSocket XOR masking: scalar vs SIMD (14–35×)
pixi run bench-http          # HeaderMap, Url.parse, Response construction throughput
pixi run bench-tcp           # TCP loopback throughput (requires network)
```

### Code Formatting

```bash
pixi run format              # format all source files in-place
pixi run format-check        # check formatting without modifying (CI)
```

### API Docs

```bash
pixi run docs                # build + serve at http://localhost:3000/flare/
pixi run docs-build          # static HTML → target/doc/ (CI / GitHub Pages)
```

## Layer Architecture

```
flare.io    ─ BufReader (Readable trait)
    │
flare.ws    ─ WebSocket client (RFC 6455)
flare.http  ─ HTTP/1.1 client + HeaderMap + URL
    │
flare.tls   ─ TLS 1.2/1.3 via OpenSSL FFI
    │
flare.tcp   ─ TcpStream + TcpListener
flare.udp   ─ UdpSocket
    │
flare.dns   ─ getaddrinfo(3) FFI
    │
flare.net   ─ IpAddr, SocketAddr, RawSocket, errors
```

Each layer imports only from layers below it. No circular dependencies.

## Security Properties

| Layer | Security Guarantee |
|-------|--------------------|
| `flare.net` | Null bytes, CRLF, `@` in IP strings raise `AddressParseError` before libc |
| `flare.dns` | Null/CRLF/`@` injection, >253-char hostnames, >63-char labels all raise |
| `flare.tls` | TLS ≥ 1.2 only; RC4/NULL/EXPORT/3DES ciphers disabled; SNI always sent |
| `flare.http` | Header injection prevention (`\r`/`\n` in name/value raises `HeaderInjectionError`) |
| `flare.http` | DoS limits: max 100 headers, 8 KB values, 64 KB header block, 100 MB body |
| `flare.ws`  | Client→server frames masked (RFC 6455 §5.3); `Sec-WebSocket-Accept` verified |

## Performance

### WebSocket XOR Masking (Apple M-series, NEON 32-byte SIMD)

RFC 6455 §5.3 requires XOR-masking every client→server byte.
SIMD provides a **14–35× speedup** for production-sized payloads:

| Payload | Scalar | SIMD-32 | Speedup |
|---------|--------|---------|---------|
|  32 B   | 3.2 GB/s | >100 GB/s† | — |
| 128 B   | 2.7 GB/s | >100 GB/s† | — |
|   1 KB  | 3.2 GB/s | 112.6 GB/s | **35×** |
|  64 KB  | 3.4 GB/s |  47.8 GB/s | **14×** |
|   1 MB  | 3.4 GB/s |  54.8 GB/s | **16×** |

†Sub-µs calls exceed benchmark timer resolution.

### HTTP Header Processing (Apple M-series)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| `HeaderMap` (10 set + 3 get) | 4.5 µs | ~220K ops/s |
| `Response` construction | 1.3 µs | ~750K ops/s |
| `Url.parse` (simple) | 0.5 µs | ~2M ops/s |
| `Url.parse` (https + port) | 0.9 µs | ~1.1M ops/s |

### IP Parsing + DNS

| Operation | Throughput / Latency |
|-----------|----------------------|
| `IpAddr.parse` (IPv4) | 0.20 µs/call (5 Mops/s) |
| `IpAddr.parse` (IPv6) | 0.22 µs/call |
| `SocketAddr.parse` | 0.22 µs/call |
| `resolve("localhost")` | 0.17 ms/call — syscall + resolver cache |

## API Documentation

Generated with [mojodoc](https://github.com/ehsanmok/mojodoc):

```bash
pixi run docs          # build + serve at http://localhost:3000/flare/
pixi run docs-build    # static HTML → target/doc/ (CI / GitHub Pages)
```

## License

[MIT](./LICENSE)
