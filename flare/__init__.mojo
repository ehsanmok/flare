"""The fastest networking library for Mojo, from raw sockets up to HTTP/1.1
servers and WebSocket clients. Written in Mojo with minimal FFI (just libc
and OpenSSL for TLS).

## What you get

- Single-threaded reactor HTTP server (kqueue on macOS, epoll on Linux).
  Within 2% of single-worker nginx and about 1.96x Go ``net/http`` on
  Linux AWS EPYC. 1.10x Go ``net/http`` on Apple M-series. TFB plaintext,
  ``GOMAXPROCS=1`` and ``worker_processes 1``.
- HTTP request and response parsing is 7 to 9x faster than the
  next-fastest Mojo HTTP library on the same microbenchmarks.
- WebSocket XOR masking uses SIMD and reaches 112 GB/s on 1KB payloads,
  14 to 35x the scalar path.
- TCP, UDP, TLS, HTTP, WebSocket, and DNS in one package with IPv4 and
  IPv6 out of the box, and dual-stack DNS with automatic fallback.
- ``Handler`` trait + ``Router`` + ``App[S]`` with typed ``State[T]``
  for composable, testable request handling.
- Multicore reactor via ``HttpServer.serve_multicore`` with
  ``SO_REUSEPORT`` listeners and pthread-based CPU pinning on Linux.
- 463 tests and 16 fuzz harnesses. Over a million fuzz runs and zero
  known crashes.

## Architecture

```
flare.io       - BufReader
flare.ws       - WebSocket client + server (RFC 6455)
flare.http     - HTTP/1.1 client + reactor-backed server + cookies
flare.tls      - TLS 1.2/1.3 (OpenSSL)
flare.tcp      - TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      - UdpSocket (IPv4 + IPv6)
flare.dns      - getaddrinfo (dual-stack)
flare.net      - IpAddr, SocketAddr, RawSocket
flare.runtime  - Reactor (kqueue/epoll), TimerWheel, Event
```

Each layer only imports from layers below it. No circular dependencies.

## HTTP requests

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

``post`` with a String body sets ``Content-Type: application/json``
automatically.

## HTTP server

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

## Routing with path parameters and method dispatch

```mojo
from flare.http import Router, Request, Response, ok, HttpServer
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get("/users/:id", get_user)
    r.post("/users", home)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_with(r^)
```

## App with typed state

```mojo
from flare.http import App, Router, Request, Response, ok

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

def main() raises:
    var router = Router()
    router.get("/", home)
    var app = App(state=Counters(hits=0), handler=router^)
    # app.state_view() returns a State[Counters] for middleware layers
    # to read; serve via HttpServer.serve_with(app^).
```

## Multicore (thread-per-core)

```mojo
from flare.http import HttpServer, Router, Request, Response, ok
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", home)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_multicore(r^, num_workers=4)
```

Under the hood ``serve`` runs a single event loop on ``kqueue`` (macOS)
or ``epoll`` (Linux) with non-blocking sockets, a per-connection state
machine, and a hashed timing wheel for idle timeouts. This is the
nginx-style model, no thread per connection. HTTP/1.1 keep-alive,
RFC 7230 header validation, and configurable limits on header, body,
and URI size plus per-connection idle and write timeouts are all
handled for you.

## HTTP client with auth

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth

def main() raises:
    var client = HttpClient("https://api.example.com", BearerAuth("tok_abc"))
    var items = client.get("/items").json()
    client.post("/items", '{"name": "new"}').raise_for_status()
```

## WebSocket

```mojo
from flare.ws import WsClient

def main() raises:
    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello")
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())
```

## Cookies

```mojo
from flare.http import Cookie, CookieJar, parse_set_cookie_header

def main() raises:
    var jar = CookieJar()
    jar.set(Cookie("session", "abc123", secure=True, http_only=True))
    print(jar.to_request_header())  # session=abc123

    var c = parse_set_cookie_header("id=42; Path=/; Max-Age=3600")
    print(c.name, c.value, c.max_age)  # id 42 3600
```

## Low-level API

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
    _ = conn.write("Hello\\n".as_bytes())

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
    _ = tls.write("GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n".as_bytes())
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

### Reactor (advanced)

```mojo
from flare.runtime import Reactor, Event, INTEREST_READ

def main() raises:
    var r = Reactor()
    # Register a non-blocking fd; see ``Reactor`` docs for a full example.
```
"""

# flare.net
from .net.address import IpAddr, SocketAddr
from .net.socket import RawSocket
from .net.error import (
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    AddressInUse,
    AddressParseError,
    BrokenPipe,
    DnsError,
    Timeout,
)

# flare.dns
from .dns.resolver import resolve, resolve_v4, resolve_v6

# flare.tcp
from .tcp.stream import TcpStream
from .tcp.listener import TcpListener

# flare.udp
from .udp.socket import UdpSocket, DatagramTooLarge

# flare.tls
from .tls.config import TlsConfig, TlsVerify
from .tls.stream import TlsStream
from .tls.error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)

# flare.http
from .http.headers import HeaderMap, HeaderInjectionError
from .http.url import Url, UrlParseError
from .http.request import Request, Method
from .http.response import Response, Status
from .http.handler import Handler, FnHandler, FnHandlerCT
from .http.router import Router
from .http.app import App, State
from .http.encoding import (
    Encoding,
    compress_gzip,
    decompress_gzip,
    decompress_deflate,
    decode_content,
)
from .http.error import HttpError, TooManyRedirects
from .http.auth import Auth, BasicAuth, BearerAuth
from .http.client import HttpClient, get, post, put, patch, delete, head
from .http.server import (
    HttpServer,
    ServerConfig,
    ok,
    ok_json,
    bad_request,
    not_found,
    internal_error,
    redirect,
)
from .http.cookie import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)

# flare.ws
from .ws.frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from .ws.client import WsClient, WsHandshakeError, WsMessage
from .ws.server import WsServer

# flare.io
from .io.buf_reader import Readable, BufReader

# flare.runtime
from .runtime.event import (
    Event,
    INTEREST_READ,
    INTEREST_WRITE,
    EVENT_READABLE,
    EVENT_WRITABLE,
    EVENT_ERROR,
    EVENT_HUP,
    WAKEUP_TOKEN,
)
from .runtime.reactor import Reactor
from .runtime.timer_wheel import TimerWheel
