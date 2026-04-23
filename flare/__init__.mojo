"""The fastest networking library for Mojo🔥, from raw sockets up to HTTP/1.1
servers and WebSocket clients. Written in Mojo with a small FFI footprint
(libc, plus OpenSSL for TLS).

Write a typed request handler, plug it into ``serve(..., num_workers=N)``,
and get a thread-per-core HTTP server that does **257K req/s on 4 cores**
on Linux EPYC (TFB plaintext — 4.4x linear, 3.6x nginx-1w, 7x Go
``net/http``). Kqueue on macOS, epoll on Linux, no thread-per-connection,
no locks on the hot path.

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

## What you get

- **Write** with the ergonomics of Rust ``axum`` (trait-based ``Handler``,
  generics with ``[H: Handler & Copyable]``, ``App[S]`` over typed
  ``State[T]``, middleware as a ``Handler`` wrapping another ``Handler``)
  and the simplicity of Go ``net/http`` (plain ``def`` handlers, no
  ``async`` / ``.await`` — the reactor runs under you). Misconfigured
  servers fail the build via ``comptime assert``, not the first request.
- **Scale** with one parameter. ``srv.serve(handler, num_workers=1)`` is
  the single-threaded reactor (kqueue/epoll) — matches single-worker nginx
  on Linux EPYC and is about 1.10x Go ``net/http`` on Apple M.
  ``srv.serve(handler, num_workers=N)`` with ``N >= 2`` binds N
  ``SO_REUSEPORT`` listeners on N ``pthread`` workers with optional
  per-core pinning: **257K req/s at 4 workers, 4.4x linear scaling**.
  WebSocket XOR masking via SIMD tops **112 GB/s on 1 KB payloads**
  (14–35x scalar).
- **Parse** HTTP **7–9x faster than the next-fastest Mojo HTTP library**
  on the same microbenchmarks. Dual-stack DNS with automatic IPv4/IPv6
  fallback. RFC 7230 header validation and configurable size limits
  built in.
- **Verify** it yourself: **460 tests, 16 fuzz harnesses, over a million
  fuzz runs, zero known crashes to date**. Every example in ``examples/``
  runs on every CI build. Pre-1.0 — expect rough edges.

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
    srv.serve(r^)
```

## App with typed state

```mojo
from flare.http import App, Router, Request, Response, ok, HttpServer
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

def main() raises:
    var router = Router()
    router.get("/", home)
    var app = App(state=Counters(hits=0), handler=router^)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(app^)
```

Any ``Handler`` can be composed with middleware wrappers; middleware is
just a ``Handler`` that holds an inner ``Handler``. See
``examples/18_middleware.mojo`` for a three-layer pipeline
(``Logger`` wrapping ``RequireAuth`` wrapping a ``Router``) and
``examples/16_state.mojo`` for a middleware layer that reads application
state via ``State[T]``.

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
    srv.serve(r^, num_workers=4)
```

``num_workers=1`` (the default) is the single-threaded reactor;
``num_workers >= 2`` binds N ``SO_REUSEPORT`` listeners on N ``pthread``
workers via ``flare.runtime.scheduler.Scheduler``. Each worker gets its
own reactor; the kernel load-balances accepted connections across workers.
``pin_cores=True`` (default) pins worker N to core ``N % num_cpus`` on
Linux; it is a no-op on macOS. The upper bound on ``num_workers`` is 256.

## Comptime handler + config

For single-handler servers, ``serve_comptime[handler, config]`` specialises
the reactor loop at compile time and enforces configuration invariants via
Mojo ``comptime assert`` so misconfigured servers fail the build rather
than the first request:

```mojo
from flare.http import HttpServer, FnHandler, Request, Response, ok
from flare.http.server import ServerConfig
from flare.net import SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

comptime HELLO: FnHandler = FnHandler(hello)
comptime CONFIG: ServerConfig = ServerConfig(
    max_header_size=4096,
    max_body_size=64 * 1024,      # must be >= max_header_size (compile time)
    max_keepalive_requests=1000,
    idle_timeout_ms=30_000,
)

def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_comptime[HELLO, CONFIG]()
```

Break any invariant (e.g. ``max_body_size < max_header_size``) and Mojo
rejects the build with a pointed error. The impossible state doesn't
compile, so no runtime guard is needed.

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
