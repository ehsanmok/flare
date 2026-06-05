"""``flare`` -- a Mojo full networking stack in one library.

HTTP/1.1 + HTTP/2 server and client, WebSocket server and
client (RFC 6455), TLS 1.2/1.3 (OpenSSL with ALPN), TCP, UDP,
DNS. The HTTP server and client are version-aware:
``HttpServer.serve(handler)`` peeks the first 24 bytes of every
accepted connection and dispatches HTTP/1.1 or HTTP/2 to the
same handler. ``HttpClient.get("https://...")`` advertises ALPN
``["h2", "http/1.1"]`` and switches wires from what the server
picks. The application surface (``Router``,
middleware, typed extractors, ``Auth``, ``Session[T]``) doesn't
know which wire is talking to it.

Small FFI footprint: libc syscalls, OpenSSL for TLS, zlib +
brotli for content encoding. No HTTP framework dependency.

```mojo
from flare import HttpServer, Router, Request, Response, ok, SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=4)
```

## What flare is

One reactor per worker (``kqueue`` on macOS, ``epoll`` on
Linux, opt-in ``io_uring`` on Linux >= 6.0 via
``FLARE_BUFRING_HANDLER=1``), a ``Handler`` trait that takes plain ``def`` functions
or compiled-down structs, an RFC 7230 parser exercised by 35
fuzz harnesses (8M+ runs combined, zero known crashes), and a ``Cancel`` token plumbed to handlers via
``CancelHandler``. ``num_workers=1`` is a single-threaded
reactor; ``num_workers=N`` with ``N >= 2`` runs N pthread
workers behind per-worker ``SO_REUSEPORT`` listeners by default
(matches actix_web's listener strategy and gives the highest
steady-state throughput). Set ``FLARE_REUSEPORT_WORKERS=0`` to
opt into the single shared listener with ``EPOLLEXCLUSIVE`` --
trades 7-22 % req/s (handler vs static fast path) for a
uniformly tighter p99.99 tail under sustained load. See
``docs/benchmark.md`` for the head-to-head numbers. Static
endpoints can skip the parser entirely with
``serve_static(resp)``.

The operational core: per-request / handler / body-read deadlines,
``HttpServer.drain(timeout_ms)`` for graceful shutdown, sanitised
error responses, ``Request.peer`` threaded from the accept path,
zero-copy reads (``RequestView[origin]`` + ``ViewHandler``),
streaming response primitives (``Body`` / ``ChunkSource`` /
``StreamingResponse[B]``), and server-side TLS (``TlsAcceptor``
over OpenSSL).

The application layer: ``Router`` with path params, typed
extractors (``PathInt`` / ``QueryInt`` /
``HeaderStr`` / ``Form`` / ``Multipart`` / ``Cookies`` / ...),
generic middleware (``Logger`` / ``RequestId`` / ``Compress`` /
``CatchPanic``), ``Cors``, ``FileServer`` with HEAD + Range,
gzip + brotli content negotiation, RFC 6265 cookie jars,
HMAC-SHA256 signed cookies, and typed ``Session[T]`` stores.

## Architecture

```
flare.io       - BufReader
flare.ws       - WebSocket client + server (RFC 6455, permessage-deflate
                 with context-takeover, WS-over-h2 via RFC 8441
                 Extended CONNECT)
flare.http2    - HTTP/2 frame codec + HPACK (with table-driven Huffman
                 fast decoder) + h2c upgrade (RFC 9113 / 7541)
flare.http     - HTTP/1.1 client + reactor server + Router /
                 extractors + middleware (Logger / RequestId / Compress /
                 Cors / Retry / PostHocDeadline / Conditional) + FileServer +
                 forms + cookies + sessions + content-encoding + SSE
                 + template engine with {% block %} / {% extends %}
                 inheritance + sans-I/O parser sublayer under
                 flare.http.proto.*
flare.http.cache - RFC 9111 cache primitives (CacheControl directive
                 parser, CacheKey, InMemoryCacheStore)
flare.grpc     - gRPC primitives on flare.http2: LPM message framing,
                 canonical Status codes (with optional
                 ``grpc-status-details-bin`` payload), Metadata
                 carrier, and the unary server adapter
                 (``GrpcRequestHeaders`` typed request-headers
                 carrier → ``GrpcUnaryReply`` typed handler return
                 (``ok`` / ``err`` factories) → ``run_unary_call``
                 never-raises orchestrator that maps header / LPM /
                 handler failures to typed ``INVALID_ARGUMENT`` /
                 ``INTERNAL`` outcomes)
flare.openapi  - OpenAPI 3.1 spec model + deterministic JSON emitter
flare.quic     - Sans-I/O QUIC v1 codec primitives (varint, long /
                 short packet headers, all 22 RFC 9000 §19 transport
                 frames dispatched via the ``FrameHandler`` trait +
                 ``parse_frame_into[H]`` (per-type callbacks; no
                 intermediate union carrier), with per-type
                 ``encode_*(payload, mut out: List[UInt8])`` writers,
                 RFC 9000 §18 transport parameters, RFC 9000 §3 /
                 §13 connection + stream state machines, CUBIC +
                 HyStart++ congestion controller per RFC 9438 /
                 RFC 9406 / RFC 9002 §7.7), plus the live ``QuicListener``
                 UDP reactor and the rustls QUIC TLS drive that carry
                 HTTP/3 end-to-end
flare.h3       - Sans-I/O HTTP/3 frame codec, SETTINGS payload,
                 request-stream reader (``H3RequestReader`` +
                 ``H3RequestEventHandler`` + ``feed_into[H]`` --
                 typed ``on_headers`` / ``on_data`` / ``on_trailers``
                 callbacks), response-stream writer with QPACK-
                 encoded field sections and the ``mut out:
                 List[UInt8]`` buffer-reuse contract (RFC 9114 §4 +
                 §7)
flare.qpack    - Sans-I/O static-only QPACK encoder / decoder for
                 HTTP/3 field sections (RFC 9204 Appendix A static
                 table + literal + Huffman, shared with HPACK)
flare.crypto   - HMAC-SHA256, base64url
flare.tls      - TLS 1.2/1.3 (OpenSSL, client + server, ALPN, session resumption)
flare.tcp      - TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      - UdpSocket (IPv4 + IPv6)
flare.uds      - UnixListener + UnixStream (AF_UNIX sidecar IPC)
flare.dns      - getaddrinfo (dual-stack)
flare.net      - IpAddr, SocketAddr, RawSocket
flare.runtime  - Reactor (kqueue / epoll, opt-in io_uring on Linux),
                 TimerWheel, Scheduler, HandoffQueue +
                 WorkerHandoffPool, BufferPool, vectored I/O
flare.testing  - TestClient[H] (in-process handler exerciser) +
                 fork_server / kill_forked_server for integration tests
flare.utils    - POSIX FFI thunks (fork / waitpid / kill / usleep /
                 exit / getpid) the Mojo stdlib doesn't expose yet
```

Each layer mostly imports from layers below it. The runtime
scheduler is generic over a ``Frontend`` trait so that
``flare.runtime`` no longer imports from ``flare.http``; the HTTP
worker bring-up lives in ``flare.http.multicore`` and plugs into
the scheduler via that trait. ``flare.http`` still re-imports
``flare.http2`` for the unified reactor dispatch (the only
remaining intra-http cycle, tracked as cleanup in the source).

## HTTP requests

```mojo
from flare.http import get, post

def main() raises:
    var resp = get("https://httpbin.org/get")
    print(resp.status, resp.ok()) # 200 True

    var r = post("https://httpbin.org/post", '{"hello": "flare"}')
    r.raise_for_status()
    var data = r.json()
    print(data["json"]["hello"].string_value())
```

``post`` with a String body sets ``Content-Type: application/json``
automatically.

The server-side sections below build gradually: each one adds one new
concept on top of the previous example.

## Routing: ``Router``

One event loop (kqueue on macOS, epoll on Linux), non-blocking sockets,
a per-connection state machine, a hashed timing wheel for idle
timeouts. Routes carry path parameters (``:name``) and methods;
unknown paths return 404, known paths with the wrong method return 405
with an auto-generated ``Allow:`` header.

```mojo
from flare.http import Router, Request, Response, ok, HttpServer
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))

def create_user(req: Request) raises -> Response:
    return ok("created")

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get("/users/:id", get_user)
    r.post("/users", create_user)

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

## Typed inputs: ``Extracted[H]``

Declare the handler's extractors as the fields of a ``Handler`` struct
and wrap it in ``Extracted[H]``. The adapter reflects on the struct's
field types at compile time to pull each one from the request before
calling the inner ``serve``. Parse failures become automatic 400
responses; ``serve`` is only reached when every field has a value of
the right type.

```mojo
from flare.http import (
    Router, Handler, Request, Response, ok, HttpServer,
    Extracted, PathInt, OptionalQueryInt, HeaderStr,
)
from flare.net import SocketAddr

@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    var id: PathInt["id"]
    var page: OptionalQueryInt["page"]
    var auth: HeaderStr["Authorization"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.page = OptionalQueryInt["page"]()
        self.auth = HeaderStr["Authorization"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user=" + String(self.id.value))

def main() raises:
    var r = Router()
    r.get[Extracted[GetUser]]("/users/:id", Extracted[GetUser]())
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

The concrete ``PathInt`` / ``PathStr`` / ``QueryInt`` / ``HeaderStr``
/ etc. extractors expose ``.value`` directly as the parsed primitive.
Custom types are handled by writing your own ``Extractor`` struct.
Value-constructor extractors (``PathInt["id"].extract(req)``) are
also available for use inside plain ``def`` handlers when the
struct shape is overkill.

## Static route tables: ``ComptimeRouter``

Same routing surface as ``Router``, but the route list is a
compile-time value. Segment parsing happens at build time and the
dispatch loop unrolls per route, so the runtime does zero
string-compares on unknown paths.

```mojo
from flare.http import (
    ComptimeRoute, ComptimeRouter, Request, Response, Method, ok, HttpServer,
)
from flare.net import SocketAddr

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))

def create_user(req: Request) raises -> Response:
    return ok("created")

comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/", home),
    ComptimeRoute(Method.GET, "/users/:id", get_user),
    ComptimeRoute(Method.POST, "/users", create_user),
]

def main() raises:
    var r = ComptimeRouter[ROUTES]()
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^)
```

## Shared state via captured handlers

When a handler needs application-scoped state, build a wrapping
``Handler`` struct that captures the state by value. Middleware
itself is a ``Handler`` that holds another ``Handler``, so you
stack layers by nesting constructors, no callback chain to
thread through.

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

## Scale knob: ``num_workers``

Every server example above takes an optional ``num_workers``. At
``1`` (the default) it's the single-threaded reactor. Set it to
``default_worker_count()`` and flare runs N pthread workers,
each with its own reactor + timer wheel, with per-core pinning
on Linux. The handler type is unchanged.

By default each worker binds its own ``SO_REUSEPORT``
listener (the kernel hashes new 4-tuples to one of N
listeners; matches actix_web's listener strategy and gives
the highest steady-state throughput on dev-box workloads).
Export ``FLARE_REUSEPORT_WORKERS=0`` before launch to
opt back into the single shared listener with
``EPOLLEXCLUSIVE`` -- 7-22 % less req/s (handler vs static
fast path) for a uniformly tighter p99.99 σ under sustained
load (the kernel offers each accept event to whichever
worker is currently parked in ``epoll_wait``, so idle
workers absorb spikes). See [``docs/benchmark.md``](../docs/benchmark.md)
for the head-to-head numbers and the rationale.

```mojo
from flare.http import HttpServer, Router, Request, Response, ok
from flare.net import SocketAddr
from flare.runtime import default_worker_count

def hello(req: Request) raises -> Response:
    return ok("hello")

def main() raises:
    var r = Router()
    r.get("/", hello)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(r^, num_workers=default_worker_count())
```

``pin_cores=True`` (default) pins worker N to core ``N % num_cpus()``
on Linux and is a no-op on macOS. Upper bound on ``num_workers`` is
256.

## Fixed-body endpoints: ``serve_static``

For endpoints that always return the same bytes (health checks, TFB
plaintext, single-URL microservices), ``precompute_response`` builds
the full HTTP wire form at startup and ``HttpServer.serve_static``
runs a specialised reactor that skips the parser's Request-construction
and handler-dispatch step entirely.

```mojo
from flare.http import HttpServer, precompute_response
from flare.net import SocketAddr

def main() raises:
    var resp = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_static(resp)
```

Keep-alive and ``Connection: close`` wire forms are both pre-encoded;
the reactor picks the right one per request from the parsed Connection
header.

## Comptime handler + config

For single-handler servers, ``serve_comptime[handler, config]`` specialises
the reactor loop at compile time and enforces configuration invariants via
Mojo ``comptime assert`` so misconfigured servers fail the build rather
than the first request:

```mojo
from flare.http import HttpServer, Request, Response, ok
from flare.http.handler import FnHandler
from flare.http.server import ServerConfig
from flare.net import SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hello")

comptime HELLO: FnHandler = FnHandler(hello)
comptime CONFIG: ServerConfig = ServerConfig(
    max_header_size=4096,
    max_body_size=64 * 1024, # must be >= max_header_size (compile time)
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

## HTTP/2: same client, same server, version-aware

There is no separate ``Http2Client`` / ``Http2Server`` to learn:
the same :class:`flare.http.HttpClient` and
:class:`flare.http.HttpServer` are HTTP-version-aware internally.

```mojo
from flare.http import HttpClient

def main() raises:
    # https:// auto-negotiates via TLS+ALPN. If the server picks
    # h2 the request is driven through HTTP/2 internally; if it
    # picks http/1.1 (or doesn't speak ALPN at all) the
    # existing HTTP/1.1 wire is used. Either way you get a
    # flare.http.Response back.
    with HttpClient() as c:
        var r = c.get("https://nghttp2.org/")
        print(r.status, r.text())

    # http:// is HTTP/1.1 by default; opt into HTTP/2 cleartext
    # via prior knowledge with prefer_h2c=True:
    with HttpClient(prefer_h2c=True, base_url="http://localhost:8080") as c:
        var r = c.get("/api/users")
        r.raise_for_status()
```

The server side is symmetric -- one accept loop dispatches both
wires per connection (preface peek for cleartext, ALPN ``h2``
for TLS):

```mojo
from flare.http import HttpServer, Request, Response, ok
from flare.net import SocketAddr

def hello(req: Request) raises -> Response:
    return ok("hi")

def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    # The same handler is dispatched whether the client speaks
    # HTTP/1.1 or HTTP/2 over the same port.
    srv.serve(hello, num_workers=4)
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
    print(jar.to_request_header()) # session=abc123

    var c = parse_set_cookie_header("id=42; Path=/; Max-Age=3600")
    print(c.name, c.value, c.max_age) # id 42 3600
```

## Low-level API

### IP addresses and DNS

```mojo
from flare.net import IpAddr, SocketAddr
from flare.dns import resolve

def main() raises:
    var ip = IpAddr.parse("192.168.1.100")
    print(ip.is_private()) # True

    var addr = SocketAddr.parse("[::1]:8080")
    print(addr.ip.is_v6(), addr.port) # True 8080

    var addrs = resolve("example.com") # returns both IPv4 and IPv6
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

# ─────────────────────────────────────────────────────────────────────────
# Curated root surface.
#
# Root re-exports are restricted to the most-used types the typical
# flare application reaches for. Lower-level codecs (HTTP/2 frames,
# QUIC varints, HPACK Huffman, gRPC LPM internals, runtime advanced
# primitives, internal SIMD / intern helpers) live behind their
# respective submodules. For an "everything at the top level" feel,
# use ``from flare.prelude import *``.
# ─────────────────────────────────────────────────────────────────────────

# Errors
from .errors import IoError, ValidationError

# HTTP core types + builders
from .http.server import (
    HttpServer,
    ServerConfig,
    ShutdownReport,
    ok,
    bad_request,
    not_found,
    internal_error,
    redirect,
)
from .http.client import HttpClient, get, post, put, patch, delete, head
from .http.request import Request, Method
from .http.response import Response, Status
from .http.request_view import RequestView
from .http.url import Url, UrlParseError
from .http.headers import HeaderMap, HeaderInjectionError
from .http.cancel import Cancel
from .http.handler import Handler, CancelHandler, ViewHandler
from .http.router import Router
from .http.routes import ComptimeRoute, ComptimeRouter
from .http.auth import Auth, BasicAuth, BearerAuth
from .http.error import HttpError, TooManyRedirects
from .http.static_response import precompute_response
from .http.cookie import Cookie, CookieJar, parse_set_cookie_header

# Extractors (concrete; custom types belong as their own Extractor struct)
from .http.extract import (
    Extractor,
    PathInt,
    PathStr,
    PathFloat,
    PathBool,
    QueryInt,
    QueryStr,
    QueryFloat,
    QueryBool,
    OptionalQueryInt,
    OptionalQueryStr,
    OptionalQueryFloat,
    OptionalQueryBool,
    HeaderInt,
    HeaderStr,
    HeaderFloat,
    HeaderBool,
    OptionalHeaderInt,
    OptionalHeaderStr,
    OptionalHeaderFloat,
    OptionalHeaderBool,
    BodyBytes,
    BodyText,
    Json,
    Cookies,
    Form,
    Multipart,
    Peer,
    Extracted,
)

# Middleware stack
from .http.middleware import (
    CatchPanic,
    Compress,
    Logger,
    RequestId,
)
from .http.cors import Cors, CorsConfig
from .http.cache import Cache
from .http.fs import FileServer
from .http.reliability import Retry, RetryPolicy, PostHocDeadline

# Sessions
from .http.session import (
    Session,
    CookieSessionStore,
    InMemorySessionStore,
)

# TLS
from .tls.config import TlsConfig
from .tls.acceptor import TlsAcceptor, TlsServerConfig

# Networking
from .net.address import IpAddr, SocketAddr
from .tcp.stream import TcpStream
from .tcp.listener import TcpListener

# WebSocket (high-level only; frame codec lives in flare.ws)
from .ws.client import WsClient, WsMessage
from .ws.server import WsServer

# Testing
from .testing import TestClient

# Runtime conveniences
from .runtime._thread import num_cpus
from .runtime.scheduler import default_worker_count
