"""flare — a Mojo HTTP server (HTTP/1.1 + HTTP/2) and HTTP client
(HTTP/1.1 + HTTP/2 over h2c or TLS-ALPN h2), plus the raw TCP,
UDP, TLS, DNS, and WebSocket primitives it's all built on.
Written in Mojo with a small FFI footprint (libc, OpenSSL for
TLS, zlib + brotli for content encoding).

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

One reactor per worker (``kqueue`` on macOS, ``epoll`` on Linux),
a ``Handler`` trait that takes plain ``def`` functions or
compiled-down structs, an RFC 7230 parser with extensive fuzz
coverage, and a ``Cancel`` token plumbed to handlers via
``CancelHandler``. ``num_workers=1`` is a single-threaded reactor;
``num_workers=N`` with ``N >= 2`` runs N pthread workers behind
a single shared listener with ``EPOLLEXCLUSIVE`` (default,
tightest p99.99) or per-worker ``SO_REUSEPORT`` listeners
(opt in via ``FLARE_REUSEPORT_WORKERS=1`` for highest
throughput; see ``docs/benchmark.md``). Static endpoints can
skip the parser entirely with ``serve_static(resp)``.

The operational core: per-request / handler / body-read deadlines,
``HttpServer.drain(timeout_ms)`` for graceful shutdown, sanitised
error responses, ``Request.peer`` threaded from the accept path,
zero-copy reads (``RequestView[origin]`` + ``ViewHandler``),
streaming response primitives (``Body`` / ``ChunkSource`` /
``StreamingResponse[B]``), and server-side TLS (``TlsAcceptor``
over OpenSSL).

The application layer: ``Router`` with path params, ``App[S]`` for
shared state, typed extractors (``PathInt`` / ``QueryInt`` /
``HeaderStr`` / ``Form`` / ``Multipart`` / ``Cookies`` / ...),
generic middleware (``Logger`` / ``RequestId`` / ``Compress`` /
``CatchPanic``), ``Cors``, ``FileServer`` with HEAD + Range,
gzip + brotli content negotiation, RFC 6265 cookie jars,
HMAC-SHA256 signed cookies, and typed ``Session[T]`` stores.

## Architecture

```
flare.io       - BufReader
flare.ws       - WebSocket client + server (RFC 6455)
flare.http2    - HTTP/2 frame codec + HPACK + h2c upgrade (RFC 9113 / 7541)
flare.http     - HTTP/1.1 client + reactor server + Router / App /
                 extractors + middleware + Cors + FileServer +
                 forms + cookies + sessions + content-encoding
flare.crypto   - HMAC-SHA256, base64url
flare.tls      - TLS 1.2/1.3 (OpenSSL, client + server, ALPN)
flare.tcp      - TcpStream + TcpListener (IPv4 + IPv6)
flare.udp      - UdpSocket (IPv4 + IPv6)
flare.dns      - getaddrinfo (dual-stack)
flare.net      - IpAddr, SocketAddr, RawSocket
flare.runtime  - Reactor (kqueue/epoll), TimerWheel, Scheduler,
                 HandoffQueue + WorkerHandoffPool, Pool[T]
```

Each layer only imports from layers below it. No circular dependencies.

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
The parametric ``Path[T: ParamParser, name]`` form is still public
for users who want to plug in a custom ``ParamParser``; concrete
forms cover the common case. Value-constructor extractors
(``PathInt["id"].extract(req)``) are also available for use inside
plain ``def`` handlers when the struct shape is overkill.

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

## Shared state and middleware: ``App[S]``

``App[S, H]`` bundles application-scoped state onto a handler. A
wrapping middleware holds the state snapshot and decorates every
response. Middleware is itself a ``Handler`` that holds another
``Handler``, so you stack layers by nesting constructors, no callback
chain to thread through.

```mojo
from flare.http import App, Router, Request, Response, Handler, State, ok, HttpServer
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int

def home(req: Request) raises -> Response:
    return ok("home")

@fieldwise_init
struct WithHits[Inner: Handler](Handler):
    var inner: Self.Inner
    var snapshot: State[Counters]

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.snapshot.get().hits))
        return resp^

def main() raises:
    var router = Router()
    router.get("/", home)
    var app = App(state=Counters(hits=37), handler=router^)
    var view = app.state_view()

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(WithHits(inner=app^, snapshot=view^))
```

## Scale knob: ``num_workers``

Every server example above takes an optional ``num_workers``. At
``1`` (the default) it's the single-threaded reactor. Set it to
``default_worker_count()`` and flare runs N pthread workers,
each with its own reactor + timer wheel, with per-core pinning
on Linux. The handler type is unchanged.

By default the workers share one listener fd with
``EPOLLEXCLUSIVE`` (the kernel offers each accept event to
whichever worker is currently parked in ``epoll_wait``, giving
the tightest p99.99). Export ``FLARE_REUSEPORT_WORKERS=1``
before launch to instead bind one ``SO_REUSEPORT`` listener
per worker -- ~21 % more req/s for ~0.25 ms more p99.99 on
unpinned dev-boxes / high-core-count instances. See
[``docs/benchmark.md``](../docs/benchmark.md) for the
head-to-head numbers and the rationale.

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
from flare.http import HttpServer, FnHandler, Request, Response, ok
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
# Most-used surface — what the typical user imports.
# ─────────────────────────────────────────────────────────────────────────

from .errors import IoError, ValidationError
from .http.auth_extract import AuthError
from .http.proxy_protocol import ProxyParseError
from .http.template import TemplateError
from .net.address import IpAddr, SocketAddr
from .http.server import (
    HttpServer,
    ServerConfig,
    ShutdownReport,
    ok,
    ok_json,
    bad_request,
    not_found,
    internal_error,
    redirect,
)
from .http.request import Request, Method
from .http.response import Response, Status
from .http.response_pool import ResponsePool
from .http.intern import (
    MethodIntern,
    ValueIntern,
    intern_method_bytes,
    intern_method_string,
    intern_common_value,
    intern_common_value_string,
)
from .http.header_phf import (
    StandardHeader,
    standard_header_count,
    standard_header_name,
    lookup_standard_header_bytes,
    lookup_standard_header_string,
    is_standard_header,
)
from .http.hpack_huffman import (
    HuffmanError,
    huffman_encode,
    huffman_decode,
    huffman_encoded_length,
    huffman_decoded_length,
)
from .http.simd_parsers import (
    HttpParseError,
    simd_memmem,
    simd_percent_decode,
    simd_cookie_scan,
)
from .http.handler import (
    Handler,
    FnHandler,
    FnHandlerCT,
    CancelHandler,
    WithCancel,
    ViewHandler,
    WithViewCancel,
)
from .http.router import Router
from .http.app import App, State
from .http.client import HttpClient, get, post, put, patch, delete, head
from .http.auth import Auth, BasicAuth, BearerAuth
from .runtime._thread import num_cpus
from .runtime.scheduler import default_worker_count

# ─────────────────────────────────────────────────────────────────────────
# Networking primitives.
# ─────────────────────────────────────────────────────────────────────────

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

# flare.uds — Unix-domain sockets
from .uds.listener import UnixListener, accept_uds_fd
from .uds.stream import UnixStream

# flare.tls
from .tls.config import TlsConfig, TlsVerify
from .tls.stream import TlsStream
from .tls.error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)
from .tls.acceptor import (
    TlsAcceptor,
    TlsServerConfig,
    TlsInfo,
    TlsServerError,
    TlsServerNotImplemented,
    TLS_PROTOCOL_TLS12,
    TLS_PROTOCOL_TLS13,
)

# flare.http (additional surface beyond the most-used types re-exported above)
from .http.cancel import Cancel, CancelCell, CancelReason
from .http.headers import HeaderMap, HeaderInjectionError
from .http.header_view import HeaderMapView, parse_header_view
from .http.request_view import RequestView, parse_request_view
from .http.body import (
    Body,
    ChunkSource,
    InlineBody,
    ChunkedBody,
    drain_body,
)
from .http.streaming_response import StreamingResponse
from .http.streaming_serialize import serialize_streaming_response
from .http.url import Url, UrlParseError
from .http.routes import ComptimeRoute, ComptimeRouter
from .http.extract import (
    ParamParser,
    ParamInt,
    ParamFloat64,
    ParamBool,
    ParamString,
    Extractor,
    Path,
    Query,
    OptionalQuery,
    Header,
    OptionalHeader,
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
    Peer,
    BodyBytes,
    BodyText,
    Json,
    Cookies,
    Form,
    Multipart,
    Extracted,
)
from .http.form import (
    FormData,
    parse_form_urlencoded,
    urldecode,
    urlencode,
)
from .http.multipart import (
    MultipartPart,
    MultipartForm,
    parse_multipart_form_data,
)
from .http.session import (
    CookieSessionStore,
    InMemorySessionStore,
    Session,
    SessionCodec,
    StringSessionCodec,
    signed_cookie_decode,
    signed_cookie_decode_keys,
    signed_cookie_encode,
)
from .crypto import (
    base64url_decode,
    base64url_encode,
    hmac_sha256,
    hmac_sha256_verify,
)
from .http.encoding import (
    Encoding,
    compress_gzip,
    compress_brotli,
    decompress_gzip,
    decompress_deflate,
    decompress_brotli,
    decode_content,
)
from .http.middleware import (
    CatchPanic,
    Compress,
    Logger,
    RequestId,
    negotiate_encoding,
)
from .http.cors import Cors, CorsConfig
from .http.fs import ByteRange, FileServer, parse_range
from .http.error import HttpError, TooManyRedirects
from .http.static_response import StaticResponse, precompute_response
from .http.cookie import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)

# flare.http2
from .http2 import (
    H2Connection,
    H2Error,
    H2ErrorCode,
    H2_PREFACE,
    H2_DEFAULT_FRAME_SIZE,
    H2_MAX_FRAME_SIZE,
    HpackEncoder,
    HpackDecoder,
    HpackHeader,
    Connection as H2NetConnection,
    Frame as H2Frame,
    FrameFlags as H2FrameFlags,
    FrameHeader as H2FrameHeader,
    FrameType as H2FrameType,
    Stream as H2Stream,
    StreamState as H2StreamState,
    is_h2_alpn,
    detect_h2c_upgrade,
    encode_frame as h2_encode_frame,
    parse_frame as h2_parse_frame,
    encode_integer as h2_encode_integer,
    decode_integer as h2_decode_integer,
)

# flare.ws
from .ws.client import WsClient, WsHandshakeError, WsMessage
from .ws.server import WsServer
from .ws.frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError

# flare.io
from .io.buf_reader import Readable, BufReader

# flare.runtime (advanced / custom protocols)
from .runtime.reactor import Reactor
from .runtime.timer_wheel import TimerWheel
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
from .runtime.handoff import HandoffPolicy, HandoffQueue, WorkerHandoffPool
from .runtime.date_cache import DateCache
from .runtime.buffer_pool import BufferHandle, BufferPool
from .runtime.iovec import IoVecBuf, writev_buf, writev_buf_all
from .runtime.io_uring import (
    IoUringRing,
    IoUringParams,
    is_io_uring_available,
)
