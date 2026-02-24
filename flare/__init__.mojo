"""flare: A foundational networking library for Mojo🔥.

> **Under development.** APIs may change.

A foundational networking library for Mojo🔥, from raw socket primitives up
to HTTP/1.1 and WebSockets. Written entirely in Mojo with minimal FFI surface.

## Principles

- **Correctness above all**: typed errors everywhere; no silent failures
- **Security by default**: TLS 1.2+, injection-safe parsing, DoS limits baked in
- **Zero unnecessary C deps**: only libc (always present) and OpenSSL for TLS
- **Layered architecture**: each layer imports only from layers below it

## Layer Architecture

```
flare.io    - BufReader (Readable trait)
    |
flare.ws    - WebSocket client (RFC 6455)
flare.http  - HTTP/1.1 client + HeaderMap + URL
    |
flare.tls   - TLS 1.2/1.3 via OpenSSL FFI
    |
flare.tcp   - TcpStream + TcpListener
flare.udp   - UdpSocket
    |
flare.dns   - getaddrinfo(3) FFI
    |
flare.net   - IpAddr, SocketAddr, RawSocket, errors
```

## Quick Start: High-Level API

### One-shot HTTP helpers

No client object needed for simple requests. `post` with a `String` body sets
`Content-Type: application/json` automatically, no format parameter needed:

```mojo
from flare.http import get, post

fn main() raises:
    var resp = get("https://httpbin.org/get")
    print(resp.status, resp.ok())          # 200 True
    print(resp.text()[:80])

    # String body sets Content-Type: application/json automatically
    var r = post("https://httpbin.org/post", '{"hello": "flare"}')
    r.raise_for_status()
    print(r.json()["json"]["hello"].string_value())
```

### HttpClient: base URL, authentication, JSON

`HttpClient` takes base URL and auth as positional arguments, the most
natural call-site syntax:

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth, HttpError

fn main() raises:
    # Base URL as first positional arg, relative paths resolved automatically
    var client = HttpClient("https://api.example.com")
    client.post("/items", '{"name": "flare"}').raise_for_status()

    # HTTP Basic authentication (RFC 7617), auth as first positional
    var auth_client = HttpClient(BasicAuth("alice", "s3cr3t"))
    auth_client.get("https://httpbin.org/basic-auth/alice/s3cr3t").raise_for_status()

    # Base URL + Bearer token, both positional
    with HttpClient("https://api.example.com", BearerAuth("tok_abc123")) as c:
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

    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello!")
        print(ws.recv().text_payload())
```

### WebSocket with WsMessage

`recv_message()` returns a typed `WsMessage` wrapper, no raw opcode checks:

```mojo
from flare.ws import WsClient, WsMessage

fn main() raises:
    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello, flare!")
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())
```

### Buffered I/O: BufReader

`BufReader[S: Readable]` wraps any readable stream for efficient line reads:

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
    while True:
        var line = reader.readline()
        if line == "" or line == "\r\n":
            break
        print(line, end="")
```

## Quick Start: Low-Level API

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
from flare.tcp import TcpStream

fn main() raises:
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
    # TLS 1.2/1.3, cert verified against pixi CA bundle by default
    var tls = TlsStream.connect("example.com", 443, TlsConfig())
    _ = tls.write("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n".as_bytes())
    tls.close()

    # Skip cert verification (testing only)
    var insecure = TlsStream.connect("localhost", 8443, TlsConfig.insecure())
```

### HTTP/1.1: response details

```mojo
from flare.http import HttpClient, Status, Url

fn main() raises:
    var client = HttpClient()
    var resp = client.get("http://httpbin.org/get")
    if resp.status == Status.OK:
        print(resp.text()[:80])
    var ct = resp.headers.get("content-type")  # case-insensitive lookup

    var u = Url.parse("https://api.example.com:8443/v1/users?page=2")
    print(u.host, u.port, u.path)
```

### WebSocket: raw frame API

```mojo
from flare.ws import WsClient, WsFrame

fn main() raises:
    var ws = WsClient.connect("ws://echo.websocket.events")
    ws.send_text("Hello, flare WebSocket!")
    var frame = ws.recv()
    print(frame.text_payload())
    ws.close()
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
from .http.encoding import Encoding
from .http.error import HttpError, TooManyRedirects
from .http.auth import BasicAuth, BearerAuth
from .http.client import HttpClient, get, post, put, delete, head
from .http.server import HttpServer

# flare.ws
from .ws.frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from .ws.client import WsClient, WsHandshakeError, WsMessage
from .ws.server import WsServer

# flare.io
from .io.buf_reader import Readable, BufReader
