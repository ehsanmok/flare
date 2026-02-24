"""flare: A foundational networking library for Mojo🔥.

> **Under development** — APIs may change.

A complete, layered networking stack from raw POSIX socket primitives up to
HTTP/1.1 and WebSockets. Written entirely in Mojo with a minimal FFI surface
(only libc + OpenSSL).

## Principles

- **Correctness above all** — typed errors at every layer; no silent failures
- **Security by default** — TLS 1.2+, injection-safe header/address parsing
- **Zero unnecessary C deps** — only libc (always present) and OpenSSL for TLS
- **Layered architecture** — each layer imports only from the layer below it

## Layer Architecture

```
flare.ws    — WebSocket client + server (RFC 6455)
flare.http  — HTTP/1.1 client + server
    │
flare.tls   — TLS 1.2/1.3 via OpenSSL FFI
    │
flare.tcp   — TcpStream + TcpListener
flare.udp   — UdpSocket
    │
flare.dns   — getaddrinfo(3) FFI
    │
flare.net   — IpAddr, SocketAddr, errors, RawSocket
```

## Installation

Add to your `pixi.toml`:

```toml
[workspace]
channels = ["https://conda.modular.com/max-nightly", "conda-forge"]
preview  = ["pixi-build"]

[dependencies]
flare = { git = "https://github.com/ehsanmok/flare.git", branch = "main" }
```

Then run `pixi install` — OpenSSL is automatically installed as a dependency.

## Quick Start

### Addresses and errors

```mojo
from flare.net import IpAddr, SocketAddr, NetworkError

fn main() raises:
    var ip   = IpAddr.parse("192.168.1.1")
    print(ip.is_private())           # True
    var addr = SocketAddr.parse("127.0.0.1:8080")
    print(addr.port)                  # 8080
```

### DNS resolution

```mojo
from flare.dns import resolve, resolve_v4

fn main() raises:
    var addrs = resolve("example.com")
    for a in addrs:
        print(a)                      # 93.184.216.34
```

### TCP echo client

```mojo
from flare.tcp import TcpStream
from flare.net import SocketAddr

fn main() raises:
    var conn = TcpStream.connect(SocketAddr.localhost(9000))
    _ = conn.write("hello\\n".as_bytes())
    var buf = List[UInt8](capacity=1024)
    buf.resize(1024, 0)
    var n = conn.read(buf.unsafe_ptr(), len(buf))
    conn.close()
```

### TLS client

```mojo
from flare.tls import TlsStream, TlsConfig

fn main() raises:
    var stream = TlsStream.connect("example.com", 443, TlsConfig())
    _ = stream.write("GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n".as_bytes())
    stream.close()
```

### HTTP client

```mojo
from flare.http import HttpClient, Status

fn main() raises:
    var client = HttpClient()
    var resp   = client.get("https://example.com/")
    if resp.status == Status.OK:
        print(resp.text())

    # POST JSON — String body sets Content-Type: application/json automatically
    var resp2 = client.post("https://httpbin.org/post", '{"key": "value"}')
    resp2.raise_for_status()
    var data = resp2.json()  # returns mojson.Value
    print(data["json"]["key"].string_value())
```

### HTTP authentication

```mojo
from flare.http import HttpClient, BasicAuth, BearerAuth

fn main() raises:
    var client = HttpClient(BasicAuth("alice", "s3cr3t"))
    var resp = client.get("https://httpbin.org/basic-auth/alice/s3cr3t")
    resp.raise_for_status()
    var data = resp.json()             # mojson.Value
    print(data["authenticated"].bool_value())
```

### WebSocket client

```mojo
from flare.ws import WsClient, WsFrame, WsOpcode, WsMessage

fn main() raises:
    with WsClient.connect("ws://echo.websocket.events") as ws:
        ws.send_text("hello!")
        var msg = ws.recv_message()
        if msg.is_text:
            print(msg.as_text())
```

## Public API

### flare.net

```mojo
from flare.net import (
    IpAddr, SocketAddr, RawSocket,
    NetworkError, ConnectionRefused, ConnectionTimeout, ConnectionReset,
    AddressInUse, AddressParseError, BrokenPipe, DnsError, Timeout,
)
```

### flare.dns

```mojo
from flare.dns import resolve, resolve_v4, resolve_v6
```

### flare.tcp

```mojo
from flare.tcp import TcpStream, TcpListener
```

### flare.udp

```mojo
from flare.udp import UdpSocket, DatagramTooLarge
```

### flare.tls

```mojo
from flare.tls import (
    TlsConfig, TlsVerify, TlsStream,
    TlsHandshakeError, CertificateExpired,
    CertificateHostnameMismatch, CertificateUntrusted,
)
```

### flare.http

```mojo
from flare.http import (
    HttpClient, HttpServer,
    Request, Response, HeaderMap, Url,
    Method, Status, Encoding,
    HeaderInjectionError, UrlParseError,
    HttpError, TooManyRedirects,
    BasicAuth, BearerAuth,
    get, post, put, delete, head,
)
```

### flare.ws

```mojo
from flare.ws import (
    WsClient, WsServer,
    WsFrame, WsOpcode, WsCloseCode,
    WsProtocolError, WsHandshakeError,
    WsMessage,
)
```

### flare.io

```mojo
from flare.io import Readable, BufReader
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
from .dns.resolve import resolve, resolve_v4, resolve_v6

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
