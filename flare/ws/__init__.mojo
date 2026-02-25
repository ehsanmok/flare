"""WebSocket client and server (RFC 6455).

Built on `flare.http` (HTTP Upgrade handshake) and `flare.tcp`. Supports
text and binary frames, ping/pong keep-alives, masking (client→server), and
clean close handshake. SIMD-accelerated payload masking for payloads ≥128 bytes.

## Public API

```mojo
from flare.ws import (
    WsClient, WsServer,
    WsFrame, WsOpcode, WsCloseCode,
    WsProtocolError, WsHandshakeError,
)
```

- `WsClient`        — WebSocket client: `connect`, `send`, `recv`, `close`.
- `WsServer`        — WebSocket server: upgrades HTTP connections to WebSocket.
- `WsFrame`         — A single WebSocket frame: `text`, `binary`, `ping`, `pong`, `close`.
- `WsOpcode`        — Opcode byte constants (`TEXT`, `BINARY`, `PING`, `PONG`, `CLOSE`).
- `WsCloseCode`     — Close status code constants (`NORMAL`, `GOING_AWAY`, …).
- `WsProtocolError` — Raised on RFC 6455 protocol violations.
- `WsHandshakeError` — Raised when the HTTP Upgrade handshake fails.

## Example

```mojo
from flare.ws import WsClient, WsFrame, WsOpcode

fn main() raises:
    # Connect to a WebSocket echo server
    var ws = WsClient.connect("ws://echo.websocket.events")

    # Send a text frame
    _ = ws.send(WsFrame.text("hello, flare!"))

    # Receive echo
    var frame = ws.recv()
    if frame.opcode == WsOpcode.TEXT:
        print(frame.text_payload())  # hello, flare!

    # Ping / pong
    _ = ws.send(WsFrame.ping())
    var pong = ws.recv()             # WsOpcode.PONG

    # Clean close
    ws.close()
```

### TLS WebSocket

```mojo
from flare.ws import WsClient
from flare.tls import TlsConfig

fn main() raises:
    var ws = WsClient.connect("wss://echo.websocket.events", TlsConfig())
    _ = ws.send(WsFrame.text("secure hello"))
    var frame = ws.recv()
    print(frame.text_payload())
    ws.close()
```
"""

from .frame import WsFrame, WsOpcode, WsCloseCode, WsProtocolError
from .client import WsClient, WsHandshakeError, WsMessage
from .server import WsServer, WsConnection
