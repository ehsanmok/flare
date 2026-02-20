"""UDP datagram sockets.

Built on `flare.net` POSIX socket primitives. Provides connectionless,
best-effort datagram delivery. Use `flare.tcp` for reliable ordered delivery.

## Public API

```mojo
from flare.udp import UdpSocket, DatagramTooLarge
```

- `UdpSocket`       — A UDP socket for `send_to` / `recv_from` operations.
- `DatagramTooLarge` — Raised when a payload exceeds the 65,507-byte UDP limit.

## Example

```mojo
from flare.udp import UdpSocket
from flare.net import SocketAddr

fn main() raises:
    # Sender (no bind needed for outbound-only sockets)
    var tx = UdpSocket.unbound()
    tx.send_to("hello".as_bytes(), SocketAddr.localhost(9001))
    tx.close()

    # Receiver
    var rx = UdpSocket.bind(SocketAddr.localhost(9001))
    var buf = List[UInt8](capacity=65535)
    buf.resize(65535, 0)
    var (n, from_addr) = rx.recv_from(Span[UInt8](buf))
    print(String(buf[:n]))           # hello
    rx.close()
```
"""

from .socket import UdpSocket, DatagramTooLarge
