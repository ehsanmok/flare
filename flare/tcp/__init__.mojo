"""Blocking TCP streams and listeners.

Built on `flare.net` POSIX socket primitives. Every connection has
`TCP_NODELAY` set by default for low-latency I/O.

## Public API

```mojo
from flare.tcp import TcpStream, TcpListener
```

- `TcpStream`   — A connected TCP socket: `connect`, `read`, `write`, `close`.
- `TcpListener` — A bound, listening TCP socket: `bind`, `accept`.

All operations raise typed errors from `flare.net` on failure.

## Example

```mojo
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr

fn echo_server() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(9000))
    var client   = listener.accept()

    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    var n = client.read(buf.unsafe_ptr(), len(buf))
    _ = client.write(Span[UInt8](buf)[:n])  # echo back
    client.close()

fn echo_client() raises:
    var conn = TcpStream.connect(SocketAddr.localhost(9000))
    _ = conn.write("hello\\n".as_bytes())
    var buf = List[UInt8](capacity=4096)
    buf.resize(4096, 0)
    _ = conn.read(buf.unsafe_ptr(), len(buf))
    conn.close()
```
"""

from .stream import TcpStream
from .listener import TcpListener
