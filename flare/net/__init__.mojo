"""Raw POSIX socket primitives — the foundation of the flare networking stack.

All higher-level modules (`flare.tcp`, `flare.udp`, `flare.dns`, …) import from
here and never call libc directly.

## Public API

```mojo
from flare.net import IpAddr, SocketAddr, RawSocket
from flare.net import (
    NetworkError, ConnectionRefused, ConnectionTimeout, ConnectionReset,
    AddressInUse, AddressParseError, BrokenPipe, DnsError, Timeout,
)
```

## Example

```mojo
from flare.net import IpAddr, SocketAddr

fn main() raises:
    var ip   = IpAddr.parse("93.184.216.34")
    print(ip.is_global())            # True
    print(ip.is_private())           # False

    var addr = SocketAddr.parse("127.0.0.1:8080")
    print(addr.port)                 # 8080
    print(addr.ip.is_loopback())     # True

    var local = SocketAddr.localhost(9000)
    print(local)                     # 127.0.0.1:9000
```
"""

from .address import IpAddr, SocketAddr
from .socket import RawSocket
from .error import (
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
