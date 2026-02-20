"""TLS/SSL layer — wraps `TcpStream` with OpenSSL encryption.

Provides TLS 1.2 and TLS 1.3 over any `TcpStream`. The OpenSSL C wrapper
shared library is built automatically on `pixi install` via
`flare/tls/ffi/build.sh`.

## Public API

```mojo
from flare.tls import TlsConfig, TlsVerify, TlsStream
from flare.tls import (
    TlsHandshakeError, CertificateExpired,
    CertificateHostnameMismatch, CertificateUntrusted,
)
```

- `TlsConfig`                  — Certificate/key/CA bundle configuration.
- `TlsVerify`                  — Peer verification mode constants.
- `TlsStream`                  — Encrypted TCP stream (handshake + read/write).
- `TlsHandshakeError`          — Generic TLS handshake failure.
- `CertificateExpired`         — Server cert has passed its `notAfter` date.
- `CertificateHostnameMismatch` — Cert CN/SAN does not match the target host.
- `CertificateUntrusted`       — Cert not trusted by any CA in the bundle.

## Example

```mojo
from flare.tls import TlsStream, TlsConfig

fn main() raises:
    # HTTPS request using system CA bundle (default)
    var stream = TlsStream.connect("example.com", 443, TlsConfig())
    _ = stream.write(
        "GET / HTTP/1.1\\r\\nHost: example.com\\r\\nConnection: close\\r\\n\\r\\n"
        .as_bytes()
    )
    var buf = List[UInt8](capacity=8192)
    buf.resize(8192, 0)
    var n = stream.read(buf.unsafe_ptr(), len(buf))
    print(String(buf[:n]))
    stream.close()
```
"""

from .config import TlsConfig, TlsVerify
from .stream import TlsStream
from .error import (
    TlsHandshakeError,
    CertificateExpired,
    CertificateHostnameMismatch,
    CertificateUntrusted,
)
