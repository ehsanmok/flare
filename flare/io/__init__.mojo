"""Buffered I/O utilities for flare streams.

Provides ``Readable`` — a trait for byte-stream types — and ``BufReader``
— a generic buffered reader with line-oriented helpers.

## Public API

```mojo
from flare.io import Readable, BufReader
```

- ``Readable``  — Trait satisfied by ``TcpStream`` and ``TlsStream``.
- ``BufReader`` — Wraps any ``Readable`` and adds ``readline``,
  ``read_until``, ``read_exact``.

## Example

```mojo
from flare.tcp import TcpStream
from flare.io import BufReader

fn main() raises:
    var s = TcpStream.connect("example.com", 80)
    s.write_all("GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n".as_bytes())
    var r = BufReader(s^)
    var status = r.readline()
    print(status)   # HTTP/1.0 200 OK (or similar)
```
"""

from .buf_reader import Readable, BufReader
