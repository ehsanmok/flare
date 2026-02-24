"""DNS resolution via `getaddrinfo(3)`.

Wraps the POSIX `getaddrinfo` syscall to resolve hostnames to IP addresses.
Supports IPv4-only, IPv6-only, and dual-stack resolution.

## Public API

```mojo
from flare.dns import resolve, resolve_v4, resolve_v6
```

- `resolve(host)`    — All addresses (IPv4 + IPv6), ordered by OS preference.
- `resolve_v4(host)` — IPv4-only results (`AF_INET`).
- `resolve_v6(host)` — IPv6-only results (`AF_INET6`).

All functions raise `DnsError` (from `flare.net`) on lookup failure.

## Example

```mojo
from flare.dns import resolve, resolve_v4, resolve_v6

fn main() raises:
    # All addresses
    for addr in resolve("example.com"):
        print(addr)                 # 93.184.216.34

    # IPv4 only
    var v4 = resolve_v4("localhost")
    print(v4[0])                    # 127.0.0.1

    # IPv6 only
    var v6 = resolve_v6("localhost")
    print(v6[0])                    # ::1
```
"""

from .resolver import resolve, resolve_v4, resolve_v6
