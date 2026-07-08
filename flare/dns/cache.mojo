"""TTL-bounded DNS resolution cache.

An additive layer over the sync :func:`flare.dns.resolve`: a value-type
cache the caller owns and threads through repeated lookups. Within a
host's TTL a lookup is served from memory with no ``getaddrinfo(3)``
syscall; past the TTL the next lookup re-resolves and refreshes the
entry. The sync ``resolve`` / ``resolve_v4`` / ``resolve_v6`` functions
are untouched -- callers that do not want caching pay nothing.

```mojo
from flare.dns import DnsCache

var cache = DnsCache(ttl_ms=30_000)
var a = cache.resolve("example.com")   # one syscall
var b = cache.resolve("example.com")   # served from cache, no syscall
print(cache.resolve_count())            # 1
```

This is a single-threaded value type (the owner serializes access); it
has no internal lock. A shared cache across reactor workers could reuse
the same pointer-backed interior-mutable handle pattern as
``flare.http._client.alt_svc.AltSvcStore`` plus a mutex, layered on top
of this pure cache without changing its logic.
"""

from std.collections import Dict, List

from ..http.cancel import Cancel
from ..net import IpAddr
from ..runtime._libc_time import monotonic_now_ms
from .async_resolve import order_happy_eyeballs, resolve_async
from .resolver import resolve


@fieldwise_init
struct _CachedAddrs(Copyable, Movable):
    """One cached resolution: the address list + its absolute expiry
    (monotonic ms)."""

    var addrs: List[IpAddr]
    var expires_at_ms: Int


struct DnsCache(Movable):
    """A TTL-bounded resolution cache over the sync resolver.

    Fields are owned by the caller; the cache mutates through ``mut
    self`` (no interior mutability), so it composes anywhere the caller
    already holds it mutably (a client's dial path, a worker loop).
    """

    var _by_host: Dict[String, _CachedAddrs]
    var _ttl_ms: Int
    var _resolves: Int
    """Count of underlying ``resolve`` syscalls performed (cache
    misses + expiries). Lets a test assert a within-TTL lookup did not
    hit the resolver."""
    var _hits: Int
    """Count of lookups served from a fresh cache entry."""

    def __init__(out self, ttl_ms: Int = 30_000):
        """Create a cache with the given per-entry TTL in milliseconds
        (default 30 s). ``ttl_ms <= 0`` makes every entry immediately
        stale (every lookup re-resolves)."""
        self._by_host = Dict[String, _CachedAddrs]()
        self._ttl_ms = ttl_ms
        self._resolves = 0
        self._hits = 0

    def resolve(mut self, host: String) raises -> List[IpAddr]:
        """Return the addresses for ``host``, served from cache when a
        fresh entry exists, else re-resolved (and cached) via
        :func:`flare.dns.resolve`.

        Raises:
            DnsError / AddressParseError: propagated from the underlying
                resolver on a miss; failures are not cached.
        """
        var now = monotonic_now_ms()
        try:
            var hit = self._by_host[host].copy()
            if now < hit.expires_at_ms:
                self._hits += 1
                return hit.addrs.copy()
        except:
            pass  # miss / absent: fall through to a fresh resolve
        var fresh = resolve(host)
        self._resolves += 1
        self._by_host[host] = _CachedAddrs(
            addrs=fresh.copy(), expires_at_ms=now + self._ttl_ms
        )
        return fresh^

    def resolve_async(
        mut self, host: String, cancel: Cancel
    ) raises -> List[IpAddr]:
        """Cache-aware off-reactor resolve: serve a fresh entry from
        memory (no thread spawn), else resolve on a pool thread via
        :func:`flare.dns.resolve_async` and cache the result.

        Same caching semantics as :meth:`resolve`; only the miss path
        differs (off-thread, cancellable). Failures are not cached."""
        var now = monotonic_now_ms()
        try:
            var hit = self._by_host[host].copy()
            if now < hit.expires_at_ms:
                self._hits += 1
                return hit.addrs.copy()
        except:
            pass
        var fresh = resolve_async(host, cancel)
        self._resolves += 1
        self._by_host[host] = _CachedAddrs(
            addrs=fresh.copy(), expires_at_ms=now + self._ttl_ms
        )
        return fresh^

    def resolve_ordered(mut self, host: String) raises -> List[IpAddr]:
        """Like :meth:`resolve` but returns the addresses in RFC 8305
        happy-eyeballs connection-attempt order (interleaved IPv6/IPv4)
        so a dialer can race the families."""
        return order_happy_eyeballs(self.resolve(host))

    def invalidate(mut self, host: String):
        """Drop any cached entry for ``host`` (e.g. after a dial to the
        cached address failed). No-op if absent."""
        try:
            _ = self._by_host.pop(host)
        except:
            pass

    def clear(mut self):
        """Drop all cached entries."""
        self._by_host = Dict[String, _CachedAddrs]()

    @always_inline
    def resolve_count(self) -> Int:
        """Number of underlying resolver syscalls performed so far."""
        return self._resolves

    @always_inline
    def hit_count(self) -> Int:
        """Number of lookups served from a fresh cache entry."""
        return self._hits

    @always_inline
    def size(self) -> Int:
        """Number of hosts currently cached (fresh or stale)."""
        return len(self._by_host)
