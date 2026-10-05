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

Entries live for the cache's own ``ttl_ms`` (``Int.MAX`` means "until
evicted": the expiry saturates instead of wrapping). ``getaddrinfo(3)`` does
not report the record's DNS TTL, so a record whose TTL is shorter than
``ttl_ms`` is served past it; pick ``ttl_ms`` with that in mind. Host
names are matched case-insensitively and without a trailing dot, as DNS
matches them. The cache holds at most ``max_entries`` hosts; when it is
full, expired entries go first, then the one closest to expiry.

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
struct _CachedAddrs(Copyable):
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
    var _max_entries: Int

    def __init__(out self, ttl_ms: Int = 30_000, max_entries: Int = 1024):
        """Create a cache with the given per-entry TTL in milliseconds
        (default 30 s) holding at most ``max_entries`` hosts. ``ttl_ms
        <= 0`` makes every entry immediately stale (every lookup
        re-resolves). The bound is new: a process that looked up many
        distinct names grew the cache without limit."""
        self._by_host = Dict[String, _CachedAddrs]()
        self._ttl_ms = ttl_ms
        self._resolves = 0
        self._hits = 0
        self._max_entries = max_entries if max_entries > 0 else 1

    @staticmethod
    def _key(host: String) -> String:
        """``Example.COM.`` and ``example.com`` are one name."""
        var b = host.as_bytes()
        var n = len(b)
        if n > 1 and b[n - 1] == UInt8(ord(".")):
            n -= 1
        var out = List[UInt8](capacity=n)
        for i in range(n):
            var c = b[i]
            if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
                c += 32
            out.append(c)
        return String(unsafe_from_utf8=Span[UInt8, _](out))

    def _store(mut self, key: String, var addrs: List[IpAddr], now: Int):
        if key not in self._by_host and len(self._by_host) >= self._max_entries:
            var expired = List[String]()
            var oldest = String("")
            var oldest_at = Int.MAX
            for kv in self._by_host.items():
                if kv.value.expires_at_ms <= now:
                    expired.append(kv.key)
                elif kv.value.expires_at_ms <= oldest_at:
                    # ``<=``: a saturated expiry equals the ``Int.MAX``
                    # seed and must still be a candidate victim.
                    oldest_at = kv.value.expires_at_ms
                    oldest = kv.key
            for i in range(len(expired)):
                try:
                    _ = self._by_host.pop(expired[i])
                except:
                    pass
            if len(self._by_host) >= self._max_entries and oldest != "":
                try:
                    _ = self._by_host.pop(oldest)
                except:
                    pass
        # Saturate: ``now + ttl_ms`` wraps negative for a "cache forever"
        # TTL (``Int.MAX``) and the entry would be born expired. ``now`` is
        # a monotonic reading (>= 0), so ``Int.MAX - now`` cannot overflow.
        var expires_at = (
            Int.MAX if self._ttl_ms > Int.MAX - now else now + self._ttl_ms
        )
        self._by_host[key] = _CachedAddrs(
            addrs=addrs^, expires_at_ms=expires_at
        )

    def resolve(mut self, host: String) raises -> List[IpAddr]:
        """Return the addresses for ``host``, served from cache when a
        fresh entry exists, else re-resolved (and cached) via
        :func:`flare.dns.resolve`.

        Raises:
            DnsError / AddressParseError: propagated from the underlying
                resolver on a miss; failures are not cached.
        """
        var now = monotonic_now_ms()
        var key = DnsCache._key(host)
        try:
            var hit = self._by_host[key].copy()
            if now < hit.expires_at_ms:
                self._hits += 1
                return hit.addrs.copy()
        except:
            pass  # miss / absent: fall through to a fresh resolve
        var fresh = resolve(host)
        self._resolves += 1
        self._store(key, fresh.copy(), now)
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
        var key = DnsCache._key(host)
        try:
            var hit = self._by_host[key].copy()
            if now < hit.expires_at_ms:
                self._hits += 1
                return hit.addrs.copy()
        except:
            pass
        var fresh = resolve_async(host, cancel)
        self._resolves += 1
        self._store(key, fresh.copy(), now)
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
            _ = self._by_host.pop(DnsCache._key(host))
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
