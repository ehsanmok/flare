# PLATFORM: any
# RESOLVED: NET-03 fixed on fix/formal-findings
"""NET-03: DnsCache with a very large ttl_ms never serves a hit.

Lean: Flare.Bugs.NET_03.huge_ttl_never_hits (counterexample),
Flare.Bugs.NET_03.storeFixed_hits_within_ttl and
Flare.Bugs.NET_03.storeFixed_size_bound (fix meets spec).
flare/dns/cache.mojo:96-142 @59bda50.

Expected: DnsCache(ttl_ms=Int.MAX) ("cache forever") serves the second
lookup of a host from memory: resolve_count() == 1, hit_count() == 1.
Before the fix: _store computes expires_at_ms = now + ttl_ms in wrapping Int
arithmetic. now (monotonic ms) + Int.MAX wraps to a negative number, so
every entry is already expired and every lookup calls getaddrinfo:
resolve_count() == 2, hit_count() == 0.

Minimal fix: saturate the expiry (Int.MAX when ttl_ms > Int.MAX - now).
Saturation alone would expose a second, latent defect: the eviction
scan starts from oldest_at = Int.MAX with a strict '<', so when every
live entry expires at Int.MAX nothing is evicted and the cache grows
past max_entries. The fix therefore also uses '<=' in that scan (Lean
proves the combined fix keeps size <= max_entries).
"""

from flare.dns import DnsCache


def main() raises:
    var cache = DnsCache(ttl_ms=Int.MAX)
    _ = cache.resolve("localhost")
    _ = cache.resolve("localhost")
    if cache.resolve_count() != 1 or cache.hit_count() != 1:
        print(
            "BUG REPRODUCED: DnsCache(ttl_ms=Int.MAX) resolved",
            cache.resolve_count(),
            "times with",
            cache.hit_count(),
            "hits for two lookups of the same host",
        )
        raise Error("NET-03")
    print("OK: second lookup served from cache")
