"""Unit tests for the TTL DNS cache (W3).

Verifies the additive :class:`flare.dns.DnsCache` over the sync resolver:
within the TTL a repeated lookup is served from memory (the resolver
syscall counter does not advance); a zero TTL re-resolves every time;
``invalidate`` / ``clear`` drop entries. Uses ``localhost`` so the test
never depends on external DNS.
"""

from std.testing import assert_equal, assert_true

from flare.dns import DnsCache


def test_within_ttl_no_second_syscall() raises:
    var cache = DnsCache(ttl_ms=60_000)
    var a = cache.resolve("localhost")
    var b = cache.resolve("localhost")
    assert_true(len(a) > 0, "first resolve empty")
    assert_true(len(b) > 0, "second resolve empty")
    assert_equal(cache.resolve_count(), 1)  # second served from cache
    assert_equal(cache.hit_count(), 1)


def test_zero_ttl_always_resolves() raises:
    var cache = DnsCache(ttl_ms=0)
    _ = cache.resolve("localhost")
    _ = cache.resolve("localhost")
    assert_equal(cache.resolve_count(), 2)
    assert_equal(cache.hit_count(), 0)


def test_distinct_hosts_each_resolve() raises:
    var cache = DnsCache(ttl_ms=60_000)
    _ = cache.resolve("localhost")
    _ = cache.resolve("127.0.0.1")
    assert_equal(cache.resolve_count(), 2)
    assert_equal(cache.size(), 2)


def test_invalidate_forces_resolve() raises:
    var cache = DnsCache(ttl_ms=60_000)
    _ = cache.resolve("localhost")
    cache.invalidate("localhost")
    _ = cache.resolve("localhost")
    assert_equal(cache.resolve_count(), 2)


def test_clear_drops_all() raises:
    var cache = DnsCache(ttl_ms=60_000)
    _ = cache.resolve("localhost")
    cache.clear()
    assert_equal(cache.size(), 0)
    _ = cache.resolve("localhost")
    assert_equal(cache.resolve_count(), 2)


def main() raises:
    test_within_ttl_no_second_syscall()
    test_zero_ttl_always_resolves()
    test_distinct_hosts_each_resolve()
    test_invalidate_forces_resolve()
    test_clear_drops_all()
    print("test_dns_cache: 5 passed")
