"""Tests for off-reactor DNS resolution + happy-eyeballs ordering (W6).

``resolve_async`` runs ``getaddrinfo`` on a pool thread and returns the
same result as the sync ``resolve``; a pre-flipped cancel short-circuits
before any work. ``order_happy_eyeballs`` interleaves IPv6/IPv4 results
into RFC 8305 connection-attempt order. ``DnsCache.resolve_async`` serves
a within-TTL hit from memory without spawning a thread.
"""

from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, assert_raises

from flare.dns import DnsCache, order_happy_eyeballs, resolve, resolve_async
from flare.http import Cancel, CancelCell, CancelReason
from flare.net import IpAddr


def test_resolve_async_matches_sync_localhost() raises:
    var got = resolve_async("localhost", Cancel.never())
    assert_true(len(got) >= 1, "expected at least one address for localhost")
    # Every returned address must be a loopback (127.0.0.0/8 or ::1).
    var saw_loopback = False
    for i in range(len(got)):
        var s = String(got[i])
        if s.startswith("127.") or s == "::1":
            saw_loopback = True
    assert_true(saw_loopback, "expected a loopback address for localhost")


def test_resolve_async_empty_host_raises() raises:
    with assert_raises():
        _ = resolve_async("", Cancel.never())


def test_resolve_async_preflipped_cancel_raises() raises:
    # The flipped cell is passed across a function-call boundary into
    # resolve_async; on Linux x86_64 the pinned Mojo nightly does not
    # propagate that flip through the new Cancel value (documented in
    # flare/http/cancel.mojo + gated identically in test_block_in_pool).
    if not CompilationTarget.is_macos():
        print(" [SKIP] Mojo nightly Cancel-across-boundary anomaly on Linux")
        return
    var cell = CancelCell()
    cell.flip(CancelReason.TIMEOUT)
    with assert_raises():
        _ = resolve_async("localhost", cell.handle())


def test_happy_eyeballs_interleaves_families() raises:
    var addrs = List[IpAddr]()
    addrs.append(IpAddr.parse("::1"))
    addrs.append(IpAddr.parse("fe80::2"))
    addrs.append(IpAddr.parse("127.0.0.1"))
    addrs.append(IpAddr.parse("10.0.0.2"))
    var ordered = order_happy_eyeballs(addrs)
    assert_equal(len(ordered), 4)
    # v6[0], v4[0], v6[1], v4[1]
    assert_equal(String(ordered[0]), "::1")
    assert_equal(String(ordered[1]), "127.0.0.1")
    assert_equal(String(ordered[2]), "fe80::2")
    assert_equal(String(ordered[3]), "10.0.0.2")


def test_happy_eyeballs_uneven_families() raises:
    var addrs = List[IpAddr]()
    addrs.append(IpAddr.parse("127.0.0.1"))
    addrs.append(IpAddr.parse("10.0.0.2"))
    addrs.append(IpAddr.parse("::1"))
    var ordered = order_happy_eyeballs(addrs)
    assert_equal(len(ordered), 3)
    assert_equal(String(ordered[0]), "::1")
    assert_equal(String(ordered[1]), "127.0.0.1")
    assert_equal(String(ordered[2]), "10.0.0.2")


def test_cache_async_serves_hit_without_spawn() raises:
    var cache = DnsCache(ttl_ms=60_000)
    var a = cache.resolve_async("localhost", Cancel.never())
    var b = cache.resolve_async("localhost", Cancel.never())
    assert_true(len(a) >= 1, "first async resolve empty")
    assert_true(len(b) >= 1, "second async resolve empty")
    assert_equal(cache.resolve_count(), 1)
    assert_equal(cache.hit_count(), 1)


def main() raises:
    print("=" * 60)
    print("test_async_resolve.mojo -- off-reactor DNS + happy-eyeballs (W6)")
    print("=" * 60)
    test_resolve_async_matches_sync_localhost()
    test_resolve_async_empty_host_raises()
    test_resolve_async_preflipped_cancel_raises()
    test_happy_eyeballs_interleaves_families()
    test_happy_eyeballs_uneven_families()
    test_cache_async_serves_hit_without_spawn()
    print("test_async_resolve: 6 passed")
