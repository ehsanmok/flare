"""Unit tests for the HTTP cache primitives."""

from std.testing import assert_equal, assert_true, assert_false

from flare.http.cache import (
    CacheControl,
    CacheKey,
    CacheEntry,
    InMemoryCacheStore,
    derive_cache_key,
    parse_cache_control,
)


def test_parse_cache_control_basic() raises:
    var cc = parse_cache_control(String("max-age=3600, public"))
    assert_true(cc.public)
    assert_false(cc.private)
    assert_false(cc.no_store)
    assert_true(cc.max_age.__bool__())
    assert_equal(cc.max_age.unsafe_take(), 3600)


def test_parse_cache_control_no_cache_no_store() raises:
    var cc = parse_cache_control(String("no-cache, no-store"))
    assert_true(cc.no_cache)
    assert_true(cc.no_store)
    assert_false(cc.public)


def test_parse_cache_control_revalidation_directives() raises:
    var cc = parse_cache_control(
        String(
            "must-revalidate, proxy-revalidate, stale-while-revalidate=60,"
            " stale-if-error=120"
        )
    )
    assert_true(cc.must_revalidate)
    assert_true(cc.proxy_revalidate)
    assert_true(cc.stale_while_revalidate.__bool__())
    assert_equal(cc.stale_while_revalidate.unsafe_take(), 60)
    assert_true(cc.stale_if_error.__bool__())
    assert_equal(cc.stale_if_error.unsafe_take(), 120)


def test_parse_cache_control_case_insensitive() raises:
    var cc = parse_cache_control(String("MAX-AGE=300, Public"))
    assert_true(cc.public)
    assert_equal(cc.max_age.unsafe_take(), 300)


def test_parse_cache_control_immutable_rfc8246() raises:
    var cc = parse_cache_control(String("max-age=86400, immutable"))
    assert_true(cc.immutable)


def test_parse_cache_control_unknown_directives_surface() raises:
    """RFC 9111 §5.2 says unknown directives must be passed
    through; the parser surfaces them so middleware can decide."""
    var cc = parse_cache_control(String("private, x-vendor-extension"))
    assert_true(cc.private)
    assert_equal(len(cc.unknown_directives), 1)
    assert_equal(cc.unknown_directives[0], String("x-vendor-extension"))


def test_parse_cache_control_invalid_max_age_drops() raises:
    """Malformed numeric values silently drop per RFC 9111 §5.2."""
    var cc = parse_cache_control(String("max-age=not-a-number"))
    assert_false(cc.max_age.__bool__())


def test_cache_key_round_trip() raises:
    var k1 = derive_cache_key(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/path?q=1"),
    )
    var k2 = derive_cache_key(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/path?q=1"),
    )
    assert_true(k1 == k2)


def test_cache_key_vary_changes_key() raises:
    var k1 = derive_cache_key(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/"),
    )
    var vary = List[Tuple[String, String]]()
    vary.append((String("accept-language"), String("en-US")))
    var k2 = derive_cache_key(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/"),
        vary,
    )
    assert_false(k1 == k2)


def test_in_memory_store_round_trip() raises:
    var store = InMemoryCacheStore()
    var key = derive_cache_key(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/"),
    )
    var body = List[UInt8]()
    body.append(UInt8(ord("h")))
    body.append(UInt8(ord("i")))
    var entry = CacheEntry.basic(
        status=200,
        headers=List[Tuple[String, String]](),
        body=body^,
        inserted_at_ms=Int64(1000),
    )
    store.put(key, entry)
    var got = store.get(key)
    assert_true(got.__bool__())
    var fetched = got.unsafe_take()
    assert_equal(fetched.status, 200)
    assert_equal(len(fetched.body), 2)
    assert_equal(Int(fetched.body[0]), ord("h"))


def test_in_memory_store_capacity_eviction() raises:
    """A bounded store at capacity must evict the oldest entry
    when a new key is inserted."""
    var store = InMemoryCacheStore.with_capacity(2)
    var k1 = CacheKey(raw=String("k1"))
    var k2 = CacheKey(raw=String("k2"))
    var k3 = CacheKey(raw=String("k3"))
    var e1 = CacheEntry.basic(
        status=200,
        headers=List[Tuple[String, String]](),
        body=List[UInt8](),
        inserted_at_ms=Int64(0),
    )
    var e2 = CacheEntry.basic(
        status=200,
        headers=List[Tuple[String, String]](),
        body=List[UInt8](),
        inserted_at_ms=Int64(0),
    )
    var e3 = CacheEntry.basic(
        status=200,
        headers=List[Tuple[String, String]](),
        body=List[UInt8](),
        inserted_at_ms=Int64(0),
    )
    store.put(k1, e1)
    store.put(k2, e2)
    assert_equal(store.len(), 2)
    store.put(k3, e3)  # should evict k1
    assert_equal(store.len(), 2)
    assert_false(store.get(k1).__bool__())
    assert_true(store.get(k2).__bool__())
    assert_true(store.get(k3).__bool__())


def test_in_memory_store_remove() raises:
    var store = InMemoryCacheStore()
    var key = CacheKey(raw=String("test"))
    var entry = CacheEntry.basic(
        status=200,
        headers=List[Tuple[String, String]](),
        body=List[UInt8](),
        inserted_at_ms=Int64(0),
    )
    store.put(key, entry^)
    assert_equal(store.len(), 1)
    store.remove(key)
    assert_equal(store.len(), 0)
    assert_false(store.get(key).__bool__())


def main() raises:
    test_parse_cache_control_basic()
    test_parse_cache_control_no_cache_no_store()
    test_parse_cache_control_revalidation_directives()
    test_parse_cache_control_case_insensitive()
    test_parse_cache_control_immutable_rfc8246()
    test_parse_cache_control_unknown_directives_surface()
    test_parse_cache_control_invalid_max_age_drops()
    test_cache_key_round_trip()
    test_cache_key_vary_changes_key()
    test_in_memory_store_round_trip()
    test_in_memory_store_capacity_eviction()
    test_in_memory_store_remove()
    print("test_cache: OK")
