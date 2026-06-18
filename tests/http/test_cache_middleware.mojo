"""End-to-end tests for the ``Cache[Inner, S]`` middleware.

Closes the D2 line item of the v0.8 finishing pass: the parsed
freshness primitives (D1) plug into a real middleware that other
``Handler``-shaped middlewares can compose on top of.

Cases cover the four paths the middleware decides between:
- **Miss → fill → hit**: first request reaches the inner handler;
  second request gets the cached body + ``X-Cache: HIT``.
- **Stale bypass**: an entry with ``Cache-Control: max-age=0``
  always bypasses the cache regardless of insertion timestamp.
- **``no-store`` respected**: responses tagged ``no-store`` never
  enter the store (RFC 9111 §5.2.2.5).
- **``Set-Cookie`` is opaque**: responses with ``Set-Cookie``
  bypass the cache (cookies are user-identifying; storing them
  in a shared cache leaks identity).
- **Method gating**: ``POST`` always bypasses the read path;
  successful ``POST`` invalidates any matching cache entry
  (RFC 9111 §4.4).
- **Vary segregation**: two requests to the same URL with
  different ``Accept-Language`` get different cache entries.
"""

from std.collections import List
from std.memory import UnsafePointer, alloc
from std.testing import assert_equal, assert_false, assert_true

from flare.http import (
    HeaderMap,
    Handler,
    Request,
    Response,
)
from flare.http.cache import (
    Cache,
    InMemoryCacheStore,
)


struct _CountingHandler(Copyable, Defaultable, Handler, Movable):
    """Handler that increments a per-test counter via a heap
    address (mirrors how ``Metrics[Inner]`` shares state across
    middleware copies). The counter lets each test assert how
    many times the inner served vs. the cache served.
    """

    var counter_addr: Int
    """Heap-allocated counter cell address. Leaked at test
    process exit because tests are short-lived."""

    var status: Int
    """Status to return."""

    var cache_control: String
    """``Cache-Control`` header value to set on the response."""

    var vary: String
    """``Vary`` header value to set on the response."""

    var body: String
    """Response body."""

    var set_cookie: Bool
    """Emit a ``Set-Cookie`` header (for the opacity test)."""

    def __init__(out self):
        var p = alloc[Int](1)
        p[0] = 0
        self.counter_addr = Int(p)
        self.status = 200
        self.cache_control = String("max-age=60")
        self.vary = String("")
        self.body = String("hello")
        self.set_cookie = False

    def serve(self, req: Request) raises -> Response:
        var p = UnsafePointer[Int, MutUntrackedOrigin](
            unsafe_from_address=self.counter_addr
        )
        p[0] = p[0] + 1
        var resp = Response(self.status)
        var body_bytes = List[UInt8]()
        for b in self.body.as_bytes():
            body_bytes.append(b)
        resp.body = body_bytes^
        if self.cache_control.byte_length() > 0:
            resp.headers.set(String("Cache-Control"), self.cache_control)
        if self.vary.byte_length() > 0:
            resp.headers.set(String("Vary"), self.vary)
        if self.set_cookie:
            resp.headers.set(String("Set-Cookie"), String("session=abc"))
        return resp^

    def _count(self) -> Int:
        var p = UnsafePointer[Int, MutUntrackedOrigin](
            unsafe_from_address=self.counter_addr
        )
        return p[0]


def _req(method: String, url: String) -> Request:
    return Request(method=method, url=url)


def test_miss_then_hit() raises:
    var inner = _CountingHandler()
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    var r1 = cache.serve(_req(String("GET"), String("/x")))
    assert_equal(r1.status, 200)
    var r2 = cache.serve(_req(String("GET"), String("/x")))
    assert_equal(r2.status, 200)
    assert_equal(r2.headers.get(String("X-Cache")), String("HIT"))
    # Inner only served once; the second request was a cache hit.
    assert_equal(cache.inner._count(), 1)


def test_no_store_response_not_cached() raises:
    var inner = _CountingHandler()
    inner.cache_control = String("no-store")
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    _ = cache.serve(_req(String("GET"), String("/x")))
    _ = cache.serve(_req(String("GET"), String("/x")))
    assert_equal(cache.inner._count(), 2)


def test_max_age_zero_bypasses_cache() raises:
    var inner = _CountingHandler()
    inner.cache_control = String("max-age=0")
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    _ = cache.serve(_req(String("GET"), String("/x")))
    _ = cache.serve(_req(String("GET"), String("/x")))
    # ``max-age=0`` means the entry is never fresh, so each
    # request reaches the inner handler.
    assert_equal(cache.inner._count(), 2)


def test_set_cookie_response_not_cached() raises:
    var inner = _CountingHandler()
    inner.set_cookie = True
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    _ = cache.serve(_req(String("GET"), String("/x")))
    _ = cache.serve(_req(String("GET"), String("/x")))
    assert_equal(cache.inner._count(), 2)


def test_post_bypasses_read_path() raises:
    var inner = _CountingHandler()
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    _ = cache.serve(_req(String("POST"), String("/x")))
    _ = cache.serve(_req(String("POST"), String("/x")))
    # POST always reaches the inner handler.
    assert_equal(cache.inner._count(), 2)


def test_post_invalidates_stored_entry() raises:
    var inner = _CountingHandler()
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    # Prime the cache with a GET.
    _ = cache.serve(_req(String("GET"), String("/x")))
    # A successful POST to the same URI invalidates the entry.
    _ = cache.serve(_req(String("POST"), String("/x")))
    # The subsequent GET must re-fetch from the inner.
    _ = cache.serve(_req(String("GET"), String("/x")))
    # 1 (initial GET) + 1 (POST) + 1 (refetch after invalidation).
    assert_equal(cache.inner._count(), 3)


def test_non_cacheable_status_skipped() raises:
    var inner = _CountingHandler()
    inner.status = 500  # not on the RFC 9111 §3 cacheable list
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    _ = cache.serve(_req(String("GET"), String("/x")))
    _ = cache.serve(_req(String("GET"), String("/x")))
    assert_equal(cache.inner._count(), 2)


def test_vary_segregates_entries() raises:
    var inner = _CountingHandler()
    inner.vary = String("Accept-Language")
    var cache = Cache[_CountingHandler, InMemoryCacheStore](
        inner^, InMemoryCacheStore()
    )
    var req_en = _req(String("GET"), String("/x"))
    req_en.headers.set(String("Accept-Language"), String("en"))
    var req_fr = _req(String("GET"), String("/x"))
    req_fr.headers.set(String("Accept-Language"), String("fr"))
    _ = cache.serve(req_en)
    _ = cache.serve(req_fr)
    # Two distinct Vary buckets -> two inner serves.
    assert_equal(cache.inner._count(), 2)
    # A repeat of the en request reuses the en entry.
    var req_en2 = _req(String("GET"), String("/x"))
    req_en2.headers.set(String("Accept-Language"), String("en"))
    var r = cache.serve(req_en2)
    assert_equal(r.headers.get(String("X-Cache")), String("HIT"))
    assert_equal(cache.inner._count(), 2)


def main() raises:
    test_miss_then_hit()
    test_no_store_response_not_cached()
    test_max_age_zero_bypasses_cache()
    test_set_cookie_response_not_cached()
    test_post_bypasses_read_path()
    test_post_invalidates_stored_entry()
    test_non_cacheable_status_skipped()
    test_vary_segregates_entries()
    print("test_cache_middleware: OK")
