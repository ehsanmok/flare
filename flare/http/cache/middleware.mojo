"""HTTP cache middleware (RFC 9111).

``Cache[Inner, S]`` wraps an inner :class:`~flare.http.Handler` with
an RFC 9111-shaped HTTP cache backed by a pluggable
:class:`CacheStore`. On a request the middleware:

1. Computes the cache key from the request method + effective
   request URI, expanded by any prior ``Vary`` selection.
2. Looks the key up in the store. If hit + still fresh per
   :func:`is_fresh`, serves the stored response directly (no
   call into the inner handler, no parser run, no allocation
   beyond the response copy).
3. On miss or stale, calls the inner handler. If the response
   is cacheable (status code on the RFC 9111 §3 allow-list, no
   ``Cache-Control: no-store``, no ``Set-Cookie``), stores it
   with the parsed ``CacheControl`` + ``Vary`` carried alongside.

The middleware is generic over the store so callers can swap the
in-memory bounded store for a filesystem-backed or external
adapter without touching the handler graph. ``S`` only needs to
satisfy the :class:`CacheStore` trait.

The middleware intentionally does *not* drive conditional
revalidation (``If-None-Match`` / ``If-Modified-Since``) on its
own -- that surface lives in :class:`flare.http.Conditional`, and
users compose the two as ``Cache[Conditional[Inner], S]`` when
they want both. The split keeps each concern testable.

The cache is request-scoped: only ``GET`` and ``HEAD`` requests
hit the cache. ``POST`` / ``PUT`` / ``DELETE`` / ``PATCH`` /
``CONNECT`` / ``OPTIONS`` / ``TRACE`` invalidate any stored entry
for the same key on completion of a successful response, but
do not themselves consult the cache (RFC 9111 §4 + §4.4).

References:
- RFC 9111 §3 (storing responses).
- RFC 9111 §4 (constructing responses from caches).
- RFC 9111 §4.4 (invalidating stored responses).
- RFC 9110 §15.1 (status code semantics).
"""

from std.collections import List, Optional
from std.memory import UnsafePointer
from std.time import perf_counter_ns

from .control import (
    CacheControl,
    is_fresh,
    parse_cache_control,
    parse_vary_header,
)
from .key import CacheKey, derive_cache_key
from .store import CacheEntry, CacheStore, InMemoryCacheStore
from ..handler import Handler
from ..headers import HeaderMap
from ..request import Request
from ..response import Response
from ...runtime.pool import Pool


@always_inline
def _now_ms() -> UInt64:
    """Wall-clock ``ms`` since an arbitrary monotonic epoch. The
    cache stores all timestamps relative to this clock so age
    math is monotonic across the middleware's lifetime.
    """
    return UInt64(perf_counter_ns() // 1_000_000)


@always_inline
def _is_cacheable_method(method: String) -> Bool:
    """RFC 9111 §3: ``GET`` and ``HEAD`` are the only methods
    flare caches on the read path. ``POST`` responses are
    cacheable in theory but require explicit ``Cache-Control``
    + ``Content-Location`` discipline that real apps rarely set
    correctly; we exclude them by default and revisit if
    callers ask."""
    return method == String("GET") or method == String("HEAD")


@always_inline
def _is_invalidating_method(method: String) -> Bool:
    """RFC 9111 §4.4: unsafe methods invalidate stored responses
    for the same URI on success."""
    if method == String("POST"):
        return True
    if method == String("PUT"):
        return True
    if method == String("DELETE"):
        return True
    if method == String("PATCH"):
        return True
    return False


@always_inline
def _is_cacheable_status(status: Int) -> Bool:
    """The status codes that are heuristically cacheable per
    RFC 9110 §15.1 + RFC 9111 §3. Other codes (3xx redirects
    that aren't 301, 4xx, 5xx) are not stored by default; the
    middleware lets the origin re-issue them every time so
    error pages don't get pinned in the cache."""
    if status == 200:
        return True
    if status == 203:
        return True
    if status == 204:
        return True
    if status == 300:
        return True
    if status == 301:
        return True
    if status == 410:
        return True
    return False


def _response_cache_control(headers: HeaderMap) -> CacheControl:
    var raw = headers.get(String("Cache-Control"))
    if raw.byte_length() == 0:
        return CacheControl()
    return parse_cache_control(raw)


def _response_vary(headers: HeaderMap) -> String:
    return headers.get(String("Vary"))


def _has_set_cookie(headers: HeaderMap) -> Bool:
    return headers.contains(String("Set-Cookie"))


def _extract_vary_pairs(
    request_headers: HeaderMap, vary_value: String
) raises -> List[Tuple[String, String]]:
    """Resolve a response's ``Vary`` header against the current
    request's headers, producing the ``(field-name, field-value)``
    list :func:`derive_cache_key` consumes for secondary-key
    derivation. Names are lowercased so two callers building keys
    for the same logical request produce identical strings.
    """
    var out = List[Tuple[String, String]]()
    var fields = parse_vary_header(vary_value)
    for i in range(len(fields)):
        var name = fields[i]
        if name == String("*"):
            continue
        var value = request_headers.get(name)
        out.append((name, value))
    return out^


def _request_authority(req: Request) -> String:
    """Best-effort authority extraction.

    The cache key needs *some* authority component so two hosts
    served by the same process don't collide on identical paths.
    The ``Host:`` header (RFC 9110 §7.2) is the canonical source
    on H1; H2's ``:authority`` pseudo-header lands here via the
    server's translation layer. When neither is set (test
    client, in-process call) we use a sentinel so the key still
    composes.
    """
    var host = req.headers.get(String("Host"))
    if host.byte_length() > 0:
        return host
    return String("_")


def _request_path(req: Request) -> String:
    """The cache key uses the full request-target including the
    query string (RFC 9111 §2: "Whether or not the query string
    is included is at the cache's discretion, but it is the
    safer default"). flare always includes it -- skipping the
    query would let two structurally different searches collide
    on the same `/search` path."""
    return req.url


def _alloc_store_or_zero[
    S: CacheStore & ImplicitlyDestructible & Movable & Defaultable,
]() -> Int:
    """Heap-allocate a fresh ``S`` and return its address, or 0
    on allocator failure. Defaultable middleware ``__init__``
    cannot raise; we mirror the :class:`flare.http.Metrics`
    convention of swallowing the alloc failure and returning 0,
    so the first ``Cache.serve`` trips on a null-pointer deref
    if the system is truly out of memory -- surfacing the OOM
    at the right call site rather than silently bypassing the
    cache."""
    try:
        return Pool[S].alloc_move(S())
    except:
        return 0


def _alloc_store_or_zero_move[
    S: CacheStore & ImplicitlyDestructible & Movable,
](var store: S) -> Int:
    """Same as :func:`_alloc_store_or_zero` but moves an
    already-built ``S`` value into the heap cell."""
    try:
        return Pool[S].alloc_move(store^)
    except:
        return 0


struct Cache[
    Inner: Handler & Copyable & Defaultable,
    S: CacheStore & ImplicitlyDestructible & Movable,
](Copyable, Defaultable, Handler, Movable):
    """RFC 9111 HTTP cache middleware.

    The middleware composes on top of any :class:`CacheStore`
    implementation. The default :class:`InMemoryCacheStore` is a
    bounded FIFO; callers that want stricter LRU eviction or an
    external store (Redis / memcached) swap the store without
    touching the rest of the chain.

    The store lives on the heap (via :class:`flare.runtime.Pool`)
    and the middleware holds the address as an ``Int``; copies of
    the middleware therefore share the same store, which matches
    the per-worker singleton shape that ``Logger`` /
    :class:`flare.http.Metrics` already use. The cell is leaked
    at process exit (worker pthreads live the lifetime of the
    server, so nothing meaningful to free); a future
    ``ArcPointer`` upgrade can swap the leak for ref-counting
    once nightly surfaces a stable shared-pointer type.

    Parameters:
        Inner: the inner handler.
        S: the cache store; must satisfy the :class:`CacheStore`
           trait.

    Example::

        from flare.http.cache import (
            Cache,
            InMemoryCacheStore,
        )
        var server = HttpServer(
            Cache[MyHandler, InMemoryCacheStore](
                inner=MyHandler(),
                store=InMemoryCacheStore.with_capacity(1024),
            )
        )
    """

    var inner: Self.Inner
    """The wrapped handler."""

    var store_addr: Int
    """Heap address of the shared :class:`CacheStore` cell.
    Allocated in ``__init__``; intentionally leaked at process
    exit (see struct doc)."""

    def __init__(out self):
        self.inner = Self.Inner()
        self.store_addr = _alloc_store_or_zero[Self.S]()

    def __init__(out self, var inner: Self.Inner, var store: Self.S):
        self.inner = inner^
        self.store_addr = _alloc_store_or_zero_move[Self.S](store^)

    def _store_ptr(self) -> UnsafePointer[Self.S, MutUntrackedOrigin]:
        return Pool[Self.S].get_ptr(self.store_addr)

    def _build_key(self, req: Request) raises -> CacheKey:
        """Compute the primary cache key for ``req``.

        The base key is method + URI; ``Vary`` segregation
        (RFC 9111 §4.1) layers on top via a deterministic suffix
        derived from the response's ``Vary`` field-name list (see
        :func:`_build_full_key`). The split lets the lookup path
        do two ``store.get`` calls: one for the base key (which
        carries the stored Vary metadata so we know what to
        suffix), one for the full key (which carries the body).
        """
        return derive_cache_key(
            req.method,
            String("http"),
            _request_authority(req),
            _request_path(req),
        )

    def _build_full_key(
        self, req: Request, vary_value: String
    ) raises -> CacheKey:
        """Extend the base key with the request's resolved
        ``Vary``-selected header values.

        Field names are case-insensitive; values are stripped of
        OWS and joined with a separator that cannot occur in a
        valid header value (LF), keeping the suffix
        deterministic across runs.
        """
        var pairs = _extract_vary_pairs(req.headers, vary_value)
        return derive_cache_key(
            req.method,
            String("http"),
            _request_authority(req),
            _request_path(req),
            pairs^,
        )

    def _store_response(
        self, req: Request, var response: Response
    ) raises -> Response:
        """Persist a fresh response into the cache, returning the
        original ``Response`` value untouched.

        Storing copies the headers + body since the response will
        be moved out to the caller; we want the entry to outlive
        the caller's handler.

        When the response carries a ``Vary`` header (RFC 9111
        §4.1), we store at two keys:

        - The **base key** -- a marker entry carrying the Vary
          field-name list. The lookup path consults this first
          to learn what selected-header values to suffix when
          building the full key.
        - The **full key** -- the actual cached entry. Each
          ``Vary`` bucket gets its own full key, so an ``en``
          request and an ``fr`` request to the same URI do not
          overwrite each other.
        """
        if not _is_cacheable_method(req.method):
            return response^
        if not _is_cacheable_status(response.status):
            return response^
        var cc = _response_cache_control(response.headers)
        if cc.no_store:
            return response^
        if _has_set_cookie(response.headers):
            return response^
        var vary_value = _response_vary(response.headers)
        var headers_copy = List[Tuple[String, String]]()
        var names_to_keep = self._user_visible_header_names(response.headers)
        for i in range(len(names_to_keep)):
            var name = names_to_keep[i]
            var v = response.headers.get(name)
            headers_copy.append((name, v))
        var body_copy = response.body.copy()
        var base_key = self._build_key(req)
        if vary_value.byte_length() == 0:
            var entry = CacheEntry(
                status=response.status,
                headers=headers_copy^,
                body=body_copy^,
                inserted_at_ms=Int64(_now_ms()),
                cache_control=cc^,
                vary=vary_value,
                date_ms=Optional[Int64](),
            )
            self._store_ptr()[].put(base_key, entry^)
        else:
            var marker = CacheEntry(
                status=response.status,
                headers=List[Tuple[String, String]](),
                body=List[UInt8](),
                inserted_at_ms=Int64(_now_ms()),
                cache_control=cc.copy(),
                vary=vary_value,
                date_ms=Optional[Int64](),
            )
            self._store_ptr()[].put(base_key, marker^)
            var full_key = self._build_full_key(req, vary_value)
            var entry = CacheEntry(
                status=response.status,
                headers=headers_copy^,
                body=body_copy^,
                inserted_at_ms=Int64(_now_ms()),
                cache_control=cc^,
                vary=vary_value,
                date_ms=Optional[Int64](),
            )
            self._store_ptr()[].put(full_key, entry^)
        return response^

    def _user_visible_header_names(self, headers: HeaderMap) -> List[String]:
        """Return the list of header names worth snapshotting for
        a cached response. We skip transport-level fields
        (``Date`` / ``Connection`` / ``Content-Length``) because
        the wire path re-derives them on every serialisation;
        snapshotting them would just create stale duplicates."""
        var candidates = List[String]()
        candidates.append(String("Content-Type"))
        candidates.append(String("Cache-Control"))
        candidates.append(String("Vary"))
        candidates.append(String("ETag"))
        candidates.append(String("Last-Modified"))
        candidates.append(String("Content-Encoding"))
        var keep = List[String]()
        for i in range(len(candidates)):
            if headers.contains(candidates[i]):
                keep.append(candidates[i])
        return keep^

    def _build_hit_response(self, entry: CacheEntry) raises -> Response:
        """Materialise a :class:`Response` from a cached entry.

        We copy the bytes because the store owns them and may be
        consulted by another worker concurrently; the cost is a
        single ``memcpy`` of the body and a small allocation for
        the header map. The ``X-Cache: HIT`` header is added so
        callers can observe the cache decision without
        instrumenting the middleware itself.
        """
        var resp = Response(entry.status)
        for i in range(len(entry.headers)):
            var pair = entry.headers[i]
            resp.headers.set(pair[0], pair[1])
        resp.headers.set(String("X-Cache"), String("HIT"))
        resp.body = entry.body.copy()
        return resp^

    def serve(self, req: Request) raises -> Response:
        if _is_invalidating_method(req.method):
            var resp = self.inner.serve(req)
            if resp.status >= 200 and resp.status < 400:
                # RFC 9111 §4.4: invalidate the URI's cached entry
                # on a successful unsafe response. Cache keys are
                # method-qualified (§2 primary key), but
                # invalidation targets the URI regardless of
                # method, so we rebuild keys for the cacheable
                # methods (GET / HEAD) and remove each.
                var get_key = derive_cache_key(
                    String("GET"),
                    String("http"),
                    _request_authority(req),
                    _request_path(req),
                )
                var head_key = derive_cache_key(
                    String("HEAD"),
                    String("http"),
                    _request_authority(req),
                    _request_path(req),
                )
                self._store_ptr()[].remove(get_key)
                self._store_ptr()[].remove(head_key)
            return resp^
        if not _is_cacheable_method(req.method):
            return self.inner.serve(req)
        var base_key = self._build_key(req)
        var base_hit = self._store_ptr()[].get(base_key)
        if base_hit:
            var base_entry = base_hit.value().copy()
            if base_entry.vary.byte_length() == 0:
                # No-Vary entry: the base entry is the cached
                # response. Check freshness and return.
                if is_fresh(
                    base_entry.cache_control,
                    base_entry.inserted_at_ms,
                    base_entry.date_ms,
                    req.headers,
                    _now_ms(),
                ):
                    return self._build_hit_response(base_entry)
            else:
                # Vary marker: re-derive the full key from the
                # stored Vary, then look up the bucket-specific
                # entry. ``Vary: *`` always misses.
                var fields = parse_vary_header(base_entry.vary)
                var has_star = False
                for i in range(len(fields)):
                    if fields[i] == String("*"):
                        has_star = True
                        break
                if not has_star:
                    var full_key = self._build_full_key(req, base_entry.vary)
                    var full_hit = self._store_ptr()[].get(full_key)
                    if full_hit:
                        var entry = full_hit.value().copy()
                        if is_fresh(
                            entry.cache_control,
                            entry.inserted_at_ms,
                            entry.date_ms,
                            req.headers,
                            _now_ms(),
                        ):
                            return self._build_hit_response(entry)
        var fresh = self.inner.serve(req)
        return self._store_response(req, fresh^)
