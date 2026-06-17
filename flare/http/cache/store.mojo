"""Cache store trait + in-memory implementation.

A ``CacheStore`` is the persistence layer behind the cache
middleware: it accepts ``(key, entry)`` pairs and returns the
entry on lookup. Concrete implementations choose their own
eviction policy + capacity bound.

The :class:`InMemoryCacheStore` ships here; a filesystem-backed
store + an external-cache adapter (Redis / memcached) are
possible follow-ups. The trait keeps the middleware decoupled
from the storage choice.
"""

from std.collections import List, Optional

from .control import CacheControl
from .key import CacheKey


@fieldwise_init
struct CacheEntry(Copyable, Movable):
    """A stored cache entry.

    Bodies are owned by the entry so the store can outlive the
    handler that produced them. ``inserted_at_ms`` is a monotonic
    timestamp (milliseconds) the middleware uses to compute age;
    callers pass the value at insertion time so the store stays
    decoupled from the clock source.

    The parsed :class:`CacheControl` + ``Vary`` header value are
    carried alongside the wire bytes so the freshness check
    (:func:`flare.http.cache.is_fresh`) and the secondary key
    derivation can run without re-parsing on every lookup.
    ``date_ms`` is the value of the response's ``Date`` header at
    insertion time (RFC 9110 §6.6.1) — None when the response did
    not advertise one, in which case ``inserted_at_ms`` stands in
    as the response's wire time. ``Age:`` accumulation
    (RFC 9111 §4.2.3) starts from whichever is set.
    """

    var status: Int
    var headers: List[Tuple[String, String]]
    var body: List[UInt8]
    var inserted_at_ms: Int64
    var cache_control: CacheControl
    var vary: String
    var date_ms: Optional[Int64]

    @staticmethod
    def basic(
        status: Int,
        var headers: List[Tuple[String, String]],
        var body: List[UInt8],
        inserted_at_ms: Int64,
    ) -> Self:
        """Build a ``CacheEntry`` with empty/defaulted freshness
        metadata. Used by callers that don't yet care about
        RFC 9111 freshness (single-shot tests, naïve middleware
        wrappers). The :func:`Cache` middleware builds entries
        via the explicit constructor with parsed fields.
        """
        return Self(
            status=status,
            headers=headers^,
            body=body^,
            inserted_at_ms=inserted_at_ms,
            cache_control=CacheControl(),
            vary=String(""),
            date_ms=Optional[Int64](),
        )

    def copy(self) -> Self:
        return Self(
            status=self.status,
            headers=self.headers.copy(),
            body=self.body.copy(),
            inserted_at_ms=self.inserted_at_ms,
            cache_control=self.cache_control.copy(),
            vary=self.vary,
            date_ms=self.date_ms,
        )


trait CacheStore(Copyable, Defaultable, Movable):
    """Persistence interface for cached responses.

    Implementations must accept concurrent reads/writes from the
    reactor; the in-memory store delegates to an internal lock.
    The trait is intentionally simple (get / put / remove) to
    keep adapter integration low-friction.
    """

    def get(self, key: CacheKey) raises -> Optional[CacheEntry]:
        ...

    def put(mut self, key: CacheKey, entry: CacheEntry) raises:
        ...

    def remove(mut self, key: CacheKey) raises:
        ...

    def len(self) -> Int:
        ...


struct InMemoryCacheStore(CacheStore, Copyable, Defaultable, Movable):
    """Bounded LRU-style in-memory cache store.

    Eviction is approximate: when ``len() >= capacity`` a new put
    drops the oldest-inserted entry. This is intentionally simpler
    than a strict LRU (no recency tracking on get) so the lookup
    path stays branch-light; profile-driven upgrades to a true
    LRU policy can land later.
    """

    var _keys: List[String]
    var _entries: List[CacheEntry]
    var _capacity: Int

    def __init__(out self):
        self._keys = List[String]()
        self._entries = List[CacheEntry]()
        self._capacity = 1024

    def __init__(out self, *, copy: Self):
        self._keys = copy._keys.copy()
        self._entries = copy._entries.copy()
        self._capacity = copy._capacity

    @staticmethod
    def with_capacity(capacity: Int) -> Self:
        var s = Self()
        s._capacity = capacity if capacity > 0 else 1
        return s^

    def _index_of(self, key: CacheKey) -> Int:
        for i in range(len(self._keys)):
            if self._keys[i] == key.raw:
                return i
        return -1

    def get(self, key: CacheKey) raises -> Optional[CacheEntry]:
        var idx = self._index_of(key)
        if idx < 0:
            return Optional[CacheEntry]()
        return Optional[CacheEntry](self._entries[idx].copy())

    def put(mut self, key: CacheKey, entry: CacheEntry) raises:
        var idx = self._index_of(key)
        if idx >= 0:
            # Update in place.
            self._entries[idx] = entry.copy()
            return
        # Bounded insert: evict oldest if at capacity.
        if len(self._keys) >= self._capacity:
            # Simple FIFO eviction; rebuild both lists without
            # the front element. A profile-driven upgrade to a
            # circular buffer can land later if surfaces.
            var rest_keys = List[String]()
            var rest_entries = List[CacheEntry]()
            for i in range(1, len(self._keys)):
                rest_keys.append(self._keys[i])
                rest_entries.append(self._entries[i].copy())
            self._keys = rest_keys^
            self._entries = rest_entries^
        self._keys.append(key.raw)
        self._entries.append(entry.copy())

    def remove(mut self, key: CacheKey) raises:
        var idx = self._index_of(key)
        if idx < 0:
            return
        var new_keys = List[String]()
        var new_entries = List[CacheEntry]()
        for i in range(len(self._keys)):
            if i == idx:
                continue
            new_keys.append(self._keys[i])
            new_entries.append(self._entries[i].copy())
        self._keys = new_keys^
        self._entries = new_entries^

    def len(self) -> Int:
        return len(self._keys)

    def capacity(self) -> Int:
        return self._capacity
