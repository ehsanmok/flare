"""``flare.http.cache`` — RFC 9111 HTTP cache primitives.

This package ships the data model + in-memory store layer that a
cache middleware composes on top of. The full RFC 9111 conformance
surface (Vary header negotiation, stale-while-revalidate /
stale-if-error refresh policy, validator-driven conditional
revalidation) is staged incrementally; this package currently
provides:

- :class:`CacheControl` — parsed ``Cache-Control`` directive set.
- :func:`parse_cache_control` — header parser.
- :func:`parse_vary_header` — ``Vary`` header field-name parser.
- :func:`is_fresh` — RFC 9111 §4.2 freshness check, honours both
  response- and request-side ``Cache-Control``.
- :class:`CacheKey` — request → cache lookup key derivation.
- :class:`CacheEntry` — stored response wrapper carrying the
  parsed :class:`CacheControl` + ``Vary`` value alongside the
  wire bytes.
- :class:`InMemoryCacheStore` — minimal LRU-bounded store.

The middleware shim that *uses* this layer (``Cache[Inner, S]``)
lands once the store + key derivation surface stabilises.
"""

from .control import (
    CacheControl,
    is_fresh,
    parse_cache_control,
    parse_vary_header,
)
from .key import CacheKey, derive_cache_key
from .middleware import Cache
from .store import (
    CacheEntry,
    CacheStore,
    InMemoryCacheStore,
)
