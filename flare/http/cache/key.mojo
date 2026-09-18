"""Cache key derivation (RFC 9111 §4 "Constructing Responses
from Caches").

A cache key uniquely identifies a stored response. The minimum
inputs are the request method + the effective request URI; the
``Vary`` response header expands this with selected request
headers so two requests to the same URI with different
``Accept-Language`` headers store separate entries.

This module produces a deterministic string key from those
inputs. The serialisation format is internal; consumers should
treat keys as opaque tokens. Concrete store implementations may
hash the key into a fixed-width identifier.
"""

from std.collections import List
from std.collections.span import Span


@fieldwise_init
struct CacheKey(Copyable):
    """Opaque cache key. ``raw`` is the deterministic string used
    by store implementations."""

    var raw: String

    def __eq__(self, other: CacheKey) -> Bool:
        return self.raw == other.raw


def derive_cache_key(
    method: String,
    scheme: String,
    authority: String,
    path: String,
    vary_headers: List[Tuple[String, String]] = List[Tuple[String, String]](),
) -> CacheKey:
    """Build a cache key for a request.

    ``vary_headers`` is the resolved set of ``(header-name,
    header-value)`` pairs the caller computed by inspecting a
    prior response's ``Vary`` header (RFC 9111 §4.1). Header
    names are case-insensitive; the caller should lowercase
    before passing them in so two writers building keys for the
    same logical request produce identical strings.
    """
    var key = String()
    key += method
    key += " "
    key += scheme
    key += "://"
    key += authority
    key += path
    if len(vary_headers) > 0:
        key += " | vary"
        for i in range(len(vary_headers)):
            key += " "
            key += vary_headers[i][0]
            key += "="
            key += vary_headers[i][1]
    return CacheKey(raw=key^)
