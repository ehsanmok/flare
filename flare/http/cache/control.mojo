"""``Cache-Control`` header parser (RFC 9111 §5.2).

The ``Cache-Control`` header carries a comma-separated list of
directives. Each directive is either a bare token (e.g.
``no-cache``, ``no-store``, ``public``, ``private``) or a
token=value pair (e.g. ``max-age=3600``, ``s-maxage=300``,
``stale-while-revalidate=60``).

Tokens are case-insensitive; this parser normalises to lowercase.
Unknown directives are surfaced through ``unknown_directives`` so
middleware can decide whether to honour or skip them (e.g.
``immutable`` is RFC 8246, not RFC 9111).

Reference:
- RFC 9111 §5.2 "Cache-Control".
- RFC 9111 §4.2 "Freshness".
- RFC 9111 §4.1 "Calculating Secondary Keys with Vary".
- RFC 9110 §6.6.1 "Date".
- RFC 8246 (``immutable``).
"""

from std.collections import List, Optional

from ..headers import HeaderMap


@fieldwise_init
struct CacheControl(Copyable, Defaultable):
    """Parsed Cache-Control directive set.

    Boolean directives are True when present; numeric directives
    are Optional[Int] (None when absent, ``Some(seconds)`` when
    present with a value). Negative or unparseable numeric values
    are silently dropped per RFC 9111 §5.2 ("If the value is
    invalid, it should be treated as if it were not present").
    """

    var no_cache: Bool
    var no_store: Bool
    var no_transform: Bool
    var public: Bool
    var private: Bool
    var must_revalidate: Bool
    var proxy_revalidate: Bool
    var immutable: Bool
    var max_age: Optional[Int]
    var s_maxage: Optional[Int]
    var stale_while_revalidate: Optional[Int]
    var stale_if_error: Optional[Int]
    var unknown_directives: List[String]

    def __init__(out self):
        self.no_cache = False
        self.no_store = False
        self.no_transform = False
        self.public = False
        self.private = False
        self.must_revalidate = False
        self.proxy_revalidate = False
        self.immutable = False
        self.max_age = Optional[Int]()
        self.s_maxage = Optional[Int]()
        self.stale_while_revalidate = Optional[Int]()
        self.stale_if_error = Optional[Int]()
        self.unknown_directives = List[String]()

    def copy(self) -> Self:
        return Self(
            no_cache=self.no_cache,
            no_store=self.no_store,
            no_transform=self.no_transform,
            public=self.public,
            private=self.private,
            must_revalidate=self.must_revalidate,
            proxy_revalidate=self.proxy_revalidate,
            immutable=self.immutable,
            max_age=self.max_age,
            s_maxage=self.s_maxage,
            stale_while_revalidate=self.stale_while_revalidate,
            stale_if_error=self.stale_if_error,
            unknown_directives=self.unknown_directives.copy(),
        )


def _lower(s: String) -> String:
    var out = String()
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        var c = p[i]
        if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _trim(s: String) -> String:
    var n = s.byte_length()
    if n == 0:
        return s
    var p = s.unsafe_ptr()
    var lo = 0
    while lo < n and (
        p[lo] == UInt8(ord(" "))
        or p[lo] == UInt8(ord("\t"))
        or p[lo] == UInt8(ord("\r"))
        or p[lo] == UInt8(ord("\n"))
    ):
        lo += 1
    var hi = n
    while hi > lo and (
        p[hi - 1] == UInt8(ord(" "))
        or p[hi - 1] == UInt8(ord("\t"))
        or p[hi - 1] == UInt8(ord("\r"))
        or p[hi - 1] == UInt8(ord("\n"))
    ):
        hi -= 1
    var out = String()
    for i in range(lo, hi):
        out += chr(Int(p[i]))
    return out^


def _parse_int(s: String) -> Optional[Int]:
    var n = s.byte_length()
    if n == 0:
        return Optional[Int]()
    var p = s.unsafe_ptr()
    var acc = 0
    for i in range(n):
        var c = p[i]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            return Optional[Int]()
        acc = acc * 10 + (Int(c) - ord("0"))
    return Optional[Int](acc)


def _split_directives(value: String) -> List[String]:
    """Split a Cache-Control value on commas, honouring quoted-
    string boundaries so values like ``private="X-Foo, X-Bar"``
    don't get bisected mid-quotes."""
    var out = List[String]()
    var p = value.unsafe_ptr()
    var n = value.byte_length()
    var i = 0
    var start = 0
    var in_quotes = False
    while i < n:
        var c = p[i]
        if c == UInt8(ord('"')) and (i == 0 or p[i - 1] != UInt8(ord("\\"))):
            in_quotes = not in_quotes
        elif c == UInt8(ord(",")) and not in_quotes:
            var piece = String()
            for j in range(start, i):
                piece += chr(Int(p[j]))
            out.append(_trim(piece))
            start = i + 1
        i += 1
    if start < n:
        var piece = String()
        for j in range(start, n):
            piece += chr(Int(p[j]))
        out.append(_trim(piece))
    return out^


def parse_cache_control(value: String) -> CacheControl:
    """Parse a Cache-Control header value into a structured
    directive set.

    The parser is permissive per RFC 9111 §5.2: malformed numeric
    values silently drop, unknown directives are surfaced through
    ``unknown_directives`` rather than rejected. Callers that
    want strict behaviour can inspect ``unknown_directives``
    after the fact.
    """
    var cc = CacheControl()
    var pieces = _split_directives(value)
    for i in range(len(pieces)):
        var directive = pieces[i]
        if directive.byte_length() == 0:
            continue
        # Split on '=' (first occurrence only; values may contain '=').
        var eq_at = -1
        var p = directive.unsafe_ptr()
        var n = directive.byte_length()
        for j in range(n):
            if p[j] == UInt8(ord("=")):
                eq_at = j
                break
        var name: String
        var val: String
        if eq_at == -1:
            name = _lower(_trim(directive))
            val = String()
        else:
            var k = String()
            for j in range(eq_at):
                k += chr(Int(p[j]))
            name = _lower(_trim(k))
            var v = String()
            for j in range(eq_at + 1, n):
                v += chr(Int(p[j]))
            val = _trim(v)
            # Strip surrounding quotes on the value, if any.
            if val.byte_length() >= 2:
                var vp = val.unsafe_ptr()
                if vp[0] == UInt8(ord('"')) and vp[
                    val.byte_length() - 1
                ] == UInt8(ord('"')):
                    var unq = String()
                    for j in range(1, val.byte_length() - 1):
                        unq += chr(Int(vp[j]))
                    val = unq^
        if name == String("no-cache"):
            cc.no_cache = True
        elif name == String("no-store"):
            cc.no_store = True
        elif name == String("no-transform"):
            cc.no_transform = True
        elif name == String("public"):
            cc.public = True
        elif name == String("private"):
            cc.private = True
        elif name == String("must-revalidate"):
            cc.must_revalidate = True
        elif name == String("proxy-revalidate"):
            cc.proxy_revalidate = True
        elif name == String("immutable"):
            cc.immutable = True
        elif name == String("max-age"):
            cc.max_age = _parse_int(val)
        elif name == String("s-maxage"):
            cc.s_maxage = _parse_int(val)
        elif name == String("stale-while-revalidate"):
            cc.stale_while_revalidate = _parse_int(val)
        elif name == String("stale-if-error"):
            cc.stale_if_error = _parse_int(val)
        else:
            cc.unknown_directives.append(name)
    return cc^


def parse_vary_header(value: String) -> List[String]:
    """Parse a ``Vary`` response header into its constituent field
    names per RFC 9111 §4.1 (secondary-key derivation).

    The header is a comma-separated list of header names; tokens
    are case-insensitive and stripped of surrounding whitespace
    on output. A single ``*`` value (RFC 9110 §12.5.5) signals
    that the response varies on aspects the cache cannot see and
    callers must treat the entry as unconditionally non-reusable;
    we surface it explicitly in the returned list so the caller
    can short-circuit, rather than silently dropping it.
    """
    var out = List[String]()
    var n = value.byte_length()
    if n == 0:
        return out^
    var pieces = _split_directives(value)
    for i in range(len(pieces)):
        var p = _lower(_trim(pieces[i]))
        if p.byte_length() == 0:
            continue
        out.append(p^)
    return out^


def _epoch_age_seconds(
    entry_inserted_at_ms: Int64,
    entry_date_ms: Optional[Int64],
    now_ms: UInt64,
) -> Int:
    """Compute ``Age`` per RFC 9111 §4.2.3 (simplified):
    ``age = now - date_value``, or ``now - inserted_at`` if the
    response did not carry a ``Date`` header.

    Inputs are millisecond timestamps; the return value is
    seconds (per RFC 9111 §1.3 the freshness math is integer
    seconds). Negative ages (clock skew) clamp to zero.
    """
    var base_ms: Int64
    if entry_date_ms:
        base_ms = entry_date_ms.value()
    else:
        base_ms = entry_inserted_at_ms
    var now_signed = Int64(now_ms)
    if now_signed < base_ms:
        return 0
    var delta_ms = now_signed - base_ms
    return Int(delta_ms // Int64(1000))


def _request_max_age(request_headers: HeaderMap) -> Optional[Int]:
    """If the client supplied ``Cache-Control: max-age=N``, return
    ``N`` (clamped to ≥ 0). ``max-age=0`` is a real freshness
    override and is returned as ``Some(0)``."""
    var raw = request_headers.get(String("Cache-Control"))
    if raw.byte_length() == 0:
        return Optional[Int]()
    var cc = parse_cache_control(raw)
    return cc.max_age


def _request_no_cache(request_headers: HeaderMap) -> Bool:
    """RFC 9111 §5.2.1.4: a request with ``Cache-Control:
    no-cache`` MUST force the cache to revalidate (i.e. treat any
    stored response as stale for the purposes of reuse)."""
    var raw = request_headers.get(String("Cache-Control"))
    if raw.byte_length() == 0:
        return False
    var cc = parse_cache_control(raw)
    return cc.no_cache


def is_fresh(
    response_cc: CacheControl,
    inserted_at_ms: Int64,
    date_ms: Optional[Int64],
    request_headers: HeaderMap,
    now_ms: UInt64,
) -> Bool:
    """Return True if a stored response is still fresh at
    ``now_ms`` under the RFC 9111 §4.2 freshness model.

    The check honours, in order:

    1. Request-side ``Cache-Control: no-cache`` -> never fresh
       (RFC 9111 §5.2.1.4).
    2. Response-side ``no-store`` / ``no-cache`` /
       ``must-revalidate`` -> never fresh.
    3. Request-side ``max-age=N`` -> the entry is fresh iff
       ``age <= min(request_max_age, response_freshness_lifetime)``
       (RFC 9111 §5.2.1.1). ``max-age=0`` is the standard "force
       revalidation" override.
    4. Response-side ``s-maxage`` (if shared cache) or
       ``max-age`` (otherwise) -> the freshness lifetime.
    5. ``immutable`` (RFC 8246) -> always fresh while
       freshness lifetime is non-zero.

    This implementation treats the cache as a *private* cache
    (per-handler in-process store); ``s-maxage`` is honoured only
    when ``max-age`` is absent. Shared-cache semantics land with
    the proxy adapter in a later release.

    The function does not consult the ``Expires`` header
    (RFC 9110 §5.3) because ``Cache-Control: max-age`` always
    overrides it (RFC 9111 §5.3) and modern responses set the
    former; a future commit can add ``Expires`` for the long tail
    of legacy origins.
    """
    if _request_no_cache(request_headers):
        return False
    if response_cc.no_store or response_cc.no_cache:
        return False
    if response_cc.must_revalidate:
        return False
    var lifetime: Optional[Int]
    if response_cc.max_age:
        lifetime = response_cc.max_age
    elif response_cc.s_maxage:
        lifetime = response_cc.s_maxage
    else:
        lifetime = Optional[Int]()
    if not lifetime:
        return False
    var lifetime_s = lifetime.value()
    if lifetime_s <= 0:
        return False
    var age = _epoch_age_seconds(inserted_at_ms, date_ms, now_ms)
    var rq_max = _request_max_age(request_headers)
    if rq_max:
        var rq = rq_max.value()
        # RFC 9111 §5.2.1.1: ``max-age=0`` is the canonical
        # "force revalidation" override (the client is unwilling
        # to accept a cached response without a successful
        # validation against the origin). Treat it as a hard miss
        # so callers don't get a 0-second-old hit on the freshly
        # populated entry.
        if rq <= 0:
            return False
        if age > rq:
            return False
    if response_cc.immutable:
        return age < lifetime_s
    return age < lifetime_s
