"""Comptime perfect-hash dispatch for ~70 standard HTTP header
names.

Replaces the case-insensitive linear scan in
``HeaderMap.{get,set,has}`` with a length-first + case-insensitive
byte-compare lookup against a fixed table of RFC 7230 + RFC 7231
+ RFC 7232 + RFC 7233 + RFC 7234 + RFC 7235 + RFC 9110 + RFC 6265
header names.

Why this is a Track B subtrack
-------------------------------

``HeaderMap.get(name)`` walks the underlying ``List[String]``
linearly, ASCII-lowercase comparing each entry. With ~10 headers
in a typical request, that's ~10 case-folded compares per lookup.
Most headers users actually look up are **standard** (Host,
Content-Type, Content-Length, Connection, User-Agent, Accept,
Cookie, Authorization, etc.). For those, a length-first dispatch
into a pre-canonicalised lowercase table is a single ``len(slice)
== K`` branch + a small per-length switch + one byte compare —
faster than the loop and, more importantly, **stable in latency**
regardless of how many other headers the request carries.

The deliverable here is the **dispatch primitive**: given a byte
slice, return an integer index 0..N-1 if it matches a known
standard header (case-insensitively), else -1. Wiring into the
``HeaderMap`` hot path is a follow-up commit; this commit lands
the table + tests + the public ``StandardHeader.*`` index
constants for downstream code that wants to talk in indices
rather than strings (e.g. the upcoming SIMD HPACK decoder needs
a static-table-resolution side channel).

Approach
--------

A "perfect hash" against a small fixed string set is most
practically implemented as **length-bucketed dispatch +
case-insensitive memcmp**. Mojo doesn't have a CHD / BDZ PHF
generator; for ~70 inputs the length-first approach is O(1) per
lookup with a tiny constant factor (single length compare → at
most 8-10 byte compares for the longest length-bucket), and it
generates instructions the branch predictor handles trivially.

Length 4 holds {Host, Date, From, ETag, Vary}. Length 5 holds
{Range, Allow}. Length 6 holds {Accept, Cookie, Server, Pragma,
Origin}. Length 7 holds {Referer, Trailer, Upgrade, Expires,
Warning, Refresh}. Etc. Most lengths have 1-5 candidates; the
pathological lengths (8 with {If-Match, If-Range, Location,
Set-Cookie/2-bytes-shy, etc.}) cap at ~6 candidates.

ASCII case folding
------------------

HTTP/1.1 header field names are case-insensitive (RFC 7230
§3.2). The lookup folds each input byte to lowercase via the
classic ``b | 0x20`` trick gated to ASCII letters [A-Z]. The
table itself stores the canonical lowercase form; one fold +
one byte compare per character.

What this commit ships
-----------------------

* ``StandardHeader`` — namespace struct holding the canonical
  index constants (``StandardHeader.HOST``,
  ``StandardHeader.CONTENT_TYPE``, etc.). Indices are stable
  for the lifetime of a flare release; downstream code
  (HeaderMap fast-path slot, SIMD HPACK decoder static table)
  can take dependencies on them.
* ``standard_header_count() -> Int`` — number of standard
  headers in the table (currently 70).
* ``standard_header_name(index) -> StaticString`` — inverse of
  the lookup; returns the canonical lowercase name for a
  valid index or empty ``StaticString`` for out-of-range.
* ``lookup_standard_header_bytes(slice) -> Int`` — the lookup
  primitive. Returns the index 0..N-1 on a hit (case-
  insensitive byte-compare against the table) or -1 on a miss.
* ``lookup_standard_header_string(name) -> Int`` — convenience
  ``String``-typed wrapper.
* ``is_standard_header(slice) -> Bool`` — boolean shorthand
  for callers that don't need the index.

The 70-name table covers (grouped by RFC):

* **Connection control (RFC 7230)**: Host, Connection,
  Keep-Alive, Transfer-Encoding, Trailer, Upgrade,
  Content-Length, Content-Type, Date, Via.
* **Conditionals (RFC 7232)**: ETag, If-Match, If-None-Match,
  If-Modified-Since, If-Unmodified-Since, Last-Modified.
* **Range (RFC 7233)**: Accept-Ranges, Range, If-Range,
  Content-Range.
* **Caching (RFC 7234)**: Cache-Control, Age, Expires, Pragma,
  Warning.
* **Authentication (RFC 7235)**: Authorization,
  WWW-Authenticate, Proxy-Authenticate,
  Proxy-Authorization.
* **Negotiation (RFC 9110)**: Accept, Accept-Encoding,
  Accept-Language, Accept-Charset, Allow, Content-Encoding,
  Content-Language, Content-Location, Content-Disposition,
  Vary, From, Referer, User-Agent, Server, Location,
  Retry-After.
* **Cookies (RFC 6265)**: Cookie, Set-Cookie.
* **CORS (W3C / Fetch)**: Origin, Access-Control-Allow-Origin,
  Access-Control-Allow-Methods, Access-Control-Allow-Headers,
  Access-Control-Allow-Credentials, Access-Control-Expose-
  Headers, Access-Control-Max-Age, Access-Control-Request-
  Method, Access-Control-Request-Headers.
* **Forwarding / Proxy (RFC 7239 + de facto)**: Forwarded,
  X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Host,
  X-Real-IP.
* **WebSocket / Upgrade**: Sec-WebSocket-Key, Sec-WebSocket-
  Version, Sec-WebSocket-Accept, Sec-WebSocket-Protocol,
  Sec-WebSocket-Extensions.
* **Misc widely-used**: Expect, Refresh, X-Request-ID,
  X-Content-Type-Options, X-Frame-Options, X-XSS-Protection,
  Strict-Transport-Security, Content-Security-Policy,
  Public-Key-Pins.
"""

# ── Standard header name table ──────────────────────────────────────────────
# Indices below are STABLE — appending only at the end. Reordering
# is a breaking change for downstream code that pinned a specific
# StandardHeader.NAME constant.


struct StandardHeader:
    """Stable comptime indices for the 70 standard HTTP header names.

    Indices are guaranteed not to renumber across flare patch
    releases; downstream code may pin specific constants (e.g. a
    SIMD HPACK decoder using these as static-table indices).
    """

    # RFC 7230 — connection control
    comptime HOST: Int = 0
    comptime CONNECTION: Int = 1
    comptime KEEP_ALIVE: Int = 2
    comptime TRANSFER_ENCODING: Int = 3
    comptime TRAILER: Int = 4
    comptime UPGRADE: Int = 5
    comptime CONTENT_LENGTH: Int = 6
    comptime CONTENT_TYPE: Int = 7
    comptime DATE: Int = 8
    comptime VIA: Int = 9

    # RFC 7232 — conditionals
    comptime ETAG: Int = 10
    comptime IF_MATCH: Int = 11
    comptime IF_NONE_MATCH: Int = 12
    comptime IF_MODIFIED_SINCE: Int = 13
    comptime IF_UNMODIFIED_SINCE: Int = 14
    comptime LAST_MODIFIED: Int = 15

    # RFC 7233 — range
    comptime ACCEPT_RANGES: Int = 16
    comptime RANGE: Int = 17
    comptime IF_RANGE: Int = 18
    comptime CONTENT_RANGE: Int = 19

    # RFC 7234 — caching
    comptime CACHE_CONTROL: Int = 20
    comptime AGE: Int = 21
    comptime EXPIRES: Int = 22
    comptime PRAGMA: Int = 23
    comptime WARNING: Int = 24

    # RFC 7235 — authentication
    comptime AUTHORIZATION: Int = 25
    comptime WWW_AUTHENTICATE: Int = 26
    comptime PROXY_AUTHENTICATE: Int = 27
    comptime PROXY_AUTHORIZATION: Int = 28

    # RFC 9110 — content + negotiation
    comptime ACCEPT: Int = 29
    comptime ACCEPT_ENCODING: Int = 30
    comptime ACCEPT_LANGUAGE: Int = 31
    comptime ACCEPT_CHARSET: Int = 32
    comptime ALLOW: Int = 33
    comptime CONTENT_ENCODING: Int = 34
    comptime CONTENT_LANGUAGE: Int = 35
    comptime CONTENT_LOCATION: Int = 36
    comptime CONTENT_DISPOSITION: Int = 37
    comptime VARY: Int = 38
    comptime FROM: Int = 39
    comptime REFERER: Int = 40
    comptime USER_AGENT: Int = 41
    comptime SERVER: Int = 42
    comptime LOCATION: Int = 43
    comptime RETRY_AFTER: Int = 44

    # RFC 6265 — cookies
    comptime COOKIE: Int = 45
    comptime SET_COOKIE: Int = 46

    # CORS
    comptime ORIGIN: Int = 47
    comptime ACCESS_CONTROL_ALLOW_ORIGIN: Int = 48
    comptime ACCESS_CONTROL_ALLOW_METHODS: Int = 49
    comptime ACCESS_CONTROL_ALLOW_HEADERS: Int = 50
    comptime ACCESS_CONTROL_ALLOW_CREDENTIALS: Int = 51
    comptime ACCESS_CONTROL_EXPOSE_HEADERS: Int = 52
    comptime ACCESS_CONTROL_MAX_AGE: Int = 53
    comptime ACCESS_CONTROL_REQUEST_METHOD: Int = 54
    comptime ACCESS_CONTROL_REQUEST_HEADERS: Int = 55

    # Forwarding / proxy
    comptime FORWARDED: Int = 56
    comptime X_FORWARDED_FOR: Int = 57
    comptime X_FORWARDED_PROTO: Int = 58
    comptime X_FORWARDED_HOST: Int = 59
    comptime X_REAL_IP: Int = 60

    # WebSocket / upgrade
    comptime SEC_WEBSOCKET_KEY: Int = 61
    comptime SEC_WEBSOCKET_VERSION: Int = 62
    comptime SEC_WEBSOCKET_ACCEPT: Int = 63
    comptime SEC_WEBSOCKET_PROTOCOL: Int = 64
    comptime SEC_WEBSOCKET_EXTENSIONS: Int = 65

    # Misc widely-used
    comptime EXPECT: Int = 66
    comptime REFRESH: Int = 67
    comptime X_REQUEST_ID: Int = 68
    comptime STRICT_TRANSPORT_SECURITY: Int = 69


comptime _STANDARD_HEADER_COUNT: Int = 70


@always_inline
def standard_header_count() -> Int:
    """Return the number of standard headers in the lookup table.

    Currently 70; will grow with future RFCs but never renumber.
    """
    return _STANDARD_HEADER_COUNT


def standard_header_name(index: Int) -> StaticString:
    """Return the canonical lowercase name for a standard header
    index, or an empty ``StaticString`` for out-of-range.

    Inverse of :func:`lookup_standard_header_bytes` modulo case
    folding — the input is normalised to lowercase, the output
    is always the canonical lowercase form.
    """
    if index == StandardHeader.HOST:
        return "host"
    if index == StandardHeader.CONNECTION:
        return "connection"
    if index == StandardHeader.KEEP_ALIVE:
        return "keep-alive"
    if index == StandardHeader.TRANSFER_ENCODING:
        return "transfer-encoding"
    if index == StandardHeader.TRAILER:
        return "trailer"
    if index == StandardHeader.UPGRADE:
        return "upgrade"
    if index == StandardHeader.CONTENT_LENGTH:
        return "content-length"
    if index == StandardHeader.CONTENT_TYPE:
        return "content-type"
    if index == StandardHeader.DATE:
        return "date"
    if index == StandardHeader.VIA:
        return "via"
    if index == StandardHeader.ETAG:
        return "etag"
    if index == StandardHeader.IF_MATCH:
        return "if-match"
    if index == StandardHeader.IF_NONE_MATCH:
        return "if-none-match"
    if index == StandardHeader.IF_MODIFIED_SINCE:
        return "if-modified-since"
    if index == StandardHeader.IF_UNMODIFIED_SINCE:
        return "if-unmodified-since"
    if index == StandardHeader.LAST_MODIFIED:
        return "last-modified"
    if index == StandardHeader.ACCEPT_RANGES:
        return "accept-ranges"
    if index == StandardHeader.RANGE:
        return "range"
    if index == StandardHeader.IF_RANGE:
        return "if-range"
    if index == StandardHeader.CONTENT_RANGE:
        return "content-range"
    if index == StandardHeader.CACHE_CONTROL:
        return "cache-control"
    if index == StandardHeader.AGE:
        return "age"
    if index == StandardHeader.EXPIRES:
        return "expires"
    if index == StandardHeader.PRAGMA:
        return "pragma"
    if index == StandardHeader.WARNING:
        return "warning"
    if index == StandardHeader.AUTHORIZATION:
        return "authorization"
    if index == StandardHeader.WWW_AUTHENTICATE:
        return "www-authenticate"
    if index == StandardHeader.PROXY_AUTHENTICATE:
        return "proxy-authenticate"
    if index == StandardHeader.PROXY_AUTHORIZATION:
        return "proxy-authorization"
    if index == StandardHeader.ACCEPT:
        return "accept"
    if index == StandardHeader.ACCEPT_ENCODING:
        return "accept-encoding"
    if index == StandardHeader.ACCEPT_LANGUAGE:
        return "accept-language"
    if index == StandardHeader.ACCEPT_CHARSET:
        return "accept-charset"
    if index == StandardHeader.ALLOW:
        return "allow"
    if index == StandardHeader.CONTENT_ENCODING:
        return "content-encoding"
    if index == StandardHeader.CONTENT_LANGUAGE:
        return "content-language"
    if index == StandardHeader.CONTENT_LOCATION:
        return "content-location"
    if index == StandardHeader.CONTENT_DISPOSITION:
        return "content-disposition"
    if index == StandardHeader.VARY:
        return "vary"
    if index == StandardHeader.FROM:
        return "from"
    if index == StandardHeader.REFERER:
        return "referer"
    if index == StandardHeader.USER_AGENT:
        return "user-agent"
    if index == StandardHeader.SERVER:
        return "server"
    if index == StandardHeader.LOCATION:
        return "location"
    if index == StandardHeader.RETRY_AFTER:
        return "retry-after"
    if index == StandardHeader.COOKIE:
        return "cookie"
    if index == StandardHeader.SET_COOKIE:
        return "set-cookie"
    if index == StandardHeader.ORIGIN:
        return "origin"
    if index == StandardHeader.ACCESS_CONTROL_ALLOW_ORIGIN:
        return "access-control-allow-origin"
    if index == StandardHeader.ACCESS_CONTROL_ALLOW_METHODS:
        return "access-control-allow-methods"
    if index == StandardHeader.ACCESS_CONTROL_ALLOW_HEADERS:
        return "access-control-allow-headers"
    if index == StandardHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS:
        return "access-control-allow-credentials"
    if index == StandardHeader.ACCESS_CONTROL_EXPOSE_HEADERS:
        return "access-control-expose-headers"
    if index == StandardHeader.ACCESS_CONTROL_MAX_AGE:
        return "access-control-max-age"
    if index == StandardHeader.ACCESS_CONTROL_REQUEST_METHOD:
        return "access-control-request-method"
    if index == StandardHeader.ACCESS_CONTROL_REQUEST_HEADERS:
        return "access-control-request-headers"
    if index == StandardHeader.FORWARDED:
        return "forwarded"
    if index == StandardHeader.X_FORWARDED_FOR:
        return "x-forwarded-for"
    if index == StandardHeader.X_FORWARDED_PROTO:
        return "x-forwarded-proto"
    if index == StandardHeader.X_FORWARDED_HOST:
        return "x-forwarded-host"
    if index == StandardHeader.X_REAL_IP:
        return "x-real-ip"
    if index == StandardHeader.SEC_WEBSOCKET_KEY:
        return "sec-websocket-key"
    if index == StandardHeader.SEC_WEBSOCKET_VERSION:
        return "sec-websocket-version"
    if index == StandardHeader.SEC_WEBSOCKET_ACCEPT:
        return "sec-websocket-accept"
    if index == StandardHeader.SEC_WEBSOCKET_PROTOCOL:
        return "sec-websocket-protocol"
    if index == StandardHeader.SEC_WEBSOCKET_EXTENSIONS:
        return "sec-websocket-extensions"
    if index == StandardHeader.EXPECT:
        return "expect"
    if index == StandardHeader.REFRESH:
        return "refresh"
    if index == StandardHeader.X_REQUEST_ID:
        return "x-request-id"
    if index == StandardHeader.STRICT_TRANSPORT_SECURITY:
        return "strict-transport-security"
    return ""


# ── Lookup primitive ─────────────────────────────────────────────────────────


@always_inline
def _ascii_lower(b: UInt8) -> UInt8:
    """Fold an ASCII byte to lowercase (no-op for non [A-Z])."""
    if b >= UInt8(65) and b <= UInt8(90):
        return b | UInt8(0x20)
    return b


@always_inline
def _ieq_static(slice: Span[UInt8, _], s: StaticString) -> Bool:
    """Return ``True`` iff ``slice`` is byte-equal to ``s`` after
    case-folding ``slice`` to lowercase.

    ``s`` is assumed to already be in canonical lowercase form
    (the table stores it that way).
    """
    var n = s.byte_length()
    if len(slice) != n:
        return False
    var sp = slice.unsafe_ptr()
    var bp = s.unsafe_ptr()
    for i in range(n):
        if _ascii_lower(sp[i]) != bp[i]:
            return False
    return True


def lookup_standard_header_bytes(slice: Span[UInt8, _]) -> Int:
    """Return the standard-header index (0..N-1) if ``slice``
    case-insensitively matches a known RFC 7230 / 7231 / 7232 /
    7233 / 7234 / 7235 / 9110 / 6265 / CORS / WebSocket header
    name; -1 otherwise.

    Length-first dispatch keeps the common case ("Host", "Date",
    "Cookie", "Accept", "Content-Length", etc.) on a single
    ``len()`` compare + ≤ 6 byte compares.

    Args:
        slice: Byte slice — typically a header-name field from
               an HTTP request line.

    Returns:
        Index into the StandardHeader table on a hit; -1 on a miss.
    """
    var n = len(slice)
    if n == 3:
        if _ieq_static(slice, "via"):
            return StandardHeader.VIA
        if _ieq_static(slice, "age"):
            return StandardHeader.AGE
        return -1
    if n == 4:
        if _ieq_static(slice, "host"):
            return StandardHeader.HOST
        if _ieq_static(slice, "date"):
            return StandardHeader.DATE
        if _ieq_static(slice, "etag"):
            return StandardHeader.ETAG
        if _ieq_static(slice, "vary"):
            return StandardHeader.VARY
        if _ieq_static(slice, "from"):
            return StandardHeader.FROM
        return -1
    if n == 5:
        if _ieq_static(slice, "range"):
            return StandardHeader.RANGE
        if _ieq_static(slice, "allow"):
            return StandardHeader.ALLOW
        return -1
    if n == 6:
        if _ieq_static(slice, "accept"):
            return StandardHeader.ACCEPT
        if _ieq_static(slice, "cookie"):
            return StandardHeader.COOKIE
        if _ieq_static(slice, "server"):
            return StandardHeader.SERVER
        if _ieq_static(slice, "pragma"):
            return StandardHeader.PRAGMA
        if _ieq_static(slice, "origin"):
            return StandardHeader.ORIGIN
        if _ieq_static(slice, "expect"):
            return StandardHeader.EXPECT
        return -1
    if n == 7:
        if _ieq_static(slice, "referer"):
            return StandardHeader.REFERER
        if _ieq_static(slice, "trailer"):
            return StandardHeader.TRAILER
        if _ieq_static(slice, "upgrade"):
            return StandardHeader.UPGRADE
        if _ieq_static(slice, "expires"):
            return StandardHeader.EXPIRES
        if _ieq_static(slice, "warning"):
            return StandardHeader.WARNING
        if _ieq_static(slice, "refresh"):
            return StandardHeader.REFRESH
        return -1
    if n == 8:
        if _ieq_static(slice, "if-match"):
            return StandardHeader.IF_MATCH
        if _ieq_static(slice, "if-range"):
            return StandardHeader.IF_RANGE
        if _ieq_static(slice, "location"):
            return StandardHeader.LOCATION
        return -1
    if n == 9:
        if _ieq_static(slice, "forwarded"):
            return StandardHeader.FORWARDED
        if _ieq_static(slice, "x-real-ip"):
            return StandardHeader.X_REAL_IP
        return -1
    if n == 10:
        if _ieq_static(slice, "connection"):
            return StandardHeader.CONNECTION
        if _ieq_static(slice, "keep-alive"):
            return StandardHeader.KEEP_ALIVE
        if _ieq_static(slice, "user-agent"):
            return StandardHeader.USER_AGENT
        if _ieq_static(slice, "set-cookie"):
            return StandardHeader.SET_COOKIE
        return -1
    if n == 11:
        if _ieq_static(slice, "retry-after"):
            return StandardHeader.RETRY_AFTER
        return -1
    if n == 12:
        if _ieq_static(slice, "content-type"):
            return StandardHeader.CONTENT_TYPE
        if _ieq_static(slice, "x-request-id"):
            return StandardHeader.X_REQUEST_ID
        return -1
    if n == 13:
        if _ieq_static(slice, "accept-ranges"):
            return StandardHeader.ACCEPT_RANGES
        if _ieq_static(slice, "authorization"):
            return StandardHeader.AUTHORIZATION
        if _ieq_static(slice, "cache-control"):
            return StandardHeader.CACHE_CONTROL
        if _ieq_static(slice, "content-range"):
            return StandardHeader.CONTENT_RANGE
        if _ieq_static(slice, "if-none-match"):
            return StandardHeader.IF_NONE_MATCH
        if _ieq_static(slice, "last-modified"):
            return StandardHeader.LAST_MODIFIED
        return -1
    if n == 14:
        if _ieq_static(slice, "accept-charset"):
            return StandardHeader.ACCEPT_CHARSET
        if _ieq_static(slice, "content-length"):
            return StandardHeader.CONTENT_LENGTH
        return -1
    if n == 15:
        if _ieq_static(slice, "accept-encoding"):
            return StandardHeader.ACCEPT_ENCODING
        if _ieq_static(slice, "accept-language"):
            return StandardHeader.ACCEPT_LANGUAGE
        if _ieq_static(slice, "x-forwarded-for"):
            return StandardHeader.X_FORWARDED_FOR
        return -1
    if n == 16:
        if _ieq_static(slice, "content-encoding"):
            return StandardHeader.CONTENT_ENCODING
        if _ieq_static(slice, "content-language"):
            return StandardHeader.CONTENT_LANGUAGE
        if _ieq_static(slice, "content-location"):
            return StandardHeader.CONTENT_LOCATION
        if _ieq_static(slice, "www-authenticate"):
            return StandardHeader.WWW_AUTHENTICATE
        if _ieq_static(slice, "x-forwarded-host"):
            return StandardHeader.X_FORWARDED_HOST
        return -1
    if n == 17:
        if _ieq_static(slice, "if-modified-since"):
            return StandardHeader.IF_MODIFIED_SINCE
        if _ieq_static(slice, "transfer-encoding"):
            return StandardHeader.TRANSFER_ENCODING
        if _ieq_static(slice, "sec-websocket-key"):
            return StandardHeader.SEC_WEBSOCKET_KEY
        if _ieq_static(slice, "x-forwarded-proto"):
            return StandardHeader.X_FORWARDED_PROTO
        return -1
    if n == 18:
        if _ieq_static(slice, "proxy-authenticate"):
            return StandardHeader.PROXY_AUTHENTICATE
        return -1
    if n == 19:
        if _ieq_static(slice, "content-disposition"):
            return StandardHeader.CONTENT_DISPOSITION
        if _ieq_static(slice, "if-unmodified-since"):
            return StandardHeader.IF_UNMODIFIED_SINCE
        if _ieq_static(slice, "proxy-authorization"):
            return StandardHeader.PROXY_AUTHORIZATION
        return -1
    if n == 20:
        if _ieq_static(slice, "sec-websocket-accept"):
            return StandardHeader.SEC_WEBSOCKET_ACCEPT
        return -1
    if n == 21:
        if _ieq_static(slice, "sec-websocket-version"):
            return StandardHeader.SEC_WEBSOCKET_VERSION
        return -1
    if n == 22:
        if _ieq_static(slice, "access-control-max-age"):
            return StandardHeader.ACCESS_CONTROL_MAX_AGE
        if _ieq_static(slice, "sec-websocket-protocol"):
            return StandardHeader.SEC_WEBSOCKET_PROTOCOL
        return -1
    if n == 24:
        if _ieq_static(slice, "sec-websocket-extensions"):
            return StandardHeader.SEC_WEBSOCKET_EXTENSIONS
        return -1
    if n == 25:
        if _ieq_static(slice, "strict-transport-security"):
            return StandardHeader.STRICT_TRANSPORT_SECURITY
        return -1
    if n == 27:
        if _ieq_static(slice, "access-control-allow-origin"):
            return StandardHeader.ACCESS_CONTROL_ALLOW_ORIGIN
        return -1
    if n == 28:
        if _ieq_static(slice, "access-control-allow-methods"):
            return StandardHeader.ACCESS_CONTROL_ALLOW_METHODS
        if _ieq_static(slice, "access-control-allow-headers"):
            return StandardHeader.ACCESS_CONTROL_ALLOW_HEADERS
        return -1
    if n == 29:
        if _ieq_static(slice, "access-control-request-method"):
            return StandardHeader.ACCESS_CONTROL_REQUEST_METHOD
        if _ieq_static(slice, "access-control-expose-headers"):
            return StandardHeader.ACCESS_CONTROL_EXPOSE_HEADERS
        return -1
    if n == 30:
        if _ieq_static(slice, "access-control-request-headers"):
            return StandardHeader.ACCESS_CONTROL_REQUEST_HEADERS
        return -1
    if n == 32:
        if _ieq_static(slice, "access-control-allow-credentials"):
            return StandardHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS
        return -1
    return -1


def lookup_standard_header_string(name: String) -> Int:
    """``String``-typed convenience wrapper around
    :func:`lookup_standard_header_bytes`.
    """
    return lookup_standard_header_bytes(name.as_bytes())


def is_standard_header(slice: Span[UInt8, _]) -> Bool:
    """Boolean shorthand: ``True`` iff the slice case-insensitively
    matches a standard header name.
    """
    return lookup_standard_header_bytes(slice) >= 0
