"""Conditional GET / PUT middleware (RFC 9110 §13).

``Conditional[Inner]`` evaluates the four standard precondition
headers against the response that the wrapped ``Inner`` handler
produces:

- ``If-Match``         (RFC 9110 §13.1.1) → 412 Precondition Failed
                                              when no token matches
                                              the response ETag.
- ``If-None-Match``    (RFC 9110 §13.1.2) → 304 Not Modified for
                                              GET / HEAD; 412 for
                                              other methods.
- ``If-Modified-Since`` (RFC 9110 §13.1.3) → 304 Not Modified for
                                              GET / HEAD when the
                                              resource hasn't
                                              changed since the
                                              client's cached copy.
- ``If-Unmodified-Since`` (RFC 9110 §13.1.4) → 412 Precondition
                                                  Failed for any
                                                  method when the
                                                  resource has
                                                  changed since
                                                  ``Last-Modified``.

When the inner response carries no ``ETag``, this middleware can
generate a weak one from a 64-bit FNV-1a hash of the body. Auto-ETag
is opt-in via ``Conditional.with_auto_etag`` (default off — the
caller explicitly chooses whether to pay the body-hash cost on each
request, since for large bodies it's not free).

Behaviour notes:

- Precedence per RFC 9110 §13.2.2: If-Match > If-Unmodified-Since >
  If-None-Match > If-Modified-Since. Conditional honours the order
  exactly; the first failing precondition short-circuits.
- Strong vs weak comparison: If-Match always uses strong comparison
  (only strong ETags match). If-None-Match uses weak comparison
  when the request method is GET / HEAD and strong otherwise — the
  spec's distinction between "safe / cacheable" and "state-changing"
  methods.
- The inner handler still runs (we need its response to read the
  ETag / Last-Modified headers); the middleware only rewrites the
  outbound status + body. For a cache-aware origin you'd usually
  put a body-skipping fast-path inside the inner handler that
  computes ETag without rendering — that's an inner-handler
  optimisation orthogonal to this middleware.
- 304 Not Modified responses must drop the body and the
  Content-Length header per RFC 9110 §15.4.5. Conditional does this.
- 412 responses keep the body bytes the inner handler emitted (so
  the caller sees the conflict reason); only the status code is
  rewritten.

Example:

```mojo
from flare.http import Conditional, Router, Response, ok

def handler(req: Request) raises -> Response:
    var resp = ok("hello")
    resp.headers.set("ETag", '"abc123"')
    return resp^

var app = Conditional[Router](Router())  # wraps any Handler-shaped Inner
```
"""

from std.collections import Optional

from .handler import Handler
from .request import Request
from .response import Response
from ..runtime.date_cache import civil_to_unix_seconds


# ── ETag matcher ────────────────────────────────────────────────────────────


@fieldwise_init
struct _StrippedEtag(Copyable):
    """Decomposed ETag token: ``is_weak`` flag + opaque body
    (without the surrounding double quotes).

    Returned from :func:`_strip_etag`. An ``opaque == ""`` value
    means the input was malformed (no surrounding double quotes,
    or a missing closing quote); the caller treats malformed as
    "no match"."""

    var is_weak: Bool
    var opaque: String


def _strip_etag(s: String) -> _StrippedEtag:
    """Decompose an ETag wire token into :class:`_StrippedEtag`.

    Spec shape: ``ETag = [ "W/" ] DQUOTE *etagc DQUOTE``."""
    var n = s.byte_length()
    if n == 0:
        return _StrippedEtag(False, String(""))
    var p = s.unsafe_ptr()
    var is_weak = False
    var i = 0
    if (
        n >= 2
        and Int(p[unsafe_offset=0]) == ord("W")
        and Int(p[unsafe_offset=1]) == ord("/")
    ):
        is_weak = True
        i = 2
    if i >= n or Int(p[unsafe_offset=i]) != ord('"'):
        return _StrippedEtag(False, String(""))
    var start = i + 1
    var end = -1
    var j = start
    while j < n:
        if Int(p[unsafe_offset=j]) == ord('"'):
            end = j
            break
        j += 1
    if end < 0:
        return _StrippedEtag(False, String(""))
    var out = String(capacity_bytes=end - start + 1)
    for k in range(start, end):
        out += chr(Int(p[unsafe_offset=k]))
    return _StrippedEtag(is_weak, out^)


def _etag_matches(
    client_token: String, server_etag: String, strong: Bool
) -> Bool:
    """RFC 9110 §8.8.3.2 comparison:

    - Strong: only matches if both sides are strong AND the opaque
      tokens are byte-identical.
    - Weak: matches if the opaque tokens are byte-identical
      (regardless of strong / weak prefix on either side).

    The wildcard ``*`` is handled by the caller; we expect an
    already-stripped, non-wildcard token here.
    """
    var c = _strip_etag(client_token)
    var s = _strip_etag(server_etag)
    if c.opaque.byte_length() == 0 or s.opaque.byte_length() == 0:
        return False
    if strong and (c.is_weak or s.is_weak):
        return False
    return c.opaque == s.opaque


def _split_csv(s: String) -> List[String]:
    """Split a comma-separated header value, trimming OWS around
    each entry. Tolerates double-spaces / tabs."""
    var out = List[String]()
    var n = s.byte_length()
    if n == 0:
        return out^
    var p = s.unsafe_ptr()
    var i = 0
    while i < n:
        # Skip leading OWS.
        while i < n and (
            Int(p[unsafe_offset=i]) == ord(" ")
            or Int(p[unsafe_offset=i]) == ord("\t")
        ):
            i += 1
        var start = i
        # Find next comma OR end-of-string.
        while i < n and Int(p[unsafe_offset=i]) != ord(","):
            i += 1
        # Trim trailing OWS.
        var end = i
        while end > start and (
            Int(p[unsafe_offset=end - 1]) == ord(" ")
            or Int(p[unsafe_offset=end - 1]) == ord("\t")
        ):
            end -= 1
        if end > start:
            var entry = String(capacity_bytes=end - start + 1)
            for k in range(start, end):
                entry += chr(Int(p[unsafe_offset=k]))
            out.append(entry^)
        if i < n:
            i += 1  # skip the comma
    return out^


def _any_etag_matches(csv: String, server_etag: String, strong: Bool) -> Bool:
    """Check whether any token in a comma-separated If-Match /
    If-None-Match header matches ``server_etag``. Wildcard ``*``
    matches when ``server_etag`` is non-empty (any current
    representation)."""
    var entries = _split_csv(csv)
    for i in range(len(entries)):
        var e = entries[i]
        if e == "*":
            if server_etag.byte_length() > 0:
                return True
            continue
        if _etag_matches(e, server_etag, strong):
            return True
    return False


# ── HTTP-date comparator ────────────────────────────────────────────────────


def _parse_int_at(p: Pointer[UInt8, _], off: Int, length: Int) -> Int:
    """Read ``length`` decimal digits at ``p[off:off+length]``.
    Returns -1 on a non-digit byte."""
    var v = 0
    for k in range(length):
        var c = Int(p[unsafe_offset=off + k])
        if c < ord("0") or c > ord("9"):
            return -1
        v = v * 10 + (c - ord("0"))
    return v


def _month_index_at(p: Pointer[UInt8, _], off: Int) -> Int:
    """Match a 3-byte month abbreviation at ``p[off:off+3]``
    against ``"JanFebMarAprMayJunJulAugSepOctNovDec"``. Returns
    -1 on a non-match."""
    comptime months = StaticString("JanFebMarAprMayJunJulAugSepOctNovDec")
    var mp = months.unsafe_ptr()
    var c0 = p[unsafe_offset=off]
    var c1 = p[unsafe_offset=off + 1]
    var c2 = p[unsafe_offset=off + 2]
    for k in range(12):
        if (
            mp[unsafe_offset=k * 3] == c0
            and mp[unsafe_offset=k * 3 + 1] == c1
            and mp[unsafe_offset=k * 3 + 2] == c2
        ):
            return k
    return -1


def _httpdate_to_unix(s: String) -> Int:
    """Best-effort HTTP-date → Unix-epoch second parser.

    Recognises the IMF-fixdate shape mandated by RFC 9110 §5.6.7:
    ``Sun, 06 Nov 1994 08:49:37 GMT``. Returns ``-1`` on any parse
    failure (caller treats parse-failure as "header-absent")."""
    var n = s.byte_length()
    if n != 29:
        # Strict IMF-fixdate length. RFC 850 + asctime are deferred;
        # in practice ~all modern caches emit IMF-fixdate.
        return -1
    var p = s.unsafe_ptr()
    if Int(p[unsafe_offset=3]) != ord(","):
        return -1

    var day = _parse_int_at(p, 5, 2)
    var mon = _month_index_at(p, 8)
    var year = _parse_int_at(p, 12, 4)
    var hh = _parse_int_at(p, 17, 2)
    var mm = _parse_int_at(p, 20, 2)
    var ss = _parse_int_at(p, 23, 2)
    if day < 0 or mon < 0 or year < 0 or hh < 0 or mm < 0 or ss < 0:
        return -1

    return civil_to_unix_seconds(year, mon + 1, day, hh, mm, ss)


# ── FNV-1a body hash for auto-ETag ──────────────────────────────────────────


comptime _FNV_OFFSET: UInt64 = UInt64(14695981039346656037)
comptime _FNV_PRIME: UInt64 = UInt64(1099511628211)


def fnv1a_etag(body: Span[UInt8, _]) -> String:
    """Return a weak ETag derived from a 64-bit FNV-1a hash of ``body``.

    Format: ``W/"<16-hex-digits>"``. Weak rather than strong because
    the hash is not collision-proof under adversarial input — for a
    GET-cache key this is fine (304 short-circuits a re-fetch); for
    state-changing requests use a strong ETag from your data layer
    instead.
    """
    var h: UInt64 = _FNV_OFFSET
    var p = body.unsafe_ptr()
    for i in range(len(body)):
        h ^= UInt64(Int(p[unsafe_offset=i]))
        h = h * _FNV_PRIME
    var hex_chars = String("0123456789abcdef")
    var hp = hex_chars.unsafe_ptr()
    var out = String('W/"')
    for i in range(16):
        var shift = (15 - i) * 4
        var nibble = Int((h >> UInt64(shift)) & UInt64(0xF))
        out += chr(Int(hp[unsafe_offset=nibble]))
    out += '"'
    return out^


# ── Conditional[Inner] ─────────────────────────────────────────────────────


@fieldwise_init
struct Validators(Copyable):
    """The current validators of the resource a request targets, as
    returned by a :data:`ValidatorLookup`. Either field may be empty."""

    var etag: String
    """Current ``ETag`` (e.g. ``'"v7"'``), or empty if none."""
    var last_modified: String
    """Current ``Last-Modified`` as an HTTP-date, or empty if none."""


comptime ValidatorLookup = def(Request) raises thin -> Validators
"""Looks up the current validators for the resource ``req`` targets,
without changing it. Lets :class:`Conditional` evaluate preconditions
on an unsafe method *before* the handler runs."""

comptime _PRE_PASS: Int = 0
comptime _PRE_304: Int = 304
comptime _PRE_412: Int = 412


def _evaluate_preconditions(
    req: Request, server_etag: String, server_last_modified: String
) -> Int:
    """RFC 9110 sec 13.2.2 evaluation order. Returns ``_PRE_PASS``,
    ``_PRE_304`` or ``_PRE_412``."""
    var if_match = req.headers.get("if-match")
    var if_unmodified_since = req.headers.get("if-unmodified-since")
    var if_none_match = req.headers.get("if-none-match")
    var if_modified_since = req.headers.get("if-modified-since")
    var method = req.method  # already uppercase per the parser
    var is_safe = method == "GET" or method == "HEAD"

    # 1. If-Match (strong comparison).
    if if_match.byte_length() > 0:
        if not _any_etag_matches(if_match, server_etag, True):
            return _PRE_412
    elif if_unmodified_since.byte_length() > 0:
        # 2. If-Unmodified-Since (only honoured when If-Match absent).
        var client_t = _httpdate_to_unix(if_unmodified_since)
        var server_t = _httpdate_to_unix(server_last_modified)
        if client_t > 0 and server_t > 0 and server_t > client_t:
            return _PRE_412

    # 3. If-None-Match: weak comparison for safe methods, strong otherwise.
    if if_none_match.byte_length() > 0:
        if _any_etag_matches(if_none_match, server_etag, not is_safe):
            return _PRE_304 if is_safe else _PRE_412
    elif is_safe and if_modified_since.byte_length() > 0:
        # 4. If-Modified-Since (only honoured when If-None-Match absent
        #    AND the request is GET/HEAD).
        var client_t = _httpdate_to_unix(if_modified_since)
        var server_t = _httpdate_to_unix(server_last_modified)
        if client_t > 0 and server_t > 0 and server_t <= client_t:
            return _PRE_304
    return _PRE_PASS


def _has_preconditions(req: Request) -> Bool:
    return (
        req.headers.contains("if-match")
        or req.headers.contains("if-unmodified-since")
        or req.headers.contains("if-none-match")
        or req.headers.contains("if-modified-since")
    )


struct Conditional[Inner: Handler & Copyable](Copyable, Handler):
    """Honour RFC 9110 §13 precondition headers around ``Inner``.

    **Safe methods** (GET, HEAD): calls ``inner.serve(req)`` first, since
    the response's ``ETag`` / ``Last-Modified`` are the validators, then
    rewrites a 2xx to 304 / 412 when a precondition fails. Error
    responses are passed through untouched.

    **Unsafe methods** (PUT, POST, DELETE, ...): preconditions exist to
    stop a lost update, so they must be checked *before* the handler
    changes anything. With a :data:`ValidatorLookup` (see
    :meth:`with_validators`) the current validators are looked up
    first and a failing request gets 412 without reaching ``Inner``.
    Without one this middleware cannot know the current state, and it
    passes the request and response through unchanged: the handler must
    check ``If-Match`` itself. Evaluating afterwards -- what this used
    to do -- ran the write and then told the client it had failed.

    The middleware never mutates the ``Inner`` response when all
    preconditions pass — pass-through is byte-identical so a cache
    revalidation downstream sees the same headers as a non-cached
    response.

    Toggles:

    - ``auto_etag`` (default ``False``) — when the inner response
      has no ``ETag``, generate a weak one via ``fnv1a_etag``
      before evaluating ``If-None-Match`` / ``If-Match``.

    Example:

        ```mojo
        var c = Conditional[Router](Router())
        var c2 = Conditional[Router].with_auto_etag(Router())
        var c3 = Conditional[Router].with_validators(Router(), lookup_doc)
        ```
    """

    var inner: Self.Inner
    var auto_etag: Bool
    var lookup: Optional[ValidatorLookup]

    def __init__(out self, var inner: Self.Inner):
        self.inner = inner^
        self.auto_etag = False
        self.lookup = None

    @staticmethod
    def with_auto_etag(var inner: Self.Inner) -> Conditional[Self.Inner]:
        """Construct a ``Conditional[Inner]`` that auto-generates a
        weak FNV-1a ETag for any inner response missing one."""
        var out = Conditional[Self.Inner](inner^)
        out.auto_etag = True
        return out^

    @staticmethod
    def with_validators(
        var inner: Self.Inner, lookup: ValidatorLookup
    ) -> Conditional[Self.Inner]:
        """Construct a ``Conditional[Inner]`` that evaluates
        preconditions on unsafe methods before dispatch, using
        ``lookup`` for the resource's current validators."""
        var out = Conditional[Self.Inner](inner^)
        out.lookup = Optional[ValidatorLookup](lookup)
        return out^

    def serve(self, req: Request) raises -> Response:
        var is_safe = req.method == "GET" or req.method == "HEAD"
        if not is_safe:
            if self.lookup and _has_preconditions(req):
                var v = self.lookup.value()(req)
                if (
                    _evaluate_preconditions(req, v.etag, v.last_modified)
                    != _PRE_PASS
                ):
                    var failed = Response(status=412)
                    failed.reason = String("Precondition Failed")
                    return failed^
            return self.inner.serve(req).lower()

        var resp = self.inner.serve(req).lower()
        # Only a successful representation has validators worth
        # comparing; a 404 must stay a 404, not become a 304.
        if resp.status < 200 or resp.status >= 300:
            return resp^

        # Auto-ETag: only synthesise if the inner didn't set one.
        if self.auto_etag and not resp.headers.contains("etag"):
            if len(resp.body) > 0:
                resp.headers.set("ETag", fnv1a_etag(Span[UInt8, _](resp.body)))

        var verdict = _evaluate_preconditions(
            req, resp.headers.get("etag"), resp.headers.get("last-modified")
        )
        if verdict == _PRE_304:
            return _make_304(resp^)
        if verdict == _PRE_412:
            return _make_412(resp^)
        return resp^


def _make_304(var resp: Response) -> Response:
    """Rewrite ``resp`` into a 304 Not Modified per RFC 9110 §15.4.5.

    Drops the body and the Content-Length header (a 304 MUST NOT
    include a message body); preserves ETag / Last-Modified /
    Cache-Control / Vary so the cache validator round-trips."""
    resp.status = 304
    resp.reason = String("Not Modified")
    resp.body = List[UInt8]()
    if resp.headers.contains("content-length"):
        _ = resp.headers.remove("content-length")
    if resp.headers.contains("content-type"):
        _ = resp.headers.remove("content-type")
    return resp^


def _make_412(var resp: Response) -> Response:
    """Rewrite ``resp`` into a 412 Precondition Failed.

    Keeps the original body so the client can read any
    server-provided diagnostic; only the status + reason flip."""
    resp.status = 412
    resp.reason = String("Precondition Failed")
    return resp^
