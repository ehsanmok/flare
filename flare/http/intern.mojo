"""Interned ``StaticString`` table for HTTP method names + common
header values (Track B3).

Replaces the parser hot path's per-request ``String`` allocation
for the 9 RFC 7231 method names (GET, POST, PUT, PATCH, DELETE,
HEAD, OPTIONS, CONNECT, TRACE) and a small set of frequently-seen
header *values* (``text/html`` / ``text/plain`` / ``application/
json`` / ``application/octet-stream`` / ``gzip`` / ``br`` /
``deflate`` / ``identity`` / ``keep-alive`` / ``close``,
``HTTP/1.0`` / ``HTTP/1.1``) with shared ``StaticString``
constants.

Why this is a Track B subtrack
-------------------------------

`flare.http.server._parse_http_request_bytes` allocates the
method String *twice* per request today (the
``String(String(unsafe_from_utf8=...))`` double-wrap on line ~803
of ``server.mojo``). Under TFB plaintext at 220K req/s + 4
workers, that's ~1.7M allocations / s for the method string
alone, with ~99 % of them being one of "GET" or "POST". Folding
those into a shared ``StaticString`` constant drops the allocation
to a single ``String.copy()`` of a 3-4 byte SSO buffer (which is
free on every Mojo target where short-string-optimisation kicks
in below the inline-String threshold).

The savings on the value-side are smaller per-call but
compounding: every ``Compress[Inner]`` middleware response sets
``Content-Encoding: gzip`` (or ``br``); every keep-alive response
sets ``Connection: keep-alive``; every JSON response sets
``Content-Type: application/json``. Caching those as
``StaticString`` lets future hot-path serializers compare against
the interned shape without an allocation.

What this commit ships
-----------------------

* ``MethodIntern`` — namespace struct holding the 9 method
  ``StaticString`` constants. Mirrors the
  ``flare.http.request.Method`` namespace but with
  ``StaticString``-typed fields so the constants can be passed
  into ``intern_method_bytes`` lookups without a round-trip
  through ``String``.
* ``ValueIntern`` — namespace struct holding the common
  Content-Type / Content-Encoding / Connection / version
  ``StaticString`` constants.
* ``intern_method_bytes(Span[UInt8, _]) -> Optional[String]`` —
  returns ``Optional[String]`` built from the interned
  ``StaticString`` when ``slice`` exactly equals one of the
  9 method names, otherwise ``None``. Caller that gets ``None``
  back falls back to its existing String-construction path.
* ``intern_common_value(Span[UInt8, _]) -> Optional[String]``
  — same shape for the value table.
* Both lookups are O(1) per slice — first dispatched by length,
  then a tiny per-length switch (most lengths have ≤ 2
  candidates).

Wiring into the parser is a follow-up commit; this commit lands
the primitive + tests + re-exports so the wiring change is
mechanical.

Implementation notes
--------------------

Lookup is **length-first dispatch + byte compare**. ``GET`` /
``PUT`` (length 3) and ``POST`` / ``HEAD`` (length 4) cover
~95 % of real-world traffic; the longer methods (PATCH / DELETE
/ OPTIONS / CONNECT / TRACE) are fall-through. The branch
predictor learns "length=3 → GET" within the first few requests
on any given connection. No hash table, no Dict, no
multiplication.

The value table is similarly length-dispatched. Lengths uniquely
identify most candidates (``br`` is the only 2-char encoding,
``gzip`` the only 4-char one; ``HTTP/1.0`` and ``HTTP/1.1``
share length 8 and are differentiated by the last byte; etc.).
"""

from std.collections import Optional


# ── Method intern table ──────────────────────────────────────────────────────


struct MethodIntern:
    """Interned ``StaticString`` constants for the 9 RFC 7231
    method names.

    Mirrors the ``flare.http.request.Method`` namespace but with
    ``StaticString``-typed fields. Use the constants directly when
    you need a static literal of a method name; use
    :func:`intern_method_bytes` when you have a byte slice and want
    to know whether it matches a known method without paying for
    a fresh ``String`` allocation.
    """

    comptime GET: StaticString = "GET"
    comptime POST: StaticString = "POST"
    comptime PUT: StaticString = "PUT"
    comptime PATCH: StaticString = "PATCH"
    comptime DELETE: StaticString = "DELETE"
    comptime HEAD: StaticString = "HEAD"
    comptime OPTIONS: StaticString = "OPTIONS"
    comptime CONNECT: StaticString = "CONNECT"
    comptime TRACE: StaticString = "TRACE"


# ── Common value intern table ─────────────────────────────────────────────────


struct ValueIntern:
    """Interned ``StaticString`` constants for header values that
    show up on virtually every HTTP response.

    Categories:

    * **Content-Type**: text/html, text/plain, application/json,
      application/octet-stream.
    * **Content-Encoding**: gzip, br, deflate, identity.
    * **Connection**: keep-alive, close.
    * **HTTP version**: HTTP/1.0, HTTP/1.1.

    Add to this list (here, not at the call site) when bench
    profiles surface a value that's allocated > 100K / s.
    """

    comptime CONTENT_TYPE_TEXT_HTML: StaticString = "text/html"
    comptime CONTENT_TYPE_TEXT_PLAIN: StaticString = "text/plain"
    comptime CONTENT_TYPE_JSON: StaticString = "application/json"
    comptime CONTENT_TYPE_OCTET: StaticString = "application/octet-stream"

    comptime ENCODING_GZIP: StaticString = "gzip"
    comptime ENCODING_BR: StaticString = "br"
    comptime ENCODING_DEFLATE: StaticString = "deflate"
    comptime ENCODING_IDENTITY: StaticString = "identity"

    comptime CONNECTION_KEEP_ALIVE: StaticString = "keep-alive"
    comptime CONNECTION_CLOSE: StaticString = "close"

    comptime VERSION_1_0: StaticString = "HTTP/1.0"
    comptime VERSION_1_1: StaticString = "HTTP/1.1"


# ── Internal helpers ─────────────────────────────────────────────────────────


@always_inline
def _bytes_equal_static(slice: Span[UInt8, _], s: StaticString) -> Bool:
    """Return ``True`` iff ``slice`` is byte-identical to ``s``.

    Fast path: length compare first, then per-byte compare. The
    SIMD short-string compare in stdlib's ``String.__eq__`` is
    not available against ``Span[UInt8]`` directly, so we open-code
    the comparison.
    """
    var n = s.byte_length()
    if len(slice) != n:
        return False
    var sp = slice.unsafe_ptr()
    var bp = s.unsafe_ptr()
    for i in range(n):
        if sp[i] != bp[i]:
            return False
    return True


@always_inline
def _string_from_static(s: StaticString) -> String:
    """Return a fresh ``String`` whose backing copies from a
    ``StaticString``.

    For short strings (≤ ~24 bytes on every Mojo target with
    short-string-optimisation), the copy is a few inline-buffer
    bytes — no heap allocation. For longer strings, this *does*
    allocate; the savings vs. ``String(String(unsafe_from_utf8=...))``
    come from the elision of the intermediate UTF-8 String
    construction.
    """
    return String(s)


# ── Public lookup API ────────────────────────────────────────────────────────


def intern_method_bytes(slice: Span[UInt8, _]) -> Optional[String]:
    """Return the interned method name as ``Optional[String]`` if
    ``slice`` exactly matches one of the 9 RFC 7231 methods,
    otherwise ``None``.

    Length-first dispatch keeps the common case (``GET`` / ``POST``)
    on a single byte-length compare + 3-4 byte memcmp.

    Args:
        slice: Byte slice — typically the method-name region of an
               HTTP/1.1 request line.

    Returns:
        ``Some(String)`` for a known method (``"GET"`` / ``"POST"``
        / ...); ``None`` otherwise. The returned ``String`` is
        built from the interned ``StaticString`` so the byte
        contents come from a process-lifetime constant rather
        than the per-request request buffer.
    """
    var n = len(slice)
    if n == 3:
        if _bytes_equal_static(slice, MethodIntern.GET):
            return _string_from_static(MethodIntern.GET)
        if _bytes_equal_static(slice, MethodIntern.PUT):
            return _string_from_static(MethodIntern.PUT)
        return None
    if n == 4:
        if _bytes_equal_static(slice, MethodIntern.POST):
            return _string_from_static(MethodIntern.POST)
        if _bytes_equal_static(slice, MethodIntern.HEAD):
            return _string_from_static(MethodIntern.HEAD)
        return None
    if n == 5:
        if _bytes_equal_static(slice, MethodIntern.PATCH):
            return _string_from_static(MethodIntern.PATCH)
        if _bytes_equal_static(slice, MethodIntern.TRACE):
            return _string_from_static(MethodIntern.TRACE)
        return None
    if n == 6:
        if _bytes_equal_static(slice, MethodIntern.DELETE):
            return _string_from_static(MethodIntern.DELETE)
        return None
    if n == 7:
        if _bytes_equal_static(slice, MethodIntern.OPTIONS):
            return _string_from_static(MethodIntern.OPTIONS)
        if _bytes_equal_static(slice, MethodIntern.CONNECT):
            return _string_from_static(MethodIntern.CONNECT)
        return None
    return None


def intern_common_value(slice: Span[UInt8, _]) -> Optional[String]:
    """Return the interned header value as ``Optional[String]`` if
    ``slice`` matches one of the well-known content-type /
    content-encoding / connection / version values, otherwise
    ``None``.

    Same length-first dispatch as :func:`intern_method_bytes`.

    Args:
        slice: Byte slice — typically a header value in the
               request / response wire form.

    Returns:
        ``Some(String)`` for a recognised value; ``None`` otherwise.
    """
    var n = len(slice)
    if n == 2:
        if _bytes_equal_static(slice, ValueIntern.ENCODING_BR):
            return _string_from_static(ValueIntern.ENCODING_BR)
        return None
    if n == 4:
        if _bytes_equal_static(slice, ValueIntern.ENCODING_GZIP):
            return _string_from_static(ValueIntern.ENCODING_GZIP)
        return None
    if n == 5:
        if _bytes_equal_static(slice, ValueIntern.CONNECTION_CLOSE):
            return _string_from_static(ValueIntern.CONNECTION_CLOSE)
        return None
    if n == 7:
        if _bytes_equal_static(slice, ValueIntern.ENCODING_DEFLATE):
            return _string_from_static(ValueIntern.ENCODING_DEFLATE)
        return None
    if n == 8:
        if _bytes_equal_static(slice, ValueIntern.ENCODING_IDENTITY):
            return _string_from_static(ValueIntern.ENCODING_IDENTITY)
        if _bytes_equal_static(slice, ValueIntern.VERSION_1_0):
            return _string_from_static(ValueIntern.VERSION_1_0)
        if _bytes_equal_static(slice, ValueIntern.VERSION_1_1):
            return _string_from_static(ValueIntern.VERSION_1_1)
        return None
    if n == 9:
        if _bytes_equal_static(slice, ValueIntern.CONTENT_TYPE_TEXT_HTML):
            return _string_from_static(ValueIntern.CONTENT_TYPE_TEXT_HTML)
        return None
    if n == 10:
        if _bytes_equal_static(slice, ValueIntern.CONTENT_TYPE_TEXT_PLAIN):
            return _string_from_static(ValueIntern.CONTENT_TYPE_TEXT_PLAIN)
        if _bytes_equal_static(slice, ValueIntern.CONNECTION_KEEP_ALIVE):
            return _string_from_static(ValueIntern.CONNECTION_KEEP_ALIVE)
        return None
    if n == 16:
        if _bytes_equal_static(slice, ValueIntern.CONTENT_TYPE_JSON):
            return _string_from_static(ValueIntern.CONTENT_TYPE_JSON)
        return None
    if n == 24:
        if _bytes_equal_static(slice, ValueIntern.CONTENT_TYPE_OCTET):
            return _string_from_static(ValueIntern.CONTENT_TYPE_OCTET)
        return None
    return None


def intern_method_string(s: String) -> Optional[String]:
    """``String``-typed convenience wrapper around
    :func:`intern_method_bytes`.

    For callers that already have a ``String`` and want to
    canonicalise it; the byte-slice form is preferred on the
    parser hot path.
    """
    return intern_method_bytes(s.as_bytes())


def intern_common_value_string(s: String) -> Optional[String]:
    """``String``-typed convenience wrapper around
    :func:`intern_common_value`.
    """
    return intern_common_value(s.as_bytes())
