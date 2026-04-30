"""Borrowed header storage.

``HeaderMapView[origin]`` stores headers as ``(name_start, name_len,
value_start, value_len)`` offsets into a single byte buffer the
caller owns (typically ``ConnHandle.read_buf``). Lookups compare
against the buffer in place — no per-header ``String`` allocation
on the read path.

Owned ``HeaderMap`` (``flare/http/headers.mojo``) stays the type of
record for response writers (``Response.headers``) and as the
``into_owned()`` target for handlers that need to keep headers
alive past one event-loop iteration.

This commit is **additive**: ``Request`` still carries an owned
``HeaderMap``, and ``_parse_http_request_bytes`` still allocates.
The ``HeaderMapView`` -> ``Request.headers`` wiring lands with the
``RequestView[origin]`` refactor in S2.5; until then ``HeaderMapView``
is a standalone type usable for any byte-range header parsing
(WebSocket handshakes, HTTP/2 HEADERS frames , custom
protocol layering).

Closes Track 1.5 of design-0.5 modulo the integration step.

Example:

    var raw = "GET / HTTP/1.1\r\nHost: x\r\nX-A: 1\r\n\r\n".as_bytes()
    var view = parse_header_view(Span[UInt8, _](raw))
    assert_equal(view.get("host"), "x") # case-insensitive
    assert_equal(view.get("X-A"), "1")
    assert_equal(view.len(), 2)
    var owned = view.into_owned() # one allocation, copies bytes

The header offsets list itself does allocate (Mojo's ``List``
manages its own backing buffer), but each lookup avoids the
per-header ``String`` copy that ``HeaderMap.get`` would have done.
For a 12-header request the parse path makes 12 + 12 + 1
String allocations (12 keys, 12 values, one HeaderMap struct
internally). The view path makes one ``List[Int]`` allocation
holding 4 * 12 ints.
"""

from .headers import HeaderMap, _eq_icase


# ── Helpers ─────────────────────────────────────────────────────────────────

comptime _CR: UInt8 = 13
comptime _LF: UInt8 = 10
comptime _COLON: UInt8 = 58
comptime _SPACE: UInt8 = 32
comptime _HTAB: UInt8 = 9


@always_inline
def _is_ascii_space(c: UInt8) -> Bool:
    """Return True for SP / HTAB. RFC 7230 OWS."""
    return c == _SPACE or c == _HTAB


@always_inline
def _is_token_char(c: UInt8) -> Bool:
    """RFC 7230 §3.2.6 token chars (header field-name).

    Mirrors the predicate in ``flare/http/server.mojo`` but local
    so this module can be used without pulling in the legacy
    parser. Range: ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" /
    "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~".
    """
    if c >= 65 and c <= 90:
        return True
    if c >= 97 and c <= 122:
        return True
    if c >= 48 and c <= 57:
        return True
    if c == 33 or c == 35 or c == 36 or c == 37 or c == 38:
        return True
    if c == 39 or c == 42 or c == 43 or c == 45 or c == 46:
        return True
    if c == 94 or c == 95 or c == 96 or c == 124 or c == 126:
        return True
    return False


@always_inline
def _eq_icase_bytes(
    a: Span[UInt8, _], b_start: Int, b_len: Int, buf: Span[UInt8, _]
) -> Bool:
    """Case-insensitive ASCII compare of ``a`` against ``buf[b_start:b_start+b_len]``.

    Inlined so the per-header lookup stays in registers.
    """
    if len(a) != b_len:
        return False
    var ap = a.unsafe_ptr()
    var bp = buf.unsafe_ptr() + b_start
    for i in range(b_len):
        var ac = ap[i]
        var bc = bp[i]
        if ac >= 65 and ac <= 90:
            ac = ac + 32
        if bc >= 65 and bc <= 90:
            bc = bc + 32
        if ac != bc:
            return False
    return True


# ── HeaderMapView ───────────────────────────────────────────────────────────


struct HeaderMapView[origin: Origin](Movable):
    """Borrowed header collection.

    Holds offsets into a caller-owned byte buffer (``self.buf``)
    plus a parallel ``List[Int]`` of ``(name_start, name_len,
    value_start, value_len)`` quadruples (4 ints per header).

    Lookups are case-insensitive ASCII; comparison runs against the
    underlying ``buf`` in place.

    The ``origin`` parameter ties the view's lifetime to the
    buffer it borrows from. Mojo's borrow checker prevents the
    view from outliving the buffer.
    """

    var buf: Span[UInt8, Self.origin]
    """The byte buffer the view borrows from. Typically
    ``ConnHandle.read_buf`` for the reactor read path; may be any
    ``Span[UInt8, ...]`` for tests / WS handshake / future HTTP/2
    HEADERS frame readers."""

    var _offsets: List[Int]
    """Flat 4*N list: for header ``i``,
    ``[i*4]`` = name_start, ``[i*4+1]`` = name_len,
    ``[i*4+2]`` = value_start, ``[i*4+3]`` = value_len.

    Stored flat (not as ``List[Tuple]`` or ``List[_HdrSlot]``) so a
    single contiguous allocation backs all N headers."""

    @always_inline
    def __init__(out self, buf: Span[UInt8, Self.origin]):
        """Empty view bound to ``buf``. Use ``parse_header_view`` to
        populate from raw header bytes."""
        self.buf = buf
        self._offsets = List[Int]()

    @always_inline
    def __init__(
        out self, buf: Span[UInt8, Self.origin], var offsets: List[Int]
    ):
        """Populated view. ``len(offsets)`` must be a multiple of 4."""
        self.buf = buf
        self._offsets = offsets^

    @always_inline
    def len(self) -> Int:
        """Number of headers in the view."""
        return len(self._offsets) // 4

    def get(self, name: String) -> StringSlice[Self.origin]:
        """Return the value of the first header named ``name``,
        case-insensitive. Returns an empty slice if not present.

        The returned slice borrows from ``self.buf``; its lifetime
        is tied to the view's ``origin``. No allocation.
        """
        var name_bytes = name.as_bytes()
        var n = self.len()
        for i in range(n):
            var nstart = self._offsets[i * 4]
            var nlen = self._offsets[i * 4 + 1]
            if _eq_icase_bytes(name_bytes, nstart, nlen, self.buf):
                var vstart = self._offsets[i * 4 + 2]
                var vlen = self._offsets[i * 4 + 3]
                return StringSlice[Self.origin](
                    unsafe_from_utf8=self.buf[vstart : vstart + vlen]
                )
        return StringSlice[Self.origin](unsafe_from_utf8=self.buf[0:0])

    def contains(self, name: String) -> Bool:
        """True if a header named ``name`` is present
        (case-insensitive)."""
        var name_bytes = name.as_bytes()
        var n = self.len()
        for i in range(n):
            var nstart = self._offsets[i * 4]
            var nlen = self._offsets[i * 4 + 1]
            if _eq_icase_bytes(name_bytes, nstart, nlen, self.buf):
                return True
        return False

    def into_owned(self) raises -> HeaderMap:
        """Materialise an owned ``HeaderMap`` by copying each header's
        bytes out of the borrowed buffer into ``String``s.

        One allocation per header (key + value). Use this only when
        the handler needs to keep headers alive past the connection's
        event-loop iteration; the borrowed view itself does **not**
        allocate per header.
        """
        var out = HeaderMap()
        var n = self.len()
        for i in range(n):
            var nstart = self._offsets[i * 4]
            var nlen = self._offsets[i * 4 + 1]
            var vstart = self._offsets[i * 4 + 2]
            var vlen = self._offsets[i * 4 + 3]
            var k = String(unsafe_from_utf8=self.buf[nstart : nstart + nlen])
            var v = String(unsafe_from_utf8=self.buf[vstart : vstart + vlen])
            out.set(k, v)
        return out^


# ── Parser ──────────────────────────────────────────────────────────────────


def parse_header_view[
    origin: Origin
](data: Span[UInt8, origin]) raises -> HeaderMapView[origin]:
    """Parse CRLF-separated header lines into a ``HeaderMapView``.

    Expects the request line + ``\\r\\n`` to already be stripped:
    ``data`` should start at the first header line and end at (or
    after) the empty CRLF that terminates the header block. Stops
    at the first empty line.

    Header values are trimmed of leading / trailing OWS (SP / HTAB)
    per RFC 7230 §3.2.4. The trim is offset arithmetic on the
    underlying buffer — no allocation.

    Raises ``Error`` on malformed lines (missing colon, empty header
    name).

    Args:
        data: Header bytes (may include CRLF terminators between
              lines and a trailing empty CRLF).

    Returns:
        A populated ``HeaderMapView`` borrowing from ``data``.
    """
    var offsets = List[Int]()
    var n = len(data)
    var p = data.unsafe_ptr()
    var i = 0

    while i < n:
        # Find end of line (LF). RFC 7230 mandates CRLF but some
        # tooling sends bare LF; we accept either.
        var line_end = i
        while line_end < n and p[line_end] != _LF:
            line_end += 1

        # Empty line marks end of headers.
        var stripped_end = line_end
        if stripped_end > i and p[stripped_end - 1] == _CR:
            stripped_end -= 1
        if stripped_end == i:
            break

        # Find colon.
        var colon = -1
        var j = i
        while j < stripped_end:
            if p[j] == _COLON:
                colon = j
                break
            j += 1
        if colon < 0:
            raise Error("header line missing colon")

        var nstart = i
        var nlen = colon - i
        if nlen == 0:
            raise Error("empty header name")

        # RFC 7230 §3.2.6 — the field-name is a token; reject any
        # non-token byte (CTLs, separators, high-bit, etc.). Catches
        # smuggling attempts that chain a malformed header into the
        # next request boundary.
        for k in range(nstart, nstart + nlen):
            if not _is_token_char(p[k]):
                raise Error("invalid character in header name")

        # Trim OWS on the value side.
        var vstart = colon + 1
        while vstart < stripped_end and _is_ascii_space(p[vstart]):
            vstart += 1
        var vend = stripped_end
        while vend > vstart and _is_ascii_space(p[vend - 1]):
            vend -= 1
        var vlen = vend - vstart

        # RFC 7230 §3.2.4 — the field-value must NOT contain bare
        # CR / LF / NUL. CR / LF embedded in the value is the classic
        # response-splitting / header-injection vector. NUL is an
        # implementation-defined-behaviour foot-gun.
        for k in range(vstart, vend):
            var vc = p[k]
            if vc == 0 or vc == _LF or vc == _CR:
                raise Error("invalid byte in header value")

        offsets.append(nstart)
        offsets.append(nlen)
        offsets.append(vstart)
        offsets.append(vlen)

        # Move past LF.
        i = line_end + 1

    return HeaderMapView[origin](buf=data, offsets=offsets^)
