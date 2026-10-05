"""Sans-I/O framing for ``Transfer-Encoding: chunked`` request bodies.

RFC 9112 sec 7.1. Two questions the server reactor needs answered, both
pure functions over a byte buffer:

- :func:`scan_chunked_end` -- has the whole body arrived yet? The
  reactor cannot use ``Content-Length`` to size a chunked request, so
  without this it has no completeness signal at all and treats the
  request as finished the moment the headers land.
- :func:`decode_chunked_body` -- turn the framed bytes into the body the
  handler sees, plus any trailer fields.

Kept in the sans-I/O sublayer so both the server reactor and any future
client sharing can use it without either importing the other's
transport code. No sockets, no allocation beyond the output buffer.

Chunk-size lines are hex, optionally followed by ``;ext=val``
parameters, which are skipped per RFC 9112 sec 7.1.1. Trailer fields
after the terminating chunk are walked over so the end offset is
correct, but not surfaced -- no inbound caller needs them yet. A size
line or trailer line that contains a bare LF is malformed: an LF-splitting
front end would end the line (and so the body) somewhere else.
"""

from std.collections import List


comptime CHUNKED_INCOMPLETE: Int = -1
"""``scan_chunked_end``: more bytes needed."""
comptime CHUNKED_MALFORMED: Int = -2
"""``scan_chunked_end``: the framing is invalid; reject with 400."""


@always_inline
def _lower(b: UInt8) -> UInt8:
    if b >= UInt8(65) and b <= UInt8(90):
        return b + UInt8(32)
    return b


def _matches_at(
    buf: Span[UInt8, _], pos: Int, needle: Span[UInt8, _], limit: Int
) -> Bool:
    """Case-insensitive compare of ``needle`` against ``buf[pos:]``."""
    if pos + len(needle) > limit:
        return False
    for k in range(len(needle)):
        if _lower(buf[pos + k]) != _lower(needle[k]):
            return False
    return True


comptime TE_ABSENT: Int = 0
"""``request_te_framing``: no ``Transfer-Encoding`` field; frame by
``Content-Length`` (or no body)."""
comptime TE_CHUNKED: Int = 1
"""``request_te_framing``: exactly ``chunked``; frame by chunk size lines."""
comptime TE_INVALID: Int = -1
"""``request_te_framing``: the framing is ambiguous or malformed; 400."""
comptime TE_UNSUPPORTED: Int = -2
"""``request_te_framing``: a transfer coding other than ``chunked`` was
applied; flare does not decode those, so 501 (RFC 9112 sec 6.1)."""


def classify_transfer_coding(value: String) -> Int:
    """Classify a ``Transfer-Encoding`` value as a request framing.

    ``value`` is every ``Transfer-Encoding`` field of the message joined
    with ``,`` -- RFC 9110 sec 5.3 makes repeated fields and a comma
    list the same thing, so the decision must look at all of them, not
    the first or the last.

    Returns:
        ``TE_CHUNKED`` when the list is exactly ``chunked``;
        ``TE_UNSUPPORTED`` when ``chunked`` is last but another coding
        precedes it; ``TE_INVALID`` when ``chunked`` is not the final
        coding, appears twice, or the list is empty. RFC 9112 sec 6.3
        requires a 400 for a request whose final coding is not chunked,
        since its length cannot be determined.
    """
    var tokens = List[String]()
    for part in value.split(","):
        var t = String(part).strip(" \t").lower()
        if t.byte_length() > 0:
            tokens.append(t)
    if len(tokens) == 0:
        return TE_INVALID
    if tokens[len(tokens) - 1] != "chunked":
        return TE_INVALID
    for i in range(len(tokens) - 1):
        if tokens[i] == "chunked":
            return TE_INVALID
    if len(tokens) > 1:
        return TE_UNSUPPORTED
    return TE_CHUNKED


@always_inline
def _colon_after_name(buf: Span[UInt8, _], pos: Int, limit: Int) -> Int:
    """Offset one past the ``:`` that ends a field name, or -1.

    ``pos`` is just past the name. SP and HTAB between the name and the
    colon are skipped: the parser strips them under
    ``allow_ows_around_colon``, so a reactor that required the colon
    right after the name would frame ``Transfer-Encoding : chunked`` by
    ``Content-Length`` while the parser read it as chunked. Strict mode
    still rejects such a line in the parser, so skipping is safe there.
    """
    var p = pos
    while p < limit and (buf[p] == UInt8(32) or buf[p] == UInt8(9)):
        p += 1
    if p < limit and buf[p] == UInt8(58):
        return p + 1
    return -1


def request_te_framing(
    buf: Span[UInt8, _], headers_end: Int, allow_content_length: Bool = False
) -> Int:
    """Decide ``Transfer-Encoding`` framing from the raw header block.

    A byte scan rather than a ``HeaderMap`` lookup, because the reactor
    has to answer this *before* it parses and the minimal-parser path
    never builds a ``HeaderMap``. It reads header lines the way the
    parser does -- field name anchored at the start of a line (lines end
    at LF, a preceding CR dropped) and followed by ``:``, with optional
    SP/HTAB in between -- and it reads *every* ``Transfer-Encoding``
    line, so it cannot disagree with the parser about which one counts.

    Args:
        buf: Buffer holding the request head.
        headers_end: Offset one past the ``CRLFCRLF`` terminator.
        allow_content_length: When False (strict), a ``Content-Length``
            alongside ``Transfer-Encoding`` is ``TE_INVALID``: the two
            framings disagree and a front end may have used the other.

    Returns:
        One of ``TE_ABSENT``, ``TE_CHUNKED``, ``TE_INVALID``,
        ``TE_UNSUPPORTED``.
    """
    var te_name = String("transfer-encoding").as_bytes()
    var cl_name = String("content-length").as_bytes()
    var n = headers_end
    var joined = String("")
    var saw_te = False
    var saw_cl = False
    # Skip the request line: header names only start after its line end.
    # A line ends at LF, with the CR before it dropped, the way the parser
    # reads it under ``allow_lf_only_line_endings``. Strict mode rejects a
    # bare LF, so this only widens what the reactor sees, never what the
    # parser accepts.
    var i = 0
    while i < n and buf[i] != UInt8(10):
        i += 1
    i += 1
    while i < n:
        var e = i
        while e < n and buf[e] != UInt8(10):
            e += 1
        if e >= n:
            break
        var line_end = e
        if line_end > i and buf[line_end - 1] == UInt8(13):
            line_end -= 1
        if _matches_at(buf, i, te_name, line_end):
            var p = _colon_after_name(buf, i + len(te_name), line_end)
            if p >= 0:
                saw_te = True
                var v = String(capacity_bytes=line_end - p)
                for k in range(p, line_end):
                    v += chr(Int(buf[k]))
                if joined.byte_length() > 0:
                    joined += ","
                joined += v
        elif _matches_at(buf, i, cl_name, line_end):
            if _colon_after_name(buf, i + len(cl_name), line_end) >= 0:
                saw_cl = True
        i = e + 1
    if not saw_te:
        return TE_ABSENT
    if saw_cl and not allow_content_length:
        return TE_INVALID
    return classify_transfer_coding(joined)


def header_says_chunked(buf: Span[UInt8, _], headers_end: Int) -> Bool:
    """True when the request is framed by ``Transfer-Encoding: chunked``.

    Kept for callers that only need the yes/no answer. Anything that
    must also reject a malformed or unsupported coding should call
    :func:`request_te_framing` instead.
    """
    return request_te_framing(buf, headers_end, True) == TE_CHUNKED


@always_inline
def _hex_val(b: UInt8) -> Int:
    """Hex digit value, or -1 when ``b`` is not a hex digit."""
    if b >= UInt8(48) and b <= UInt8(57):
        return Int(b) - 48
    if b >= UInt8(97) and b <= UInt8(102):
        return Int(b) - 87
    if b >= UInt8(65) and b <= UInt8(70):
        return Int(b) - 55
    return -1


comptime CHUNK_LINE_MAX: Int = 4096
"""Longest chunk-size line (size plus extensions) or trailer line
accepted. Without a cap, a peer can send extension bytes that never
reach CRLF and keep a request incomplete for as long as the connection
lives. The cap is on the line's content, CRLF excluded, and applies the
same whether the line arrives whole or in pieces."""


@always_inline
def _has_lf(buf: Span[UInt8, _], lo: Int, hi: Int) -> Bool:
    """True when ``buf[lo:hi]`` holds an LF byte.

    A chunk-size line (extensions included) or a trailer line is a
    token/quoted-string sequence (RFC 9112 sec 7.1.1) and never holds
    LF. A bare LF is a line end to a recipient that accepts it
    (RFC 9112 sec 2.2), so a line that contains one is framed
    differently by such a front end -- request smuggling.
    """
    for k in range(lo, hi):
        if buf[k] == UInt8(10):
            return True
    return False


def scan_chunked_end(buf: Span[UInt8, _], start: Int, max_body: Int) -> Int:
    """Return the offset one past a complete chunked body.

    Walks the chunk-size lines without copying any payload. Returns
    ``CHUNKED_INCOMPLETE`` when more bytes are needed,
    ``CHUNKED_MALFORMED`` on invalid framing or when the decoded size
    would exceed ``max_body``, otherwise the absolute end offset
    (after the terminating chunk and its trailer section).

    ``max_body`` is checked against the running decoded total, not the
    wire total, and is checked *during* the walk -- a chunked upload
    must not be allowed to grow the read buffer past the configured
    limit before anyone notices.

    Stateless: every call walks from ``start``. A caller that polls
    the same growing buffer should use :func:`scan_chunked_resume`.
    """
    var cursor = start
    var decoded_total = 0
    return scan_chunked_resume(buf, cursor, decoded_total, max_body)


def scan_chunked_resume(
    buf: Span[UInt8, _], mut cursor: Int, mut decoded_total: Int, max_body: Int
) -> Int:
    """``scan_chunked_end`` that remembers how far it got.

    ``cursor`` and ``decoded_total`` are advanced past every chunk that
    has fully arrived, so the next call starts at the first incomplete
    chunk instead of at the top of the body. The reactor re-polls
    after every read; restarting from the top made a body of many
    small chunks, delivered in many small segments, quadratic in its
    length.

    Args:
        buf: Buffer holding the request.
        cursor: On entry, where the next unscanned chunk-size line
            starts (``headers_end`` for a fresh request). Advanced in
            place.
        decoded_total: Payload bytes in the chunks before ``cursor``.
            Advanced in place.
        max_body: Cap on the decoded body.

    Returns:
        As for :func:`scan_chunked_end`.
    """
    var n = len(buf)
    var pos = cursor
    while True:
        # chunk-size [ chunk-ext ] CRLF
        var line_end = -1
        var i = pos
        while i + 1 < n:
            if buf[i] == UInt8(13) and buf[i + 1] == UInt8(10):
                line_end = i
                break
            i += 1
        if line_end < 0:
            # One byte of slack for a CR that may be the first half of
            # the CRLF: a line of exactly CHUNK_LINE_MAX bytes cut after
            # its CR is not over the cap (the complete-line test below
            # accepts it), so the verdict cannot depend on the cut.
            if n - pos > CHUNK_LINE_MAX + 1:
                return CHUNKED_MALFORMED
            return CHUNKED_INCOMPLETE
        if line_end - pos > CHUNK_LINE_MAX:
            return CHUNKED_MALFORMED
        if _has_lf(buf, pos, line_end):
            return CHUNKED_MALFORMED
        var size = 0
        var digits = 0
        var j = pos
        while j < line_end:
            var c = buf[j]
            if c == UInt8(59):  # ';' -- chunk extensions, ignored
                break
            var v = _hex_val(c)
            if v < 0:
                return CHUNKED_MALFORMED
            size = size * 16 + v
            digits += 1
            if size > max_body:
                return CHUNKED_MALFORMED
            j += 1
        if digits == 0:
            return CHUNKED_MALFORMED
        var data_start = line_end + 2
        if size == 0:
            # Terminating chunk: optional trailer fields, then CRLF.
            var t = data_start
            while True:
                if t + 1 >= n:
                    return CHUNKED_INCOMPLETE
                if buf[t] == UInt8(13) and buf[t + 1] == UInt8(10):
                    return t + 2
                # Skip one trailer line.
                var k = t
                var found = -1
                while k + 1 < n:
                    if buf[k] == UInt8(13) and buf[k + 1] == UInt8(10):
                        found = k
                        break
                    k += 1
                if found < 0:
                    if n - t > CHUNK_LINE_MAX + 1:
                        return CHUNKED_MALFORMED
                    return CHUNKED_INCOMPLETE
                if found - t > CHUNK_LINE_MAX:
                    return CHUNKED_MALFORMED
                if _has_lf(buf, t, found):
                    return CHUNKED_MALFORMED
                t = found + 2
        if decoded_total + size > max_body:
            return CHUNKED_MALFORMED
        # data CRLF
        var next_pos = data_start + size + 2
        if next_pos > n:
            return CHUNKED_INCOMPLETE
        if buf[data_start + size] != UInt8(13) or buf[
            data_start + size + 1
        ] != UInt8(10):
            return CHUNKED_MALFORMED
        pos = next_pos
        cursor = pos
        decoded_total += size


def decode_chunked_body(
    buf: Span[UInt8, _], start: Int, mut out: List[UInt8]
) raises -> Int:
    """Append the decoded body to ``out``; return the end offset.

    Assumes :func:`scan_chunked_end` already accepted this buffer, so
    framing errors here raise rather than being reported as a status.
    Trailer fields are skipped; use :func:`decode_chunked_trailers` if
    the caller wants them.
    """
    var n = len(buf)
    var pos = start
    while True:
        var line_end = -1
        var i = pos
        while i + 1 < n:
            if buf[i] == UInt8(13) and buf[i + 1] == UInt8(10):
                line_end = i
                break
            i += 1
        if line_end < 0:
            raise Error("chunked: truncated size line")
        var size = 0
        var j = pos
        while j < line_end:
            var c = buf[j]
            if c == UInt8(59):
                break
            var v = _hex_val(c)
            if v < 0:
                raise Error("chunked: bad hex in size line")
            size = size * 16 + v
            j += 1
        var data_start = line_end + 2
        if size == 0:
            var t = data_start
            while t + 1 < n:
                if buf[t] == UInt8(13) and buf[t + 1] == UInt8(10):
                    return t + 2
                var k = t
                var found = -1
                while k + 1 < n:
                    if buf[k] == UInt8(13) and buf[k + 1] == UInt8(10):
                        found = k
                        break
                    k += 1
                if found < 0:
                    raise Error("chunked: truncated trailer")
                t = found + 2
            raise Error("chunked: truncated terminator")
        if data_start + size > n:
            raise Error("chunked: truncated chunk data")
        for k in range(size):
            out.append(buf[data_start + k])
        pos = data_start + size + 2
