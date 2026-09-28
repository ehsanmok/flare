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
correct, but not surfaced -- no inbound caller needs them yet.
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


def request_te_framing(
    buf: Span[UInt8, _], headers_end: Int, allow_content_length: Bool = False
) -> Int:
    """Decide ``Transfer-Encoding`` framing from the raw header block.

    A byte scan rather than a ``HeaderMap`` lookup, because the reactor
    has to answer this *before* it parses and the minimal-parser path
    never builds a ``HeaderMap``. It reads header lines the way the
    parser does -- field name anchored at the start of a line and
    followed directly by ``:`` -- and it reads *every*
    ``Transfer-Encoding`` line, so it cannot disagree with the parser
    about which one counts.

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
    # Skip the request line: header names only start after a CRLF.
    var i = 0
    while i + 1 < n and not (buf[i] == UInt8(13) and buf[i + 1] == UInt8(10)):
        i += 1
    i += 2
    while i < n:
        var e = i
        while e + 1 < n and not (
            buf[e] == UInt8(13) and buf[e + 1] == UInt8(10)
        ):
            e += 1
        if e + 1 >= n:
            break
        if _matches_at(buf, i, te_name, e):
            var p = i + len(te_name)
            if p < e and buf[p] == UInt8(58):  # ':'
                saw_te = True
                var v = String(capacity_bytes=e - p)
                for k in range(p + 1, e):
                    v += chr(Int(buf[k]))
                if joined.byte_length() > 0:
                    joined += ","
                joined += v
        elif _matches_at(buf, i, cl_name, e):
            var p = i + len(cl_name)
            if p < e and buf[p] == UInt8(58):
                saw_cl = True
        i = e + 2
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
    """
    var n = len(buf)
    var pos = start
    var decoded_total = 0
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
            return CHUNKED_INCOMPLETE
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
                    return CHUNKED_INCOMPLETE
                t = found + 2
        decoded_total += size
        if decoded_total > max_body:
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
