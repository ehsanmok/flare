"""``multipart/form-data`` parsing (RFC 7578).

Browsers emit ``multipart/form-data`` for forms with file inputs or a
non-default ``enctype``. The body is a sequence of parts separated
by a boundary string declared in the request's
``Content-Type: multipart/form-data; boundary=<token>`` header. Each
part has its own headers and body bytes; binary file uploads do not
need any encoding (text fields stay verbatim too).

Wire format:

    --boundary\\r\\n
    Content-Disposition: form-data; name="<field>"; filename="<file>"\\r\\n
    Content-Type: <mime>\\r\\n
    \\r\\n
    <bytes...>\\r\\n
    --boundary\\r\\n
    Content-Disposition: form-data; name="<text-field>"\\r\\n
    \\r\\n
    <text...>\\r\\n
    --boundary--\\r\\n

This module ships:

- ``MultipartPart`` — one form part: name, optional filename, optional
  content type, body bytes, raw header map.
- ``MultipartForm`` — name → part(s) collection; supports lookup by
  name plus iteration in receive order.
- ``parse_multipart_form_data`` — bytes + ``Content-Type`` header →
  ``MultipartForm``. The ``Multipart`` extractor in
  [`extract.mojo`](extract.mojo) is the typed wrapper.

The parser is buffered (the entire body is a ``List[UInt8]`` already
held by ``Request.body``); a streaming variant on top of
``ChunkSource`` is left for a future revision when uploads exceed
``ServerConfig.max_body_size``.
"""

from std.collections import Optional


@always_inline
def _bytes_eq(
    haystack: Span[UInt8, _], at: Int, needle: Span[UInt8, _]
) -> Bool:
    """Return True if ``haystack[at:at+len(needle)] == needle``.

    Bounds-safe: returns False if ``at + len(needle) > len(haystack)``.
    """
    var hn = len(haystack)
    var nn = len(needle)
    if at + nn > hn:
        return False
    for i in range(nn):
        if haystack[at + i] != needle[i]:
            return False
    return True


def _find_bytes(
    haystack: Span[UInt8, _], needle: Span[UInt8, _], start: Int = 0
) -> Int:
    """Return the first index in ``haystack[start:]`` where ``needle`` occurs, or -1.
    """
    var hn = len(haystack)
    var nn = len(needle)
    if nn == 0:
        return start
    if hn < nn:
        return -1
    var limit = hn - nn
    for i in range(start, limit + 1):
        if _bytes_eq(haystack, i, needle):
            return i
    return -1


def _extract_boundary(content_type: String) raises -> String:
    """Extract the ``boundary=`` parameter from a ``Content-Type`` value.

    Args:
        content_type: Raw header value such as
                      ``"multipart/form-data; boundary=abc123"``.

    Returns:
        The boundary token (without the leading ``--``). Quotes around
        the boundary are stripped per RFC 2046.

    Raises:
        Error: When the header is missing the ``boundary=`` parameter
               or the parameter is empty.
    """
    var n = content_type.byte_length()
    if n == 0:
        raise Error("multipart: missing Content-Type")
    var lower = String(capacity=n)
    var src = content_type.unsafe_ptr()
    for i in range(n):
        var c = src[i]
        if c >= 65 and c <= 90:
            lower += chr(Int(c) + 32)
        else:
            lower += chr(Int(c))
    var key = "boundary="
    var key_len = key.byte_length()
    var key_p = key.unsafe_ptr()
    var lower_p = lower.unsafe_ptr()
    var pos = -1
    var limit = n - key_len
    var i = 0
    while i <= limit:
        var matched = True
        for j in range(key_len):
            if lower_p[i + j] != key_p[j]:
                matched = False
                break
        if matched:
            pos = i
            break
        i += 1
    if pos < 0:
        raise Error("multipart: missing boundary parameter")
    var start = pos + key_len
    var end = n
    for j in range(start, n):
        if src[j] == 59:  # ';'
            end = j
            break
    if start < end and src[start] == 34:  # '"'
        if end - 1 > start and src[end - 1] == 34:
            return String(
                unsafe_from_utf8=content_type.as_bytes()[start + 1 : end - 1]
            )
        return String(unsafe_from_utf8=content_type.as_bytes()[start + 1 : end])
    var boundary = String(unsafe_from_utf8=content_type.as_bytes()[start:end])
    boundary = String(boundary.strip())
    if boundary.byte_length() == 0:
        raise Error("multipart: empty boundary parameter")
    return boundary^


def _parse_disposition_param(disp: String, name: String) -> String:
    """Return parameter ``name`` from a ``Content-Disposition`` value.

    Returns ``""`` when the parameter is absent. Quoted-string values
    are unquoted; unquoted values run until the next ``;``.
    """
    var n = disp.byte_length()
    var key = name + "="
    var key_len = key.byte_length()
    if n < key_len:
        return ""
    var src = disp.unsafe_ptr()
    var key_p = key.unsafe_ptr()
    var i = 0
    while i + key_len <= n:
        var matched = True
        for j in range(key_len):
            var c = src[i + j]
            var k = key_p[j]
            if c >= 65 and c <= 90:
                c = c + 32
            if k >= 65 and k <= 90:
                k = k + 32
            if c != k:
                matched = False
                break
        if matched:
            if (
                i == 0
                or src[i - 1] == 32
                or src[i - 1] == 59
                or src[i - 1] == 9
            ):
                var start = i + key_len
                if start < n and src[start] == 34:
                    var end = start + 1
                    while end < n and src[end] != 34:
                        end += 1
                    return String(
                        unsafe_from_utf8=disp.as_bytes()[start + 1 : end]
                    )
                else:
                    var end = start
                    while end < n and src[end] != 59:
                        end += 1
                    return String(
                        String(
                            unsafe_from_utf8=disp.as_bytes()[start:end]
                        ).strip()
                    )
        i += 1
    return ""


struct MultipartPart(Copyable, Movable):
    """A single part inside a ``multipart/form-data`` body.

    Fields:
        name:         ``name="..."`` from ``Content-Disposition``;
                      empty if absent (treated as malformed).
        filename:     ``filename="..."`` if present (file uploads);
                      empty for plain text fields.
        content_type: ``Content-Type`` of this part if specified;
                      empty otherwise (defaults to
                      ``text/plain; charset=US-ASCII`` per RFC 7578
                      §4.4 if a consumer needs a non-empty fallback).
        body:         The part's raw payload bytes (no trailing CRLF).
        headers:      Every header line for this part as a parallel
                      ``List[String]`` pair.
    """

    var name: String
    var filename: String
    var content_type: String
    var body: List[UInt8]
    var header_keys: List[String]
    var header_values: List[String]

    def __init__(out self):
        self.name = ""
        self.filename = ""
        self.content_type = ""
        self.body = List[UInt8]()
        self.header_keys = List[String]()
        self.header_values = List[String]()

    def text(self) -> String:
        """Decode the part body as a UTF-8 ``String``."""
        if len(self.body) == 0:
            return ""
        var out = String(capacity=len(self.body) + 1)
        for b in self.body:
            out += chr(Int(b))
        return out^

    def is_file(self) -> Bool:
        """Return True if this part represents a file upload (has ``filename``).
        """
        return self.filename.byte_length() > 0

    def header(self, key: String) -> String:
        """Return part-level header ``key`` (case-insensitive), or ``""``."""
        var n = len(self.header_keys)
        for i in range(n):
            if self.header_keys[i].byte_length() != key.byte_length():
                continue
            var ap = self.header_keys[i].unsafe_ptr()
            var bp = key.unsafe_ptr()
            var matched = True
            for j in range(key.byte_length()):
                var ac = ap[j]
                var bc = bp[j]
                if ac >= 65 and ac <= 90:
                    ac = ac + 32
                if bc >= 65 and bc <= 90:
                    bc = bc + 32
                if ac != bc:
                    matched = False
                    break
            if matched:
                return self.header_values[i]
        return ""


struct MultipartForm(Copyable, Defaultable, Movable):
    """All parts of a parsed ``multipart/form-data`` body in receive order."""

    var parts: List[MultipartPart]

    def __init__(out self):
        self.parts = List[MultipartPart]()

    def len(self) -> Int:
        """Return the number of parts in this form."""
        return len(self.parts)

    def get(self, name: String) -> Optional[MultipartPart]:
        """Return the first part whose ``Content-Disposition`` ``name`` matches.
        """
        for i in range(len(self.parts)):
            if self.parts[i].name == name:
                return Optional[MultipartPart](self.parts[i].copy())
        return Optional[MultipartPart]()

    def get_all(self, name: String) -> List[MultipartPart]:
        """Return every part with ``Content-Disposition`` ``name == name``."""
        var out = List[MultipartPart]()
        for i in range(len(self.parts)):
            if self.parts[i].name == name:
                out.append(self.parts[i].copy())
        return out^

    def value(self, name: String) -> String:
        """Convenience: return the first text value for ``name`` or ``""``."""
        var p = self.get(name)
        if p:
            return p.value().text()
        return ""

    def file(self, name: String) -> Optional[MultipartPart]:
        """Return the first file part whose ``name`` matches, or ``None``."""
        for i in range(len(self.parts)):
            if self.parts[i].name == name and self.parts[i].is_file():
                return Optional[MultipartPart](self.parts[i].copy())
        return Optional[MultipartPart]()

    def contains(self, name: String) -> Bool:
        """Return True if any part with ``name`` exists."""
        for i in range(len(self.parts)):
            if self.parts[i].name == name:
                return True
        return False


def parse_multipart_form_data(
    body: List[UInt8], content_type: String
) raises -> MultipartForm:
    """Parse a buffered multipart/form-data body.

    Args:
        body:         The raw request body bytes.
        content_type: The request's ``Content-Type`` header value
                      (must include ``boundary=<token>``).

    Returns:
        A populated ``MultipartForm``.

    Raises:
        Error: When the boundary parameter is missing, the body does
               not begin with the expected delimiter, or any part is
               truncated (no closing CRLF before the next boundary).
    """
    var boundary = _extract_boundary(content_type)
    var bb = List[UInt8]()
    bb.append(UInt8(45))
    bb.append(UInt8(45))
    for c in boundary.as_bytes():
        bb.append(c)
    var double_crlf = List[UInt8]()
    double_crlf.append(UInt8(13))
    double_crlf.append(UInt8(10))
    double_crlf.append(UInt8(13))
    double_crlf.append(UInt8(10))

    var body_span = Span[UInt8, _](body)
    var bb_span = Span[UInt8, _](bb)
    var dcrlf_span = Span[UInt8, _](double_crlf)

    var first = _find_bytes(body_span, bb_span, 0)
    if first < 0:
        raise Error("multipart: leading boundary not found")
    var pos = first + len(bb_span)

    var form = MultipartForm()

    while pos < len(body):
        # Look at the two bytes after the boundary.
        if pos + 2 <= len(body):
            if body[pos] == 45 and body[pos + 1] == 45:
                # Closing boundary: --<bnd>--
                return form^
        # Skip CRLF after boundary.
        if pos + 2 <= len(body) and body[pos] == 13 and body[pos + 1] == 10:
            pos += 2
        else:
            raise Error("multipart: missing CRLF after boundary")
        # Find header / body split.
        var hdr_end = _find_bytes(body_span, dcrlf_span, pos)
        if hdr_end < 0:
            raise Error("multipart: part has no header terminator")
        var header_block = String(unsafe_from_utf8=body_span[pos:hdr_end])
        pos = hdr_end + 4
        # Locate next boundary (preceded by CRLF).
        var next_boundary = _find_bytes(body_span, bb_span, pos)
        if next_boundary < 0:
            raise Error("multipart: part has no closing boundary")
        # Strip the CRLF preceding the boundary marker if present.
        var body_end = next_boundary
        if (
            body_end >= 2
            and body[body_end - 1] == 10
            and body[body_end - 2] == 13
        ):
            body_end -= 2

        var part = MultipartPart()
        var part_body = List[UInt8]()
        part_body.reserve(body_end - pos)
        for i in range(pos, body_end):
            part_body.append(body[i])
        part.body = part_body^

        # Parse header lines.
        var hn = header_block.byte_length()
        var hp = header_block.unsafe_ptr()
        var line_start = 0
        while line_start < hn:
            var line_end = hn
            for j in range(line_start, hn - 1):
                if hp[j] == 13 and hp[j + 1] == 10:
                    line_end = j
                    break
            var line = String(
                unsafe_from_utf8=header_block.as_bytes()[line_start:line_end]
            )
            line_start = line_end + 2
            if line.byte_length() == 0:
                continue
            var colon = -1
            for k in range(line.byte_length()):
                if line.unsafe_ptr()[k] == 58:  # ':'
                    colon = k
                    break
            if colon <= 0:
                continue
            var key = String(unsafe_from_utf8=line.as_bytes()[:colon])
            var value = String(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :]).strip()
            )
            part.header_keys.append(key)
            part.header_values.append(value)
            var key_lower = String(capacity=key.byte_length())
            for k in range(key.byte_length()):
                var c = key.unsafe_ptr()[k]
                if c >= 65 and c <= 90:
                    key_lower += chr(Int(c) + 32)
                else:
                    key_lower += chr(Int(c))
            if key_lower == "content-disposition":
                part.name = _parse_disposition_param(value, "name")
                part.filename = _parse_disposition_param(value, "filename")
            elif key_lower == "content-type":
                part.content_type = value

        form.parts.append(part^)
        pos = next_boundary + len(bb_span)

    return form^
