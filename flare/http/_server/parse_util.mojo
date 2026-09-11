"""Low-level HTTP/1.1 lexing helpers for ``flare.http._server.parse``.

The byte-level primitives the request parsers build on: ASCII
``String`` construction without UTF-8 validation, the CRLFCRLF /
Content-Length scan wrappers, RFC 7230 token / field-value classifiers,
CRLF line readers (strict + lenient), and decimal integer parsing.
``flare.http.server`` re-exports every name here under its original
name. Split out of ``parse.mojo`` to keep both files inside the
reactor-size budget.
"""

from ..proto.ascii import ascii_unchecked_string


@always_inline
def _ascii_unchecked_string(span: Span[UInt8, _]) -> String:
    """Construct a ``String`` from ASCII bytes without UTF-8 validation.

    Thin wrapper over the canonical
    :func:`flare.http.proto.ascii.ascii_unchecked_string` helper,
    kept under this module's namespace because the H1 reactor
    code throughout :mod:`flare.http._server_reactor_impl` and
    the parser imports it locally; the canonical helper lives in
    the sans-I/O parser layer.

    Caller contract: the bytes MUST already be valid ASCII
    (< 0x80). HTTP/1.1 wire artefacts -- method, URL, version,
    header name, header value -- all satisfy this via the RFC
    7230 token / VCHAR checks the parser already runs upstream.
    """
    return ascii_unchecked_string(span)


@always_inline
def _ascii_safe(s: String) -> String:
    """Render ``s`` with every byte outside printable ASCII (0x20-0x7E)
    replaced by ``'?'``.

    Request-line artefacts (method, request-target, version) reach the
    parser as raw wire bytes and are wrapped into ``String`` via the
    unchecked ASCII constructor, so they can carry arbitrary
    attacker-controlled bytes >= 0x80. Concatenating such a ``String``
    into an ``Error`` message yields a value that is not guaranteed to be
    valid UTF-8; any downstream codepoint-aware consumer (a logger, the
    sanitized 4xx body, a fuzz harness scanning the message) then aborts
    on a non-codepoint-boundary slice. Mapping the message preview to
    printable ASCII keeps the diagnostic useful without reflecting raw
    bytes back out.
    """
    var n = s.byte_length()
    if n == 0:
        return String("")
    var p = s.unsafe_ptr()
    var out = String(capacity=n)
    for i in range(n):
        var c = p[unsafe_offset=i]
        if c >= 32 and c <= 126:
            out += chr(Int(c))
        else:
            out += "?"
    return out^


@always_inline
def _ascii_strip_slice(span: Span[UInt8, _]) -> String:
    """Return an owned ``String`` equal to ``span`` with ASCII whitespace
    (SPACE and HTAB) trimmed from both ends.

    Replaces the ``String(String(unsafe_from_utf8=...)).strip()`` triple
    that previously allocated three ``String`` objects per header
    half. The fast path does a single pointer-based construction of
    the final owned ``String`` from the trimmed sub-span via the
    ``_ascii_unchecked_string`` helper (no UTF-8 validation).
    """
    var n = len(span)
    var start = 0
    while start < n:
        var c = span[start]
        if c != 32 and c != 9:
            break
        start += 1
    var stop = n
    while stop > start:
        var c = span[stop - 1]
        if c != 32 and c != 9:
            break
        stop -= 1
    if stop <= start:
        return String("")
    return _ascii_unchecked_string(span[start:stop])


@always_inline
def _find_crlfcrlf(data: List[UInt8], start: Int) -> Int:
    """Find \\r\\n\\r\\n in data starting at ``start``.

    Returns the byte offset just past the sequence (start of body),
    or -1 if not found.

    Thin wrapper over ``flare.http._scan.find_crlfcrlf`` with the
    default SIMD width (32 lanes) so the public call site keeps the
    same signature as the scalar implementation. Callers who
    need a non-default width can import ``find_crlfcrlf`` directly.
    """
    from .._scan import find_crlfcrlf as _sc_find

    return _sc_find(data, start)


def _scan_content_length(data: List[UInt8], header_end: Int) -> Int:
    """Scan for ``Content-Length:`` in the header block and parse it.

    Thin wrapper over ``flare.http._scan.scan_content_length`` at the
    default SIMD width. Returns ``0`` when the header is absent.
    """
    from .._scan import scan_content_length as _sc_len

    return _sc_len(data, header_end)


# ── RFC 7230 token validation ─────────────────────────────────────────────────


@always_inline
def _is_token_char(c: UInt8) -> Bool:
    """Return True if ``c`` is a valid HTTP token character (RFC 7230 §3.2.6).

    token = 1*tchar
    tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
            "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
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
def _is_field_value_char(c: UInt8) -> Bool:
    """Return True if ``c`` is valid in an HTTP header field value (RFC 7230 §3.2).

    field-value = *( field-content / obs-fold )
    field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    field-vchar = VCHAR / obs-text
    VCHAR = 0x21-0x7E; obs-text = 0x80-0xFF; SP = 0x20; HTAB = 0x09
    """
    if c == 9 or c == 32:
        return True
    if c >= 33 and c <= 126:
        return True
    if c >= 128:
        return True
    return False


def _read_line_buf_lenient(
    data: Span[UInt8, _], mut pos: Int, allow_lf_only: Bool
) raises -> String:
    """Read one line, enforcing CRLF in strict mode.

    Strict (``allow_lf_only=False``) rejects bare LF terminators
    per RFC 9112 §2.2; lenient accepts both CRLF and LF. Bytes
    are passed through verbatim so the parser's per-byte
    validators can inspect them (NUL / control / obs-text
    handling lives at the parser).
    """
    var n = len(data)
    var start = pos
    var end = -1
    var i = start
    var saw_cr_before_lf = False
    while i < n:
        var c = data[i]
        if c == 10:
            end = i
            saw_cr_before_lf = i > start and data[i - 1] == 13
            break
        i += 1

    if end < 0:
        end = n

    if not allow_lf_only and end < n and end > start and not saw_cr_before_lf:
        raise Error("bare LF line terminator (RFC 9112 §2.2 requires CRLF)")

    pos = end + 1 if end < n else end

    var stop = end
    if stop > start and data[stop - 1] == 13:
        stop -= 1

    if stop <= start:
        return String("")

    return _ascii_unchecked_string(data[start:stop])


def _read_line_buf(data: Span[UInt8, _], mut pos: Int) -> String:
    """Read one CRLF/LF-terminated line from a byte span, advancing ``pos``.

    Replaces NUL and non-ASCII bytes with '?' since HTTP headers are ASCII
    per RFC 7230.

    Fast path: scan once for the LF terminator while checking for bad
    bytes; if none are found, build the line in a single
    ``String(unsafe_from_utf8=span)`` call. The slow path only runs on
    malformed / non-ASCII requests and preserves the previous
    byte-at-a-time sanitisation semantics.
    """
    var n = len(data)
    var start = pos
    var end = -1
    var has_bad = False
    var i = start
    while i < n:
        var c = data[i]
        if c == 10:
            end = i
            break
        if c == 0 or c >= 128:
            has_bad = True
        i += 1

    if end < 0:
        # No terminator — consume everything that was available.
        end = n

    # Advance the caller's cursor past the LF (or to end-of-buffer).
    pos = end + 1 if end < n else end

    # Exclude trailing CR.
    var stop = end
    if stop > start and data[stop - 1] == 13:
        stop -= 1

    if stop <= start:
        return String("")

    if not has_bad:
        # Fast path — pure ASCII, one-shot construction without
        # UTF-8 validation (the byte-scan above already proved
        # every byte is < 0x80).
        return _ascii_unchecked_string(data[start:stop])

    # Slow path: copy bytes, replacing bad ones with '?'.
    var out = String(capacity=stop - start)
    for k in range(start, stop):
        var c = data[k]
        if c == 0 or c >= 128:
            out += "?"
        else:
            out += chr(Int(c))
    return out^


def _parse_int_str(s: String) -> Int:
    """Parse a non-negative decimal integer string; returns 0 on failure."""
    var result = 0
    var trimmed = s.strip()
    for i in range(trimmed.byte_length()):
        var c = Int(trimmed.unsafe_ptr()[unsafe_offset=i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result
