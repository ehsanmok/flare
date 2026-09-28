"""HTTP/1.1 client response parsing extracted from ``flare.http.client``.

The response-side helpers that used to trail the ``HttpClient`` struct
in ``client.mojo``: raw socket draining, the RFC 7230 response parser,
status-line + header splitting, chunked / Content-Length body
extraction, and the framed TCP / TLS readers.
``flare.http.client`` re-exports the names its callers rely on
(``_parse_http_response`` / ``_decode_chunked`` /
``_extract_body_and_trailers`` plus the ``_read_http_response_*``
readers) so existing imports keep resolving unchanged.
"""

from ..response import Response
from .._scan import parse_content_length
from ..proto.chunked import (
    CHUNKED_INCOMPLETE,
    CHUNKED_MALFORMED,
    scan_chunked_resume,
)
from ..headers import HeaderMap
from ...tcp import TcpStream
from ...tls import TlsStream
from ...io.buf_reader import Readable
from ...net import NetworkError


comptime _READ_BUF_SIZE: Int = 16384  # 16 KiB per read chunk


def _read_all_tls(mut stream: TlsStream) raises -> List[UInt8]:
    """Read all available bytes from a TLS stream until EOF.

    Args:
        stream: An open ``TlsStream``.

    Returns:
        All bytes received.
    """
    var buf = List[UInt8](capacity=_READ_BUF_SIZE)
    buf.resize(_READ_BUF_SIZE, 0)
    var out = List[UInt8](capacity=4096)
    while True:
        var n = stream.read(buf.unsafe_ptr(), len(buf))
        if n == 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


def _read_all_tcp(mut stream: TcpStream) raises -> List[UInt8]:
    """Read all available bytes from a TCP stream until EOF.

    Args:
        stream: An open ``TcpStream``.

    Returns:
        All bytes received.
    """
    var buf = List[UInt8](capacity=_READ_BUF_SIZE)
    buf.resize(_READ_BUF_SIZE, 0)
    var out = List[UInt8](capacity=4096)
    while True:
        var n = stream.read(buf.unsafe_ptr(), len(buf))
        if n == 0:
            break
        for i in range(n):
            out.append(buf[i])
    return out^


comptime _FRAME_NONE: Int = 0
"""No body: HEAD, 1xx, 204, 304, or a 2xx to CONNECT."""
comptime _FRAME_LENGTH: Int = 1
"""Body delimited by ``Content-Length``."""
comptime _FRAME_CHUNKED: Int = 2
"""Body delimited by chunked framing."""
comptime _FRAME_CLOSE: Int = 3
"""Body runs to the end of the connection."""


@fieldwise_init
struct _ResponseHead(Movable):
    var status: Int
    var reason: String
    var headers: HeaderMap


def _parse_response_head(head: List[UInt8]) raises -> _ResponseHead:
    """Parse a response head (status line + fields, no final CRLFCRLF).

    One set of rules for every HTTP/1.1 reader in the client, buffered
    and streaming alike. They used to disagree: the buffered parser
    skipped colonless lines and accepted obs-fold (``" evil: v"``
    became a header named ``evil``) and whitespace before the colon
    (``Content-Length : 5``), all of which the streaming reader already
    refused.
    """
    var lines = _split_lines(_bytes_to_str(head))
    if len(lines) == 0:
        raise NetworkError("HTTP response empty")
    var sl = _parse_status_line(lines[0])
    if sl.code < 100 or sl.code > 599:
        raise NetworkError("HTTP response: invalid status code")
    var headers = HeaderMap()
    for li in range(1, len(lines)):
        var ln = lines[li]
        var raw = ln.as_bytes()
        if len(raw) == 0:
            continue
        # RFC 9112 sec 5.2: obs-fold is not a field line.
        if raw[0] == 32 or raw[0] == 9:
            raise NetworkError("HTTP response: obs-fold line rejected")
        var colon = ln.find(":")
        if colon <= 0:
            raise NetworkError("HTTP response: malformed header line")
        # RFC 9112 sec 5.1: no whitespace between name and colon.
        if raw[colon - 1] == 32 or raw[colon - 1] == 9:
            raise NetworkError("HTTP response: whitespace before header colon")
        var k = String(String(unsafe_from_utf8=ln.as_bytes()[:colon]))
        var v = String(
            String(unsafe_from_utf8=ln.as_bytes()[colon + 1 :]).strip()
        )
        headers.append(k, v)
    return _ResponseHead(sl.code, sl.reason, headers^)


def _response_framing(
    method: String, status: Int, headers: HeaderMap
) raises -> Tuple[Int, Int]:
    """``(mode, content_length)`` for a final (non-1xx) response.

    RFC 9112 sec 6.3, in the order it gives: HEAD, 1xx, 204, 304 and a
    2xx to CONNECT have no body; then Transfer-Encoding, which must be
    exactly ``chunked`` and may not come with Content-Length; then a
    single Content-Length; else read to close. A repeated
    Content-Length is refused even when the values agree, as the server
    side refuses it by default.
    """
    var verb = method.upper()
    if (
        verb == "HEAD"
        or status < 200
        or status == 204
        or status == 304
        or (verb == "CONNECT" and status < 300)
    ):
        return (_FRAME_NONE, 0)
    var lengths = headers.get_all("content-length")
    if len(lengths) > 1:
        raise NetworkError("HTTP response: duplicate Content-Length")
    var content_length = -1
    if len(lengths) == 1:
        content_length = parse_content_length(lengths[0])
        if content_length < 0:
            raise NetworkError("HTTP response: invalid Content-Length")
    var encodings = headers.get_all("transfer-encoding")
    if len(encodings) > 0:
        if len(encodings) != 1 or _lower_str(encodings[0]) != "chunked":
            raise NetworkError("HTTP response: unsupported Transfer-Encoding")
        if content_length >= 0:
            raise NetworkError(
                "response carries both Transfer-Encoding: chunked and"
                " Content-Length (RFC 9112 sec 6.3 forbids; would enable"
                " response smuggling)"
            )
        return (_FRAME_CHUNKED, -1)
    if content_length >= 0:
        return (_FRAME_LENGTH, content_length)
    return (_FRAME_CLOSE, -1)


def _parse_http_response(
    raw: List[UInt8], method: String = "GET"
) raises -> Response:
    """Parse a raw HTTP/1.1 response byte buffer.

    Informational 1xx heads before the final response are skipped (a
    ``103 Early Hints`` used to be returned as the response). 101 is
    returned as is, for the h2c upgrade path. The body follows
    :func:`_response_framing`: ``method`` matters, since a response to
    HEAD has a Content-Length and no body.

    Args:
        raw: All bytes received from the server.
        method: The request method.

    Returns:
        Parsed ``Response``.

    Raises:
        NetworkError: If the head is malformed, the framing is
            ambiguous, or a ``Content-Length`` body is truncated.
    """
    var start = 0
    while True:
        var header_end = _find_crlf2_from(raw, start)
        if header_end < 0:
            raise NetworkError("HTTP response missing header terminator")
        var head_bytes = List[UInt8](capacity=header_end - start)
        for i in range(start, header_end):
            head_bytes.append(raw[i])
        var head = _parse_response_head(head_bytes)
        var body_start = header_end + 4
        if head.status >= 100 and head.status < 200 and head.status != 101:
            start = body_start
            continue
        var framing = _response_framing(method, head.status, head.headers)
        var trailers = HeaderMap()
        var body = List[UInt8]()
        if framing[0] == _FRAME_CHUNKED:
            body = _decode_chunked(raw, body_start, trailers)
        elif framing[0] == _FRAME_LENGTH:
            var cl = framing[1]
            if len(raw) - body_start < cl:
                raise NetworkError(
                    "HTTP response: body shorter than its Content-Length"
                )
            body = List[UInt8](capacity=cl)
            for i in range(body_start, body_start + cl):
                body.append(raw[i])
        elif framing[0] == _FRAME_CLOSE:
            body = List[UInt8](capacity=len(raw) - body_start)
            for i in range(body_start, len(raw)):
                body.append(raw[i])
        var resp = Response(status=head.status, reason=head.reason)
        resp.headers = head.headers.copy()
        resp.body = body^
        resp.trailers = trailers^
        return resp^


def _find_crlf2_from(data: List[UInt8], start: Int) -> Int:
    """``_find_crlf2`` from offset ``start``."""
    var i = start
    while i + 3 < len(data):
        if (
            data[i] == 13
            and data[i + 1] == 10
            and data[i + 2] == 13
            and data[i + 3] == 10
        ):
            return i
        i += 1
    return -1


def _find_crlf2(data: List[UInt8]) -> Int:
    """Return byte offset of ``\\r\\n\\r\\n`` in ``data``, or -1."""
    var n = len(data)
    for i in range(n - 3):
        if (
            data[i] == 13
            and data[i + 1] == 10
            and data[i + 2] == 13
            and data[i + 3] == 10
        ):
            return i
    return -1


def _bytes_to_str(data: List[UInt8]) -> String:
    """Convert a byte list to a String, replacing non-printable and non-ASCII bytes.

    HTTP/1.1 headers must be ASCII (RFC 7230 §3.2.6). NUL bytes and non-ASCII
    bytes are replaced with ``?`` so that every input byte maps to exactly one
    output character, keeping byte-position arithmetic in ``_split_lines`` safe.
    NUL (0x00) is replaced because Mojo strings are NUL-terminated internally
    and embedded NULs can cause panics in string operations.
    """
    var s = String(capacity_bytes=len(data) + 1)
    for b in data:
        var c = Int(b)
        if c == 0:
            s += "?"
        elif c < 128:
            s += chr(c)
        else:
            s += "?"
    return s^


def _split_lines(s: String) -> List[String]:
    """Split ``s`` by ``\\r\\n`` or ``\\n``."""
    var lines = List[String]()
    var start = 0
    var i = 0
    var n = s.byte_length()
    while i < n:
        if (
            s.unsafe_ptr()[unsafe_offset=i] == 13
            and i + 1 < n
            and s.unsafe_ptr()[unsafe_offset=i + 1] == 10
        ):
            lines.append(String(String(unsafe_from_utf8=s.as_bytes()[start:i])))
            start = i + 2
            i += 2
        elif s.unsafe_ptr()[unsafe_offset=i] == 10:
            lines.append(String(String(unsafe_from_utf8=s.as_bytes()[start:i])))
            start = i + 1
            i += 1
        else:
            i += 1
    if start < n:
        lines.append(String(String(unsafe_from_utf8=s.as_bytes()[start:n])))
    return lines^


struct _StatusLine:
    var code: Int
    var reason: String

    def __init__(out self, code: Int, reason: String):
        self.code = code
        self.reason = reason


def _parse_status_line(line: String) raises -> _StatusLine:
    """Parse ``HTTP/1.1 200 OK`` into a ``_StatusLine``.

    Args:
        line: The first line of the HTTP response.

    Returns:
        A ``_StatusLine`` with the parsed status code and reason phrase.

    Raises:
        NetworkError: If the format is unrecognised.
    """
    # Must start with "HTTP/"
    if not line.startswith("HTTP/"):
        raise NetworkError("invalid HTTP status line: " + line)
    # Find first space after version
    var sp1 = _str_find(line, " ")
    if sp1 < 0:
        raise NetworkError("malformed HTTP status line: " + line)
    var rest = String(
        String(String(unsafe_from_utf8=line.as_bytes()[sp1 + 1 :])).lstrip()
    )
    if rest.byte_length() < 3:
        raise NetworkError("HTTP status code too short: " + line)
    # Parse 3-digit code
    var code = 0
    for i in range(3):
        var c = Int(rest.unsafe_ptr()[unsafe_offset=i])
        if c < 48 or c > 57:
            raise NetworkError("non-numeric HTTP status code in: " + line)
        code = code * 10 + (c - 48)
    var reason = String("")
    if rest.byte_length() > 4:
        reason = String(String(unsafe_from_utf8=rest.as_bytes()[4:]))
    return _StatusLine(code, reason^)


def _str_find(s: String, sub: String) -> Int:
    """Return the index of the first ``sub`` in ``s``, or -1."""
    var n = s.byte_length()
    var m = sub.byte_length()
    if m == 0:
        return 0
    for i in range(n - m + 1):
        var ok = True
        for j in range(m):
            if (
                s.unsafe_ptr()[unsafe_offset=i + j]
                != sub.unsafe_ptr()[unsafe_offset=j]
            ):
                ok = False
                break
        if ok:
            return i
    return -1


def _lower_str(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity_bytes=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[unsafe_offset=i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _extract_body_and_trailers(
    raw: List[UInt8],
    body_start: Int,
    headers: HeaderMap,
    mut trailers: HeaderMap,
) raises -> List[UInt8]:
    """Extract the response body + (when chunked) any trailer
    fields from the raw byte buffer.

    Handles:

    - ``Transfer-Encoding: chunked`` (with optional trailer
      fields after the zero-chunk; populates ``trailers``).
    - ``Content-Length: N``.
    - Connection-close (remainder of buffer).

    Args:
        raw: Full raw response bytes.
        body_start: Byte offset of the first body byte.
        headers: Parsed response headers.
        trailers: Output ``HeaderMap`` populated with any trailer
            fields parsed from the chunked body.

    Returns:
        Decoded body bytes.

    Raises:
        NetworkError: If chunked encoding is malformed, or if both
            ``Transfer-Encoding: chunked`` and ``Content-Length``
            are present (RFC 7230 §3.3.3 request-smuggling guard),
            or if a trailer field is forbidden per RFC 7230
            §4.1.2.
    """
    var te = _lower_str(headers.get("Transfer-Encoding"))
    var cl_str = headers.get("Content-Length")
    if "chunked" in te:
        if cl_str.byte_length() > 0:
            raise NetworkError(
                "response carries both Transfer-Encoding: chunked and"
                " Content-Length (RFC 7230 §3.3.3 forbids; would enable"
                " request smuggling)"
            )
        return _decode_chunked(raw, body_start, trailers)

    if cl_str.byte_length() > 0:
        var cl = _parse_int(cl_str)
        var available = len(raw) - body_start
        var body = List[UInt8](capacity=min(cl, available))
        var end = body_start + cl
        if end > len(raw):
            end = len(raw)
        for i in range(body_start, end):
            body.append(raw[i])
        return body^

    # Connection-close: body is everything remaining
    var body = List[UInt8](capacity=len(raw) - body_start)
    for i in range(body_start, len(raw)):
        body.append(raw[i])
    return body^


def _extract_body(
    raw: List[UInt8], body_start: Int, headers: HeaderMap
) raises -> List[UInt8]:
    """Backwards-compatible wrapper over
    :func:`_extract_body_and_trailers` for callers that don't care
    about trailer fields. The trailer ``HeaderMap`` is built and
    discarded; the smuggling + trailer-validity checks still run.
    """
    var trailers = HeaderMap()
    return _extract_body_and_trailers(raw, body_start, headers, trailers)


def _is_forbidden_trailer(name: String) -> Bool:
    """Return ``True`` if ``name`` is forbidden as a trailer field
    per RFC 7230 §4.1.2.

    The RFC bans framing headers (``Transfer-Encoding``,
    ``Content-Length``), routing headers (``Host``), the
    ``Trailer`` header itself (no nesting), authentication
    (``Authorization``, ``Set-Cookie``, ``Cookie``), and
    response-control / message-modifier headers
    (``Cache-Control``, ``Expires``, ``Date``, ``Location``,
    ``Retry-After``, ``Vary``, ``Warning``, ``Age``, ``Expect``,
    ``Pragma``, ``Range``, ``TE``).

    flare ships the practical security subset: framing, routing,
    auth, and the ``Trailer`` self-reference. The remaining
    response-control entries are caller-controlled and won't
    enable smuggling -- they're left to the caller's policy.
    """
    var lower = _lower_str(name)
    if lower == "transfer-encoding":
        return True
    if lower == "content-length":
        return True
    if lower == "host":
        return True
    if lower == "trailer":
        return True
    if lower == "authorization":
        return True
    if lower == "set-cookie":
        return True
    if lower == "cookie":
        return True
    return False


def _decode_chunked(
    raw: List[UInt8], start: Int, mut trailers: HeaderMap
) raises -> List[UInt8]:
    """Decode a ``Transfer-Encoding: chunked`` body and any
    trailer fields that follow the zero-length chunk.

    Args:
        raw: Complete raw byte buffer.
        start: Byte offset of the first chunk-size line.
        trailers: Output ``HeaderMap`` populated with any trailer
            fields parsed after the zero-length chunk per RFC
            7230 §4.1.2.

    Returns:
        Reassembled body bytes.

    Raises:
        NetworkError: If a chunk-size line is unparseable, or a
            trailer field is forbidden per RFC 7230 §4.1.2.
    """
    var out = List[UInt8](capacity=4096)
    var pos = start
    var n = len(raw)
    while pos < n:
        # Find end of chunk-size line (\r\n)
        var line_end = _find_crlf(raw, pos)
        if line_end < 0:
            break
        # Parse hex chunk size
        var size_hex = String(capacity_bytes=16)
        for i in range(pos, line_end):
            size_hex += chr(Int(raw[i]))
        # Strip extensions (;...)
        var semi = _str_find(size_hex, ";")
        if semi >= 0:
            size_hex = String(
                String(unsafe_from_utf8=size_hex.as_bytes()[:semi])
            )
        var chunk_size = _parse_hex(String(size_hex.strip()))
        pos = line_end + 2  # skip \r\n
        if chunk_size == 0:
            # Zero-chunk -- read trailer fields (RFC 7230 §4.1.2)
            # until empty CRLF terminator.
            while pos < n:
                var t_end = _find_crlf(raw, pos)
                if t_end < 0:
                    break
                if t_end == pos:
                    # Empty line -- end of trailers.
                    break
                var line = String(capacity_bytes=t_end - pos + 1)
                for i in range(pos, t_end):
                    line += chr(Int(raw[i]))
                var colon = _str_find(line, ":")
                if colon < 0:
                    raise NetworkError(
                        "malformed trailer field (no colon): " + line
                    )
                var k = String(
                    String(
                        String(unsafe_from_utf8=line.as_bytes()[:colon])
                    ).strip()
                )
                var v = String(
                    String(
                        String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
                    ).strip()
                )
                if _is_forbidden_trailer(k):
                    raise NetworkError(
                        "forbidden trailer field per RFC 7230 §4.1.2: " + k
                    )
                trailers.append(k, v)
                pos = t_end + 2
            break
        var end = pos + chunk_size
        if end > n:
            end = n
        for i in range(pos, end):
            out.append(raw[i])
        pos = end + 2  # skip trailing \r\n after chunk data
    return out^


def _find_crlf(data: List[UInt8], start: Int) -> Int:
    """Return position of ``\\r\\n`` at or after ``start``, or -1."""
    var n = len(data)
    for i in range(start, n - 1):
        if data[i] == 13 and data[i + 1] == 10:
            return i
    return -1


def _parse_int(s: String) -> Int:
    """Parse a decimal integer string; returns 0 on failure.

    Rejects strings longer than 18 digits to prevent ``Int`` overflow on
    64-bit systems (max safe decimal: 999_999_999_999_999_999 < 2^63-1).
    A valid ``Content-Length`` will never be 19+ digits in practice.
    """
    var trimmed = s.strip()
    if trimmed.byte_length() > 18:
        return 0  # overflow guard
    var result = 0
    for i in range(trimmed.byte_length()):
        var c = Int(trimmed.unsafe_ptr()[unsafe_offset=i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result


def _parse_hex(s: String) raises -> Int:
    """Parse a hexadecimal integer string.

    Args:
        s: Hex string (e.g. ``"1a3f"``).

    Returns:
        Integer value.

    Raises:
        NetworkError: If the string is empty or contains non-hex characters.
    """
    if s.byte_length() == 0:
        raise NetworkError("empty chunk-size in chunked encoding")
    # Cap at 15 hex digits (max 2^60-1): a 16th digit can push the signed Int
    # accumulator past 2^63-1 and wrap it negative, which would drive the chunk
    # cursor negative and index out of bounds. 15 hex digits already addresses
    # well past 1 EiB, far more than any real chunk.
    if s.byte_length() > 15:
        raise NetworkError("chunk-size too large in chunked encoding: " + s)
    var result = 0
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[unsafe_offset=i])
        var digit: Int
        if c >= 48 and c <= 57:
            digit = c - 48
        elif c >= 65 and c <= 70:  # A-F
            digit = c - 55
        elif c >= 97 and c <= 102:  # a-f
            digit = c - 87
        else:
            raise NetworkError("invalid hex digit in chunk-size: " + s)
        result = result * 16 + digit
    return result


def _read_http_response_tls(mut stream: TlsStream) raises -> Response:
    """Read and parse a full HTTP response from a TLS stream.

    Args:
        stream: Open ``TlsStream``.

    Returns:
        Parsed ``Response``.

    Raises:
        NetworkError: On I/O or parse error.
    """
    var raw = _read_all_tls(stream)
    return _parse_http_response(raw)


def _read_http_response_tcp(mut stream: TcpStream) raises -> Response:
    """Read and parse a full HTTP response from a TCP stream.

    Args:
        stream: Open ``TcpStream``.

    Returns:
        Parsed ``Response``.

    Raises:
        NetworkError: On I/O or parse error.
    """
    var raw = _read_all_tcp(stream)
    return _parse_http_response(raw)


comptime MAX_BUFFERED_RESPONSE_BYTES: Int = 256 * 1024 * 1024
"""Largest response the buffered client will hold in memory: head,
body and framing together. A larger one raises instead of growing the
buffer until the process runs out of memory; stream it instead."""

comptime NO_REPLY_ERROR: String = "HTTP response: no reply"
"""Prefix of every error the framed reader raises before receiving a
single response byte. The request may never have been processed, which
is the one case where retrying on a fresh connection can be safe."""

comptime _MAX_RESPONSE_HEAD_BYTES: Int = 64 * 1024
"""Largest response head (1xx heads included) accepted."""


def _wire_method(wire: String) -> String:
    """The method token of a serialised request line."""
    var sp = wire.find(" ")
    if sp <= 0:
        return "GET"
    return String(String(unsafe_from_utf8=wire.as_bytes()[:sp]))


def _read_http_response_framed_tcp(
    mut stream: TcpStream,
    mut can_reuse: Bool,
    method: String = "GET",
) raises -> Response:
    """Read one framed HTTP/1.1 response from a cleartext TCP stream.

    Thin wrapper over :func:`_read_http_response_framed` (which works
    over any ``Readable``); kept for the existing cleartext pool call
    site and its name.
    """
    return _read_http_response_framed(stream, can_reuse, method)


def _read_http_response_framed_tls(
    mut stream: TlsStream,
    mut can_reuse: Bool,
    method: String = "GET",
) raises -> Response:
    """Read one framed HTTP/1.1 response from a TLS stream, for HTTPS
    keep-alive pooling. See :func:`_read_http_response_framed`."""
    return _read_http_response_framed(stream, can_reuse, method)


def _fill[
    R: Readable
](mut stream: R, mut buf: List[UInt8], mut raw: List[UInt8]) raises -> Bool:
    var n = stream.read(buf.unsafe_ptr(), len(buf))
    if n == 0:
        return False
    if len(raw) + n > MAX_BUFFERED_RESPONSE_BYTES:
        raise NetworkError(
            "HTTP response larger than the buffered limit; stream it"
        )
    for i in range(n):
        raw.append(buf[i])
    return True


def _read_http_response_framed[
    R: Readable
](
    mut stream: R, mut can_reuse: Bool, method: String = "GET"
) raises -> Response:
    """Read one framed HTTP/1.1 response and return whether the
    connection is in a reusable state.

    Stops at the end of the framed body instead of reading until EOF,
    so the socket can go back to a connection pool. The framing follows
    :func:`_response_framing`, and so depends on ``method``: a response
    to HEAD has a Content-Length and no body, and waiting for that body
    hung the request. Informational 1xx heads are read past.

    A chunked body is walked chunk by chunk (``scan_chunked_resume``).
    It used to be found by searching the raw bytes for ``\r\n0\r\n``,
    which stopped early when the *payload* contained that pattern --
    leaving body bytes in the socket for the next pooled request to read
    as its response -- and never matched an empty chunked body at all.

    Returns:
        The response. ``can_reuse`` is set when the connection is
        cleanly at a message boundary and not marked ``close``.

    Raises:
        NetworkError: On I/O or parse error, EOF inside a message, or a
            response over ``MAX_BUFFERED_RESPONSE_BYTES``.
    """
    can_reuse = False
    var buf = List[UInt8](capacity=_READ_BUF_SIZE)
    buf.resize(_READ_BUF_SIZE, 0)
    var raw = List[UInt8](capacity=4096)

    # Heads, skipping 1xx.
    var start = 0
    var hdr_end: Int
    var status: Int
    var headers: HeaderMap
    while True:
        hdr_end = _find_crlf2_from(raw, start)
        while hdr_end < 0:
            if len(raw) - start > _MAX_RESPONSE_HEAD_BYTES:
                raise NetworkError("HTTP response head too large")
            var more: Bool
            try:
                more = _fill(stream, buf, raw)
            except e:
                if len(raw) == 0:
                    raise NetworkError(NO_REPLY_ERROR + ": " + String(e))
                raise e^
            if not more:
                if len(raw) == 0:
                    raise NetworkError(NO_REPLY_ERROR + ": peer closed")
                raise NetworkError("HTTP response: missing header terminator")
            hdr_end = _find_crlf2_from(raw, start)
        var head_bytes = List[UInt8](capacity=hdr_end - start)
        for i in range(start, hdr_end):
            head_bytes.append(raw[i])
        var head = _parse_response_head(head_bytes)
        status = head.status
        if status >= 100 and status < 200 and status != 101:
            start = hdr_end + 4
            continue
        headers = head.headers.copy()
        break

    var conn_close = False
    for v in headers.get_all("connection"):
        for tok in v.split(","):
            if String(tok).strip().lower() == "close":
                conn_close = True

    var framing = _response_framing(method, status, headers)
    var body_start = hdr_end + 4
    var end = body_start
    if framing[0] == _FRAME_LENGTH:
        end = body_start + framing[1]
        if end > MAX_BUFFERED_RESPONSE_BYTES:
            raise NetworkError(
                "HTTP response larger than the buffered limit; stream it"
            )
        while len(raw) < end:
            if not _fill(stream, buf, raw):
                raise NetworkError("Unexpected EOF in body")
    elif framing[0] == _FRAME_CHUNKED:
        var cursor = body_start
        var decoded = 0
        while True:
            var r = scan_chunked_resume(
                Span[UInt8, _](raw),
                cursor,
                decoded,
                MAX_BUFFERED_RESPONSE_BYTES,
            )
            if r == CHUNKED_MALFORMED:
                raise NetworkError("HTTP response: malformed chunked body")
            if r != CHUNKED_INCOMPLETE:
                end = r
                break
            if not _fill(stream, buf, raw):
                raise NetworkError("Unexpected EOF in chunked body")
    elif framing[0] == _FRAME_CLOSE:
        # No length and not chunked: read to EOF; not reusable.
        conn_close = True
        while _fill(stream, buf, raw):
            pass
        end = len(raw)

    # Bytes past the end of the message on a connection we did not
    # pipeline on mean the peer and we disagree about framing: never
    # hand that connection to the next request.
    var clean = len(raw) == end
    if len(raw) > end:
        raw.resize(end, 0)
    var resp = _parse_http_response(raw, method)
    can_reuse = clean and not conn_close
    return resp^
