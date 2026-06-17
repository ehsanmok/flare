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
from ..headers import HeaderMap
from ...tcp import TcpStream
from ...tls import TlsStream
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


def _parse_http_response(raw: List[UInt8]) raises -> Response:
    """Parse a raw HTTP/1.1 response byte buffer.

    Supports:
    - ``Content-Length`` delimited bodies
    - ``Transfer-Encoding: chunked`` bodies
    - Connection-close bodies (all bytes after double-CRLF)

    Args:
        raw: All bytes received from the server.

    Returns:
        Parsed ``Response``.

    Raises:
        NetworkError: If the status line is malformed or truncated.
    """
    # Find the end of headers (\r\n\r\n)
    var header_end = _find_crlf2(raw)
    if header_end < 0:
        raise NetworkError("HTTP response missing header terminator")

    # Convert header section to string
    var header_bytes = List[UInt8](capacity=header_end)
    for i in range(header_end):
        header_bytes.append(raw[i])
    var header_str = _bytes_to_str(header_bytes)

    # Parse status line
    var lines = _split_lines(header_str)
    if len(lines) == 0:
        raise NetworkError("HTTP response empty")
    var sl = _parse_status_line(lines[0])
    var status_code = sl.code
    var reason = sl.reason

    # Parse headers
    var headers = HeaderMap()
    for i in range(1, len(lines)):
        var line = lines[i]
        if line.byte_length() == 0:
            continue
        var colon = _str_find(line, ":")
        if colon < 0:
            continue
        var k = String(
            String(String(unsafe_from_utf8=line.as_bytes()[:colon])).strip()
        )
        var v = String(
            String(
                String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
            ).strip()
        )
        headers.append(k, v)

    # Extract body (everything after \r\n\r\n) plus any trailer
    # fields the chunked decoder pulled off after the zero chunk.
    var body_start = header_end + 4
    var trailers = HeaderMap()
    var body = _extract_body_and_trailers(raw, body_start, headers, trailers)

    var resp = Response(status=status_code, reason=reason^)
    resp.headers = headers^
    resp.body = body^
    resp.trailers = trailers^
    return resp^


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
    var s = String(capacity=len(data) + 1)
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
            s.unsafe_ptr()[i] == 13
            and i + 1 < n
            and s.unsafe_ptr()[i + 1] == 10
        ):
            lines.append(String(String(unsafe_from_utf8=s.as_bytes()[start:i])))
            start = i + 2
            i += 2
        elif s.unsafe_ptr()[i] == 10:
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
        var c = Int(rest.unsafe_ptr()[i])
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
            if s.unsafe_ptr()[i + j] != sub.unsafe_ptr()[j]:
                ok = False
                break
        if ok:
            return i
    return -1


def _lower_str(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
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
        var size_hex = String(capacity=16)
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
                var line = String(capacity=t_end - pos + 1)
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
        var c = Int(trimmed.unsafe_ptr()[i])
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
    # A 16-digit hex chunk size already exceeds 64 PiB; reject longer strings
    # to prevent Int overflow before the digit accumulation below.
    if s.byte_length() > 16:
        raise NetworkError("chunk-size too large in chunked encoding: " + s)
    var result = 0
    for i in range(s.byte_length()):
        var c = Int(s.unsafe_ptr()[i])
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


def _read_http_response_framed_tcp(
    mut stream: TcpStream,
    mut can_reuse: Bool,
) raises -> Response:
    """Read one framed HTTP/1.1 response and return whether the
    connection is in a reusable state.

    Unlike :func:`_read_http_response_tcp`, this reader stops at the
    end of the framed body (``Content-Length`` or
    ``Transfer-Encoding: chunked``) instead of reading until EOF, so
    the underlying socket can be returned to a connection pool for
    keep-alive reuse.

    Returns:
        ``(response, can_reuse)``: ``can_reuse`` is ``True`` when no
        ``Connection: close`` header is present, the response is
        properly framed, and the body was read cleanly.

    Raises:
        NetworkError: On I/O or parse error.
    """
    var buf = List[UInt8](capacity=_READ_BUF_SIZE)
    buf.resize(_READ_BUF_SIZE, 0)
    var raw = List[UInt8](capacity=4096)
    var hdr_end = -1

    while hdr_end < 0:
        var n = stream.read(buf.unsafe_ptr(), len(buf))
        if n == 0:
            if len(raw) == 0:
                raise NetworkError("HTTP response: peer closed before reply")
            raise NetworkError("HTTP response: missing header terminator")
        for i in range(n):
            raw.append(buf[i])
        hdr_end = _find_crlf2(raw)

    var header_bytes = List[UInt8](capacity=hdr_end)
    for i in range(hdr_end):
        header_bytes.append(raw[i])
    var header_str = _bytes_to_str(header_bytes)
    var lines = _split_lines(header_str)
    if len(lines) == 0:
        raise NetworkError("Empty HTTP response")

    var content_length = -1
    var is_chunked = False
    var conn_close = False
    for li in range(1, len(lines)):
        var ln = lines[li]
        var colon = ln.find(":")
        if colon < 0:
            continue
        var k_str = (
            String(String(unsafe_from_utf8=ln.as_bytes()[:colon]))
            .strip()
            .lower()
        )
        var v_str = String(
            String(unsafe_from_utf8=ln.as_bytes()[colon + 1 :])
        ).strip()
        if k_str == "content-length":
            try:
                content_length = atol(v_str)
            except:
                raise NetworkError("invalid Content-Length")
        elif k_str == "transfer-encoding":
            if v_str.lower() == "chunked":
                is_chunked = True
        elif k_str == "connection":
            if v_str.lower() == "close":
                conn_close = True

    var body_start = hdr_end + 4

    if is_chunked:
        # Drain chunks until we see the final ``0\r\n`` chunk
        # followed by optional trailers and the closing ``\r\n``.
        # We scan for ``\r\n0\r\n`` (start of last chunk) and then
        # for the next ``\r\n\r\n`` (end of trailers / message).
        while True:
            var pos = body_start
            var found_terminator = False
            while pos + 4 < len(raw):
                if (
                    raw[pos] == 13
                    and raw[pos + 1] == 10
                    and raw[pos + 2] == 48  # '0'
                    and raw[pos + 3] == 13
                    and raw[pos + 4] == 10
                ):
                    var t = pos + 5
                    while t + 3 < len(raw):
                        if (
                            raw[t] == 13
                            and raw[t + 1] == 10
                            and raw[t + 2] == 13
                            and raw[t + 3] == 10
                        ):
                            found_terminator = True
                            break
                        t += 1
                    if found_terminator:
                        break
                    if (
                        t + 1 == len(raw)
                        or t + 2 == len(raw)
                        or t + 3 == len(raw)
                    ):
                        break
                pos += 1
            if found_terminator:
                break
            var n2 = stream.read(buf.unsafe_ptr(), len(buf))
            if n2 == 0:
                raise NetworkError("Unexpected EOF in chunked body")
            for j in range(n2):
                raw.append(buf[j])
    elif content_length >= 0:
        var have = len(raw) - body_start
        var need = content_length - have
        while need > 0:
            var to_read = need if need < len(buf) else len(buf)
            var n3 = stream.read(buf.unsafe_ptr(), to_read)
            if n3 == 0:
                raise NetworkError("Unexpected EOF in body")
            for j in range(n3):
                raw.append(buf[j])
            need -= n3
    else:
        # No content-length and not chunked: must read to EOF;
        # cannot reuse the connection.
        conn_close = True
        while True:
            var n4 = stream.read(buf.unsafe_ptr(), len(buf))
            if n4 == 0:
                break
            for j in range(n4):
                raw.append(buf[j])

    var resp = _parse_http_response(raw)
    can_reuse = not conn_close
    return resp^
