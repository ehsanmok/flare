"""HTTP/1.1 server with buffered reads, keep-alive, and per-connection handler callbacks.

Key performance characteristics:
- Reads from the socket in chunks (configurable, default 8KB) instead of byte-at-a-time.
- Scans for the header terminator (CRLFCRLF) in the buffer before parsing.
- Supports HTTP/1.1 keep-alive (reuses connections for multiple requests).
- Serialises the full response into a single buffer for one write_all call.
- Sets recv/send timeouts on accepted sockets for DoS resilience.
- Respects HTTP/1.0 close-by-default semantics.
"""

from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from ..net import SocketAddr, NetworkError, BrokenPipe, Timeout
from ..tcp import TcpListener, TcpStream


# ── Server configuration ─────────────────────────────────────────────────────


struct ServerConfig(Copyable, Movable):
    """Configuration for the HTTP server.

    Fields:
        read_buffer_size:       Socket read chunk size in bytes (default 8192).
        max_header_size:        Maximum total bytes for request headers (default 8192).
        max_body_size:          Maximum bytes for the request body (default 10MB).
        max_uri_length:         Maximum bytes for the request URI (default 8192).
        keep_alive:             Enable HTTP/1.1 keep-alive (default True).
        max_keepalive_requests: Max requests per connection before forcing close (default 100).
        idle_timeout_ms:        Recv timeout on accepted sockets in ms (default 500). 0 disables.
        write_timeout_ms:       Send timeout on accepted sockets in ms (default 5000). 0 disables.
    """

    var read_buffer_size: Int
    var max_header_size: Int
    var max_body_size: Int
    var max_uri_length: Int
    var keep_alive: Bool
    var max_keepalive_requests: Int
    var idle_timeout_ms: Int
    var write_timeout_ms: Int

    def __init__(
        out self,
        read_buffer_size: Int = 8192,
        max_header_size: Int = 8192,
        max_body_size: Int = 10 * 1024 * 1024,
        max_uri_length: Int = 8192,
        keep_alive: Bool = True,
        max_keepalive_requests: Int = 100,
        idle_timeout_ms: Int = 500,
        write_timeout_ms: Int = 5000,
    ):
        self.read_buffer_size = read_buffer_size
        self.max_header_size = max_header_size
        self.max_body_size = max_body_size
        self.max_uri_length = max_uri_length
        self.keep_alive = keep_alive
        self.max_keepalive_requests = max_keepalive_requests
        self.idle_timeout_ms = idle_timeout_ms
        self.write_timeout_ms = write_timeout_ms


# ── HttpServer ────────────────────────────────────────────────────────────────


struct HttpServer(Movable):
    """A blocking HTTP/1.1 server with buffered reads and keep-alive support.

    Each accepted connection is handled in the calling thread.
    Reads are buffered (default 8KB chunks) for efficient I/O.
    HTTP/1.1 keep-alive is enabled by default.
    Recv/send timeouts are set on accepted sockets to prevent DoS.

    This type is ``Movable`` but not ``Copyable``.

    Example:
        ```mojo
        def handle(req: Request) raises -> Response:
            return Response(Status.OK, body="hello".as_bytes())

        var srv = HttpServer.bind(SocketAddr.localhost(8080))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener
    var config: ServerConfig

    def __init__(
        out self,
        var listener: TcpListener,
        var config: ServerConfig = ServerConfig(),
    ):
        self._listener = listener^
        self.config = config^

    def __del__(deinit self):
        self._listener.close()

    @staticmethod
    def bind(
        addr: SocketAddr, var config: ServerConfig = ServerConfig()
    ) raises -> HttpServer:
        """Bind an HTTP server on ``addr``.

        Args:
            addr:   Local address to listen on.
            config: Server configuration (optional).

        Returns:
            An ``HttpServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return HttpServer(listener^, config^)

    def serve(self, handler: def(Request) raises -> Response) raises:
        """Accept connections in a loop, calling ``handler`` for each request.

        Blocks indefinitely. Supports HTTP/1.1 keep-alive when configured.
        Sets recv/send timeouts on each accepted connection.

        Args:
            handler: Callback invoked once per parsed HTTP request.

        Raises:
            NetworkError: If the accept loop encounters a fatal error.
        """
        while True:
            var stream = self._listener.accept()
            _handle_connection_buffered(stream^, handler, self.config)

    def local_addr(self) -> SocketAddr:
        """Return the local address the server is bound to."""
        return self._listener.local_addr()

    def close(mut self):
        """Stop accepting new connections. Idempotent."""
        self._listener.close()


# ── Buffered connection handler ───────────────────────────────────────────────


def _handle_connection_buffered(
    var stream: TcpStream,
    handler: def(Request) raises -> Response,
    config: ServerConfig,
):
    """Handle an HTTP connection with buffered reads and keep-alive.

    Sets recv/send timeouts on the stream. Reads in chunks, scans for the
    header terminator, parses the request, calls the handler, writes the
    response. Loops for keep-alive connections. Respects HTTP/1.0
    close-by-default.
    """
    # Set timeouts on accepted socket for DoS resilience
    try:
        if config.idle_timeout_ms > 0:
            stream.set_recv_timeout(config.idle_timeout_ms)
        if config.write_timeout_ms > 0:
            stream.set_send_timeout(config.write_timeout_ms)
    except:
        pass

    var buf = List[UInt8](capacity=config.read_buffer_size)
    var request_count = 0

    while True:
        # 1. Read until \r\n\r\n (header end)
        var header_end = _read_until_header_end(stream, buf, config)
        if header_end < 0:
            break

        # 2. Quick-scan for Content-Length in the header section
        var content_length = _scan_content_length(buf, header_end)
        if content_length > config.max_body_size:
            _write_error_response(stream, 413, "Content Too Large", False)
            break

        # 3. Ensure we have the full body in the buffer
        var total_needed = header_end + content_length
        if not _read_until_size(stream, buf, total_needed, config):
            break

        # 4. Parse the request from the buffer
        var req: Request
        var should_close = False
        var is_http10 = False
        try:
            req = _parse_http_request_bytes(
                Span[UInt8, _](buf)[:total_needed],
                config.max_header_size,
                config.max_body_size,
                config.max_uri_length,
            )
            # Check Connection header and version before handler takes ownership
            var conn_header = _ascii_lower(req.headers.get("connection"))
            is_http10 = req.version == "HTTP/1.0"
            if conn_header == "close":
                should_close = True
            elif is_http10 and conn_header != "keep-alive":
                should_close = True
        except e:
            _write_error_response(stream, 400, "Bad Request", False)
            break

        # 5. Call handler
        var resp: Response
        try:
            resp = handler(req^)
        except e:
            _write_error_response(stream, 500, "Internal Server Error", False)
            break

        # 6. Determine keep-alive
        request_count += 1
        var keep_alive = (
            config.keep_alive
            and not should_close
            and request_count < config.max_keepalive_requests
        )

        # 7. Write response — catch only network errors
        try:
            _write_response_buffered(stream, resp, keep_alive)
        except e:
            break

        if not keep_alive:
            break

        # 8. Compact buffer: remove processed bytes, keep leftover
        if total_needed < len(buf):
            var leftover = List[UInt8](capacity=len(buf) - total_needed)
            for i in range(total_needed, len(buf)):
                leftover.append(buf[i])
            buf = leftover^
        else:
            buf.clear()

    stream.close()


# ── Buffer I/O helpers ────────────────────────────────────────────────────────


def _read_until_header_end(
    mut stream: TcpStream,
    mut buf: List[UInt8],
    config: ServerConfig,
) -> Int:
    """Read from stream into buf until \\r\\n\\r\\n is found.

    Returns the byte offset just past the \\r\\n\\r\\n (i.e. start of body),
    or -1 on EOF/error/timeout.
    """
    var header_end = _find_crlfcrlf(buf, 0)
    if header_end >= 0:
        return header_end

    var read_buf = List[UInt8](capacity=config.read_buffer_size)
    read_buf.resize(config.read_buffer_size, 0)

    while True:
        var n: Int
        try:
            n = stream.read(read_buf.unsafe_ptr(), config.read_buffer_size)
        except:
            return -1

        if n == 0:
            return -1

        var prev_len = len(buf)
        for i in range(n):
            buf.append(read_buf[i])

        if len(buf) > config.max_header_size + config.max_body_size:
            return -1

        var scan_from = prev_len - 3 if prev_len >= 3 else 0
        header_end = _find_crlfcrlf(buf, scan_from)
        if header_end >= 0:
            if header_end > config.max_header_size:
                return -1
            return header_end


def _read_until_size(
    mut stream: TcpStream,
    mut buf: List[UInt8],
    target: Int,
    config: ServerConfig,
) -> Bool:
    """Keep reading until buf has at least ``target`` bytes. Returns False on EOF/timeout.
    """
    if len(buf) >= target:
        return True

    var read_buf = List[UInt8](capacity=config.read_buffer_size)
    read_buf.resize(config.read_buffer_size, 0)

    while len(buf) < target:
        var n: Int
        try:
            n = stream.read(read_buf.unsafe_ptr(), config.read_buffer_size)
        except:
            return False
        if n == 0:
            return False
        for i in range(n):
            buf.append(read_buf[i])
    return True


@always_inline
def _find_crlfcrlf(data: List[UInt8], start: Int) -> Int:
    """Find \\r\\n\\r\\n in data starting at ``start``.

    Returns the byte offset just past the sequence (start of body),
    or -1 if not found.
    """
    var n = len(data)
    if n < 4:
        return -1
    var s = start if start >= 0 else 0
    for i in range(s, n - 3):
        if (
            data[i] == 13
            and data[i + 1] == 10
            and data[i + 2] == 13
            and data[i + 3] == 10
        ):
            return i + 4
    return -1


def _scan_content_length(data: List[UInt8], header_end: Int) -> Int:
    """Quick scan for Content-Length value in the header section.

    Searches for "content-length:" (case-insensitive) and parses the integer.
    Returns 0 if not found.
    """
    var needle = "content-length:"
    var needle_len = needle.byte_length()
    var needle_ptr = needle.unsafe_ptr()

    var i = 0
    while i < header_end - needle_len:
        var found = True
        for j in range(needle_len):
            var c = data[i + j]
            if c >= 65 and c <= 90:
                c = c + 32
            if c != needle_ptr[j]:
                found = False
                break
        if found:
            var pos = i + needle_len
            while pos < header_end and (data[pos] == 32 or data[pos] == 9):
                pos += 1
            var result = 0
            while pos < header_end and data[pos] >= 48 and data[pos] <= 57:
                result = result * 10 + Int(data[pos]) - 48
                pos += 1
            return result
        i += 1
    return 0


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


# ── Request parsing (from buffer) ────────────────────────────────────────────


def _parse_http_request_bytes(
    data: Span[UInt8, _],
    max_header_size: Int = 8_192,
    max_body_size: Int = 10 * 1024 * 1024,
    max_uri_length: Int = 8_192,
) raises -> Request:
    """Parse an HTTP/1.1 request from a byte buffer.

    Validates header names per RFC 7230 token rules and header values for
    illegal control characters. Parses HTTP version for keep-alive semantics.

    Args:
        data:            Raw HTTP/1.1 request bytes.
        max_header_size: Maximum bytes for all header lines combined.
        max_body_size:   Maximum bytes for the request body.
        max_uri_length:  Maximum bytes for the request URI.

    Returns:
        A parsed ``Request`` with version set from the request line.

    Raises:
        Error: On malformed request line, invalid tokens, or limit violations.
    """
    var pos = 0

    # 1. Request line: METHOD SP URI SP VERSION CRLF
    var req_line = _read_line_buf(data, pos)
    if req_line.byte_length() == 0:
        raise Error("empty request line")

    var sp1 = -1
    for i in range(req_line.byte_length()):
        if req_line.unsafe_ptr()[i] == 32:
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + req_line)
    var method = String(String(unsafe_from_utf8=req_line.as_bytes()[:sp1]))

    var sp2 = -1
    for i in range(sp1 + 1, req_line.byte_length()):
        if req_line.unsafe_ptr()[i] == 32:
            sp2 = i
            break
    var path: String
    var version: String
    if sp2 < 0:
        path = String(String(unsafe_from_utf8=req_line.as_bytes()[sp1 + 1 :]))
        version = "HTTP/1.1"
    else:
        path = String(
            String(unsafe_from_utf8=req_line.as_bytes()[sp1 + 1 : sp2])
        )
        version = String(
            String(unsafe_from_utf8=req_line.as_bytes()[sp2 + 1 :])
        )

    if path.byte_length() > max_uri_length:
        raise Error(
            "request URI exceeds limit of " + String(max_uri_length) + " bytes"
        )

    # 2. Headers with RFC 7230 token validation
    var headers = HeaderMap()
    var header_bytes = 0

    while True:
        var line = _read_line_buf(data, pos)
        header_bytes += line.byte_length()
        if header_bytes > max_header_size:
            raise Error(
                "request headers exceed limit of "
                + String(max_header_size)
                + " bytes"
            )
        if line.byte_length() == 0:
            break
        var colon = -1
        for i in range(line.byte_length()):
            if line.unsafe_ptr()[i] == 58:  # ':'
                colon = i
                break
        if colon >= 0:
            # Validate header name (token chars only)
            var name_valid = True
            for i in range(colon):
                if not _is_token_char(line.unsafe_ptr()[i]):
                    name_valid = False
                    break
            if not name_valid:
                raise Error("invalid character in header name")

            var k = String(
                String(String(unsafe_from_utf8=line.as_bytes()[:colon])).strip()
            )
            var v = String(
                String(
                    String(unsafe_from_utf8=line.as_bytes()[colon + 1 :])
                ).strip()
            )

            # Validate header value (no bare CR/LF/NUL)
            for i in range(v.byte_length()):
                var vc = v.unsafe_ptr()[i]
                if vc == 0 or vc == 10 or vc == 13:
                    raise Error("invalid control character in header value")
            headers.set(k, v)

    # 3. Body (Content-Length)
    var body = List[UInt8]()
    var cl_str = headers.get("Content-Length")
    if cl_str.byte_length() > 0:
        var content_length = _parse_int_str(cl_str)
        if content_length > max_body_size:
            raise Error(
                "request body exceeds limit of "
                + String(max_body_size)
                + " bytes"
            )
        if content_length > 0:
            var end = pos + content_length
            if end > len(data):
                end = len(data)
            for i in range(pos, end):
                body.append(data[i])

    var req = Request(method=method, url=path, body=body^, version=version)
    req.headers = headers^
    return req^


def _read_line_buf(data: Span[UInt8, _], mut pos: Int) -> String:
    """Read one CRLF/LF-terminated line from a byte span, advancing ``pos``.

    Replaces NUL and non-ASCII bytes with '?' since HTTP headers are ASCII
    per RFC 7230.
    """
    var line = String(capacity=256)
    while pos < len(data):
        var c = data[pos]
        pos += 1
        if c == 13:
            continue
        if c == 10:
            return line^
        if c == 0 or c >= 128:
            line += "?"
        else:
            line += chr(Int(c))
    return line^


def _parse_int_str(s: String) -> Int:
    """Parse a non-negative decimal integer string; returns 0 on failure."""
    var result = 0
    var trimmed = s.strip()
    for i in range(trimmed.byte_length()):
        var c = Int(trimmed.unsafe_ptr()[i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result


# ── Response helpers ──────────────────────────────────────────────────────────


def ok(body: String = "") -> Response:
    """Create a 200 OK response with optional text body.

    Args:
        body: Response body string. Empty by default.

    Returns:
        A ``Response`` with status 200. Sets ``Content-Type: text/plain``
        if body is non-empty.
    """
    var body_bytes = List[UInt8](capacity=body.byte_length())
    for b in body.as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, reason="OK", body=body_bytes^)
    if body.byte_length() > 0:
        try:
            resp.headers.set("Content-Type", "text/plain; charset=utf-8")
        except:
            pass
    return resp^


def ok_json(body: String) -> Response:
    """Create a 200 OK response with a JSON body.

    Args:
        body: JSON string to send.

    Returns:
        A ``Response`` with ``Content-Type: application/json``.
    """
    var body_bytes = List[UInt8](capacity=body.byte_length())
    for b in body.as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, reason="OK", body=body_bytes^)
    try:
        resp.headers.set("Content-Type", "application/json")
    except:
        pass
    return resp^


def bad_request(msg: String = "Bad Request") -> Response:
    """Create a 400 Bad Request response."""
    var body_bytes = List[UInt8](capacity=msg.byte_length())
    for b in msg.as_bytes():
        body_bytes.append(b)
    var resp = Response(
        status=Status.BAD_REQUEST, reason="Bad Request", body=body_bytes^
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def not_found(path: String = "") -> Response:
    """Create a 404 Not Found response."""
    var msg = "Not Found"
    if path.byte_length() > 0:
        msg = "Not Found: " + path
    var body_bytes = List[UInt8](capacity=msg.byte_length())
    for b in msg.as_bytes():
        body_bytes.append(b)
    var resp = Response(
        status=Status.NOT_FOUND, reason="Not Found", body=body_bytes^
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def internal_error(msg: String = "Internal Server Error") -> Response:
    """Create a 500 Internal Server Error response."""
    var body_bytes = List[UInt8](capacity=msg.byte_length())
    for b in msg.as_bytes():
        body_bytes.append(b)
    var resp = Response(
        status=Status.INTERNAL_SERVER_ERROR,
        reason="Internal Server Error",
        body=body_bytes^,
    )
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    return resp^


def redirect(url: String, status: Int = 302) -> Response:
    """Create a redirect response (302 Found by default).

    Args:
        url:    Target URL for the ``Location`` header.
        status: HTTP status code (301, 302, 307, 308). Default 302.

    Returns:
        A ``Response`` with the ``Location`` header set.
    """
    var resp = Response(status=status, reason=_status_reason(status))
    try:
        resp.headers.set("Location", url)
    except:
        pass
    return resp^


# ── Response writing ──────────────────────────────────────────────────────────


def _write_response_buffered(
    mut stream: TcpStream, resp: Response, keep_alive: Bool
) raises:
    """Serialise ``resp`` into a single buffer and write it in one call.

    Args:
        stream:     Open ``TcpStream`` for the client connection.
        resp:       The response to send.
        keep_alive: If True, sends ``Connection: keep-alive``; otherwise ``close``.

    Raises:
        NetworkError: On I/O failure.
    """
    var reason = resp.reason
    if reason.byte_length() == 0:
        reason = _status_reason(resp.status)

    var body_len = len(resp.body)

    var estimated = 64 + body_len
    for i in range(resp.headers.len()):
        estimated += (
            resp.headers._keys[i].byte_length()
            + resp.headers._values[i].byte_length()
            + 4
        )
    var wire = List[UInt8](capacity=estimated)

    _append_str(wire, "HTTP/1.1 ")
    _append_str(wire, String(resp.status))
    _append_str(wire, " ")
    _append_str(wire, reason)
    _append_str(wire, "\r\n")

    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        var kl = _ascii_lower(k)
        if kl == "content-length" or kl == "connection":
            continue
        _append_str(wire, k)
        _append_str(wire, ": ")
        _append_str(wire, resp.headers._values[i])
        _append_str(wire, "\r\n")

    _append_str(wire, "Content-Length: ")
    _append_str(wire, String(body_len))
    _append_str(wire, "\r\n")

    if keep_alive:
        _append_str(wire, "Connection: keep-alive\r\n")
    else:
        _append_str(wire, "Connection: close\r\n")

    _append_str(wire, "\r\n")

    for i in range(body_len):
        wire.append(resp.body[i])

    stream.write_all(Span[UInt8, _](wire))


def _write_error_response(
    mut stream: TcpStream, status: Int, reason: String, keep_alive: Bool
):
    """Send a minimal error response, ignoring write failures."""
    var body_str = String(status) + " " + reason
    var body = List[UInt8](capacity=body_str.byte_length())
    for b in body_str.as_bytes():
        body.append(b)
    var resp = Response(status=status, reason=reason, body=body^)
    try:
        resp.headers.set("Content-Type", "text/plain")
    except:
        pass
    try:
        _write_response_buffered(stream, resp, keep_alive)
    except:
        pass


@always_inline
def _append_str(mut buf: List[UInt8], s: String):
    """Append all bytes of ``s`` to ``buf``."""
    var ptr = s.unsafe_ptr()
    for i in range(s.byte_length()):
        buf.append(ptr[i])


@always_inline
def _ascii_lower(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=s.byte_length())
    for i in range(s.byte_length()):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out


def _status_reason(code: Int) -> String:
    """Return the canonical reason phrase for a known HTTP status code."""
    if code == 200:
        return "OK"
    if code == 201:
        return "Created"
    if code == 202:
        return "Accepted"
    if code == 204:
        return "No Content"
    if code == 301:
        return "Moved Permanently"
    if code == 302:
        return "Found"
    if code == 304:
        return "Not Modified"
    if code == 307:
        return "Temporary Redirect"
    if code == 308:
        return "Permanent Redirect"
    if code == 400:
        return "Bad Request"
    if code == 401:
        return "Unauthorized"
    if code == 403:
        return "Forbidden"
    if code == 404:
        return "Not Found"
    if code == 405:
        return "Method Not Allowed"
    if code == 408:
        return "Request Timeout"
    if code == 409:
        return "Conflict"
    if code == 413:
        return "Content Too Large"
    if code == 414:
        return "URI Too Long"
    if code == 422:
        return "Unprocessable Entity"
    if code == 500:
        return "Internal Server Error"
    if code == 501:
        return "Not Implemented"
    if code == 502:
        return "Bad Gateway"
    if code == 503:
        return "Service Unavailable"
    if code == 504:
        return "Gateway Timeout"
    return "Unknown"


# ── Legacy compatibility aliases ──────────────────────────────────────────────


def _parse_http_request(
    mut stream: TcpStream,
    max_header_size: Int,
    max_body_size: Int,
) raises -> Request:
    """Parse an HTTP/1.1 request from a TCP stream using buffered reads.

    Kept for backward compatibility with existing test code.
    """
    var buf = List[UInt8](capacity=8192)
    var read_buf = List[UInt8](capacity=8192)
    read_buf.resize(8192, 0)

    while True:
        var n = stream.read(read_buf.unsafe_ptr(), 8192)
        if n == 0:
            raise Error("empty request: connection closed")
        for i in range(n):
            buf.append(read_buf[i])
        var hdr_end = _find_crlfcrlf(buf, 0)
        if hdr_end >= 0:
            var cl = _scan_content_length(buf, hdr_end)
            var total = hdr_end + cl
            while len(buf) < total:
                n = stream.read(read_buf.unsafe_ptr(), 8192)
                if n == 0:
                    break
                for i in range(n):
                    buf.append(read_buf[i])
            return _parse_http_request_bytes(
                Span[UInt8, _](buf)[:total], max_header_size, max_body_size
            )
        if len(buf) > max_header_size + max_body_size:
            raise Error("request too large")


def _write_response(mut stream: TcpStream, resp: Response) raises:
    """Legacy response writer. Delegates to buffered version with Connection: close.
    """
    _write_response_buffered(stream, resp, keep_alive=False)
