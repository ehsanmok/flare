"""HTTP/1.1 server with per-connection handler callbacks."""

from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from ..net import SocketAddr, NetworkError
from ..tcp import TcpListener, TcpStream


struct HttpServer(Movable):
    """A blocking HTTP/1.1 server that calls a handler for each request.

    Each accepted connection is handled in the calling thread (v0.1.0).
    Async and thread-pool models are planned for v0.2.0.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _listener:        The bound TCP listener.
        _max_header_size: Maximum bytes for all request headers combined.
        _max_body_size:   Maximum bytes for the request body.

    Example:
        ```mojo
        fn handle(req: Request) raises -> Response:
            return Response(Status.OK, body="hello".as_bytes())

        var srv = HttpServer.bind(SocketAddr.localhost(8080))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener
    var _max_header_size: Int
    var _max_body_size: Int

    fn __init__(
        out self,
        var listener: TcpListener,
        max_header_size: Int = 8_192,
        max_body_size: Int = 10 * 1024 * 1024,
    ):
        self._listener = listener^
        self._max_header_size = max_header_size
        self._max_body_size = max_body_size

    fn __moveinit__(out self, deinit take: HttpServer):
        self._listener = take._listener^
        self._max_header_size = take._max_header_size
        self._max_body_size = take._max_body_size

    fn __del__(deinit self):
        self._listener.close()

    @staticmethod
    fn bind(addr: SocketAddr) raises -> HttpServer:
        """Bind an HTTP server on ``addr``.

        Args:
            addr: Local address to listen on.

        Returns:
            An ``HttpServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return HttpServer(listener^)

    fn serve(self, handler: fn(Request) raises -> Response) raises:
        """Accept connections in a loop, calling ``handler`` for each request.

        Blocks indefinitely. Call ``close()`` from another thread (or
        SIGTERM) to break the accept loop.

        On request parse errors, responds with ``400 Bad Request``.
        On unhandled exceptions from ``handler``, responds with
        ``500 Internal Server Error``.

        Args:
            handler: Callback invoked once per parsed HTTP request.

        Raises:
            NetworkError: If the accept loop encounters a fatal error.
        """
        while True:
            var stream = self._listener.accept()
            _handle_connection(
                stream^, handler, self._max_header_size, self._max_body_size
            )

    fn local_addr(self) -> SocketAddr:
        """Return the local address the server is bound to.

        Returns:
            The bound ``SocketAddr``.
        """
        return self._listener.local_addr()

    fn close(mut self):
        """Stop accepting new connections. Idempotent."""
        self._listener.close()


# ── Connection handler ────────────────────────────────────────────────────────


fn _handle_connection(
    var stream: TcpStream,
    handler: fn(Request) raises -> Response,
    max_header_size: Int,
    max_body_size: Int,
):
    """Parse one HTTP request, call handler, write response.

    Errors in parsing produce a 400 response; errors in the handler
    produce a 500 response. I/O errors are silently swallowed (the client
    closed the connection).
    """
    try:
        var req = _parse_http_request(stream, max_header_size, max_body_size)
        try:
            var resp = handler(req^)
            _write_response(stream, resp)
        except e:
            var resp500 = Response(
                Status.INTERNAL_SERVER_ERROR,
                reason="Internal Server Error",
                body=String(
                    "500 Internal Server Error: " + String(e)
                ).as_bytes(),
            )
            resp500.headers.set("Content-Type", "text/plain")
            try:
                _write_response(stream, resp500)
            except:
                pass
    except e:
        var resp400 = Response(
            Status.BAD_REQUEST,
            reason="Bad Request",
            body=String("400 Bad Request: " + String(e)).as_bytes(),
        )
        resp400.headers.set("Content-Type", "text/plain")
        try:
            _write_response(stream, resp400)
        except:
            pass
    stream.close()


# ── Request parsing ───────────────────────────────────────────────────────────


fn _read_tcp_line(mut stream: TcpStream) raises -> String:
    """Read one CRLF-terminated line from ``stream``.

    Reads one byte at a time until ``\\r\\n`` or ``\\n`` is found.
    Returns the line without the line terminator.

    Args:
        stream: Open ``TcpStream``.

    Returns:
        The line content.

    Raises:
        NetworkError: On I/O error or unexpected EOF.
    """
    var line = String(capacity=256)
    var buf = List[UInt8](capacity=1)
    buf.append(UInt8(0))
    while True:
        var n = stream.read(buf.unsafe_ptr(), 1)
        if n == 0:
            return line^
        var c = buf[0]
        if c == 13:  # CR — skip; LF follows
            continue
        if c == 10:  # LF — end of line
            return line^
        line += chr(Int(c))


fn _parse_int_str(s: String) -> Int:
    """Parse a non-negative decimal integer string; returns 0 on failure."""
    var result = 0
    var trimmed = s.strip()
    for i in range(len(trimmed)):
        var c = Int(trimmed.unsafe_ptr()[i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result


fn _read_line_buf(data: Span[UInt8], mut pos: Int) -> String:
    """Read one CRLF/LF-terminated line from a byte span, advancing ``pos``.

    Args:
        data: Input byte span.
        pos:  Current read position, updated in place.

    Returns:
        Line content without the terminator. Empty string on EOF.
    """
    var line = String(capacity=256)
    while pos < len(data):
        var c = data[pos]
        pos += 1
        if c == 13:  # CR — skip
            continue
        if c == 10:  # LF — end of line
            return line^
        line += chr(Int(c))
    return line^


fn _parse_http_request_bytes(
    data: Span[UInt8],
    max_header_size: Int = 8_192,
    max_body_size: Int = 10 * 1024 * 1024,
) raises -> Request:
    """Parse an HTTP/1.1 request from a byte buffer (for testing/fuzzing).

    Identical logic to ``_parse_http_request`` but reads from a
    ``Span[UInt8]`` instead of a ``TcpStream``.  Suitable for fuzz
    harnesses and unit tests that operate on raw bytes.

    Args:
        data:            Raw HTTP/1.1 request bytes.
        max_header_size: Maximum bytes for all header lines combined.
        max_body_size:   Maximum bytes for the request body.

    Returns:
        A parsed ``Request``.

    Raises:
        Error: On malformed request line or limit violations.
    """
    var pos = 0

    # ── 1. Request line ───────────────────────────────────────────────────────
    var req_line = _read_line_buf(data, pos)
    if len(req_line) == 0:
        raise Error("empty request line")

    var sp1 = -1
    for i in range(len(req_line)):
        if req_line.unsafe_ptr()[i] == 32:
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + req_line)
    var method = String(req_line[:sp1])

    var sp2 = -1
    for i in range(sp1 + 1, len(req_line)):
        if req_line.unsafe_ptr()[i] == 32:
            sp2 = i
            break
    var path: String
    if sp2 < 0:
        path = String(req_line[sp1 + 1 :])
    else:
        path = String(req_line[sp1 + 1 : sp2])

    # ── 2. Headers ────────────────────────────────────────────────────────────
    var headers = HeaderMap()
    var header_bytes = 0

    while True:
        var line = _read_line_buf(data, pos)
        header_bytes += len(line)
        if header_bytes > max_header_size:
            raise Error(
                "request headers exceed limit of "
                + String(max_header_size)
                + " bytes"
            )
        if len(line) == 0:
            break
        var colon = -1
        for i in range(len(line)):
            if line.unsafe_ptr()[i] == 58:  # ':'
                colon = i
                break
        if colon >= 0:
            var k = String(String(line[:colon]).strip())
            var v = String(String(line[colon + 1 :]).strip())
            headers.set(k, v)

    # ── 3. Body (Content-Length only for v0.1.0) ──────────────────────────────
    var body = List[UInt8]()
    var cl_str = headers.get("Content-Length")
    if len(cl_str) > 0:
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

    var req = Request(method=method, url=path, body=body^)
    req.headers = headers^
    return req^


fn _parse_http_request(
    mut stream: TcpStream,
    max_header_size: Int,
    max_body_size: Int,
) raises -> Request:
    """Parse an HTTP/1.1 request from a TCP stream.

    Reads the request line, headers, and optional body.
    Enforces ``max_header_size`` and ``max_body_size`` limits.

    Args:
        stream:          Open ``TcpStream`` from an accepted connection.
        max_header_size: Maximum total bytes for all header lines.
        max_body_size:   Maximum bytes for the request body.

    Returns:
        A parsed ``Request``.

    Raises:
        NetworkError: On I/O failure.
        Error:        On malformed request line or limit violations.
    """
    # ── 1. Request line ───────────────────────────────────────────────────────
    var req_line = _read_tcp_line(stream)
    if len(req_line) == 0:
        raise Error("empty request line")

    # Split on spaces: "METHOD PATH HTTP/1.1"
    var method = String(capacity=8)
    var path = String(capacity=256)
    var sp1 = -1
    for i in range(len(req_line)):
        if req_line.unsafe_ptr()[i] == 32:  # space
            sp1 = i
            break
    if sp1 < 0:
        raise Error("malformed request line: " + req_line)
    method = String(req_line[:sp1])

    var sp2 = -1
    for i in range(sp1 + 1, len(req_line)):
        if req_line.unsafe_ptr()[i] == 32:
            sp2 = i
            break
    if sp2 < 0:
        path = String(req_line[sp1 + 1 :])
    else:
        path = String(req_line[sp1 + 1 : sp2])

    # ── 2. Headers ────────────────────────────────────────────────────────────
    var headers = HeaderMap()
    var header_bytes = 0

    while True:
        var line = _read_tcp_line(stream)
        header_bytes += len(line)
        if header_bytes > max_header_size:
            raise Error(
                "request headers exceed limit of "
                + String(max_header_size)
                + " bytes"
            )
        if len(line) == 0:
            break
        var colon = -1
        for i in range(len(line)):
            if line.unsafe_ptr()[i] == 58:  # ':'
                colon = i
                break
        if colon >= 0:
            var k = String(String(line[:colon]).strip())
            var v = String(String(line[colon + 1 :]).strip())
            headers.set(k, v)

    # ── 3. Body (Content-Length only for v0.1.0) ──────────────────────────────
    var body = List[UInt8]()
    var cl_str = headers.get("Content-Length")
    if len(cl_str) > 0:
        var content_length = _parse_int_str(cl_str)
        if content_length > max_body_size:
            raise Error(
                "request body exceeds limit of "
                + String(max_body_size)
                + " bytes"
            )
        if content_length > 0:
            body.resize(content_length, 0)
            stream.read_exact(body.unsafe_ptr(), content_length)

    var req = Request(method=method, url=path, body=body^)
    req.headers = headers^
    return req^


# ── Response writing ──────────────────────────────────────────────────────────


fn _status_reason(code: Int) -> String:
    """Return the canonical reason phrase for a known HTTP status code.

    Args:
        code: HTTP status code integer.

    Returns:
        Reason phrase string, or ``"Unknown"`` for unrecognised codes.
    """
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


fn _write_response(mut stream: TcpStream, resp: Response) raises:
    """Serialise ``resp`` and write it to ``stream``.

    Adds ``Content-Length`` and ``Connection: close`` if not already set.

    Args:
        stream: Open ``TcpStream`` for the client connection.
        resp:   The response to send.

    Raises:
        NetworkError: On I/O failure.
    """
    var reason = resp.reason
    if len(reason) == 0:
        reason = _status_reason(resp.status)

    var wire = "HTTP/1.1 " + String(resp.status) + " " + reason + "\r\n"

    # Send all caller headers except Content-Length and Connection
    # (we always set those ourselves below)
    for i in range(resp.headers.len()):
        var k = resp.headers._keys[i]
        var kl = String(capacity=len(k))
        for j in range(len(k)):
            var c = k.unsafe_ptr()[j]
            if c >= 65 and c <= 90:
                kl += chr(Int(c) + 32)
            else:
                kl += chr(Int(c))
        if kl == "content-length" or kl == "connection":
            continue
        wire += k + ": " + resp.headers._values[i] + "\r\n"

    wire += "Content-Length: " + String(len(resp.body)) + "\r\n"
    wire += "Connection: close\r\n"
    wire += "\r\n"

    var wire_bytes = wire.as_bytes()
    stream.write_all(Span[UInt8](wire_bytes))
    if len(resp.body) > 0:
        stream.write_all(Span[UInt8](resp.body))
