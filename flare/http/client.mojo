"""HTTP/1.1 client with optional TLS support.

Implements a minimal but correct subset of HTTP/1.1 (RFC 7230/7231):
- ``Content-Length``-delimited responses
- ``Transfer-Encoding: chunked`` responses
- ``Connection: close`` (read until EOF) responses
- Up to ``_max_redirects`` automatic 3xx redirects
- Automatic ``Host``, ``User-Agent``, ``Connection`` headers
- Optional ``Authorization`` header via the ``Auth`` trait

Module-level convenience functions (``get``, ``post``, ``put``,
``delete``, ``head``) create a one-shot ``HttpClient`` per call and are
suitable for quick scripts.  For multiple requests, prefer instantiating
a shared ``HttpClient``.

``post`` and ``put`` accept a ``String`` body (sets
``Content-Type: application/json`` automatically), a ``mojson.Value``
body (serialised with ``dumps`` first), or a ``List[UInt8]`` body (sent
as raw bytes with no implicit ``Content-Type``).

Example:
    ```mojo
    from flare.http import get, post, HttpClient, BasicAuth, BearerAuth, Status

    # One-shot GET
    var resp = get("https://httpbin.org/get")

    # One-shot POST JSON — String body sets Content-Type automatically
    var r2 = post("https://httpbin.org/post", '{"k": 1}')

    # Session with base URL and authentication
    with HttpClient("https://httpbin.org", BasicAuth("alice", "s3cr3t")) as c:
        var r = c.get("/basic-auth/alice/s3cr3t")
        r.raise_for_status()
        print(r.text())
    ```
"""

from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from .url import Url
from .auth import Auth, BasicAuth, BearerAuth
from .error import HttpError, TooManyRedirects
from ..tcp import TcpStream
from ..tls import TlsStream, TlsConfig
from ..net import NetworkError
from mojson import dumps, Value as JsonValue


struct HttpClient(Movable):
    """A blocking HTTP/1.1 client.

    Establishes one TCP or TLS connection per request (connection pooling
    is a future feature). Respects HTTP redirects up to ``max_redirects``.

    This type is ``Movable`` but not ``Copyable``.  It supports the context
    manager protocol (``__enter__``) for use with ``with``.

    Constructors follow a natural ergonomic order:

    - ``HttpClient()`` — defaults only
    - ``HttpClient("https://api.example.com")`` — base URL positional
    - ``HttpClient(BearerAuth("token"))`` — auth first
    - ``HttpClient("https://api.example.com", BearerAuth("token"))`` — base URL + auth

    Example:
        ```mojo
        # Simple one-liner
        var resp = HttpClient().get("https://httpbin.org/get")

        # Session with base URL and auth — no repeated prefixes
        with HttpClient("https://api.example.com", BearerAuth("tok")) as c:
            c.post("/items", '{"name": "flare"}').raise_for_status()
            var items = c.get("/items").json()
        ```
    """

    var _config: TlsConfig
    var _max_redirects: Int
    var _timeout_ms: Int
    var _user_agent: String
    var _base_url: String
    var _auth_header: String  # "" = no auth; "Basic ..." or "Bearer ..."

    fn __init__(
        out self,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
    ):
        """Initialise an ``HttpClient`` with secure defaults.

        Args:
            base_url:      Optional base URL prepended to relative paths.
            max_redirects: Maximum number of redirects to follow (default 10).
            timeout_ms:    Connect + read timeout in milliseconds (default 30 s).
            user_agent:    Value for the ``User-Agent`` header.
        """
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        self._auth_header = ""

    fn __init__(
        out self,
        tls: TlsConfig,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
    ):
        """Initialise an ``HttpClient`` with custom TLS configuration.

        Args:
            tls:           TLS configuration (e.g. ``TlsConfig.insecure()``).
            base_url:      Optional base URL prepended to relative paths.
            max_redirects: Maximum number of redirects to follow.
            timeout_ms:    Connect + read timeout in milliseconds.
            user_agent:    Value for the ``User-Agent`` header.
        """
        self._config = tls.copy()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        self._auth_header = ""

    fn __init__[
        A: Auth
    ](
        out self,
        auth: A,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
    ) raises:
        """Initialise an ``HttpClient`` with authentication.

        The ``auth`` strategy is applied once at construction time — the
        resulting ``Authorization`` header is stored and re-sent with every
        request.

        Parameters:
            A: Any type implementing the ``Auth`` trait.

        Args:
            auth:          Authentication strategy (e.g. ``BasicAuth``,
                           ``BearerAuth``).
            base_url:      Optional base URL prepended to relative paths.
            max_redirects: Maximum number of redirects to follow.
            timeout_ms:    Connect + read timeout in milliseconds.
            user_agent:    Value for the ``User-Agent`` header.

        Raises:
            HeaderInjectionError: If the generated auth header contains
                CRLF characters.
        """
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        var auth_headers = HeaderMap()
        auth.apply(auth_headers)
        self._auth_header = auth_headers.get("Authorization")

    fn __init__[
        A: Auth
    ](
        out self,
        base_url: String,
        auth: A,
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
    ) raises:
        """Initialise an ``HttpClient`` with a base URL and authentication.

        Allows the most natural call-site syntax::

            with HttpClient("https://api.example.com", BearerAuth("tok")) as c:
                c.get("/users").raise_for_status()

        Parameters:
            A: Any type implementing the ``Auth`` trait.

        Args:
            base_url:      Base URL prepended to all relative request paths.
            auth:          Authentication strategy (e.g. ``BasicAuth``,
                           ``BearerAuth``).
            max_redirects: Maximum number of redirects to follow.
            timeout_ms:    Connect + read timeout in milliseconds.
            user_agent:    Value for the ``User-Agent`` header.

        Raises:
            HeaderInjectionError: If the generated auth header contains
                CRLF characters.
        """
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        var auth_headers = HeaderMap()
        auth.apply(auth_headers)
        self._auth_header = auth_headers.get("Authorization")

    fn __moveinit__(out self, deinit take: HttpClient):
        self._config = take._config^
        self._max_redirects = take._max_redirects
        self._timeout_ms = take._timeout_ms
        self._user_agent = take._user_agent^
        self._base_url = take._base_url^
        self._auth_header = take._auth_header^

    # ── Context manager ───────────────────────────────────────────────────────

    fn __enter__(var self) -> HttpClient:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``HttpClient`` (moved).
        """
        return self^

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn default() -> HttpClient:
        """Return a client with secure defaults (TLS verification enabled).

        Returns:
            An ``HttpClient`` with 30-second timeout and TLS verification.
        """
        return HttpClient()

    # ── URL resolution ────────────────────────────────────────────────────────

    fn _resolve_url(self, url: String) -> String:
        """Prepend ``_base_url`` if ``url`` is a relative path.

        Args:
            url: The URL or path to resolve.

        Returns:
            Absolute URL string.
        """
        if len(self._base_url) == 0:
            return url
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return self._base_url + url

    # ── High-level helpers ────────────────────────────────────────────────────

    fn get(self, url: String) raises -> Response:
        """Perform a GET request.

        Args:
            url: The URL to request (``http://``, ``https://``, or relative
                 path when ``base_url`` is set).

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:    On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.GET, url=self._resolve_url(url))
        return self.send(req)

    fn post(self, url: String, body: String) raises -> Response:
        """Perform a POST request with a JSON string body.

        Sets ``Content-Type: application/json`` automatically.  This is the
        default for string bodies because virtually every HTTP API that accepts
        a string payload expects JSON.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: The JSON request body as a ``String``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.

        Example:
            ```mojo
            var resp = client.post("https://httpbin.org/post", '{"key": "value"}')
            resp.raise_for_status()
            ```
        """
        var body_bytes = List[UInt8](body.as_bytes())
        var req = Request(
            method=Method.POST, url=self._resolve_url(url), body=body_bytes^
        )
        req.headers.set("Content-Type", "application/json")
        return self.send(req)

    fn post(self, url: String, body: JsonValue) raises -> Response:
        """Perform a POST request with a ``mojson.Value`` body.

        Serialises ``body`` to JSON with ``dumps`` and sets
        ``Content-Type: application/json`` automatically.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: A ``mojson.Value`` to serialise and send.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        return self.post(url, dumps(body))

    fn post(self, url: String, body: List[UInt8]) raises -> Response:
        """Perform a POST request with a raw byte body.

        No ``Content-Type`` header is set automatically; the caller is
        responsible for setting it via a custom ``Request`` if required.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: The raw request body bytes.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(
            method=Method.POST, url=self._resolve_url(url), body=body
        )
        return self.send(req)

    fn put(self, url: String, body: String) raises -> Response:
        """Perform a PUT request with a JSON string body.

        Sets ``Content-Type: application/json`` automatically.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: The JSON request body as a ``String``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var body_bytes = List[UInt8](body.as_bytes())
        var req = Request(
            method=Method.PUT, url=self._resolve_url(url), body=body_bytes^
        )
        req.headers.set("Content-Type", "application/json")
        return self.send(req)

    fn put(self, url: String, body: JsonValue) raises -> Response:
        """Perform a PUT request with a ``mojson.Value`` body.

        Serialises ``body`` to JSON with ``dumps`` and sets
        ``Content-Type: application/json`` automatically.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: A ``mojson.Value`` to serialise and send.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        return self.put(url, dumps(body))

    fn put(self, url: String, body: List[UInt8]) raises -> Response:
        """Perform a PUT request with a raw byte body.

        No ``Content-Type`` header is set automatically.

        Args:
            url:  The target URL (absolute or relative to ``base_url``).
            body: The raw request body bytes.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:     On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(
            method=Method.PUT, url=self._resolve_url(url), body=body
        )
        return self.send(req)

    fn delete(self, url: String) raises -> Response:
        """Perform a DELETE request.

        Args:
            url: The target URL.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError:    On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.DELETE, url=self._resolve_url(url))
        return self.send(req)

    fn head(self, url: String) raises -> Response:
        """Perform a HEAD request.

        Identical to ``GET`` but the server MUST NOT include a message body
        in the response (RFC 7231 §4.3.2).

        Args:
            url: The target URL.

        Returns:
            The server's ``Response`` (empty body).

        Raises:
            NetworkError:    On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.HEAD, url=self._resolve_url(url))
        return self.send(req)

    # ── Core ──────────────────────────────────────────────────────────────────

    fn send(self, req: Request) raises -> Response:
        """Send an HTTP/1.1 request and return the response.

        Handles redirect chains up to ``_max_redirects``.

        Args:
            req: The request to send.

        Returns:
            The final (possibly redirected) ``Response``.

        Raises:
            NetworkError:    On I/O failure.
            TooManyRedirects: If more than ``_max_redirects`` redirects occur.
        """
        var current_url = req.url
        var redirects = 0
        var method = req.method
        var body = req.body.copy()

        while True:
            var resp = self._do_request(method, current_url, req.headers, body)

            if resp.is_redirect() and redirects < self._max_redirects:
                var location = resp.headers.get("Location")
                if len(location) == 0:
                    return resp^  # redirect without Location: just return
                # Handle relative redirects
                if location.startswith("http://") or location.startswith(
                    "https://"
                ):
                    current_url = location
                else:
                    # Prepend origin from current URL
                    var parsed = Url.parse(current_url)
                    current_url = (
                        parsed.scheme
                        + "://"
                        + parsed.host
                        + ":"
                        + String(Int(parsed.port))
                        + location
                    )
                # POST redirect → GET (standard 301/302/303 behaviour)
                if (
                    resp.status == 301
                    or resp.status == 302
                    or resp.status == 303
                ):
                    method = Method.GET
                    body = List[UInt8]()
                redirects += 1
                continue

            if resp.is_redirect():
                raise TooManyRedirects(current_url, redirects)

            return resp^

    fn _do_request(
        self,
        method: String,
        url: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
    ) raises -> Response:
        """Perform a single HTTP/1.1 request (no redirect handling).

        Args:
            method:        HTTP method string.
            url:           Full URL string.
            extra_headers: Headers from the original request.
            body:          Request body bytes.

        Returns:
            Parsed ``Response``.

        Raises:
            NetworkError: On I/O or parse failure.
        """
        var u = Url.parse(url)

        # ── Build wire request ─────────────────────────────────────────────
        var wire = method + " " + u.request_target() + " HTTP/1.1\r\n"
        # Host header (RFC 7230 §5.4 — required)
        var host_header = u.host
        if (u.scheme == "http" and u.port != 80) or (
            u.scheme == "https" and u.port != 443
        ):
            host_header = host_header + ":" + String(Int(u.port))
        wire += "Host: " + host_header + "\r\n"
        wire += "User-Agent: " + self._user_agent + "\r\n"
        wire += "Connection: close\r\n"
        wire += "Accept: */*\r\n"

        # Authorization header from stored auth credential
        if len(self._auth_header) > 0:
            wire += "Authorization: " + self._auth_header + "\r\n"

        # Forward caller-supplied headers (skip Host — already set)
        for i in range(extra_headers.len()):
            var k = extra_headers._keys[i]
            if k.lower() != "host" and k.lower() != "authorization":
                wire += k + ": " + extra_headers._values[i] + "\r\n"

        if len(body) > 0:
            wire += "Content-Length: " + String(len(body)) + "\r\n"

        wire += "\r\n"  # end of headers

        # ── Connect and send ───────────────────────────────────────────────
        if u.is_tls():
            var stream = TlsStream.connect(u.host, u.port, self._config)
            var wire_bytes = wire.as_bytes()
            stream.write_all(Span[UInt8](wire_bytes))
            if len(body) > 0:
                stream.write_all(Span[UInt8](body))
            var resp = _read_http_response_tls(stream)
            stream.close()
            return resp^
        else:
            from ..net import SocketAddr
            from ..dns import resolve_v4

            var addrs = resolve_v4(u.host)
            if len(addrs) == 0:
                raise NetworkError("DNS resolution failed for: " + u.host)
            var stream = TcpStream.connect(SocketAddr(addrs[0], u.port))
            var wire_bytes = wire.as_bytes()
            stream.write_all(Span[UInt8](wire_bytes))
            if len(body) > 0:
                stream.write_all(Span[UInt8](body))
            var resp = _read_http_response_tcp(stream)
            stream.close()
            return resp^


# ── HTTP response parser helpers ──────────────────────────────────────────────

comptime _READ_BUF_SIZE: Int = 16384  # 16 KiB per read chunk


fn _read_all_tls(mut stream: TlsStream) raises -> List[UInt8]:
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


fn _read_all_tcp(mut stream: TcpStream) raises -> List[UInt8]:
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


fn _parse_http_response(raw: List[UInt8]) raises -> Response:
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
        if len(line) == 0:
            continue
        var colon = _str_find(line, ":")
        if colon < 0:
            continue
        var k = String(String(line[:colon]).strip())
        var v = String(String(line[colon + 1 :]).strip())
        headers.append(k, v)

    # Extract body (everything after \r\n\r\n)
    var body_start = header_end + 4
    var body = _extract_body(raw, body_start, headers)

    var resp = Response(status=status_code, reason=reason^)
    resp.headers = headers^
    resp.body = body^
    return resp^


fn _find_crlf2(data: List[UInt8]) -> Int:
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


fn _bytes_to_str(data: List[UInt8]) -> String:
    """Convert a byte list to a String (best-effort UTF-8)."""
    var s = String(capacity=len(data) + 1)
    for b in data:
        s += chr(Int(b))
    return s^


fn _split_lines(s: String) -> List[String]:
    """Split ``s`` by ``\\r\\n`` or ``\\n``."""
    var lines = List[String]()
    var start = 0
    var i = 0
    var n = len(s)
    while i < n:
        if (
            s.unsafe_ptr()[i] == 13
            and i + 1 < n
            and s.unsafe_ptr()[i + 1] == 10
        ):
            lines.append(String(s[start:i]))
            start = i + 2
            i += 2
        elif s.unsafe_ptr()[i] == 10:
            lines.append(String(s[start:i]))
            start = i + 1
            i += 1
        else:
            i += 1
    if start < n:
        lines.append(String(s[start:n]))
    return lines^


struct _StatusLine:
    var code: Int
    var reason: String

    fn __init__(out self, code: Int, reason: String):
        self.code = code
        self.reason = reason

    fn __moveinit__(out self, deinit take: _StatusLine):
        self.code = take.code
        self.reason = take.reason^


fn _parse_status_line(line: String) raises -> _StatusLine:
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
    var rest = String(String(line[sp1 + 1 :]).lstrip())
    if len(rest) < 3:
        raise NetworkError("HTTP status code too short: " + line)
    # Parse 3-digit code
    var code = 0
    for i in range(3):
        var c = Int(rest.unsafe_ptr()[i])
        if c < 48 or c > 57:
            raise NetworkError("non-numeric HTTP status code in: " + line)
        code = code * 10 + (c - 48)
    var reason = String("")
    if len(rest) > 4:
        reason = String(rest[4:])
    return _StatusLine(code, reason^)


fn _str_find(s: String, sub: String) -> Int:
    """Return the index of the first ``sub`` in ``s``, or -1."""
    var n = len(s)
    var m = len(sub)
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


fn _lower_str(s: String) -> String:
    """Return ASCII-lowercase copy of ``s``."""
    var out = String(capacity=len(s))
    for i in range(len(s)):
        var c = s.unsafe_ptr()[i]
        if c >= 65 and c <= 90:
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


fn _extract_body(
    raw: List[UInt8], body_start: Int, headers: HeaderMap
) raises -> List[UInt8]:
    """Extract the response body from the raw byte buffer.

    Handles:
    - ``Transfer-Encoding: chunked``
    - ``Content-Length: N``
    - Connection-close (remainder of buffer)

    Args:
        raw:        Full raw response bytes.
        body_start: Byte offset of the first body byte.
        headers:    Parsed response headers.

    Returns:
        Decoded body bytes.

    Raises:
        NetworkError: If chunked encoding is malformed.
    """
    var te = _lower_str(headers.get("Transfer-Encoding"))
    if "chunked" in te:
        return _decode_chunked(raw, body_start)

    var cl_str = headers.get("Content-Length")
    if len(cl_str) > 0:
        var cl = _parse_int(cl_str)
        var body = List[UInt8](capacity=cl)
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


fn _decode_chunked(raw: List[UInt8], start: Int) raises -> List[UInt8]:
    """Decode a ``Transfer-Encoding: chunked`` body.

    Args:
        raw:   Complete raw byte buffer.
        start: Byte offset of the first chunk-size line.

    Returns:
        Reassembled body bytes.

    Raises:
        NetworkError: If a chunk-size line is unparseable.
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
            size_hex = String(size_hex[:semi])
        var chunk_size = _parse_hex(String(size_hex.strip()))
        pos = line_end + 2  # skip \r\n
        if chunk_size == 0:
            break
        var end = pos + chunk_size
        if end > n:
            end = n
        for i in range(pos, end):
            out.append(raw[i])
        pos = end + 2  # skip trailing \r\n after chunk data
    return out^


fn _find_crlf(data: List[UInt8], start: Int) -> Int:
    """Return position of ``\\r\\n`` at or after ``start``, or -1."""
    var n = len(data)
    for i in range(start, n - 1):
        if data[i] == 13 and data[i + 1] == 10:
            return i
    return -1


fn _parse_int(s: String) -> Int:
    """Parse a decimal integer string; returns 0 on failure."""
    var result = 0
    var trimmed = s.strip()
    for i in range(len(trimmed)):
        var c = Int(trimmed.unsafe_ptr()[i])
        if c < 48 or c > 57:
            break
        result = result * 10 + (c - 48)
    return result


fn _parse_hex(s: String) raises -> Int:
    """Parse a hexadecimal integer string.

    Args:
        s: Hex string (e.g. ``"1a3f"``).

    Returns:
        Integer value.

    Raises:
        NetworkError: If the string is empty or contains non-hex characters.
    """
    if len(s) == 0:
        raise NetworkError("empty chunk-size in chunked encoding")
    var result = 0
    for i in range(len(s)):
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


fn _read_http_response_tls(mut stream: TlsStream) raises -> Response:
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


fn _read_http_response_tcp(mut stream: TcpStream) raises -> Response:
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


# ── Module-level convenience functions ────────────────────────────────────────


fn get(url: String) raises -> Response:
    """Perform a one-shot HTTP GET request.

    Creates a temporary ``HttpClient`` for this single request.  For multiple
    requests, use a shared ``HttpClient`` instance instead.

    Args:
        url: The URL to request (``http://`` or ``https://``).

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().get(url)


fn post(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP POST with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url:  The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.

    Example:
        ```mojo
        var resp = post("https://httpbin.org/post", '{"k": 1}')
        resp.raise_for_status()
        ```
    """
    return HttpClient().post(url, body)


fn post(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP POST with a ``mojson.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url:  The target URL.
        body: A ``mojson.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


fn post(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP POST with a raw byte body.

    Args:
        url:  The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


fn put(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP PUT with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url:  The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


fn put(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP PUT with a ``mojson.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url:  The target URL.
        body: A ``mojson.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


fn put(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP PUT with a raw byte body.

    Args:
        url:  The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


fn delete(url: String) raises -> Response:
    """Perform a one-shot HTTP DELETE request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().delete(url)


fn head(url: String) raises -> Response:
    """Perform a one-shot HTTP HEAD request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response`` (body is empty).

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().head(url)
