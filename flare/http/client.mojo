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
suitable for quick scripts. For multiple requests, prefer instantiating
a shared ``HttpClient``.

``post`` and ``put`` accept a ``String`` body (sets
``Content-Type: application/json`` automatically), a ``json.Value``
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
from ..tcp.stream import _connect_with_fallback
from ..tls import TlsStream, TlsConfig
from ..net import NetworkError
from json import dumps, Value as JsonValue
from ..net import SocketAddr
from ..dns import resolve

from ..http2.client import (
    Http2ClientConfig,
    Http2ClientConnection,
    Http2Response,
    _h2_response_to_http,
    build_h2c_settings_payload,
)
from ..http2.hpack import HpackHeader
from ..crypto.hmac import base64url_encode
from .client_pool import ClientPool
from ._client.parse import (
    _decode_chunked,
    _extract_body_and_trailers,
    _parse_http_response,
    _read_http_response_framed_tcp,
    _read_http_response_tcp,
    _read_http_response_tls,
)
from ..net.socket import RawSocket
from ..net._libc import (
    AF_INET,
    SOCK_STREAM,
    INVALID_FD,
)
from std.ffi import c_int


struct HttpClient(Movable):
    """A blocking HTTP/1.1 client.

    Establishes one TCP or TLS connection per request (connection pooling
    is a future feature). Respects HTTP redirects up to ``max_redirects``.

    This type is ``Movable`` but not ``Copyable``. It supports the context
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
    var _prefer_h2c: Bool
    """When ``True``, ``http://`` requests speak HTTP/2 cleartext
    via prior knowledge (RFC 9113 §3.4 connection preface
    immediately, no ``Upgrade`` dance). Defaults to ``False``
    so a plain ``HttpClient().get("http://...")`` keeps the
    HTTP/1.1 wire it has always used. ``https://`` URLs are
    independent of this flag -- they always advertise ALPN
    ``["h2", "http/1.1"]`` and dispatch on what the server
    picks."""
    var _h2c_upgrade: Bool
    """When ``True``, ``http://`` requests negotiate HTTP/2 over
    cleartext via the RFC 7540 §3.2 Upgrade dance: send the
    request as HTTP/1.1 with ``Connection: Upgrade,
    HTTP2-Settings`` + ``Upgrade: h2c`` + ``HTTP2-Settings:
    <base64url(SETTINGS)>``; if the server replies
    ``101 Switching Protocols``, switch the connection to h2
    and read the response from stream id 1. Servers that don't
    speak h2 just answer the original request as h1 and the
    client returns that response unchanged. Orthogonal to
    :attr:`_prefer_h2c` (prior-knowledge path); both default
    ``False``."""
    var _pool: ClientPool
    """Idle HTTP/1.1 connection pool keyed on ``(scheme, host,
    port)``. ``ClientPool.disabled()`` (the default) keeps the
    legacy close-after-each-request behaviour; calling
    :meth:`with_pool` (or
    :meth:`HttpClient.__init__(... pool=...)`) opts in. Only
    cleartext ``http://`` requests reuse pooled fds today;
    ``https://`` always full-handshakes (the TLS-resumption work
    in Commit 04 keeps that handshake cheap)."""

    def __init__(
        out self,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
    ):
        """Initialise an ``HttpClient`` with secure defaults.

        Args:
            base_url: Optional base URL prepended to relative paths.
            max_redirects: Maximum number of redirects to follow (default 10).
            timeout_ms: Connect + read timeout in milliseconds (default 30 s).
            user_agent: Value for the ``User-Agent`` header.
            prefer_h2c: When ``True``, ``http://`` requests speak
                HTTP/2 over cleartext via prior knowledge. ``https://``
                requests always negotiate via ALPN regardless.
            h2c_upgrade: When ``True``, ``http://`` requests issue an
                HTTP/1.1 ``Upgrade: h2c`` handshake (RFC 7540 §3.2)
                instead of using prior knowledge; the connection switches
                to HTTP/2 only if the server returns ``101 Switching
                Protocols``, otherwise it stays on HTTP/1.1.
        """
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        self._auth_header = ""
        self._prefer_h2c = prefer_h2c
        self._h2c_upgrade = h2c_upgrade
        self._pool = ClientPool.disabled()

    def __init__(
        out self,
        tls: TlsConfig,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
    ):
        """Initialise an ``HttpClient`` with custom TLS configuration."""
        self._config = tls.copy()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        self._auth_header = ""
        self._prefer_h2c = prefer_h2c
        self._h2c_upgrade = h2c_upgrade
        self._pool = ClientPool.disabled()

    def __init__[
        A: Auth
    ](
        out self,
        auth: A,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
    ) raises:
        """Initialise an ``HttpClient`` with authentication."""
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        var auth_headers = HeaderMap()
        auth.apply(auth_headers)
        self._auth_header = auth_headers.get("Authorization")
        self._prefer_h2c = prefer_h2c
        self._h2c_upgrade = h2c_upgrade
        self._pool = ClientPool.disabled()

    def __init__[
        A: Auth
    ](
        out self,
        base_url: String,
        auth: A,
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
    ) raises:
        """Initialise an ``HttpClient`` with a base URL and authentication."""
        self._config = TlsConfig()
        self._max_redirects = max_redirects
        self._timeout_ms = timeout_ms
        self._user_agent = user_agent
        self._base_url = base_url
        var auth_headers = HeaderMap()
        auth.apply(auth_headers)
        self._auth_header = auth_headers.get("Authorization")
        self._prefer_h2c = prefer_h2c
        self._h2c_upgrade = h2c_upgrade
        self._pool = ClientPool.disabled()

    def __del__(deinit self):
        """Free any pooled fds owned by this client.

        Idempotent on a moved-from client (``_pool._addr == 0``).
        Single-owner: copies are never produced for ``HttpClient``
        because the type is :trait:`Movable` only, so the
        ``ClientPool`` heap state is freed exactly once."""
        try:
            self._pool.free()
        except:
            pass

    def with_pool(
        var self,
        max_idle_per_host: Int = 8,
        max_idle_total: Int = 64,
        idle_timeout_ms: Int = 90_000,
    ) raises -> HttpClient:
        """Enable connection pooling on this client.

        Returns the client (move-in / move-out so the call chains
        with the regular ``HttpClient(...)`` constructor). The
        pool is keyed on ``(scheme, host, port)`` and only
        cleartext ``http://`` requests reuse pooled fds today
        (TLS pooling lands together with the resumption-aware
        pool key in a follow-up).

        Args:
            max_idle_per_host: Per-origin idle cap. Default ``8``.
            max_idle_total: Total idle cap across origins. Default
                ``64``. ``0`` disables the total cap.
            idle_timeout_ms: Max wallclock age for a pooled fd
                before lazy eviction. Default ``90_000`` ms.

        Returns:
            ``self`` with pooling enabled.

        Example:
            ```mojo
            with HttpClient(base_url="http://api.example.com")
                .with_pool() as c:
                # Two GETs reuse the same TCP connection on idle reuse.
                _ = c.get("/users")
                _ = c.get("/items")
            ```
        """
        try:
            self._pool.free()
        except:
            pass
        self._pool = ClientPool.new(
            max_idle_per_host=max_idle_per_host,
            max_idle_total=max_idle_total,
            idle_timeout_ms=idle_timeout_ms,
        )
        return self^

    def idle_count(read self) -> Int:
        """Return the total number of fds currently sitting idle in
        the pool. Returns 0 when pooling is disabled.
        """
        return self._pool.total_idle()

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(var self) -> HttpClient:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``HttpClient`` (moved).
        """
        return self^

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    def default() -> HttpClient:
        """Return a client with secure defaults (TLS verification enabled).

        Returns:
            An ``HttpClient`` with 30-second timeout and TLS verification.
        """
        return HttpClient()

    # ── URL resolution ────────────────────────────────────────────────────────

    def _resolve_url(self, url: String) -> String:
        """Prepend ``_base_url`` if ``url`` is a relative path.

        Args:
            url: The URL or path to resolve.

        Returns:
            Absolute URL string.
        """
        if self._base_url.byte_length() == 0:
            return url
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return self._base_url + url

    # ── High-level helpers ────────────────────────────────────────────────────

    def get(self, url: String) raises -> Response:
        """Perform a GET request.

        Args:
            url: The URL to request (``http://``, ``https://``, or relative
                 path when ``base_url`` is set).

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.GET, url=self._resolve_url(url))
        return self.send(req)

    def post(self, url: String, body: String) raises -> Response:
        """Perform a POST request with a JSON string body.

        Sets ``Content-Type: application/json`` automatically. This is the
        default for string bodies because virtually every HTTP API that accepts
        a string payload expects JSON.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The JSON request body as a ``String``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
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

    def post(self, url: String, body: JsonValue) raises -> Response:
        """Perform a POST request with a ``json.Value`` body.

        Serialises ``body`` to JSON with ``dumps`` and sets
        ``Content-Type: application/json`` automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: A ``json.Value`` to serialise and send.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        return self.post(url, dumps(body))

    def post(self, url: String, body: List[UInt8]) raises -> Response:
        """Perform a POST request with a raw byte body.

        No ``Content-Type`` header is set automatically; the caller is
        responsible for setting it via a custom ``Request`` if required.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The raw request body bytes.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(
            method=Method.POST, url=self._resolve_url(url), body=body
        )
        return self.send(req)

    def put(self, url: String, body: String) raises -> Response:
        """Perform a PUT request with a JSON string body.

        Sets ``Content-Type: application/json`` automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The JSON request body as a ``String``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var body_bytes = List[UInt8](body.as_bytes())
        var req = Request(
            method=Method.PUT, url=self._resolve_url(url), body=body_bytes^
        )
        req.headers.set("Content-Type", "application/json")
        return self.send(req)

    def put(self, url: String, body: JsonValue) raises -> Response:
        """Perform a PUT request with a ``json.Value`` body.

        Serialises ``body`` to JSON with ``dumps`` and sets
        ``Content-Type: application/json`` automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: A ``json.Value`` to serialise and send.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        return self.put(url, dumps(body))

    def put(self, url: String, body: List[UInt8]) raises -> Response:
        """Perform a PUT request with a raw byte body.

        No ``Content-Type`` header is set automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The raw request body bytes.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(
            method=Method.PUT, url=self._resolve_url(url), body=body
        )
        return self.send(req)

    def delete(self, url: String) raises -> Response:
        """Perform a DELETE request.

        Args:
            url: The target URL.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.DELETE, url=self._resolve_url(url))
        return self.send(req)

    def head(self, url: String) raises -> Response:
        """Perform a HEAD request.

        Identical to ``GET`` but the server MUST NOT include a message body
        in the response (RFC 7231 §4.3.2).

        Args:
            url: The target URL.

        Returns:
            The server's ``Response`` (empty body).

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(method=Method.HEAD, url=self._resolve_url(url))
        return self.send(req)

    def patch(self, url: String, body: String) raises -> Response:
        """Perform a PATCH request with a JSON string body.

        Sets ``Content-Type: application/json`` automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The JSON request body as a ``String``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var body_bytes = List[UInt8](body.as_bytes())
        var req = Request(
            method=Method.PATCH, url=self._resolve_url(url), body=body_bytes^
        )
        req.headers.set("Content-Type", "application/json")
        return self.send(req)

    def patch(self, url: String, body: JsonValue) raises -> Response:
        """Perform a PATCH request with a ``json.Value`` body.

        Serialises ``body`` to JSON with ``dumps`` and sets
        ``Content-Type: application/json`` automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: A ``json.Value`` to serialise and send.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        return self.patch(url, dumps(body))

    def patch(self, url: String, body: List[UInt8]) raises -> Response:
        """Perform a PATCH request with a raw byte body.

        No ``Content-Type`` header is set automatically.

        Args:
            url: The target URL (absolute or relative to ``base_url``).
            body: The raw request body bytes.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
            TooManyRedirects: If the redirect limit is exceeded.
        """
        var req = Request(
            method=Method.PATCH, url=self._resolve_url(url), body=body
        )
        return self.send(req)

    # ── Core ──────────────────────────────────────────────────────────────────

    def send(self, req: Request) raises -> Response:
        """Send an HTTP/1.1 request and return the response.

        Handles redirect chains up to ``_max_redirects``.

        Args:
            req: The request to send.

        Returns:
            The final (possibly redirected) ``Response``.

        Raises:
            NetworkError: On I/O failure.
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
                if location.byte_length() == 0:
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

    def _do_request(
        self,
        method: String,
        url: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
    ) raises -> Response:
        """Perform a single HTTP/1.1 request (no redirect handling).

        Args:
            method: HTTP method string.
            url: Full URL string.
            extra_headers: Headers from the original request.
            body: Request body bytes.

        Returns:
            Parsed ``Response``.

        Raises:
            NetworkError: On I/O or parse failure.
        """
        var u = Url.parse(url)

        # Pooling is enabled only for cleartext h1. The TLS path
        # always full-handshakes (TLS resumption keeps that cheap;
        # pool key-with-ALPN lands in a follow-up).
        var pool_enabled = (
            self._pool._addr != 0
            and not u.is_tls()
            and not self._prefer_h2c
            and not self._h2c_upgrade
        )

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
        if pool_enabled:
            wire += "Connection: keep-alive\r\n"
        else:
            wire += "Connection: close\r\n"
        wire += "Accept: */*\r\n"

        # Authorization header from stored auth credential
        if self._auth_header.byte_length() > 0:
            wire += "Authorization: " + self._auth_header + "\r\n"

        # Forward caller-supplied headers (skip Host — already set)
        for i in range(extra_headers.len()):
            var k = extra_headers._keys[i]
            if k.lower() != "host":
                # Only skip caller's Authorization when _auth_header is already set,
                # matching the h2/h2c paths (see _build_h2_request_headers).
                if (
                    k.lower() == "authorization"
                    and self._auth_header.byte_length() > 0
                ):
                    continue
                wire += k + ": " + extra_headers._values[i] + "\r\n"

        if len(body) > 0:
            wire += "Content-Length: " + String(len(body)) + "\r\n"

        wire += "\r\n"  # end of headers

        # ── Connect and send ───────────────────────────────────────────────
        if u.is_tls():
            # Always advertise ALPN ``["h2", "http/1.1"]`` on the
            # TLS ClientHello so the server can pick HTTP/2 if it
            # supports it. The user-visible API is unchanged: if
            # the server picks h2 we drive the request through
            # the internal :class:`Http2ClientConnection`; if it
            # picks http/1.1 (or doesn't pick anything, e.g. an
            # ALPN-unaware server) we fall through to the
            # existing HTTP/1.1 wire path. Either way we return
            # a :class:`flare.http.Response` so the caller can't
            # tell which wire was used.
            var tls_cfg = self._config.copy()
            if len(tls_cfg.alpn) == 0:
                tls_cfg.alpn = List[String]()
                tls_cfg.alpn.append("h2")
                tls_cfg.alpn.append("http/1.1")
            var stream = TlsStream.connect_timeout(
                u.host, u.port, tls_cfg^, self._timeout_ms
            )
            var negotiated = stream.alpn_selected()
            if negotiated == "h2":
                var resp_h2 = _send_h2_over_tls(
                    stream^,
                    method,
                    u,
                    extra_headers,
                    body,
                    self._user_agent,
                    self._auth_header,
                )
                return resp_h2^
            # HTTP/1.1 over TLS (existing wire).
            var wire_bytes = wire.as_bytes()
            stream.write_all(Span[UInt8, _](wire_bytes))
            if len(body) > 0:
                stream.write_all(Span[UInt8, _](body))
            var resp = _read_http_response_tls(stream)
            stream.close()
            return resp^
        else:
            var stream = _connect_with_fallback(
                u.host, u.port, self._timeout_ms
            )
            if self._prefer_h2c:
                # h2c via prior knowledge (RFC 9113 §3.4):
                # send the connection preface immediately and
                # drive the request through Http2ClientConnection
                # over the cleartext TCP stream. The response
                # comes back lowered to a regular Response.
                var resp_h2c = _send_h2_over_tcp(
                    stream^,
                    method,
                    u,
                    extra_headers,
                    body,
                    self._user_agent,
                    self._auth_header,
                )
                return resp_h2c^
            if self._h2c_upgrade:
                # h2c via the RFC 7540 §3.2 Upgrade dance: send the
                # request as h1 with ``Upgrade: h2c`` +
                # ``HTTP2-Settings``; if the server replies 101 the
                # response arrives over h2 on stream id 1, otherwise
                # the helper returns the plain h1 response.
                var resp_upg = _send_h2c_via_upgrade(
                    stream^,
                    method,
                    u,
                    extra_headers,
                    body,
                    self._user_agent,
                    self._auth_header,
                )
                return resp_upg^
            if pool_enabled:
                # Pooled keep-alive path with one stale-conn retry.
                # If the first attempt was on a pooled fd and the
                # peer FIN'd the idle keep-alive while we were
                # writing, retry once with a fresh connection (RFC
                # 7230 §6.3.1).
                stream.close()  # discard the fresh stream we just opened
                var key = ClientPool.build_key(u.scheme, u.host, Int(u.port))
                return self._send_h1_pooled(key, u.host, u.port, wire, body)
            var wire_bytes = wire.as_bytes()
            stream.write_all(Span[UInt8, _](wire_bytes))
            if len(body) > 0:
                stream.write_all(Span[UInt8, _](body))
            var resp = _read_http_response_tcp(stream)
            stream.close()
            return resp^

    def _send_h1_pooled(
        self,
        key: String,
        host: String,
        port: UInt16,
        wire: String,
        body: List[UInt8],
    ) raises -> Response:
        """Send one HTTP/1.1 request through the connection pool.

        Tries to acquire an idle fd for ``key``; if that fails or
        the pooled fd is stale (peer FIN'd the keep-alive while
        idle), opens a fresh connection. On success, releases the
        fd back to the pool when the response permits keep-alive,
        otherwise closes it.
        """
        # First try a pooled fd.
        var pooled_fd = self._pool.acquire(key)
        var attempted_pooled = pooled_fd >= 0
        var stream: TcpStream
        if attempted_pooled:
            var sock = RawSocket(
                c_int(pooled_fd), AF_INET, SOCK_STREAM, _wrap=True
            )
            stream = TcpStream(sock^, SocketAddr.localhost(port))
        else:
            stream = _connect_with_fallback(host, port, self._timeout_ms)

        var wire_bytes = wire.as_bytes()
        var io_failed = False
        try:
            stream.write_all(Span[UInt8, _](wire_bytes))
            if len(body) > 0:
                stream.write_all(Span[UInt8, _](body))
        except:
            io_failed = True

        if not io_failed:
            var can_reuse = False
            try:
                var resp = _read_http_response_framed_tcp(stream, can_reuse)
                if can_reuse:
                    # Release fd to pool: capture fd, neutralise the
                    # RawSocket so its destructor is a no-op, then
                    # push.
                    var fd = Int(stream._socket.fd)
                    stream._socket.fd = INVALID_FD
                    self._pool.release(key, fd)
                else:
                    stream.close()
                return resp^
            except:
                pass

        # IO or parse failure on a *pooled* fd is the canonical
        # stale-conn signature. Retry once with a fresh connection.
        # Failure on a *fresh* fd is a real error.
        stream.close()
        if not attempted_pooled:
            raise NetworkError("HTTP/1.1 pooled request failed")

        var fresh = _connect_with_fallback(host, port, self._timeout_ms)
        fresh.write_all(Span[UInt8, _](wire_bytes))
        if len(body) > 0:
            fresh.write_all(Span[UInt8, _](body))
        var can_reuse2 = False
        var resp2 = _read_http_response_framed_tcp(fresh, can_reuse2)
        if can_reuse2:
            var fd2 = Int(fresh._socket.fd)
            fresh._socket.fd = INVALID_FD
            self._pool.release(key, fd2)
        else:
            fresh.close()
        return resp2^


comptime _H2_READ_BUF_SIZE: Int = 16384
"""Per-syscall recv buffer size for the h2 read pump. Matches the
RFC 9113 §6.5.2 default ``max_frame_size``."""


def _build_h2_request_headers(
    extra_headers: HeaderMap,
    user_agent: String,
    auth_header: String,
) raises -> List[HpackHeader]:
    """Translate :class:`HeaderMap` to a list of :class:`HpackHeader`
    suitable for :meth:`Http2ClientConnection.send_request`.

    Lower-cases header names per RFC 9113 §8.1.2 and strips the
    connection-level headers RFC 9113 §8.2.2 forbids on h2.
    Appends ``user-agent`` and ``authorization`` from the
    HttpClient instance fields if they are not already present
    on the request's HeaderMap.
    """
    var extra = List[HpackHeader]()
    for i in range(extra_headers.len()):
        var k = extra_headers._keys[i]
        var v = extra_headers._values[i]
        var lk = String(capacity=k.byte_length() + 1)
        var kp = k.unsafe_ptr()
        for j in range(k.byte_length()):
            var c = Int(kp[j])
            if c >= 65 and c <= 90:
                lk += chr(c + 32)
            else:
                lk += chr(c)
        if (
            lk == "connection"
            or lk == "transfer-encoding"
            or lk == "keep-alive"
            or lk == "proxy-connection"
            or lk == "upgrade"
            or lk == "host"
        ):
            continue
        extra.append(HpackHeader(lk^, v))
    if extra_headers.get("User-Agent").byte_length() == 0:
        extra.append(HpackHeader("user-agent", user_agent))
    if (
        auth_header.byte_length() > 0
        and extra_headers.get("Authorization").byte_length() == 0
    ):
        extra.append(HpackHeader("authorization", auth_header))
    return extra^


def _h2_authority(u: Url) -> String:
    """Build the ``:authority`` pseudo-header value (host[:port] for
    non-default ports)."""
    var authority = u.host
    if (u.scheme == "http" and u.port != 80) or (
        u.scheme == "https" and u.port != 443
    ):
        authority = authority + ":" + String(Int(u.port))
    return authority^


def _send_h2_over_tls(
    var stream: TlsStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Drive a single HTTP/2 request over an already-handshaken TLS
    stream and return the response.

    Used by :meth:`HttpClient._do_request` when the server selected
    ALPN ``h2``. The caller is responsible for owning the
    :class:`TlsStream` -- this helper consumes it (sends GOAWAY +
    closes on the way out) and returns the lowered
    :class:`flare.http.Response`.
    """
    var conn = Http2ClientConnection()
    var extra = _build_h2_request_headers(
        extra_headers, user_agent, auth_header
    )
    var sid = conn.next_stream_id()
    conn.send_request(
        sid,
        method,
        u.scheme,
        _h2_authority(u),
        u.request_target(),
        extra,
        Span[UInt8, _](body),
    )
    var out_bytes = conn.drain()
    if len(out_bytes) > 0:
        stream.write_all(Span[UInt8, _](out_bytes))
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while not conn.response_ready(sid):
        if conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2): peer sent GOAWAY before responding to stream "
                + String(sid)
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2): peer closed connection mid-response on stream "
                + String(sid)
            )
        # Mojo 1.0.0b1: name the slice's lifetime via ``buf``
        # itself; ``buf[:n]`` was an anonymous temporary whose
        # storage could be freed before ``feed`` returned.
        conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))
    var maybe_err = conn.stream_error(sid)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream "
            + String(sid)
        )
    var h2_resp = conn.take_response(sid)
    try:
        conn.send_goaway(sid, 0)
        var goaway_bytes = conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _send_h2_over_tcp(
    var stream: TcpStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Drive a single HTTP/2 cleartext (h2c) request over a plain
    TCP stream via prior knowledge.

    Mirror of :func:`_send_h2_over_tls`, used when the caller
    constructed :class:`HttpClient` with ``prefer_h2c=True`` and
    targeted an ``http://`` URL. RFC 9113 §3.4: the client sends
    the connection preface immediately (no ``Upgrade`` dance);
    if the server doesn't speak h2, the connection just dies.
    """
    var conn = Http2ClientConnection()
    var extra = _build_h2_request_headers(
        extra_headers, user_agent, auth_header
    )
    var sid = conn.next_stream_id()
    conn.send_request(
        sid,
        method,
        u.scheme,
        _h2_authority(u),
        u.request_target(),
        extra,
        Span[UInt8, _](body),
    )
    var out_bytes = conn.drain()
    if len(out_bytes) > 0:
        stream.write_all(Span[UInt8, _](out_bytes))
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while not conn.response_ready(sid):
        if conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2c): peer sent GOAWAY before responding to stream "
                + String(sid)
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c): peer closed connection mid-response on"
                " stream "
                + String(sid)
            )
        # Mojo 1.0.0b1 Span lifetime: same fix as the h2-over-tls
        # path -- bind to the named ``buf`` rather than the
        # slice temporary.
        conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))
    var maybe_err = conn.stream_error(sid)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2c): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream "
            + String(sid)
        )
    var h2_resp = conn.take_response(sid)
    try:
        conn.send_goaway(sid, 0)
        var goaway_bytes = conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _send_h2c_via_upgrade(
    var stream: TcpStream,
    method: String,
    u: Url,
    extra_headers: HeaderMap,
    body: List[UInt8],
    user_agent: String,
    auth_header: String,
) raises -> Response:
    """Negotiate HTTP/2 cleartext via the RFC 7540 §3.2 ``Upgrade``
    dance and run the request.

    Wire flow:

    1. Client sends an HTTP/1.1 request decorated with
       ``Connection: Upgrade, HTTP2-Settings``,
       ``Upgrade: h2c``, and
       ``HTTP2-Settings: <base64url(SETTINGS-payload)>``.
    2. The server either:
       a. Accepts: replies ``101 Switching Protocols``
          + ``Connection: Upgrade`` + ``Upgrade: h2c``
          and treats the original request as stream id 1; or
       b. Declines: replies as a plain HTTP/1.1 response.
    3. On 101, the client sends the h2 connection preface
       (``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`` + a SETTINGS
       frame) and reads the response on stream id 1 over the same
       TCP fd; the original request body has already been delivered
       on the h1 wire so stream 1 is HALF_CLOSED_LOCAL from the
       client's perspective.
    4. On non-101 the helper parses the h1 response and returns it
       as-is so the caller sees a normal :class:`Response`.

    Used by :meth:`HttpClient._do_request` when the user constructed
    :class:`HttpClient` with ``h2c_upgrade=True`` and targeted an
    ``http://`` URL. Orthogonal to ``prefer_h2c`` (prior-knowledge
    path).
    """
    var h2_cfg = Http2ClientConfig()
    var settings_payload = build_h2c_settings_payload(h2_cfg)
    var settings_b64 = base64url_encode(settings_payload^)
    var wire = method + " " + u.request_target() + " HTTP/1.1\r\n"
    var host_header = u.host
    if u.port != 80:
        host_header = host_header + ":" + String(Int(u.port))
    wire += "Host: " + host_header + "\r\n"
    wire += "User-Agent: " + user_agent + "\r\n"
    wire += "Connection: Upgrade, HTTP2-Settings\r\n"
    wire += "Upgrade: h2c\r\n"
    wire += "HTTP2-Settings: " + settings_b64 + "\r\n"
    wire += "Accept: */*\r\n"
    if auth_header.byte_length() > 0:
        wire += "Authorization: " + auth_header + "\r\n"
    for i in range(extra_headers.len()):
        var k = extra_headers._keys[i]
        var lk = k.lower()
        if (
            lk == "host"
            or lk == "connection"
            or lk == "upgrade"
            or lk == "http2-settings"
        ):
            continue
        # Only skip caller's Authorization when _auth_header is already set
        if lk == "authorization" and auth_header.byte_length() > 0:
            continue
        wire += k + ": " + extra_headers._values[i] + "\r\n"
    if len(body) > 0:
        wire += "Content-Length: " + String(len(body)) + "\r\n"
    wire += "\r\n"

    var wire_bytes = wire.as_bytes()
    stream.write_all(Span[UInt8, _](wire_bytes))
    if len(body) > 0:
        stream.write_all(Span[UInt8, _](body))

    var raw = List[UInt8]()
    var hdr_end = -1
    var buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
    buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
    while hdr_end < 0:
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer closed connection before"
                " response headers"
            )
        for i in range(n):
            raw.append(buf[i])
        if len(raw) >= 4:
            var k = 0
            while k + 3 < len(raw):
                if (
                    raw[k] == 0x0D
                    and raw[k + 1] == 0x0A
                    and raw[k + 2] == 0x0D
                    and raw[k + 3] == 0x0A
                ):
                    hdr_end = k + 4
                    break
                k += 1

    var status = _parse_status_line(raw)
    if status != 101:
        var rest = raw.copy()
        var body_buf = List[UInt8](capacity=_H2_READ_BUF_SIZE)
        body_buf.resize(_H2_READ_BUF_SIZE, UInt8(0))
        while True:
            var n = stream.read(body_buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
            if n == 0:
                break
            for i in range(n):
                rest.append(body_buf[i])
        stream.close()
        return _parse_http_response(rest)

    var h2_conn = Http2ClientConnection.from_h2c_upgrade(h2_cfg^)
    var preface_bytes = h2_conn.drain()
    if len(preface_bytes) > 0:
        stream.write_all(Span[UInt8, _](preface_bytes))

    if hdr_end < len(raw):
        var leftover = List[UInt8]()
        for i in range(hdr_end, len(raw)):
            leftover.append(raw[i])
        if len(leftover) > 0:
            h2_conn.feed(Span[UInt8, _](leftover))
            var ack_bytes = h2_conn.drain()
            if len(ack_bytes) > 0:
                stream.write_all(Span[UInt8, _](ack_bytes))

    while not h2_conn.response_ready(1):
        if h2_conn.goaway_received():
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer sent GOAWAY before responding"
                " to stream 1"
            )
        var n = stream.read(buf.unsafe_ptr(), _H2_READ_BUF_SIZE)
        if n == 0:
            stream.close()
            raise NetworkError(
                "HttpClient(h2c-upgrade): peer closed connection mid-response"
                " on stream 1"
            )
        # Mojo 1.0.0b1 stricter destructor scheduling: ``buf[:n]``
        # allocated a temporary ``List`` whose backing storage was
        # destroyed before ``feed`` returned, which the kernel /
        # heap could re-use, doubling the response body on the
        # next ``read`` slice. Construct the ``Span`` directly
        # over ``buf``'s backing storage so the lifetime is the
        # named ``buf`` (which lives across the whole loop), not
        # the slice's anonymous temporary.
        h2_conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack_bytes = h2_conn.drain()
        if len(ack_bytes) > 0:
            stream.write_all(Span[UInt8, _](ack_bytes))

    var maybe_err = h2_conn.stream_error(1)
    if Bool(maybe_err):
        stream.close()
        raise NetworkError(
            "HttpClient(h2c-upgrade): peer sent RST_STREAM (error code "
            + String(maybe_err.value())
            + ") on stream 1"
        )
    var h2_resp = h2_conn.take_response(1)
    try:
        h2_conn.send_goaway(1, 0)
        var goaway_bytes = h2_conn.drain()
        if len(goaway_bytes) > 0:
            stream.write_all(Span[UInt8, _](goaway_bytes))
    except:
        pass
    stream.close()
    return _h2_response_to_http(h2_resp^)


def _parse_status_line(raw: List[UInt8]) raises -> Int:
    """Extract the status code from the leading status-line of a
    raw HTTP/1.1 response buffer.

    Returns just the numeric status (e.g. ``101`` or ``200``); the
    caller decides whether to switch protocols or fall through to a
    full h1 response parse. Used only by the h2c-via-Upgrade
    helper -- the regular response parser is :func:`_parse_http_response`.
    """
    var line_end = 0
    while line_end + 1 < len(raw):
        if raw[line_end] == 0x0D and raw[line_end + 1] == 0x0A:
            break
        line_end += 1
    if line_end + 1 >= len(raw):
        raise NetworkError("HttpClient(h2c-upgrade): no CRLF after status-line")
    var sl = String("")
    for i in range(line_end):
        sl += chr(Int(raw[i]))
    var sp1 = sl.find(" ")
    if sp1 < 0:
        raise NetworkError("HttpClient(h2c-upgrade): malformed status-line")
    var sp2 = sl.find(" ", start=sp1 + 1)
    var code_end = sp2
    if code_end < 0:
        code_end = sl.byte_length()
    var code_str = String("")
    var slp = sl.unsafe_ptr()
    for i in range(sp1 + 1, code_end):
        code_str += chr(Int(slp[i]))
    try:
        return Int(code_str)
    except:
        raise NetworkError(
            "HttpClient(h2c-upgrade): non-numeric status code in status-line"
        )


# ── Module-level convenience functions ────────────────────────────────────────


def get(url: String) raises -> Response:
    """Perform a one-shot HTTP GET request.

    Creates a temporary ``HttpClient`` for this single request. For multiple
    requests, use a shared ``HttpClient`` instance instead.

    Args:
        url: The URL to request (``http://`` or ``https://``).

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().get(url)


def post(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP POST with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
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


def post(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP POST with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


def post(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP POST with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().post(url, body)


def put(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP PUT with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def put(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP PUT with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def put(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP PUT with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().put(url, body)


def delete(url: String) raises -> Response:
    """Perform a one-shot HTTP DELETE request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().delete(url)


def head(url: String) raises -> Response:
    """Perform a one-shot HTTP HEAD request.

    Args:
        url: The target URL.

    Returns:
        The server's ``Response`` (body is empty).

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().head(url)


def patch(url: String, body: String) raises -> Response:
    """Perform a one-shot HTTP PATCH with a JSON string body.

    Sets ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: The JSON request body as a ``String``.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)


def patch(url: String, body: JsonValue) raises -> Response:
    """Perform a one-shot HTTP PATCH with a ``json.Value`` body.

    Serialises ``body`` to JSON with ``dumps`` and sets
    ``Content-Type: application/json`` automatically.

    Args:
        url: The target URL.
        body: A ``json.Value`` to serialise and send.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)


def patch(url: String, body: List[UInt8]) raises -> Response:
    """Perform a one-shot HTTP PATCH with a raw byte body.

    Args:
        url: The target URL.
        body: The raw request body bytes.

    Returns:
        The server's ``Response``.

    Raises:
        NetworkError: On connection or I/O failure.
    """
    return HttpClient().patch(url, body)
