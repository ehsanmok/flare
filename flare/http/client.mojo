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

from ..http2.client import Http2ClientConnection
from ..quic.client import QuicClientConnection
from ..h3.client import H3ClientConnection
from ..tls.rustls_quic import RustlsQuicConnector
from ..qpack import QpackHeader
from std.os import getenv
from .client_pool import ClientPool
from ._client.parse import (
    _decode_chunked,
    _extract_body_and_trailers,
    _parse_http_response,
    _read_http_response_framed_tcp,
    _read_http_response_tcp,
    _read_http_response_tls,
)
from ._client.h2_send import (
    _build_h2_request_headers,
    _send_h2_over_tcp,
    _send_h2_over_tls,
    _send_h2c_via_upgrade,
)
from ._client.alt_svc import (
    AltSvcStore,
    H3WireChoice,
    decide_h3_wire,
    monotonic_now_s,
)
from ._client.quic_pool import QuicConnectionPool
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
    var _prefer_h3: Bool
    """When ``True`` the client prefers HTTP/3 over QUIC for
    ``https://`` requests (RFC 9114). Defaults to ``False`` so the
    client keeps its h2/h1 ALPN behaviour unchanged. The decision
    is computed by :func:`flare.http._client.alt_svc.decide_h3_wire`
    in :meth:`h3_wire_choice`; the runtime dial falls back to the
    h2/h1 path on any QUIC failure (transparent policy)."""
    var _alt_svc: AltSvcStore
    """Per-origin ``Alt-Svc`` (RFC 7838) discovery cache, behind a
    pointer-backed interior-mutable handle so a read-``self`` request
    path can auto-record headers. Populated from response ``Alt-Svc``
    headers in :meth:`send` (and via :meth:`record_alt_svc`);     consulted
    by :meth:`h3_wire_choice` so an origin that advertised an h3
    endpoint upgrades transparently on the next request. Freed in
    :meth:`__del__`."""
    var _quic_pool: QuicConnectionPool
    """Idle HTTP/3 (QUIC) connection pool keyed on ``host:port``,
    behind a pointer-backed interior-mutable handle so the read-``self``
    :meth:`_send_h3` can acquire / release. Enabled by default (an
    established QUIC connection is expensive, so reuse is the right
    default), so consecutive h3 requests to one origin amortise the
    handshake. Freed in :meth:`__del__`."""

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
        self._prefer_h3 = False
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()

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
        self._prefer_h3 = False
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()

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
        self._prefer_h3 = False
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()

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
        self._prefer_h3 = False
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()

    def __del__(deinit self):
        """Free the pooled fds + the ``Alt-Svc`` store owned by this
        client.

        Idempotent on a moved-from client (``_pool._addr == 0`` /
        ``_alt_svc._addr == 0``). Single-owner: copies are never
        produced for ``HttpClient`` because the type is
        :trait:`Movable` only, so each heap state is freed exactly
        once."""
        try:
            self._pool.free()
        except:
            pass
        try:
            self._alt_svc.free()
        except:
            pass
        try:
            self._quic_pool.free()
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

    def quic_dials(read self) -> Int:
        """Number of fresh HTTP/3 (QUIC) connections this client has
        had to dial (pool misses). Stays at 1 across repeated
        same-origin h3 requests when reuse is working."""
        return self._quic_pool.dials()

    def quic_idle_count(read self) -> Int:
        """Number of established HTTP/3 connections currently idle in
        the QUIC pool."""
        return self._quic_pool.idle_count()

    def with_prefer_h3(var self, enabled: Bool = True) -> HttpClient:
        """Opt this client into HTTP/3 (move-in / move-out so it
        chains off the constructor like :meth:`with_pool`).

        When enabled, ``https://`` requests prefer h3 over QUIC; the
        decision still flows through :meth:`h3_wire_choice` and any
        QUIC dial failure falls back transparently to the existing
        h2/h1 path.

        Example:
            ```mojo
            with HttpClient("https://example.com").with_prefer_h3() as c:
                _ = c.get("/")
            ```
        """
        self._prefer_h3 = enabled
        return self^

    def record_alt_svc(self, origin: String, alt_svc_header: String) raises:
        """Record an origin's ``Alt-Svc`` response header (RFC 7838)
        into the discovery cache.

        Reads ``self`` (the cache is interior-mutable behind the
        :class:`AltSvcStore` handle), so it composes with the
        read-``self`` request surface and the transparent auto-record
        in :meth:`send`. ``origin`` is the ``host:port`` the response
        came from; ``alt_svc_header`` is the raw header value. A later
        request to the same origin then sees a fresh h3 advert via
        :meth:`h3_wire_choice`. A ``clear`` token evicts the cached
        entry. Non-h3 adverts are ignored."""
        self._alt_svc.record(origin, alt_svc_header, monotonic_now_s())

    def h3_wire_choice(self, scheme: String, host: String, port: UInt16) -> Int:
        """The transparent h3-vs-h2 decision for one request.

        Consults the ``prefer_h3`` knob + the per-origin ``Alt-Svc``
        cache and returns an
        :class:`flare.http._client.alt_svc.H3WireChoice` codepoint
        (``HTTP_3`` or ``HTTP_2_OR_LOWER``). QUIC support is compiled
        in, so the only gates are the scheme (``https`` only) and
        whether h3 is preferred or freshly advertised. The runtime
        send path falls back to h2/h1 on any QUIC dial failure
        regardless of this result."""
        var origin = host + ":" + String(Int(port))
        var available = self._alt_svc.has_fresh_h3(origin, monotonic_now_s())
        return decide_h3_wire(
            scheme,
            self._prefer_h3,
            available,
            quic_supported=True,
        )

    def _resolve_quic_ca_pem(self) raises -> String:
        """Return the trusted-roots PEM bundle (contents) for the
        QUIC connector.

        The rustls QUIC shim ships no built-in roots, so a concrete
        PEM is required (unlike the OpenSSL h1/h2 path, which can
        route an empty ``ca_bundle`` to the system default). Resolution:

        1. an explicit :attr:`TlsConfig.ca_bundle` path, else
        2. the pixi-managed ``$CONDA_PREFIX/ssl/cacert.pem`` that the
           ``ca-certificates`` dependency installs.

        The ``$CONDA_PREFIX`` path is assembled with ``String("") +=``
        accumulation rather than the ``+`` concat operator to avoid
        the Mojo ``getenv`` + literal aliasing bug documented in
        :mod:`flare.tls.config`.
        """
        if self._config.ca_bundle.byte_length() > 0:
            with open(self._config.ca_bundle, "r") as f:
                return f.read()
        var prefix = getenv("CONDA_PREFIX", "")
        if prefix == "":
            raise Error(
                "h3: no CA bundle -- set TlsConfig.ca_bundle or run inside"
                " the pixi env that provides $CONDA_PREFIX/ssl/cacert.pem"
            )
        var path = String("")
        path += prefix
        path += "/ssl/cacert.pem"
        with open(path, "r") as f:
            return f.read()

    def _dial_h3(self, u: Url) raises -> H3ClientConnection:
        """Open a fresh established :class:`H3ClientConnection` to
        ``u``'s origin (DNS -> rustls QUIC connector -> blocking QUIC
        handshake). Reports the dial to the pool's miss counter."""
        var addrs = resolve(u.host)
        var peer = SocketAddr(addrs[0], u.port)
        var alpn = List[String]()
        alpn.append("h3")
        var connector = RustlsQuicConnector(self._resolve_quic_ca_pem(), alpn^)
        var quic = QuicClientConnection.connect(peer, connector, u.host)
        self._quic_pool.note_dial()
        return H3ClientConnection(quic^)

    def _run_h3_request(
        self,
        mut h3: H3ClientConnection,
        u: Url,
        method: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
    ) raises -> Response:
        """Drive one request/response over an established (possibly
        reused) ``h3`` connection and lower the
        :class:`flare.h3.response_reader.H3Response` to a
        :class:`Response`."""
        var headers = List[QpackHeader]()
        headers.append(QpackHeader("user-agent", self._user_agent))
        if self._auth_header.byte_length() > 0:
            headers.append(QpackHeader("authorization", self._auth_header))
        for i in range(extra_headers.len()):
            var k = extra_headers._keys[i]
            var kl = k.lower()
            if kl == "host":
                continue  # :authority carries the host in h3
            if kl == "authorization" and self._auth_header.byte_length() > 0:
                continue  # stored auth wins, matching the h1/h2 paths
            headers.append(QpackHeader(kl, extra_headers._values[i]))

        var authority = u.host
        if u.port != 443:
            authority = authority + ":" + String(Int(u.port))
        var hr = h3.fetch(
            method, "https", authority, u.request_target(), headers, body
        )
        var resp = Response(hr.status, "", hr.body.copy())
        for i in range(len(hr.headers)):
            resp.headers.set(hr.headers[i].name, hr.headers[i].value)
        return resp^

    def _send_h3(
        self,
        u: Url,
        method: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
    ) raises -> Response:
        """Send one ``https://`` request over HTTP/3, reusing a pooled
        QUIC connection when one is idle for this origin.

        Acquires an idle :class:`H3ClientConnection` from the
        per-origin pool (or dials a fresh one on a miss), runs the
        request, and releases the connection back to the pool while it
        is still established. A pooled connection that fails mid-flight
        (e.g. the server idled it out) is dropped and the request is
        retried once on a fresh dial. Raises on any QUIC/h3 failure;
        the caller (:meth:`_do_request`) treats that as a transparent
        fallback to h2/h1.
        """
        var key = QuicConnectionPool.build_key(u.host, Int(u.port))
        var pooled = self._quic_pool.acquire(key)
        if pooled:
            var h3 = pooled.take()
            var failed = False
            var resp = Response(0, "", List[UInt8]())
            try:
                resp = self._run_h3_request(h3, u, method, extra_headers, body)
            except:
                failed = True
            if not failed:
                if h3.is_established():
                    self._quic_pool.release(key, h3^)
                else:
                    h3.close()
                return resp^
            # Stale reused connection: drop it and dial fresh below.
            h3.close()

        var fresh = self._dial_h3(u)
        var resp = self._run_h3_request(fresh, u, method, extra_headers, body)
        if fresh.is_established():
            self._quic_pool.release(key, fresh^)
        else:
            fresh.close()
        return resp^

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

            # Transparent Alt-Svc discovery (RFC 7838): record any
            # advertised h3 endpoint so the NEXT request to this origin
            # upgrades to HTTP/3 via h3_wire_choice. No-op when the
            # header is absent or carries no h3 advert.
            var alt_svc = resp.headers.get("Alt-Svc")
            if alt_svc.byte_length() > 0:
                try:
                    var pu = Url.parse(current_url)
                    var origin = pu.host + ":" + String(Int(pu.port))
                    self._alt_svc.record(origin, alt_svc, monotonic_now_s())
                except:
                    pass  # malformed header / parse error: ignore

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
            # HTTP/3 first when the policy says so (prefer_h3 or a
            # fresh cached Alt-Svc advert). Any QUIC/h3 failure falls
            # through transparently to the proven h2/h1 TLS path, so
            # the worst case is exactly the prior behaviour.
            if (
                self.h3_wire_choice("https", u.host, u.port)
                == H3WireChoice.HTTP_3
            ):
                try:
                    return self._send_h3(u, method, extra_headers, body)
                except:
                    pass  # transparent fallback to h2/h1
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
