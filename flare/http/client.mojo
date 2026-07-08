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

# TODO(2026-12-31, track-http-client): this module is dominated by the single
# ``HttpClient`` struct (h1/h2c/h2/h3 dial + redirect/cookie/retry/decompress +
# pool checkout). Mojo cannot split one struct's methods across files, so the
# file sits over the 1000-line Pass-B cap. Planned decomposition: move the
# free helpers + per-wire dial bodies into ``flare/http/_client/`` once the
# struct-method-split language support lands. Allowlisted in
# tools/check_reactor_size.sh until then.
from .request import Request, Method
from .response import Response, Status
from .headers import HeaderMap
from .url import Url
from .auth import Auth, BasicAuth, BearerAuth
from .error import HttpError, TooManyRedirects
from .redirect_policy import RedirectPolicy, RedirectAction, RedirectMode
from .reliability import RetryPolicy, _backoff_sleep_ms
from .encoding import decode_content
from ._client.cookie_store import CookieStore
from .body import ChunkSource
from .cancel import Cancel
from ..runtime._libc_time import libc_nanosleep_ms
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
from std.memory import UnsafePointer
from .client_pool import ClientPool
from ._client.parse import (
    _decode_chunked,
    _extract_body_and_trailers,
    _parse_http_response,
    _read_http_response_framed_tcp,
    _read_http_response_framed_tls,
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
from ._client.tls_pool import TlsConnectionPool
from ._client.h3_race import (
    RACE_H3,
    RACE_NONE,
    race_h3_h2_connect,
)
from ..net.socket import RawSocket
from ..net._libc import (
    AF_INET,
    SOCK_STREAM,
    INVALID_FD,
)
from std.ffi import c_int


def _chunk_frame_prefix(n: Int) -> String:
    """Return the chunked-transfer size line for a chunk of ``n`` bytes:
    the lowercase hex length followed by CRLF (RFC 7230 sec 4.1). The
    caller writes this, then the chunk bytes, then a trailing CRLF."""
    if n <= 0:
        return String("0\r\n")
    var digits = String("0123456789abcdef")
    var rev = List[UInt8]()
    var v = n
    while v > 0:
        rev.append(digits.as_bytes()[v & 0xF])
        v = v >> 4
    var out = String("")
    for i in range(len(rev) - 1, -1, -1):
        out += String(unsafe_from_utf8=Span[UInt8, _](rev)[i : i + 1])
    return out + "\r\n"


def _is_idempotent(method: String) -> Bool:
    """Whether ``method`` is idempotent per RFC 9110 sec 9.2.2 (safe to
    send more than once with the same effect). Only idempotent requests
    are eligible for the happy-eyeballs race, which dispatches the
    request on both the h3 and h2 wires concurrently."""
    var m = method.upper()
    return (
        m == "GET"
        or m == "HEAD"
        or m == "OPTIONS"
        or m == "PUT"
        or m == "DELETE"
        or m == "TRACE"
    )


def _race_connect_leg(
    client_addr: Int,
    is_h3: Bool,
    url: String,
) raises -> Bool:
    """Happy-eyeballs connect-leg trampoline: re-materialise the
    :class:`HttpClient` from its address, parse ``url`` (Url is move-only
    so each leg parses its own), and establish *only the connection* for
    the h3 or h2/h1 path. Passed to :func:`race_h3_h2_connect` so that
    module needs no HttpClient import. Only the h3 leg mutates client
    state (the QUIC pool), so the two concurrent legs have a single
    writer. Returns ``True`` when the connection established."""
    var client = UnsafePointer[HttpClient, MutUntrackedOrigin](
        unsafe_from_address=client_addr
    )
    var u = Url.parse(url)
    if is_h3:
        return client[]._connect_h3(u)
    return client[]._connect_h2(u)


struct HttpClient(Movable):
    """A blocking HTTP client (HTTP/1.1, HTTP/2, and HTTP/3).

    Opens one connection per request by default; opt into keep-alive
    reuse for cleartext HTTP/1.1 with :meth:`with_pool` and into HTTP/3
    QUIC connection reuse (on by default once h3 is used). Follows
    redirects per a configurable :meth:`with_redirect_policy`, optionally
    auto-decompresses responses, retries transient failures via
    :meth:`with_retry`, and keeps a session cookie jar via
    :meth:`with_cookies`.

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
    var _tls_pool: TlsConnectionPool
    """Idle HTTPS (TLS HTTP/1.1) connection pool keyed on
    ``scheme://host:port``, behind a pointer-backed interior-mutable
    handle so the read-``self`` :meth:`_send_h2_or_h1_tls` can acquire /
    release. ``TlsConnectionPool.disabled()`` (the default) keeps the
    close-after-each-request behaviour; :meth:`with_pool` opts in
    alongside the cleartext pool. Only the ``http/1.1`` ALPN result is
    pooled (an ``h2`` connection is multiplexed on the h2 path). Freed
    in :meth:`__del__`."""
    var _redirect_policy: RedirectPolicy
    """Redirect-following policy (RFC 9110 sec 15.4). Defaults to
    :meth:`RedirectPolicy.follow_all` with the constructor's
    ``max_redirects`` cap, preserving the legacy unconditional-follow
    behaviour byte-for-byte. :meth:`with_redirect_policy` swaps in a
    ``same_origin_only`` / ``deny`` policy; the decision (and any
    cross-origin Authorization suppression) flows through
    :meth:`RedirectPolicy.decide` in :meth:`_send_once`."""
    var _auto_decompress: Bool
    """When ``True`` (default), the client advertises
    ``Accept-Encoding: gzip, deflate, br`` (unless the caller set one)
    and transparently decodes a compressed response body via
    :func:`flare.http.encoding.decode_content`, stripping the
    ``Content-Encoding`` header and fixing ``Content-Length``. Identity
    / absent encodings pass through untouched, so a non-compressed
    response is byte-for-byte unchanged."""
    var _retry: RetryPolicy
    """Client request-level retry policy (distinct from the server-side
    :class:`flare.http.reliability.Retry` middleware). Only consulted
    when :attr:`_retry_enabled` is set via :meth:`with_retry`."""
    var _retry_enabled: Bool
    """Whether :meth:`with_retry` opted this client into request
    retries. ``False`` by default so a plain client issues exactly one
    attempt per request (legacy behaviour)."""
    var _cookies: CookieStore
    """Per-client cookie jar behind a pointer-backed interior-mutable
    handle (mirrors :attr:`_alt_svc`). Disabled (no-op) by default;
    :meth:`with_cookies` opts in. When enabled, :meth:`_send_once`
    captures ``Set-Cookie`` response headers and replays them as a
    ``Cookie`` request header. Freed in :meth:`__del__`."""

    def __init__(
        out self,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
        prefer_h3: Bool = False,
        auto_decompress: Bool = True,
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
            prefer_h3: When ``True``, ``https://`` requests prefer
                HTTP/3 over QUIC on first contact rather than waiting
                for an ``Alt-Svc`` advert; any QUIC dial failure falls
                back transparently to h2/h1. (Without this, h3 still
                kicks in automatically once a server advertises it via
                ``Alt-Svc``.)
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
        self._prefer_h3 = prefer_h3
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()
        self._tls_pool = TlsConnectionPool.disabled()
        self._redirect_policy = RedirectPolicy.follow_all(max_redirects)
        self._auto_decompress = auto_decompress
        self._retry = RetryPolicy()
        self._retry_enabled = False
        self._cookies = CookieStore.disabled()

    def __init__(
        out self,
        tls: TlsConfig,
        base_url: String = "",
        max_redirects: Int = 10,
        timeout_ms: Int = 30_000,
        user_agent: String = "flare/0.1.0",
        prefer_h2c: Bool = False,
        h2c_upgrade: Bool = False,
        prefer_h3: Bool = False,
        auto_decompress: Bool = True,
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
        self._prefer_h3 = prefer_h3
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()
        self._tls_pool = TlsConnectionPool.disabled()
        self._redirect_policy = RedirectPolicy.follow_all(max_redirects)
        self._auto_decompress = auto_decompress
        self._retry = RetryPolicy()
        self._retry_enabled = False
        self._cookies = CookieStore.disabled()

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
        prefer_h3: Bool = False,
        auto_decompress: Bool = True,
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
        self._prefer_h3 = prefer_h3
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()
        self._tls_pool = TlsConnectionPool.disabled()
        self._redirect_policy = RedirectPolicy.follow_all(max_redirects)
        self._auto_decompress = auto_decompress
        self._retry = RetryPolicy()
        self._retry_enabled = False
        self._cookies = CookieStore.disabled()

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
        prefer_h3: Bool = False,
        auto_decompress: Bool = True,
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
        self._prefer_h3 = prefer_h3
        self._alt_svc = AltSvcStore.new()
        self._quic_pool = QuicConnectionPool.new()
        self._tls_pool = TlsConnectionPool.disabled()
        self._redirect_policy = RedirectPolicy.follow_all(max_redirects)
        self._auto_decompress = auto_decompress
        self._retry = RetryPolicy()
        self._retry_enabled = False
        self._cookies = CookieStore.disabled()

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
        try:
            self._tls_pool.free()
        except:
            pass
        try:
            self._cookies.free()
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
        with the regular ``HttpClient(...)`` constructor). Two pools
        are enabled, both keyed on the origin: the cleartext HTTP/1.1
        pool (``http://``, reuses idle fds) and the HTTPS HTTP/1.1 pool
        (``https://``, reuses the whole established ``TlsStream`` so the
        TLS handshake is skipped on keep-alive reuse). An ``h2``-
        negotiated TLS connection is multiplexed on the h2 path and is
        not pooled here.

        Args:
            max_idle_per_host: Per-origin idle cap. Default ``8``.
            max_idle_total: Total idle cap across origins (cleartext
                pool). Default ``64``. ``0`` disables the total cap.
            idle_timeout_ms: Max wallclock age for a pooled connection
                before lazy eviction. Default ``90_000`` ms.

        Returns:
            ``self`` with pooling enabled.

        Example:
            ```mojo
            with HttpClient(base_url="https://api.example.com")
                .with_pool() as c:
                # Two GETs reuse the same TLS connection on idle reuse.
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
        try:
            self._tls_pool.free()
        except:
            pass
        self._tls_pool = TlsConnectionPool.new(
            max_idle_per_host=max_idle_per_host,
            idle_timeout_ms=idle_timeout_ms,
        )
        return self^

    def idle_count(read self) -> Int:
        """Return the total number of connections currently sitting idle
        across both keep-alive pools (cleartext HTTP/1.1 fds + HTTPS
        ``TlsStream`` connections). Returns 0 when pooling is disabled.
        """
        return self._pool.total_idle() + self._tls_pool.idle_count()

    def tls_idle_count(read self) -> Int:
        """Return the number of idle HTTPS (TLS HTTP/1.1) connections in
        the pool. Returns 0 when pooling is disabled."""
        return self._tls_pool.idle_count()

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

    def with_redirect_policy(var self, policy: RedirectPolicy) -> HttpClient:
        """Set the redirect-following policy (move-in / move-out so it
        chains off the constructor like :meth:`with_pool`).

        The default (:meth:`RedirectPolicy.follow_all`) preserves the
        legacy unconditional-follow behaviour. Swap in
        :meth:`RedirectPolicy.same_origin_only` to refuse cross-origin
        redirects (and never leak the Authorization header across
        origins), or :meth:`RedirectPolicy.deny` to surface 3xx
        responses to the caller unfollowed.

        Example:
            ```mojo
            var pol = RedirectPolicy.same_origin_only(max_redirects=5)
            with HttpClient("https://api.example.com")
                .with_redirect_policy(pol) as c:
                _ = c.get("/protected")
            ```
        """
        self._redirect_policy = policy.copy()
        return self^

    def with_retry(var self, policy: RetryPolicy = RetryPolicy()) -> HttpClient:
        """Opt into request-level retries on transient failure
        (move-in / move-out, chains off the constructor).

        Retries fire when a request raises (connection/I/O error) or
        returns a ``>= 500`` status, up to ``policy.max_attempts``
        total attempts. By default only idempotent methods (RFC 9110
        sec 9.2.2) are retried; set ``policy.retry_only_idempotent =
        False`` to retry any method. Backoff follows the same jittered
        exponential schedule as the server-side
        :class:`flare.http.reliability.Retry` middleware.

        Example:
            ```mojo
            var pol = RetryPolicy()
            pol.max_attempts = 4
            pol.initial_backoff_ms = 50
            with HttpClient().with_retry(pol) as c:
                _ = c.get("https://flaky.example.com/data")
            ```
        """
        self._retry = policy.copy()
        self._retry_enabled = True
        return self^

    def with_cookies(var self) raises -> HttpClient:
        """Enable a per-client cookie jar (move-in / move-out, chains
        off the constructor).

        When enabled, the client captures ``Set-Cookie`` response
        headers and replays the stored cookies as a ``Cookie`` request
        header on subsequent requests -- the standard session-cookie
        flow for a logged-in client. The jar is origin-agnostic (every
        stored cookie is sent on every request from this client), which
        matches the common single-origin ``HttpClient(base_url=...)``
        session.

        Example:
            ```mojo
            with HttpClient("https://api.example.com")
                .with_cookies() as c:
                _ = c.post("/login", '{"u":"a","p":"b"}')  # stores session
                _ = c.get("/me")                            # replays cookie
            ```
        """
        try:
            self._cookies.free()
        except:
            pass
        self._cookies = CookieStore.new()
        return self^

    def cookie_header(read self) raises -> String:
        """The ``Cookie`` request header value the jar would send, or
        ``""`` when cookies are disabled / the jar is empty. Useful for
        tests and introspection."""
        return self._cookies.request_header()

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
        # Empty ca_bundle parity with the OpenSSL h1/h2 path: fall back
        # to the OS trust store (rustls-native-certs) instead of
        # requiring a concrete PEM. An explicit ca_bundle still wins.
        var connector: RustlsQuicConnector
        if self._config.ca_bundle.byte_length() > 0:
            connector = RustlsQuicConnector(self._resolve_quic_ca_pem(), alpn^)
        else:
            connector = RustlsQuicConnector.with_system_roots(alpn^)
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
        auth_header: String,
    ) raises -> Response:
        """Drive one request/response over an established (possibly
        reused) ``h3`` connection and lower the
        :class:`flare.h3.response_reader.H3Response` to a
        :class:`Response`. ``auth_header`` is the effective (redirect-
        policy-gated) Authorization value for this hop."""
        var headers = List[QpackHeader]()
        headers.append(QpackHeader("user-agent", self._user_agent))
        if auth_header.byte_length() > 0:
            headers.append(QpackHeader("authorization", auth_header))
        for i in range(extra_headers.len()):
            var k = extra_headers._keys[i]
            var kl = k.lower()
            if kl == "host":
                continue  # :authority carries the host in h3
            if kl == "authorization" and auth_header.byte_length() > 0:
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

    def _connect_h3(self, u: Url) raises -> Bool:
        """Happy-eyeballs h3 leg: establish a QUIC/h3 connection to
        ``u``'s origin and leave it idle in the per-origin QUIC pool so a
        subsequent :meth:`_send_h3` reuses it (no second dial).

        Returns ``True`` once an established connection is pooled. A pool
        hit (an already-idle connection for this origin) counts as an
        instant win without re-dialing. Never sends the request -- that
        is the caller's job on the winning protocol."""
        var key = QuicConnectionPool.build_key(u.host, Int(u.port))
        var pooled = self._quic_pool.acquire(key)
        if pooled:
            var existing = pooled.take()
            if existing.is_established():
                self._quic_pool.release(key, existing^)
                return True
            existing.close()
        var fresh = self._dial_h3(u)
        if fresh.is_established():
            self._quic_pool.release(key, fresh^)
            return True
        fresh.close()
        return False

    def _connect_h2(self, u: Url) raises -> Bool:
        """Happy-eyeballs h2/h1 leg: probe that the proven TLS path is
        reachable by establishing (and ALPN-negotiating) a TLS
        connection to ``u``'s origin.

        Unless the HTTPS keep-alive pool is enabled, the probed
        connection is closed immediately, so the (rarer) h2-wins path
        re-dials TLS for the real request -- one redundant handshake. An
        ``http/1.1`` connection is pooled when ``with_pool`` is on so the
        real request reuses it; ``h2`` is not poolable here. Returns
        ``True`` when the TLS connection established."""
        var tls_cfg = self._config.copy()
        if len(tls_cfg.alpn) == 0:
            tls_cfg.alpn = List[String]()
            tls_cfg.alpn.append("h2")
            tls_cfg.alpn.append("http/1.1")
        var stream = TlsStream.connect_timeout(
            u.host, u.port, tls_cfg^, self._timeout_ms
        )
        var negotiated = stream.alpn_selected()
        if self._tls_pool.enabled() and negotiated != "h2":
            var key = TlsConnectionPool.build_key(u.scheme, u.host, Int(u.port))
            self._tls_pool.release(key, stream^)
        else:
            stream.close()
        return True

    def _send_h3(
        self,
        u: Url,
        method: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
        auth_header: String,
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
                resp = self._run_h3_request(
                    h3, u, method, extra_headers, body, auth_header
                )
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
        var resp = self._run_h3_request(
            fresh, u, method, extra_headers, body, auth_header
        )
        if fresh.is_established():
            self._quic_pool.release(key, fresh^)
        else:
            fresh.close()
        return resp^

    def _send_h2_or_h1_tls(
        self,
        u: Url,
        method: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
        wire: String,
        auth_header: String,
    ) raises -> Response:
        """The proven TLS path: ALPN-negotiate ``["h2", "http/1.1"]``
        and drive the request over HTTP/2 (via the internal
        :class:`Http2ClientConnection`) or HTTP/1.1, returning a
        :class:`Response` either way so the caller can't tell which
        wire was used. Used both as the direct h2/h1 path and as the
        h2 leg of the happy-eyeballs race. ``auth_header`` is the
        effective Authorization value for this hop (the h1 ``wire``
        already carries it; this gates the h2 path).

        When :meth:`with_pool` enabled the HTTPS pool, an idle
        ``http/1.1``-over-TLS connection is reused (skipping the TLS
        handshake) and returned to the pool when the response permits
        keep-alive; a stale pooled connection is dropped and the
        request retried once on a fresh dial (RFC 7230 sec 6.3.1). An
        ``h2`` connection is never pooled here."""
        var pool_on = self._tls_pool.enabled()
        var key = TlsConnectionPool.build_key(u.scheme, u.host, Int(u.port))

        # 1. Reuse a pooled http/1.1-over-TLS connection if available.
        #    The helper owns the moved-in stream so a stale connection
        #    is closed there and signalled back as a miss (None).
        if pool_on:
            var pooled = self._tls_pool.acquire(key)
            if pooled:
                var reused = self._send_h1_tls_pooled_once(
                    key, pooled.take(), wire, body
                )
                if reused:
                    return reused.take()
                # Stale pooled connection: dial fresh below.

        # 2. Fresh dial with ALPN negotiation.
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
                auth_header,
            )
            return resp_h2^
        # HTTP/1.1 over TLS.
        var wire_bytes = wire.as_bytes()
        stream.write_all(Span[UInt8, _](wire_bytes))
        if len(body) > 0:
            stream.write_all(Span[UInt8, _](body))
        if pool_on:
            # Framed read so the connection can return to the pool.
            var can_reuse2 = False
            var resp_f = _read_http_response_framed_tls(stream, can_reuse2)
            if can_reuse2:
                self._tls_pool.release(key, stream^)
            else:
                stream.close()
            return resp_f^
        var resp = _read_http_response_tls(stream)
        stream.close()
        return resp^

    def _send_h1_tls_pooled_once(
        self,
        key: String,
        var st: TlsStream,
        wire: String,
        body: List[UInt8],
    ) raises -> Optional[Response]:
        """Drive one HTTP/1.1 request over a pooled ``TlsStream``.

        Owns ``st``: on a clean keep-alive response the stream is
        released back to the pool and the ``Response`` is returned; on a
        stale connection (write/read failure -- the canonical idle-keep-
        alive-closed signature) the stream is closed and ``None`` is
        returned so the caller dials a fresh connection (RFC 7230
        sec 6.3.1)."""
        var io_failed = False
        try:
            var wb = wire.as_bytes()
            st.write_all(Span[UInt8, _](wb))
            if len(body) > 0:
                st.write_all(Span[UInt8, _](body))
        except:
            io_failed = True
        if not io_failed:
            var can_reuse = False
            var parsed = True
            var resp = Response(0, "", List[UInt8]())
            try:
                resp = _read_http_response_framed_tls(st, can_reuse)
            except:
                parsed = False
            if parsed:
                if can_reuse:
                    self._tls_pool.release(key, st^)
                else:
                    st.close()
                return Optional(resp^)
        # Stale connection: close and signal a pool miss.
        st.close()
        return None

    # ── Streaming request body ────────────────────────────────────────────────

    def send_chunked[
        B: ChunkSource
    ](
        self,
        method: String,
        url: String,
        mut source: B,
        content_type: String = "application/octet-stream",
    ) raises -> Response:
        """Send a request whose body is streamed from a ``ChunkSource``
        using ``Transfer-Encoding: chunked``, without materializing the
        full body in memory.

        For large uploads (multi-MB / multi-GB) this keeps client memory
        bounded to one chunk in flight: the source's ``next(cancel)`` is
        pulled, framed as a chunked-transfer chunk, and written straight
        to the socket. The body is never assembled into a single buffer.

        This is an explicit bounded-memory path over HTTP/1.1 (cleartext
        or TLS, ALPN forced to ``http/1.1``); it deliberately does not
        go through connection pooling, redirects, retries, h2, or h3
        (all of which buffer or re-send the body). Use :meth:`post` /
        :meth:`send` for those.

        Args:
            method: HTTP method (e.g. ``"POST"`` / ``"PUT"``).
            url: Target URL (absolute or relative to ``base_url``).
            source: A ``ChunkSource`` yielding body chunks; pulled to
                exhaustion (``next`` returns ``None``).
            content_type: ``Content-Type`` header value. Defaults to
                ``application/octet-stream``.

        Returns:
            The server's ``Response``.

        Raises:
            NetworkError: On connection or I/O failure.
        """
        var u = Url.parse(self._resolve_url(url))

        var host_header = u.host
        if (u.scheme == "http" and u.port != 80) or (
            u.scheme == "https" and u.port != 443
        ):
            host_header = host_header + ":" + String(Int(u.port))

        var wire = method + " " + u.request_target() + " HTTP/1.1\r\n"
        wire += "Host: " + host_header + "\r\n"
        wire += "User-Agent: " + self._user_agent + "\r\n"
        wire += "Accept: */*\r\n"
        wire += "Content-Type: " + content_type + "\r\n"
        wire += "Transfer-Encoding: chunked\r\n"
        # Streaming uploads do not pool the connection.
        wire += "Connection: close\r\n"
        wire += "\r\n"

        if u.is_tls():
            return self._send_chunked_tls(u, wire, source)
        return self._send_chunked_tcp(u, wire, source)

    def _send_chunked_tcp[
        B: ChunkSource
    ](self, u: Url, wire: String, mut source: B) raises -> Response:
        var stream = _connect_with_fallback(u.host, u.port, self._timeout_ms)
        var wb = wire.as_bytes()
        stream.write_all(Span[UInt8, _](wb))
        # One chunk in flight at a time -- the body is never materialized.
        var cancel = Cancel.never()
        while True:
            var chunk_opt = source.next(cancel)
            if not chunk_opt:
                break
            var chunk = chunk_opt.take()
            if len(chunk) == 0:
                continue
            var frame = _chunk_frame_prefix(len(chunk))
            var fb = frame.as_bytes()
            stream.write_all(Span[UInt8, _](fb))
            stream.write_all(Span[UInt8, _](chunk))
            var crlf = String("\r\n")
            var cb = crlf.as_bytes()
            stream.write_all(Span[UInt8, _](cb))
        var last = String("0\r\n\r\n")
        var lb = last.as_bytes()
        stream.write_all(Span[UInt8, _](lb))
        var resp = _read_http_response_tcp(stream)
        stream.close()
        return resp^

    def _send_chunked_tls[
        B: ChunkSource
    ](self, u: Url, wire: String, mut source: B) raises -> Response:
        # Force http/1.1 -- a chunked upload is an h1 construct.
        var tls_cfg = self._config.copy()
        tls_cfg.alpn = List[String]()
        tls_cfg.alpn.append("http/1.1")
        var stream = TlsStream.connect_timeout(
            u.host, u.port, tls_cfg^, self._timeout_ms
        )
        var wb = wire.as_bytes()
        stream.write_all(Span[UInt8, _](wb))
        var cancel = Cancel.never()
        while True:
            var chunk_opt = source.next(cancel)
            if not chunk_opt:
                break
            var chunk = chunk_opt.take()
            if len(chunk) == 0:
                continue
            var frame = _chunk_frame_prefix(len(chunk))
            var fb = frame.as_bytes()
            stream.write_all(Span[UInt8, _](fb))
            stream.write_all(Span[UInt8, _](chunk))
            var crlf = String("\r\n")
            var cb = crlf.as_bytes()
            stream.write_all(Span[UInt8, _](cb))
        var last = String("0\r\n\r\n")
        var lb = last.as_bytes()
        stream.write_all(Span[UInt8, _](lb))
        var resp = _read_http_response_tls(stream)
        stream.close()
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
        """Send an HTTP request and return the response.

        Follows redirects per the configured :class:`RedirectPolicy`
        (default: follow all, capped at ``max_redirects``), transparently
        decodes a compressed body when ``auto_decompress`` is on, and
        replays / captures cookies when the jar is enabled. When
        :meth:`with_retry` opted in, the whole exchange is retried on a
        transient failure per the :class:`RetryPolicy`.

        Args:
            req: The request to send.

        Returns:
            The final (possibly redirected) ``Response``.

        Raises:
            NetworkError: On I/O failure.
            TooManyRedirects: If the redirect cap is exceeded.
            Error: On a cross-origin redirect refused by a
                ``same_origin_only`` policy.
        """
        if self._retry_enabled:
            return self._send_with_retry(req)
        return self._send_once(req)

    def _send_with_retry(self, req: Request) raises -> Response:
        """Run :meth:`_send_once` under the client retry policy.

        Retries on a raised error or a ``>= 500`` status, up to
        ``policy.max_attempts`` total attempts, gated on method
        idempotency unless the policy opts out. Backoff reuses the
        server-middleware jittered-exponential schedule."""
        var attempts = self._retry.max_attempts
        if attempts < 1:
            attempts = 1
        var gate = (not self._retry.retry_only_idempotent) or _is_idempotent(
            req.method.upper()
        )
        if not gate:
            return self._send_once(req)
        var attempt = 1
        while True:
            try:
                var resp = self._send_once(req)
                if resp.status < 500 or attempt >= attempts:
                    return resp^
            except e:
                if attempt >= attempts:
                    raise e^
            var sleep_ms = _backoff_sleep_ms(self._retry, attempt + 1)
            if sleep_ms > 0:
                _ = libc_nanosleep_ms(sleep_ms)
            attempt += 1

    def _send_once(self, req: Request) raises -> Response:
        """One redirect-following exchange (no retry wrapper).

        Threads the effective Authorization through each hop (cleared on
        a cross-origin redirect unless the policy forwards it), attaches
        / records cookies, auto-records ``Alt-Svc``, and decompresses the
        final body."""
        var current_url = req.url
        var hops = 0
        var method = req.method
        var body = req.body.copy()
        var auth_header = self._auth_header
        var headers = req.headers.copy()
        if self._auto_decompress and not headers.contains("Accept-Encoding"):
            headers.set("Accept-Encoding", "gzip, deflate, br")

        while True:
            # Attach session cookies for this hop (jar wins over a stale
            # caller-supplied Cookie since it carries the live session).
            var cookie_hdr = self._cookies.request_header()
            if cookie_hdr.byte_length() > 0:
                headers.set("Cookie", cookie_hdr)

            var resp = self._do_request(
                method, current_url, headers, body, auth_header
            )

            # Capture Set-Cookie(s) into the jar (no-op if disabled).
            if self._cookies.enabled():
                var set_cookies = resp.headers.get_all("Set-Cookie")
                for i in range(len(set_cookies)):
                    self._cookies.record_set_cookie(set_cookies[i])

            # Transparent Alt-Svc discovery (RFC 7838).
            var alt_svc = resp.headers.get("Alt-Svc")
            if alt_svc.byte_length() > 0:
                try:
                    var pu = Url.parse(current_url)
                    var origin = pu.host + ":" + String(Int(pu.port))
                    self._alt_svc.record(origin, alt_svc, monotonic_now_s())
                except:
                    pass  # malformed header / parse error: ignore

            if not resp.is_redirect():
                return self._maybe_decompress(resp^)

            var location = resp.headers.get("Location")
            var decision = self._redirect_policy.decide(
                current_url, method, resp.status, location, hops
            )

            if decision.action == RedirectAction.FOLLOW:
                current_url = decision.next_url
                method = decision.next_method
                if decision.next_body_dropped:
                    body = List[UInt8]()
                    _ = headers.remove("Content-Type")
                if not decision.forward_authorization:
                    auth_header = String("")
                    _ = headers.remove("Authorization")
                hops += 1
                continue

            if decision.action == RedirectAction.REJECT:
                raise Error(
                    String("RedirectPolicy: cross-origin redirect to '")
                    + location
                    + String("' refused (same_origin_only)")
                )

            # STOP: empty Location or DENY -> surface the 3xx unchanged;
            # otherwise the hop cap was hit -> raise (legacy behaviour).
            if (
                location.byte_length() == 0
                or self._redirect_policy.mode == RedirectMode.DENY
            ):
                return self._maybe_decompress(resp^)
            raise TooManyRedirects(current_url, hops)

    def _maybe_decompress(self, var resp: Response) raises -> Response:
        """Decode a compressed response body in place when
        ``auto_decompress`` is on. Identity / absent / multi-stacked /
        unsupported encodings are left untouched."""
        if not self._auto_decompress:
            return resp^
        var enc = resp.headers.get("Content-Encoding")
        if enc.byte_length() == 0:
            return resp^
        var el = String(enc.strip()).lower()
        if el == "identity" or el == "":
            return resp^
        if el.find(",") >= 0:
            return resp^  # stacked encodings unsupported: leave raw
        try:
            var decoded = decode_content(Span[UInt8, _](resp.body), el)
            resp.body = decoded^
            _ = resp.headers.remove("Content-Encoding")
            resp.headers.set("Content-Length", String(len(resp.body)))
        except:
            pass  # unsupported / corrupt payload: leave the raw bytes
        return resp^

    def _do_request(
        self,
        method: String,
        url: String,
        extra_headers: HeaderMap,
        body: List[UInt8],
        auth_header: String,
    ) raises -> Response:
        """Perform a single HTTP/1.1 request (no redirect handling).

        Args:
            method: HTTP method string.
            url: Full URL string.
            extra_headers: Headers from the original request.
            body: Request body bytes.
            auth_header: Effective Authorization value for this hop
                (the redirect policy may have cleared it across a
                cross-origin redirect).

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
        # The HTTPS pool keeps the http/1.1-over-TLS connection alive;
        # the wire below must then advertise keep-alive (an h2 dial
        # ignores the h1 wire entirely, so this is harmless there).
        var tls_pool_enabled = (
            self._tls_pool._addr != 0
            and u.is_tls()
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
        if pool_enabled or tls_pool_enabled:
            wire += "Connection: keep-alive\r\n"
        else:
            wire += "Connection: close\r\n"
        wire += "Accept: */*\r\n"

        # Authorization header from the effective (redirect-gated) auth
        if auth_header.byte_length() > 0:
            wire += "Authorization: " + auth_header + "\r\n"

        # Forward caller-supplied headers (skip Host — already set)
        for i in range(extra_headers.len()):
            var k = extra_headers._keys[i]
            if k.lower() != "host":
                # Only skip caller's Authorization when the effective auth
                # is set, matching the h2/h2c paths (_build_h2_request_headers).
                if (
                    k.lower() == "authorization"
                    and auth_header.byte_length() > 0
                ):
                    continue
                wire += k + ": " + extra_headers._values[i] + "\r\n"

        if len(body) > 0:
            wire += "Content-Length: " + String(len(body)) + "\r\n"

        wire += "\r\n"  # end of headers

        # ── Connect and send ───────────────────────────────────────────────
        if u.is_tls():
            # HTTP/3 when the policy says so (prefer_h3 or a fresh
            # cached Alt-Svc advert). For idempotent methods we race h3
            # against the h2/h1 TLS path concurrently (happy-eyeballs):
            # whichever establishes + completes first wins, and a dead
            # h3 path never stalls the request. For non-idempotent
            # methods we must not duplicate the request, so we try h3
            # then fall back sequentially. Any QUIC/h3 failure falls
            # through transparently to the proven h2/h1 path.
            if (
                self.h3_wire_choice("https", u.host, u.port)
                == H3WireChoice.HTTP_3
            ):
                if _is_idempotent(method):
                    # Happy-eyeballs: race only the *connection*
                    # establishment, then send the request once on the
                    # winner (h3 preferred). Racing connects -- not whole
                    # requests -- means the idempotent request is never
                    # duplicated on the wire.
                    var winner = race_h3_h2_connect(
                        _race_connect_leg,
                        Int(UnsafePointer(to=self)),
                        url,
                    )
                    if winner == RACE_H3:
                        try:
                            return self._send_h3(
                                u, method, extra_headers, body, auth_header
                            )
                        except:
                            pass  # h3 dropped post-connect: fall back
                    # RACE_H2 or RACE_NONE (or an h3 post-connect drop):
                    # use the proven TLS path. On RACE_NONE both connects
                    # failed; _send_h2_or_h1_tls re-dials and surfaces the
                    # real error.
                    return self._send_h2_or_h1_tls(
                        u, method, extra_headers, body, wire, auth_header
                    )
                try:
                    return self._send_h3(
                        u, method, extra_headers, body, auth_header
                    )
                except:
                    pass  # transparent fallback to h2/h1
            return self._send_h2_or_h1_tls(
                u, method, extra_headers, body, wire, auth_header
            )
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
                    auth_header,
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
                    auth_header,
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
