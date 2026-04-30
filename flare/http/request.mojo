"""HTTP request type."""

from std.collections import Dict, Optional
from std.memory import UnsafePointer, alloc
from json import loads, Value
from .headers import HeaderMap
from .cookie import Cookie, CookieJar, parse_cookie_header
from ..net import IpAddr, SocketAddr
from ..tls.acceptor import TlsInfo


struct Method:
    """HTTP request method string constants (RFC 7231 §4)."""

    comptime GET: String = "GET"
    comptime POST: String = "POST"
    comptime PUT: String = "PUT"
    comptime PATCH: String = "PATCH"
    comptime DELETE: String = "DELETE"
    comptime HEAD: String = "HEAD"
    comptime OPTIONS: String = "OPTIONS"
    comptime CONNECT: String = "CONNECT"
    comptime TRACE: String = "TRACE"


struct Request(Movable):
    """An HTTP/1.1 request.

    Fields:
        method: HTTP method string (use ``Method.*`` constants).
        url: Request target (path + query), e.g. ``"/items?page=1"``.
        headers: Request headers (owned ``HeaderMap``).
        body: Request body bytes (empty for GET/HEAD).
        version: HTTP version string (default ``"HTTP/1.1"``).
        peer: Kernel-reported peer address. Populated by
                 the reactor at accept time from ``TcpStream.peer_addr()``.
                 Direct ``Request`` constructions (tests, the client side)
                 default to ``SocketAddr.localhost(0)`` so the field is
                 always observable without having to special-case "did the
                 reactor populate it." Note: this is the *kernel's* view
                 of the peer; flare does not interpret ``X-Forwarded-For``,
                 ``Forwarded:``, or PROXY-protocol metadata.
        expose_errors: When ``True``, 4xx / 5xx responses generated from
                 a raised ``Error`` may include the verbatim message in
                 their body — useful in local dev. **Default ``False``**
                 so production servers send a fixed status reason and
                 log the message (with any user-controlled bytes) to
                 stderr rather than echoing it back. Carried on the
                 request because flare is shared-nothing thread-per-core
                 and the policy is set per-server (per-``ServerConfig``);
                 the reactor copies ``ServerConfig.expose_error_messages``
                 onto every parsed ``Request`` and ``_bad_request_from_error``
                 reads it. Closes criticism §2.7.

    Path parameters extracted by ``Router`` live on a private field that
    is lazily allocated on the first ``Router`` match. Handlers that
    never go through a ``Router`` (the plaintext bench, pure static
    handlers) therefore pay zero allocation cost per request. Access
    params via ``req.params()`` or the convenience ``req.param(name)``
    / ``req.has_param(name)`` helpers.

    This type is ``Movable`` (owns the header map and body) but not
    ``Copyable`` to avoid accidental deep copies.

    Example:
        ```mojo
        var req = Request(method=Method.POST, url="http://api.example.com/items")
        req.headers.set("Content-Type", "application/json")
        req.body = '{"name":"flare"}'.as_bytes()
        ```
    """

    var method: String
    var url: String
    var headers: HeaderMap
    var body: List[UInt8]
    var version: String
    var peer: SocketAddr
    """Kernel-reported peer ``SocketAddr``. See struct docstring."""
    var expose_errors: Bool
    """Whether 4xx / 5xx responses may echo raised ``Error`` messages.
    Default False; the reactor copies
    ``ServerConfig.expose_error_messages`` onto every parsed request.
    See struct docstring."""
    var tls_info: Optional[TlsInfo]
    """Per-request TLS metadata.

    ``Some(TlsInfo)`` when the connection terminated TLS at flare's
    ``TlsAcceptor`` (set at handshake time, threaded onto every
    request on that connection). ``None`` for plain-HTTP
    connections. Handlers can inspect ``tls_info.alpn_protocol``,
    ``tls_info.sni_host``, ``tls_info.client_cert_subject``
    (mTLS), etc. to make per-request decisions.

    The reactor-side handshake state machine that populates this
    field with live values lands as a follow-up to S3.1; until
    then ``tls_info`` is always ``None`` (the field is in place
    so handlers can write production-shape code today against
    the stable shape).
    """
    var _params: Optional[
        UnsafePointer[Dict[String, String], MutExternalOrigin]
    ]
    """Lazily-allocated path-params table. ``None`` by default; ``Router``
    allocates the underlying ``Dict`` on the first path-parameter
    extraction via ``params_mut()``. The plaintext-bench fast path
    therefore pays zero ``Dict`` allocation / move cost per request,
    which closes the ~3% gap to the baseline (``Dict()`` was
    measured to cost that much per request on TFB plaintext).

    Owned by this ``Request`` — the destructor frees the ``Dict`` and
    the allocation if present. Users should access params via
    ``params()`` / ``param()`` / ``has_param()``, never through the
    raw pointer.

    Modeled as ``Optional[UnsafePointer[...]]`` (Mojo 1.0.0b1: pointers
    are non-null by design; nullable storage uses ``Optional`` with the
    null address as the niche value)."""

    def __init__(
        out self,
        method: String,
        url: String,
        body: List[UInt8] = List[UInt8](),
        version: String = "HTTP/1.1",
        peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
        expose_errors: Bool = False,
        tls_info: Optional[TlsInfo] = Optional[TlsInfo](),
    ):
        """Create a new HTTP request.

        Args:
            method: HTTP method string.
            url: Full URL or request target.
            body: Request body bytes; empty by default.
            version: HTTP version; ``"HTTP/1.1"`` by default.
            peer: Peer ``SocketAddr``; defaults to ``127.0.0.1:0``
                           for direct constructions. The reactor passes
                           the kernel-reported peer captured at accept
                           time.
            expose_errors: Whether handler / extractor error messages
                           may flow into the response body. Default
                           ``False`` (production-safe). The reactor
                           copies this from
                           ``ServerConfig.expose_error_messages``.
            tls_info: Per-request TLS metadata (Track 5.2).
                           ``Some(TlsInfo)`` when the connection
                           terminated TLS at flare's ``TlsAcceptor``;
                           ``None`` (default) for plain HTTP. Direct
                           Request constructions in tests / clients
                           default to ``None``; the reactor populates
                           it from the ``TlsAcceptor`` handshake when
                           that lands.
        """
        self.method = method
        self.url = url
        self.headers = HeaderMap()
        self.body = body.copy()
        self.version = version
        self.peer = peer
        self.expose_errors = expose_errors
        self.tls_info = tls_info.copy()
        self._params = None

    def __del__(deinit self):
        if self._params:
            var p = self._params.value()
            p.destroy_pointee()
            p.free()

    def has_params(self) -> Bool:
        """Return True if a ``Router`` populated this request's path params."""
        return Bool(self._params)

    def params_mut(mut self) -> ref[self._params] Dict[String, String]:
        """Lazily allocate and return a mutable reference to the path-params dict.

        ``Router`` calls this when it captures path parameters on a
        matched route. Tests and examples can call it to construct a
        ``Request`` with synthetic path params without going through a
        Router (e.g. when unit-testing a handler that reads
        ``req.param("id")``). The underlying ``Dict`` is allocated on
        first call, so requests that never see a Router pay zero
        allocation cost.

        Production handlers should not call this — Router owns
        param-population on the request path, and writing through this
        accessor mid-request would be surprising. It's public only so
        the test surface doesn't have to reach for an underscored
        name.
        """
        if not self._params:
            # Use Mojo's native allocator (``std.memory.alloc`` returns a
            # ``MutExternalOrigin``-tagged pointer) rather than libc
            # ``malloc``/``free`` via FFI: ``external_call["free", ...]``
            # conflicts with the stdlib's own ``free`` declaration at
            # MLIR legalization time when this module is pulled into a
            # fuzz-environment compile (mozz harness).
            var ptr = alloc[Dict[String, String]](1)
            ptr.init_pointee_move(Dict[String, String]())
            self._params = ptr
        return self._params.value()[]

    def param(self, name: String) raises -> String:
        """Return path param ``name``. Raises ``Error`` if missing.

        Equivalent to ``req.params()[name]`` but does not allocate an
        empty ``Dict`` when no params are present (raises immediately
        instead).
        """
        if not self._params:
            raise Error("path param not found: " + name)
        return self._params.value()[][name]

    def has_param(self, name: String) -> Bool:
        """Return True if path param ``name`` is set (no allocation)."""
        if not self._params:
            return False
        return name in self._params.value()[]

    def query_param(self, name: String) -> String:
        """Return the first query-string value for ``name``, or ``""``.

        Scans the URL's query string (the substring after ``?``, stopping
        at ``#``) for ``name=value`` pairs separated by ``&``. Case-sensitive
        key match. Does not percent-decode; callers should decode if they
        expect encoded bytes. Allocation-free on requests that have no
        query string (fast path checks for ``?`` in the URL first).

        Args:
            name: Query parameter name.

        Returns:
            The first value for ``name``, or an empty string if absent.
        """
        var n = self.url.byte_length()
        var p = self.url.unsafe_ptr()
        var q = -1
        for i in range(n):
            if p[i] == 63:  # '?'
                q = i + 1
                break
        if q < 0:
            return ""
        # Strip fragment.
        var end = n
        for i in range(q, n):
            if p[i] == 35:  # '#'
                end = i
                break
        var key_n = name.byte_length()
        var kp = name.unsafe_ptr()
        var cursor = q
        while cursor < end:
            # Find end of this pair.
            var pair_end = end
            for i in range(cursor, end):
                if p[i] == 38:  # '&'
                    pair_end = i
                    break
            # Find '=' within the pair.
            var eq = pair_end
            for i in range(cursor, pair_end):
                if p[i] == 61:  # '='
                    eq = i
                    break
            var this_key_n = eq - cursor
            if this_key_n == key_n:
                var matched = True
                for j in range(key_n):
                    if p[cursor + j] != kp[j]:
                        matched = False
                        break
                if matched:
                    if eq < pair_end:
                        return String(
                            unsafe_from_utf8=self.url.as_bytes()[
                                eq + 1 : pair_end
                            ]
                        )
                    return ""
            cursor = pair_end + 1
        return ""

    def has_query_param(self, name: String) -> Bool:
        """Return True if query parameter ``name`` is present (even if empty).

        Args:
            name: Query parameter name.

        Returns:
            True if the key is present in the URL's query string.
        """
        var n = self.url.byte_length()
        var p = self.url.unsafe_ptr()
        var q = -1
        for i in range(n):
            if p[i] == 63:  # '?'
                q = i + 1
                break
        if q < 0:
            return False
        var end = n
        for i in range(q, n):
            if p[i] == 35:  # '#'
                end = i
                break
        var key_n = name.byte_length()
        var kp = name.unsafe_ptr()
        var cursor = q
        while cursor < end:
            var pair_end = end
            for i in range(cursor, end):
                if p[i] == 38:
                    pair_end = i
                    break
            var eq = pair_end
            for i in range(cursor, pair_end):
                if p[i] == 61:
                    eq = i
                    break
            var this_key_n = eq - cursor
            if this_key_n == key_n:
                var matched = True
                for j in range(key_n):
                    if p[cursor + j] != kp[j]:
                        matched = False
                        break
                if matched:
                    return True
            cursor = pair_end + 1
        return False

    def text(self) -> String:
        """Decode the request body as a UTF-8 string.

        Returns:
            The body decoded as a ``String``. Empty string if body is empty.
        """
        if len(self.body) == 0:
            return ""
        var out = String(capacity=len(self.body) + 1)
        for b in self.body:
            out += chr(Int(b))
        return out^

    def json(self) raises -> Value:
        """Parse the request body as JSON.

        Returns:
            A ``json.Value`` representing the parsed JSON document.

        Raises:
            Error: If the body is not valid JSON.
        """
        return loads(self.text())

    def content_length(self) -> Int:
        """Return the Content-Length header value, or 0 if absent."""
        var cl = self.headers.get("content-length")
        if cl.byte_length() == 0:
            return 0
        var result = 0
        for i in range(cl.byte_length()):
            var c = Int(cl.unsafe_ptr()[i])
            if c < 48 or c > 57:
                break
            result = result * 10 + (c - 48)
        return result

    def cookies(self) -> CookieJar:
        """Parse the ``Cookie`` request header(s) into a ``CookieJar``.

        Walks every ``Cookie`` header value (multiple headers are
        legal under RFC 7230 paragraph 3.2.2) and feeds each to
        ``parse_cookie_header``. Returns an empty jar if no
        ``Cookie`` header is present.
        """
        var jar = CookieJar()
        var values = self.headers.get_all("cookie")
        if len(values) == 0:
            return jar^
        for v in values:
            var parsed = parse_cookie_header(v)
            for c in parsed:
                jar.set(c.copy())
        return jar^

    def cookie(self, name: String) -> String:
        """Return the value of cookie ``name`` from the ``Cookie`` header."""
        var values = self.headers.get_all("cookie")
        for v in values:
            var parsed = parse_cookie_header(v)
            for c in parsed:
                if c.name == name:
                    return c.value
        return ""

    def has_cookie(self, name: String) -> Bool:
        """Return ``True`` if cookie ``name`` is set on this request."""
        var values = self.headers.get_all("cookie")
        for v in values:
            var parsed = parse_cookie_header(v)
            for c in parsed:
                if c.name == name:
                    return True
        return False

    def connection_close(self) -> Bool:
        """Return True if ``Connection: close`` is set."""
        var conn = self.headers.get("connection")
        if conn.byte_length() == 0:
            return False
        var lower = String(capacity=conn.byte_length())
        for i in range(conn.byte_length()):
            var c = conn.unsafe_ptr()[i]
            if c >= 65 and c <= 90:
                lower += chr(Int(c) + 32)
            else:
                lower += chr(Int(c))
        return lower == "close"
