"""HTTP request type."""

from std.collections import Dict
from std.ffi import c_size_t, external_call
from std.memory import UnsafePointer
from std.sys.info import size_of
from json import loads, Value
from .headers import HeaderMap


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
        method:  HTTP method string (use ``Method.*`` constants).
        url:     Request target (path + query), e.g. ``"/items?page=1"``.
        headers: Request headers (owned ``HeaderMap``).
        body:    Request body bytes (empty for GET/HEAD).
        version: HTTP version string (default ``"HTTP/1.1"``).

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
    var _params: UnsafePointer[Dict[String, String], MutExternalOrigin]
    """Lazily-allocated path-params table. Null by default; ``Router``
    allocates the underlying ``Dict`` on the first path-parameter
    extraction via ``params_mut()``. The plaintext-bench fast path
    therefore pays zero ``Dict`` allocation / move cost per request,
    which closes the ~3% gap to the v0.3.0 baseline (``Dict()`` was
    measured to cost that much per request on TFB plaintext).

    Owned by this ``Request`` — the destructor frees the ``Dict`` and
    the allocation if present. Users should access params via
    ``params()`` / ``param()`` / ``has_param()``, never through the
    raw pointer."""

    def __init__(
        out self,
        method: String,
        url: String,
        body: List[UInt8] = List[UInt8](),
        version: String = "HTTP/1.1",
    ):
        """Create a new HTTP request.

        Args:
            method:  HTTP method string.
            url:     Full URL or request target.
            body:    Request body bytes; empty by default.
            version: HTTP version; ``"HTTP/1.1"`` by default.
        """
        self.method = method
        self.url = url
        self.headers = HeaderMap()
        self.body = body.copy()
        self.version = version
        self._params = UnsafePointer[Dict[String, String], MutExternalOrigin]()

    def __del__(deinit self):
        if self._params:
            self._params.destroy_pointee()
            _ = external_call["free", NoneType](
                self._params.bitcast[NoneType]()
            )

    def has_params(self) -> Bool:
        """Return True if a ``Router`` populated this request's path params."""
        return Bool(self._params)

    def _params_mut(mut self) -> ref[self._params] Dict[String, String]:
        """Router-internal: lazily allocate and return a mutable ref.

        Not part of the public API. The ``Router`` calls this when it
        captures path parameters on a matched route so the underlying
        ``Dict`` is only allocated when a route actually has parameters.
        """
        if not self._params:
            # libc malloc via FFI (Mojo's stdlib allocators do not
            # currently expose an ``alloc`` factory for ``Dict`` under
            # the ``MutExternalOrigin`` instantiation we use on this
            # field).
            var raw = external_call[
                "malloc", UnsafePointer[UInt8, MutExternalOrigin]
            ](c_size_t(size_of[Dict[String, String]]()))
            var ptr = raw.bitcast[Dict[String, String]]()
            ptr.init_pointee_move(Dict[String, String]())
            self._params = ptr
        return self._params[]

    def param(self, name: String) raises -> String:
        """Return path param ``name``. Raises ``Error`` if missing.

        Equivalent to ``req.params()[name]`` but does not allocate an
        empty ``Dict`` when no params are present (raises immediately
        instead).
        """
        if not self._params:
            raise Error("path param not found: " + name)
        return self._params[][name]

    def has_param(self, name: String) -> Bool:
        """Return True if path param ``name`` is set (no allocation)."""
        if not self._params:
            return False
        return name in self._params[]

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
