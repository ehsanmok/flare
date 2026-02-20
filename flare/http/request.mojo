"""HTTP request type."""

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
        url:     Full URL string, e.g. ``"https://example.com/path?q=1"``.
        headers: Request headers (owned ``HeaderMap``).
        body:    Request body bytes (empty for GET/HEAD).
        version: HTTP version string (default ``"HTTP/1.1"``).

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

    fn __init__(
        out self,
        method: String,
        url: String,
        body: List[UInt8] = List[UInt8](),
        version: String = "HTTP/1.1",
    ):
        """Create a new HTTP request.

        Args:
            method:  HTTP method string.
            url:     Full URL.
            body:    Request body bytes; empty by default.
            version: HTTP version; ``"HTTP/1.1"`` by default.
        """
        self.method = method
        self.url = url
        self.headers = HeaderMap()
        self.body = body.copy()
        self.version = version

    fn __moveinit__(out self, deinit take: Request):
        self.method = take.method^
        self.url = take.url^
        self.headers = take.headers^
        self.body = take.body^
        self.version = take.version^
