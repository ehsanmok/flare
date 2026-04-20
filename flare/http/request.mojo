"""HTTP request type."""

from std.collections import Dict
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
        params:  Path parameters extracted by ``Router`` (empty unless a
                 ``Router`` handled the request). Maps parameter name
                 (e.g. ``"id"``) to the matched segment value.

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
    var params: Dict[String, String]

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
        self.params = Dict[String, String]()

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
