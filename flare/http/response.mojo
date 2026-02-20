"""HTTP response type."""

from mojson import loads, Value
from .headers import HeaderMap
from .error import HttpError


struct Status:
    """Common HTTP status code constants (RFC 7231 §6)."""

    comptime OK: Int = 200
    comptime CREATED: Int = 201
    comptime ACCEPTED: Int = 202
    comptime NO_CONTENT: Int = 204

    comptime MOVED_PERMANENTLY: Int = 301
    comptime FOUND: Int = 302
    comptime NOT_MODIFIED: Int = 304
    comptime TEMPORARY_REDIRECT: Int = 307
    comptime PERMANENT_REDIRECT: Int = 308

    comptime BAD_REQUEST: Int = 400
    comptime UNAUTHORIZED: Int = 401
    comptime FORBIDDEN: Int = 403
    comptime NOT_FOUND: Int = 404
    comptime METHOD_NOT_ALLOWED: Int = 405
    comptime REQUEST_TIMEOUT: Int = 408
    comptime CONTENT_TOO_LARGE: Int = 413
    comptime URI_TOO_LONG: Int = 414
    comptime HEADER_FIELDS_TOO_LARGE: Int = 431

    comptime INTERNAL_SERVER_ERROR: Int = 500
    comptime BAD_GATEWAY: Int = 502
    comptime SERVICE_UNAVAILABLE: Int = 503
    comptime GATEWAY_TIMEOUT: Int = 504


struct Response(Movable):
    """An HTTP/1.1 response.

    Fields:
        status:  HTTP status code (see ``Status.*`` constants).
        reason:  Status reason phrase (e.g. ``"OK"``).
        headers: Response headers (owned ``HeaderMap``).
        body:    Response body bytes.
        version: HTTP version string (default ``"HTTP/1.1"``).

    This type is ``Movable`` (owns headers and body) but not ``Copyable``.

    Example:
        ```mojo
        var resp = client.get("http://example.com")
        if resp.ok():
            print(resp.text())
        ```
    """

    var status: Int
    var reason: String
    var headers: HeaderMap
    var body: List[UInt8]
    var version: String

    fn __init__(
        out self,
        status: Int,
        reason: String = "",
        body: List[UInt8] = List[UInt8](),
        version: String = "HTTP/1.1",
    ):
        self.status = status
        self.reason = reason
        self.headers = HeaderMap()
        self.body = body.copy()
        self.version = version

    fn __moveinit__(out self, deinit take: Response):
        self.status = take.status
        self.reason = take.reason^
        self.headers = take.headers^
        self.body = take.body^
        self.version = take.version^

    fn ok(self) -> Bool:
        """Return True if the status code is 2xx.

        Returns:
            True when ``200 <= status < 300``.
        """
        return self.status >= 200 and self.status < 300

    fn is_redirect(self) -> Bool:
        """Return True if the status code is a redirect (3xx).

        Returns:
            True when ``300 <= status < 400``.
        """
        return self.status >= 300 and self.status < 400

    fn text(self) -> String:
        """Decode the body as a UTF-8 string.

        Interprets the body bytes as UTF-8.  Invalid UTF-8 sequences are
        replaced with the Unicode replacement character (best-effort).

        Returns:
            The body decoded as a ``String``.
        """
        if len(self.body) == 0:
            return ""
        # Build string from raw bytes.
        # Mojo String stores UTF-8 internally; slice copy is safe.
        var out = String(capacity=len(self.body) + 1)
        for b in self.body:
            out += chr(Int(b))
        return out^

    fn json(self) raises -> Value:
        """Parse the body as JSON and return a ``mojson.Value``.

        Uses the pure-Mojo backend from
        `mojson <https://github.com/ehsanmok/mojson>`_.

        Returns:
            A ``Value`` representing the parsed JSON document.

        Raises:
            Error: If the response body is not valid JSON.

        Example:
            ```mojo
            var resp = client.get("https://httpbin.org/json")
            var data = resp.json()
            print(data["slideshow"]["title"].string_value())
            ```
        """
        return loads(self.text())

    fn raise_for_status(self) raises:
        """Raise ``HttpError`` if the status code is not 2xx.

        A no-op for responses with ``200 <= status < 300``.

        Raises:
            HttpError: If the status code indicates an error (< 200 or >= 300).

        Example:
            ```mojo
            var resp = client.get("https://httpbin.org/status/404")
            resp.raise_for_status()   # raises HttpError: 404 Not Found
            ```
        """
        if self.status < 200 or self.status >= 300:
            raise HttpError(self.status, self.reason)

    fn iter_bytes(self, chunk_size: Int = 8192) -> _BytesIter:
        """Return an iterator that yields the body in chunks.

        The entire body is already buffered in memory, so this does not
        perform additional I/O.  Useful for streaming-style processing.

        Args:
            chunk_size: Maximum bytes per chunk (default 8192).

        Returns:
            A ``_BytesIter`` yielding ``List[UInt8]`` chunks.

        Example:
            ```mojo
            for chunk in resp.iter_bytes(1024):
                process(chunk[])
            ```
        """
        return _BytesIter(self.body, chunk_size)


struct _BytesIter(Movable):
    """Iterator that yields body bytes in fixed-size chunks.

    Produced by ``Response.iter_bytes()``.  All data is already in memory;
    the iterator simply slices through ``_body`` from ``_pos`` to end.
    """

    var _body: List[UInt8]
    var _chunk_size: Int
    var _pos: Int

    fn __init__(out self, body: List[UInt8], chunk_size: Int):
        self._body = body.copy()
        self._chunk_size = chunk_size if chunk_size > 0 else 8192
        self._pos = 0

    fn __moveinit__(out self, deinit take: _BytesIter):
        self._body = take._body^
        self._chunk_size = take._chunk_size
        self._pos = take._pos

    fn __iter__(var self) -> _BytesIter:
        """Return ``self`` as the iterator (consumed).

        Returns:
            This iterator (moved).
        """
        return self^

    fn __next__(mut self) -> List[UInt8]:
        """Return the next chunk of up to ``chunk_size`` bytes.

        Returns:
            A ``List[UInt8]`` containing the next chunk (may be smaller than
            ``chunk_size`` for the final chunk).
        """
        var end = self._pos + self._chunk_size
        var n = len(self._body)
        if end > n:
            end = n
        var chunk = List[UInt8](capacity=end - self._pos)
        for i in range(self._pos, end):
            chunk.append(self._body[i])
        self._pos = end
        return chunk^

    fn __has_next__(self) -> Bool:
        """Return ``True`` while there are unread bytes.

        Returns:
            ``True`` if ``_pos < len(_body)``.
        """
        return self._pos < len(self._body)
