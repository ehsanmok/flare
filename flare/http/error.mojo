"""HTTP-level error types.

Provides ``HttpError`` (raised on non-2xx responses when
``raise_for_status()`` is called) and ``TooManyRedirects`` (raised when
a redirect chain exceeds the configured limit).

Example:
    ```mojo
    from flare.http import HttpClient, HttpError

    fn main() raises:
        var client = HttpClient()
        try:
            client.get("https://httpbin.org/status/404").raise_for_status()
        except e: HttpError:
            print("HTTP", e.status, e.reason)
    ```
"""

from format import Writable, Writer


struct HttpError(Copyable, Movable, Stringable, Writable):
    """Raised by ``Response.raise_for_status()`` on non-2xx responses.

    Fields:
        status: The HTTP status code (e.g. 404, 500).
        reason: The HTTP reason phrase (e.g. ``"Not Found"``).
        url:    The URL that returned the error (empty if unknown).

    Example:
        ```mojo
        raise HttpError(404, "Not Found", "https://example.com/missing")
        ```
    """

    var status: Int
    var reason: String
    var url: String

    fn __init__(out self, status: Int, reason: String = "", url: String = ""):
        """Initialise an ``HttpError``.

        Args:
            status: HTTP status code (e.g. 404).
            reason: HTTP reason phrase (e.g. ``"Not Found"``).
            url:    URL that returned the error.
        """
        self.status = status
        self.reason = reason
        self.url = url

    fn __copyinit__(out self, copy: HttpError):
        self.status = copy.status
        self.reason = copy.reason
        self.url = copy.url

    fn __moveinit__(out self, deinit take: HttpError):
        self.status = take.status
        self.reason = take.reason^
        self.url = take.url^

    fn __str__(self) -> String:
        """Return a human-readable description of the error.

        Returns:
            A string such as ``"HttpError: 404 Not Found (https://example.com)"``.
        """
        var s = "HttpError: " + String(self.status)
        if len(self.reason) > 0:
            s += " " + self.reason
        if len(self.url) > 0:
            s += " (" + self.url + ")"
        return s^

    fn write_to[W: Writer, //](self, mut writer: W):
        """Write the error description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("HttpError: ", self.status)
        if len(self.reason) > 0:
            writer.write(" ", self.reason)
        if len(self.url) > 0:
            writer.write(" (", self.url, ")")


struct TooManyRedirects(Copyable, Movable, Stringable, Writable):
    """Raised when a redirect chain exceeds the configured maximum.

    Fields:
        url:   The URL at which the limit was reached.
        count: The number of redirects that were followed.

    Example:
        ```mojo
        raise TooManyRedirects("https://example.com", 10)
        ```
    """

    var url: String
    var count: Int

    fn __init__(out self, url: String, count: Int):
        """Initialise a ``TooManyRedirects`` error.

        Args:
            url:   The URL that caused the limit to be exceeded.
            count: Number of redirects followed before giving up.
        """
        self.url = url
        self.count = count

    fn __copyinit__(out self, copy: TooManyRedirects):
        self.url = copy.url
        self.count = copy.count

    fn __moveinit__(out self, deinit take: TooManyRedirects):
        self.url = take.url^
        self.count = take.count

    fn __str__(self) -> String:
        """Return a human-readable description of the error.

        Returns:
            A string such as ``"TooManyRedirects: 10 redirects at https://..."``
        """
        return (
            "TooManyRedirects: "
            + String(self.count)
            + " redirects at "
            + self.url
        )

    fn write_to[W: Writer, //](self, mut writer: W):
        """Write the error description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write(
            "TooManyRedirects: ",
            self.count,
            " redirects at ",
            self.url,
        )
