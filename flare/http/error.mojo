"""HTTP-level error types.

Provides ``HttpError`` (raised on non-2xx responses when
``raise_for_status()`` is called) and ``TooManyRedirects`` (raised when
a redirect chain exceeds the configured limit).

Example:
    ```mojo
    from flare.http import HttpClient, HttpError

    def main() raises:
        var client = HttpClient()
        try:
            client.get("https://httpbin.org/status/404").raise_for_status()
        except e: HttpError:
            print("HTTP", e.status, e.reason)
    ```
"""

from std.format import Writable, Writer


struct HttpError(Copyable, Movable, Writable):
    """Raised by ``Response.raise_for_status()`` on non-2xx responses.

    Fields:
        status: The HTTP status code (e.g. 404, 500).
        reason: The HTTP reason phrase (e.g. ``"Not Found"``).
        url: The URL that returned the error (empty if unknown).

    Example:
        ```mojo
        raise HttpError(404, "Not Found", "https://example.com/missing")
        ```
    """

    var status: Int
    var reason: String
    var url: String

    def __init__(out self, status: Int, reason: String = "", url: String = ""):
        """Initialise an ``HttpError``.

        Args:
            status: HTTP status code (e.g. 404).
            reason: HTTP reason phrase (e.g. ``"Not Found"``).
            url: URL that returned the error.
        """
        self.status = status
        self.reason = reason
        self.url = url

    def write_to[W: Writer, //](self, mut writer: W):
        """Write the error description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write("HttpError: ", self.status)
        if self.reason.byte_length() > 0:
            writer.write(" ", self.reason)
        if self.url.byte_length() > 0:
            writer.write(" (", self.url, ")")


struct TooManyRedirects(Copyable, Movable, Writable):
    """Raised when a redirect chain exceeds the configured maximum.

    Fields:
        url: The URL at which the limit was reached.
        count: The number of redirects that were followed.

    Example:
        ```mojo
        raise TooManyRedirects("https://example.com", 10)
        ```
    """

    var url: String
    var count: Int

    def __init__(out self, url: String, count: Int):
        """Initialise a ``TooManyRedirects`` error.

        Args:
            url: The URL that caused the limit to be exceeded.
            count: Number of redirects followed before giving up.
        """
        self.url = url
        self.count = count

    def write_to[W: Writer, //](self, mut writer: W):
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
