"""One streaming response type over HTTP/1.1, HTTP/2 and HTTP/3.

``HttpStreamResponse`` is what :meth:`flare.http.HttpClient.get_streaming`
and its siblings hand back. It carries the response head -- status,
reason, headers -- and pulls the body incrementally, so a multi-gigabyte
download costs one buffer rather than one allocation the size of the
body.

Three backends sit behind it:

- ``HttpDownload[_H2Transport]`` for HTTP/1.1 over either TCP or TLS,
  since :class:`_H2Transport` already erases that distinction;
- :class:`Http2Download` for an h2 stream;
- :class:`Http3Download` for an h3 stream.

The erasure follows the one idiom the repo already uses: a
:class:`flare.runtime.Pool` address per backend, exactly one of them
non-zero. ``Pool.alloc_move`` never returns 0, so the zero address
doubles as the "closed" sentinel and ``close`` is idempotent. This is
the same shape :class:`_H2Transport` uses for TCP-versus-TLS, one level
down.

The alternative -- a ``_kind: Int`` tag plus one address -- reads more
naturally but does not work as well here: ``Pool[T]`` is monomorphised
per ``T``, so every ``get_ptr`` and ``free`` still has to name its
concrete type at the call site. The tag would buy nothing and cost a
field.
"""

from std.collections import Optional

from ...runtime.pool import Pool
from ..error import HttpError
from ..headers import HeaderMap
from .download import HttpDownload
from .h2_download import Http2Download
from .h2_transport import _H2Transport
from .h3_download import Http3Download


comptime _DEFAULT_READ_ALL_LIMIT: Int = 16 * 1024 * 1024
"""Default ceiling for :meth:`HttpStreamResponse.read_all`.

16 MiB. ``read_all`` exists for the case where you know the body is
small; a caller who does not know reaches for ``read_chunk`` instead, so
the default is deliberately low enough to catch a mistake rather than
high enough to accommodate one."""


struct HttpStreamResponse(Movable):
    """A response whose body is pulled incrementally, on any wire.

    The head is available as soon as this is returned. The body is not
    buffered: call :meth:`read_chunk` until it returns an empty list, or
    :meth:`read_all` when the body is known to be small.

    Exactly one backend address is non-zero. ``close`` frees it and
    zeroes the field, so the destructor is a no-op afterwards and
    double-close is safe.

    Example:
        ```mojo
        with HttpClient() as c:
            var r = c.get_streaming("https://example.com/big.bin")
            r.raise_for_status()
            var total = 0
            while True:
                var chunk = r.read_chunk(65536)
                if len(chunk) == 0:
                    break
                total += len(chunk)
            r.close()
        ```
    """

    var status: Int
    """HTTP status code from the response head."""

    var reason: String
    """Reason phrase. Empty on HTTP/2 and HTTP/3, which do not send one."""

    var headers: HeaderMap
    """Response headers, lowercased."""

    var trailers: HeaderMap
    """Trailing headers. Empty until the body reaches end of stream, and
    on wires or responses that carry none."""

    var _wire: String
    """``"http/1.1"``, ``"h2"`` or ``"h3"`` -- the wire this was served
    on, after negotiation."""

    var _h1_addr: Int
    """Pool cell holding the HTTP/1.1 reader, or 0."""

    var _h2_addr: Int
    """Pool cell holding the HTTP/2 reader, or 0."""

    var _h3_addr: Int
    """Pool cell holding the HTTP/3 reader, or 0."""

    var _done: Bool
    """Set once a read has reported end of stream."""

    def __init__(
        out self,
        status: Int,
        var reason: String,
        var headers: HeaderMap,
        var wire: String,
        h1_addr: Int = 0,
        h2_addr: Int = 0,
        h3_addr: Int = 0,
    ):
        """Wrap a head and exactly one backend cell.

        Args:
            status: HTTP status code.
            reason: Reason phrase, empty on h2 and h3.
            headers: Response headers.
            wire: The negotiated wire name.
            h1_addr: Pool cell of an ``HttpDownload``, or 0.
            h2_addr: Pool cell of an ``Http2Download``, or 0.
            h3_addr: Pool cell of an ``Http3Download``, or 0.
        """
        self.status = status
        self.reason = reason^
        self.headers = headers^
        self.trailers = HeaderMap()
        self._wire = wire^
        self._h1_addr = h1_addr
        self._h2_addr = h2_addr
        self._h3_addr = h3_addr
        self._done = False

    def __deinit__(deinit self):
        Pool[HttpDownload[_H2Transport]].free(self._h1_addr)
        Pool[Http2Download].free(self._h2_addr)
        Pool[Http3Download].free(self._h3_addr)

    def protocol(self) -> String:
        """The wire this response was served on.

        Returns:
            ``"http/1.1"``, ``"h2"`` or ``"h3"``.
        """
        return self._wire

    def header(self, name: String) -> String:
        """Look up one response header, case-insensitively.

        Args:
            name: Field name.

        Returns:
            The value, or an empty string when absent.
        """
        return self.headers.get(name)

    def ok(self) -> Bool:
        """Whether the status is 2xx.

        Returns:
            True for 200 through 299.
        """
        return self.status >= 200 and self.status < 300

    def raise_for_status(self) raises:
        """Raise unless the status is 2xx.

        Raises:
            HttpError: Carrying the status and reason.
        """
        if not self.ok():
            raise HttpError(self.status, self.reason)

    def done(self) -> Bool:
        """Whether the body has reached end of stream.

        Returns:
            True once a read has reported EOS.
        """
        return self._done

    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Pull up to ``max_bytes`` more bytes of the body.

        Args:
            max_bytes: Ceiling for this pull. Must be positive.

        Returns:
            The bytes read. An empty list means end of stream; every
            later call also returns empty.

        Raises:
            NetworkError: On an I/O error, or a mid-transfer reset.
            Error: If ``max_bytes`` is not positive.
        """
        if max_bytes <= 0:
            raise Error("HttpStreamResponse.read_chunk: max_bytes must be > 0")
        if self._done:
            return List[UInt8]()
        var out: List[UInt8]
        if self._h1_addr != 0:
            out = (
                Pool[HttpDownload[_H2Transport]]
                .get_ptr(self._h1_addr)[]
                .read_chunk(max_bytes)
            )
            if len(out) == 0:
                self.trailers = (
                    Pool[HttpDownload[_H2Transport]]
                    .get_ptr(self._h1_addr)[]
                    .trailers.copy()
                )
        elif self._h2_addr != 0:
            ref d2 = Pool[Http2Download].get_ptr(self._h2_addr)[]
            out = d2.read_chunk(max_bytes)
            if len(out) == 0:
                self.trailers = d2.trailers.copy()
        elif self._h3_addr != 0:
            ref d3 = Pool[Http3Download].get_ptr(self._h3_addr)[]
            out = d3.read_chunk(max_bytes)
            if len(out) == 0:
                self.trailers = d3.trailers.copy()
        else:
            return List[UInt8]()
        if len(out) == 0:
            self._done = True
        return out^

    def read_all(
        mut self, limit: Int = _DEFAULT_READ_ALL_LIMIT
    ) raises -> List[UInt8]:
        """Read the whole remaining body into memory.

        For a body of unknown size prefer :meth:`read_chunk`; this is for
        the case where you already know it is small.

        Args:
            limit: Refuse past this many bytes.

        Returns:
            Every remaining byte of the body.

        Raises:
            NetworkError: On an I/O error.
            Error: If the body exceeds ``limit``.
        """
        var acc = List[UInt8]()
        while True:
            var chunk = self.read_chunk(65536)
            if len(chunk) == 0:
                break
            if len(acc) + len(chunk) > limit:
                raise Error(
                    "HttpStreamResponse.read_all: body exceeds "
                    + String(limit)
                    + " bytes; use read_chunk for a body this size"
                )
            acc.extend(chunk^)
        return acc^

    def close(mut self):
        """Release the connection and cancel the stream if incomplete.

        On h2 and h3 an incomplete stream is reset so the peer stops
        sending; on HTTP/1.1 the socket is closed, which is the only
        signal that wire has. Idempotent, and never raises: this runs on
        teardown paths where raising would mask the original error.
        """
        if self._h2_addr != 0:
            try:
                Pool[Http2Download].get_ptr(self._h2_addr)[].cancel()
            except:
                pass
        if self._h3_addr != 0:
            try:
                Pool[Http3Download].get_ptr(self._h3_addr)[].cancel()
            except:
                pass
        Pool[HttpDownload[_H2Transport]].free(self._h1_addr)
        Pool[Http2Download].free(self._h2_addr)
        Pool[Http3Download].free(self._h3_addr)
        self._h1_addr = 0
        self._h2_addr = 0
        self._h3_addr = 0
        self._done = True
