"""Incremental body reader over one HTTP/2 stream.

Wraps an :class:`Http2ClientConnection` plus the stream id of a request
whose head has already arrived, and turns the pair into something that
yields body bytes a chunk at a time.

The flow-control loop is the part worth reading carefully.
``enable_response_streaming`` tells the connection to hold this stream's
receive credit rather than returning it on arrival, which is what keeps
a large body bounded. ``drain_body`` then hands back the buffered bytes
*and queues a WINDOW_UPDATE into the connection's outbox*. If that frame
is never written the peer stops sending at the initial window and the
read blocks forever. So every pull here is drain, write, and only then
read more -- the same order :class:`flare.grpc.GrpcServerStream` uses.
"""

from std.collections import Optional

from ...net import NetworkError
from ...http2.client import Http2ClientConnection
from ..headers import HeaderMap
from .h2_transport import _H2Transport


comptime _H2_READ_BUF: Int = 16384
"""Bytes pulled from the socket per refill."""


struct Http2Download(Movable):
    """Reads one HTTP/2 response body incrementally.

    Owns the transport and the connection: an h2 streaming download does
    not share its connection, because the deferred-credit mode it turns
    on applies per stream but the read loop here would starve any
    sibling stream on the same connection anyway.
    """

    var _t: _H2Transport
    """The TCP or TLS transport underneath."""

    var _conn: Http2ClientConnection
    """The HTTP/2 connection driver."""

    var _sid: Int
    """Stream id of the request being read."""

    var trailers: HeaderMap
    """Trailing headers, populated at end of stream."""

    var _eos: Bool
    """Set once the stream has ended."""

    var _pending: List[UInt8]
    """Bytes read past a caller's ``max_bytes``, handed back first on the
    next pull. ``drain_body`` returns whatever the connection buffered,
    which can exceed one caller's ceiling."""

    def __init__(
        out self,
        var transport: _H2Transport,
        var conn: Http2ClientConnection,
        sid: Int,
    ):
        """Take ownership of a connection whose response head has landed.

        Args:
            transport: The live transport (ownership transferred).
            conn: The h2 connection driver (ownership transferred).
            sid: Stream id of the in-flight request.
        """
        self._t = transport^
        self._conn = conn^
        self._sid = sid
        self.trailers = HeaderMap()
        self._eos = False
        self._pending = List[UInt8]()

    def _flush(mut self) raises:
        """Write whatever the connection has queued.

        Called after every ``drain_body`` because that is what puts the
        WINDOW_UPDATE on the wire. Skipping it stalls the transfer at the
        initial window.
        """
        var out = self._conn.drain()
        if len(out) > 0:
            self._t.write_all(Span[UInt8, _](out))

    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Pull up to ``max_bytes`` of body.

        Args:
            max_bytes: Ceiling for this pull.

        Returns:
            Body bytes, or an empty list at end of stream.

        Raises:
            NetworkError: On an I/O error or a stream reset.
        """
        if len(self._pending) > 0:
            return self._take_pending(max_bytes)
        if self._eos:
            return List[UInt8]()
        while True:
            var got = self._conn.drain_body(self._sid)
            # Always flush: drain_body queued the credit return.
            self._flush()
            if len(got) > 0:
                if len(got) > max_bytes:
                    # Hand back the ceiling and keep the rest buffered in
                    # the connection by pushing it back is not possible,
                    # so slice and stash locally instead.
                    var head = List[UInt8](capacity=max_bytes)
                    for i in range(max_bytes):
                        head.append(got[i])
                    var tail = List[UInt8](capacity=len(got) - max_bytes)
                    for i in range(max_bytes, len(got)):
                        tail.append(got[i])
                    self._pushback(tail^)
                    return head^
                return got^
            var err = self._conn.stream_error(self._sid)
            if err:
                raise NetworkError(
                    "h2 streaming download: stream "
                    + String(self._sid)
                    + " reset with code "
                    + String(err.value())
                )
            if self._conn.stream_ended(self._sid):
                self._finish()
                return List[UInt8]()
            if not self._refill():
                self._finish()
                return List[UInt8]()

    def _take_pending(mut self, max_bytes: Int) -> List[UInt8]:
        """Hand back up to ``max_bytes`` of previously over-read body."""
        if len(self._pending) <= max_bytes:
            var all = self._pending^
            self._pending = List[UInt8]()
            return all^
        var head = List[UInt8](capacity=max_bytes)
        for i in range(max_bytes):
            head.append(self._pending[i])
        var rest = List[UInt8](capacity=len(self._pending) - max_bytes)
        for i in range(max_bytes, len(self._pending)):
            rest.append(self._pending[i])
        self._pending = rest^
        return head^

    def _pushback(mut self, var tail: List[UInt8]):
        """Stash bytes the caller's ceiling did not have room for."""
        self._pending = tail^

    def _finish(mut self) raises:
        """Record end of stream and capture trailers."""
        self._eos = True
        var tr = self._conn.response_trailers(self._sid)
        for i in range(len(tr)):
            self.trailers.append(tr[i].name, tr[i].value)

    def _refill(mut self) raises -> Bool:
        """Read one buffer from the socket into the connection.

        Returns:
            False when the peer closed without ending the stream.
        """
        var buf = List[UInt8](capacity=_H2_READ_BUF)
        buf.resize(_H2_READ_BUF, 0)
        var n = self._t.read(Pointer(to=buf[0]), _H2_READ_BUF)
        if n <= 0:
            return False
        self._conn.feed(Span[UInt8, _](buf)[0:n])
        self._flush()
        return True

    def cancel(mut self) raises:
        """Reset the stream so the peer stops sending.

        Called by :meth:`HttpStreamResponse.close` when a caller walks
        away mid-body.
        """
        if self._eos:
            return
        self._conn.cancel_stream(self._sid)
        try:
            self._flush()
        except:
            pass
        self._eos = True
