"""Incremental body reader over one HTTP/3 stream.

Wraps an :class:`Http3ClientConnection` and a stream id whose response
head has already arrived, and yields the body a chunk at a time.

Two differences from the HTTP/2 reader are worth knowing. QUIC credit is
returned by the connection's own ``poll_responses`` rather than by an
explicit drain, so there is no WINDOW_UPDATE ordering hazard here. And
every wait is bounded: ``poll_body`` takes a timeout, and a peer that
goes quiet mid-body would otherwise park the caller indefinitely, so the
read loop carries a deadline and gives up with a ``NetworkError``
instead.
"""

from std.collections import Optional

from ...net import NetworkError
from ...http3.client import Http3ClientConnection
from ..headers import HeaderMap


comptime _H3_POLL_MS: Int = 100
"""Per-poll timeout handed to ``poll_body``."""

comptime _H3_DEFAULT_IDLE_MS: Int = 30_000
"""Default ceiling on a single stalled read, when the client carries no
read timeout of its own. Thirty seconds of *no progress*, not thirty
seconds per body: the deadline resets whenever bytes arrive."""


struct Http3Download(Movable):
    """Reads one HTTP/3 response body incrementally."""

    var _conn: Http3ClientConnection
    """The HTTP/3 connection driver (ownership transferred)."""

    var _sid: UInt64
    """Stream id of the request being read."""

    var trailers: HeaderMap
    """Trailing headers. HTTP/3 trailers are not surfaced by the reader
    yet, so this stays empty; the field exists so the three backends
    present the same shape."""

    var _eos: Bool
    """Set once the stream has ended."""

    var _idle_ms: Int
    """Ceiling on a single stalled read, in milliseconds."""

    def __init__(
        out self,
        var conn: Http3ClientConnection,
        sid: UInt64,
        idle_ms: Int = _H3_DEFAULT_IDLE_MS,
    ):
        """Take ownership of a connection whose response head has landed.

        Args:
            conn: The h3 connection driver (ownership transferred).
            sid: Stream id of the in-flight request.
            idle_ms: Give up after this long with no progress. ``0``
                waits indefinitely, which is almost never what you want
                against a peer you do not control.
        """
        self._conn = conn^
        self._sid = sid
        self.trailers = HeaderMap()
        self._eos = False
        self._idle_ms = idle_ms

    def read_chunk(mut self, max_bytes: Int = 65536) raises -> List[UInt8]:
        """Pull up to ``max_bytes`` of body.

        Args:
            max_bytes: Ceiling for this pull. HTTP/3 frames arrive whole,
                so a single DATA frame larger than this is returned in
                full rather than split.

        Returns:
            Body bytes, or an empty list at end of stream.

        Raises:
            NetworkError: On a stream error, or when no byte arrives
                within the idle ceiling.
        """
        if self._eos:
            return List[UInt8]()
        var waited = 0
        while True:
            var chunk = self._conn.poll_body(self._sid, _H3_POLL_MS)
            if len(chunk.data) > 0:
                return chunk.data.copy()
            if chunk.done:
                self._eos = True
                return List[UInt8]()
            waited += _H3_POLL_MS
            if self._idle_ms > 0 and waited >= self._idle_ms:
                raise NetworkError(
                    "h3 streaming download: no progress on stream "
                    + String(self._sid)
                    + " for "
                    + String(self._idle_ms)
                    + " ms"
                )

    def cancel(mut self) raises:
        """Reset the stream so the peer stops sending.

        Sends STOP_SENDING and RESET_STREAM once, and marks the stream
        reset locally so nothing further is written on it.
        """
        if self._eos:
            return
        self._conn.quic.cancel_stream(self._sid)
        self._eos = True
