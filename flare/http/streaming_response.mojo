"""Streaming response with a parametric body type.

``Response`` is the buffered response shape: ``body:
List[UInt8]`` materialised before the first send. For
unbounded / large / Server-Sent-Event style outputs that would
defeat the buffer-then-send model, ``StreamingResponse[B: Body]``
carries a ``B: Body`` instance — the reactor pulls chunks from
``B.next_chunk(cancel)`` on writable edges and emits
``Transfer-Encoding: chunked`` framing when ``B.content_length()``
is unknown.

Why a sibling type rather than ``Response[B: Body]`` parametric:

The natural shape would be ``Response = Response[InlineBody]``
type alias with the existing helpers (``ok``, ``not_found``,
...) returning the alias. The parametric alias *does* compile
cleanly today (``ParametricResponse[InlineBody]`` +
``ParametricResponse[ChunkedBody[Source]]`` both parse and
specialise), but the blocker is migration churn:

1. Making ``Response`` parametric requires changing every
   ``Response(status=..., body=List[UInt8](...))`` constructor
   call across the codebase (~50+ callsites in tests, examples,
   and the reactor). The constructor arguments would need to
   shift from ``List[UInt8]`` to a ``Body`` impl.
2. The migration touches the public API: every user that wrote
   ``def handler() raises -> Response`` would need to either
   keep using the alias form or accept ``Response[InlineBody]``
   verbatim. The alias is non-breaking but the type-erasure
   would surface in error messages.
3. The sibling type works today and is opt-in -- handlers that
   want streaming return ``StreamingResponse[ChunkedBody[Source]]``;
   handlers that do not are not affected.

The end-user shape is identical to the planned parametric
``Response[B]``; only the public name differs. The migration is
queued for the QUIC server work, where the response abstraction
will need to grow anyway (h3 frames vs h2 frames vs h1 wire
chunks) and a single parametric type makes that grow honestly
rather than via three sibling types.

``StreamingResponse[B]`` is fully additive: every existing
handler / helper / test / example continues to use ``Response``
unchanged. Handlers that want streaming opt in by returning a
``StreamingResponse[ChunkedBody[Source]]`` from a
``StreamingHandler``.

Example:

    from flare.http import (
        StreamingResponse, ChunkSource, ChunkedBody, Cancel, Status,
    )
    from std.collections import Optional

    @fieldwise_init
    struct CountingSource(ChunkSource, Copyable):
        var n: Int

        def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
            if cancel.cancelled() or self.n == 0:
                return Optional[List[UInt8]]()
            self.n -= 1
            var b = List[UInt8]()
            b.append(ord("x"))
            return Optional[List[UInt8]](b^)

    var resp = StreamingResponse[ChunkedBody[CountingSource]](
        status=Status.OK,
        reason="OK",
        body=ChunkedBody[CountingSource](source=CountingSource(n=10)),
    )
    # The reactor's serve_streaming entry point (C5) drives
    # body.next_chunk(cancel) on each writable edge; emits
    # ``Transfer-Encoding: chunked`` framing because
    # ``ChunkedBody.content_length()`` is None.
"""

from .body import Body
from .headers import HeaderMap


struct StreamingResponse[B: Body](Movable):
    """An HTTP/1.1 response whose body is produced incrementally.

    Fields:
        status: HTTP status code (use ``Status.*`` constants).
        reason: Status reason phrase (e.g. ``"OK"``).
        headers: Response headers (owned ``HeaderMap``).
        version: HTTP version string (default ``"HTTP/1.1"``).
        body: The streaming body source. Must implement the
                 ``Body`` trait. Common impls: ``InlineBody``
                 (single-chunk, ``Content-Length`` framing) and
                 ``ChunkedBody[Source]`` (multi-chunk,
                 ``Transfer-Encoding: chunked`` framing).

    Movable but not Copyable — the underlying ``B`` body source
    typically owns mutable state across chunks (an SSE generator
    rewrites its buffer in place; a file-streamer holds a file
    handle). Copying would split the state in ways callers don't
    want.

    Wire framing the reactor uses:

    - ``body.content_length()`` returns ``Some(n)`` ->
      ``Content-Length: n`` header, single inline write of N
      bytes from the first ``next_chunk`` (subsequent calls
      return ``None``).
    - ``body.content_length()`` returns ``None`` ->
      ``Transfer-Encoding: chunked`` header, per-chunk RFC 7230
      §4.1 framing (hex length + CRLF + bytes + CRLF + final
      ``0\\r\\n\\r\\n``).
    """

    var status: Int
    var reason: String
    var headers: HeaderMap
    var version: String
    var body: Self.B
    var trailers: HeaderMap
    """Trailer fields emitted after the chunked body (RFC 7230
    §4.1.2). Empty by default; callers populate before / during
    body emission. Only emitted when the body is chunk-framed
    (``body.content_length()`` returns ``None``); ignored under
    Content-Length framing where trailers are not legal. The
    serialiser auto-sets the ``Trailer:`` header listing the
    declared trailer names so peers know what to expect."""

    def __init__(
        out self,
        status: Int,
        var body: Self.B,
        reason: String = "",
        version: String = "HTTP/1.1",
    ):
        """Construct a streaming response.

        Args:
            status: HTTP status code.
            body: Streaming body (ownership transferred).
            reason: Status reason phrase. If empty, the reactor
                     will fill in a default from the status code.
            version: HTTP version string.
        """
        self.status = status
        self.reason = reason
        self.headers = HeaderMap()
        self.version = version
        self.body = body^
        self.trailers = HeaderMap()

    def ok(self) -> Bool:
        """Return True if the status code is 2xx."""
        return self.status >= 200 and self.status < 300

    def is_redirect(self) -> Bool:
        """Return True if the status code is a redirect (3xx)."""
        return self.status >= 300 and self.status < 400

    def is_client_error(self) -> Bool:
        """Return True if the status code is a client error (4xx)."""
        return self.status >= 400 and self.status < 500

    def is_server_error(self) -> Bool:
        """Return True if the status code is a server error (5xx)."""
        return self.status >= 500 and self.status < 600
