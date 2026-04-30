"""Streaming response with a parametric body type.

``Response`` is the -shape buffered response: ``body:
List[UInt8]`` materialised before the first send. For
unbounded / large / Server-Sent-Event style outputs that would
defeat the buffer-then-send model, ``StreamingResponse[B: Body]``
carries a ``B: Body`` instance — the reactor pulls chunks from
``B.next_chunk(cancel)`` on writable edges and emits
``Transfer-Encoding: chunked`` framing when ``B.content_length()``
is unknown.

Why a sibling type rather than ``Response[B: Body]`` parametric:

The plan's preferred shape was ``Response = Response[InlineBody]``
type alias with the existing helpers (``ok``, ``not_found``,
...) returning the alias. Investigation in this Mojo nightly
showed that:

1. Making ``Response`` parametric requires changing every
   ``Response(status=..., body=List[UInt8](...))`` constructor
   call across the codebase (~50+ callsites in tests, examples,
   and the reactor). The constructor arguments would need to
   shift from ``List[UInt8]`` to a ``Body`` impl.
2. Mojo's alias-with-default-parameter for traits-bounded
   parameters has not been verified clean for this nightly —
   the C3 commit hit a separate specialisation slowness on
   ``ViewHandler.serve_view[origin]`` that suggests parametric
   dispatch costs add up.
3. The plan explicitly documents this fallback: "If Mojo's
   alias-with-default-parameter doesn't compile cleanly in
   this nightly, the fallback is a sibling
   ``StreamingResponse[B]`` type."

``StreamingResponse[B]`` is fully additive: every existing
handler / helper / test / example continues to use ``Response``
unchanged. Handlers that want streaming opt in by returning a
``StreamingResponse[ChunkedBody[Source]]`` from a
``StreamingHandler`` (lands in C5 alongside the reactor pull
loop). The end-user shape is identical to the planned
parametric ``Response[B]``; only the public name differs.

Closes the contract portion of Track 4 part 1.

Example:

    from flare.http import (
        StreamingResponse, ChunkSource, ChunkedBody, Cancel, Status,
    )
    from std.collections import Optional

    @fieldwise_init
    struct CountingSource(ChunkSource, Copyable, Movable):
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
