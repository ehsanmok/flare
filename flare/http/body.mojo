"""Streaming response body primitives.

The ``Response.body: List[UInt8]`` field forces the entire
response body to materialise before the first ``send`` — a 100MB
download allocates 100MB per concurrent client, regardless of the
peer's read speed. Track 4 of design-0.5 promotes streaming bodies
into : the reactor pulls chunks on writable edges so that:

- 100MB downloads cost a few KB of buffer per connection (one
  chunk in flight at a time).
- Server-Sent Events, file downloads, log tails, AI-token
  streaming — all the cases where the response body isn't bounded
  at handler-return time — work naturally without a separate API
  surface.
- Backpressure falls out of construction: when the peer is slow,
  the kernel send buffer fills, the reactor doesn't ask for the
  next chunk. No high-water marks needed.

Pieces in place after this commit:

- ``ChunkSource`` trait: anything that can produce one chunk of
  bytes per ``next(cancel)`` call.
- ``Body`` trait: anything that can be rendered as a sequence of
  byte chunks; declares ``content_length()`` (Optional, for
  setting the header) and ``next_chunk(cancel)``.
- ``InlineBody``: today's behaviour packaged as a ``Body`` impl
  — wraps a ``List[UInt8]`` and yields it as one chunk.
- ``ChunkedBody[Source: ChunkSource]``: adapter from a user
  ``ChunkSource`` to the ``Body`` trait.

Pieces deferred (documented per-section):

- Making ``Response`` parametric over ``B: Body`` (so handlers
  can return ``Response[ChunkedBody[MySource]]``). Today's
  ``Response`` keeps its concrete ``List[UInt8]`` body field;
  user code that wants streaming uses ``ChunkSource`` directly
  with the reactor adoption that lands as a follow-up.
- The reactor's ``Transfer-Encoding: chunked`` write loop —
  pulls the next chunk on each writable edge. The piece that
  delivers the headline "100MB without 100MB allocation" lands
  with the reactor adoption.
- The SSE example (``examples/24_sse.mojo``) demonstrates the
  ``ChunkSource`` + ``ChunkedBody`` shape against an in-process
  loop; the network-side demo follows the reactor adoption.

This split keeps the diff reviewable. The shape and public API
of ``ChunkSource`` / ``Body`` / ``InlineBody`` / ``ChunkedBody``
are stable from this commit forward; integration into
``Response`` and the reactor lands without breaking handlers.

Closes the trait portion of Track 4.
"""

from std.collections import Optional

from .cancel import Cancel


# ── Traits ─────────────────────────────────────────────────────────────────


trait ChunkSource(ImplicitlyDestructible, Movable):
    """A source of byte chunks.

    Implementors yield successive chunks via ``next(cancel)``;
    a ``None`` return signals end-of-stream. The ``cancel`` token
    lets long-running sources short-circuit when the client
    disconnects (peer FIN), the request times out, or the server
    drains.

    Implementors may own buffer state across calls (an SSE source
    might rewrite its internal buffer in place); the chunk
    returned must remain valid until the **next** call to
    ``next``.
    """

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        """Produce the next chunk, or ``None`` to signal end-of-stream.

        Args:
            cancel: Per-request cancel token. Sources should poll
                ``cancel.cancelled()`` between expensive steps.

        Returns:
            The next chunk's bytes, or ``None`` to terminate the
            stream.

        Raises:
            Error: On unrecoverable source error; the reactor will
                close the connection.
        """
        ...


trait Body(ImplicitlyDestructible, Movable):
    """An HTTP response body.

    Two shipped impls today:

    - ``InlineBody``: wraps a ``List[UInt8]``; yields one chunk
      and signals end-of-stream. The default for -style
      handlers that return a complete body.
    - ``ChunkedBody[Source]``: adapter around a ``ChunkSource``;
      yields chunks until the source returns ``None``.

    Bodies that know their length up front declare it via
    ``content_length()`` so the reactor can set the
    ``Content-Length`` header and skip ``Transfer-Encoding:
    chunked`` framing. Sources that don't (e.g. SSE) return
    ``None`` from ``content_length()`` and the reactor sends
    chunked.
    """

    def content_length(self) -> Optional[Int]:
        """Return the body's known total byte count, or ``None``
        for an unknown / open-ended length.

        Bodies that return a concrete ``Int`` get
        ``Content-Length: N`` header and inline framing. Bodies
        that return ``None`` get ``Transfer-Encoding: chunked``
        framing and no ``Content-Length``.
        """
        ...

    def next_chunk(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        """Produce the next chunk, or ``None`` to signal end-of-stream.

        Same contract as ``ChunkSource.next``; the reactor calls
        this on each writable edge.
        """
        ...


# ── InlineBody ─────────────────────────────────────────────────────────────


struct InlineBody(Body, Movable):
    """Single-shot body — the prior ``List[UInt8]`` shape packaged
    as a ``Body`` impl.

    On the first call to ``next_chunk`` returns the entire byte
    buffer; on subsequent calls returns ``None``. ``content_length()``
    is the buffer's length.

    Use this when the handler can produce the entire body before
    returning (the typical request / response flow). For streaming
    cases reach for ``ChunkedBody``.
    """

    var _bytes: List[UInt8]
    var _consumed: Bool

    def __init__(out self, var bytes: List[UInt8]):
        self._bytes = bytes^
        self._consumed = False

    def content_length(self) -> Optional[Int]:
        return Optional[Int](len(self._bytes))

    def next_chunk(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if self._consumed:
            return Optional[List[UInt8]]()
        var out = self._bytes.copy()
        self._consumed = True
        return Optional[List[UInt8]](out^)


# ── ChunkedBody ────────────────────────────────────────────────────────────


struct ChunkedBody[Source: ChunkSource](Body, Movable):
    """Adapts a ``ChunkSource`` to the ``Body`` trait.

    ``content_length()`` is always ``None`` (chunked sources have
    no fixed length); the reactor will use ``Transfer-Encoding:
    chunked`` framing when this body is rendered. The Source's
    ``next(cancel)`` is forwarded directly.

    Example:
        ```mojo
        struct Counter(ChunkSource):
            var i: Int
            var buf: String

            fn next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
                if cancel.cancelled() or self.i >= 100:
                    return Optional[List[UInt8]]()
                self.buf = "data: " + String(self.i) + "\\n\\n"
                self.i += 1
                var out = List[UInt8]()
                for b in self.buf.as_bytes():
                    out.append(b)
                return Optional[List[UInt8]](out^)
        ```
    """

    var source: Self.Source

    def __init__(out self, var source: Self.Source):
        self.source = source^

    def content_length(self) -> Optional[Int]:
        return Optional[Int]()

    def next_chunk(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        return self.source.next(cancel)


# ── Iteration helper ───────────────────────────────────────────────────────


def drain_body[B: Body](mut body: B, cancel: Cancel) raises -> List[UInt8]:
    """Pull every chunk from ``body`` and concatenate into a
    single ``List[UInt8]``.

    Test / utility helper for users who want to assert against a
    body's full contents. Production callers go through the
    reactor's per-edge pull loop (which lands with the reactor
    adoption follow-up).

    Stops if ``cancel.cancelled()`` flips True between chunks.
    """
    var out = List[UInt8]()
    while True:
        if cancel.cancelled():
            break
        var chunk_opt = body.next_chunk(cancel)
        if not chunk_opt:
            break
        var chunk = chunk_opt.value().copy()
        for b in chunk:
            out.append(b)
    return out^
