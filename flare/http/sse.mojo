"""Server-Sent Events (W3C SSE / RFC 9110 ``text/event-stream``).

This module promotes the ``ChunkSource`` SSE pattern that example 24
demonstrated to a first-class flare primitive:

- :class:`SseEvent` — a single SSE record (data + optional id +
  optional event-type + optional retry interval).
- :func:`format_sse_event` — serialise an event to the wire bytes
  prescribed by `WHATWG HTML §9.2.6
  <https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream>`__.
- :class:`SseChannel` — a small in-memory FIFO + cancel-aware
  ``ChunkSource`` wrapper. The handler ``push``-es events; the
  reactor pulls one event per writable edge.
- :func:`sse_response` — the canonical "give me a Response with
  the right headers wired up" helper, paired with
  :class:`SseStreamingResponse[B]` for the streaming-body variant.

What this fixes vs example 24:

1. The handler doesn't have to roll its own ``ChunkSource`` for
   every endpoint — :class:`SseChannel` is the 80% case (a queue
   that real systems push events into).
2. Wire serialisation is centralised and spec-conformant: each
   ``data`` field that contains ``\\n`` is split into multiple
   ``data:`` lines per WHATWG §9.2.4; trailing ``\\n\\n`` is
   always emitted as the event terminator; ``id:`` /
   ``event:`` / ``retry:`` lines are emitted only when set.
3. Response headers are spec-correct out of the box:
   ``Content-Type: text/event-stream``, ``Cache-Control: no-cache``,
   ``Connection: keep-alive``, ``X-Accel-Buffering: no`` (the
   nginx-specific knob that disables proxy-side buffering, which
   would otherwise trickle events to the client in 4 KiB lumps).

Example:

```mojo
from flare.http import (
    SseChannel, SseEvent, SseStreamingResponse, sse_response,
)

def stream(req: Request) raises -> Response:
    # Bounded source: emit 5 events then close.
    var ch = SseChannel()
    for i in range(5):
        ch.push(SseEvent.data("tick=" + String(i)))
    ch.close()
    return sse_response(ch)
```

Reactor adoption: same as example 24 — wires through the existing
``ChunkedBody[SseChannel]`` path; no new reactor surface.
"""

from std.collections import Optional

from .body import Body, ChunkSource, ChunkedBody, InlineBody
from .cancel import Cancel
from .response import Response


# ── SseEvent ────────────────────────────────────────────────────────────────


@fieldwise_init
struct SseEvent(Copyable, Movable):
    """A single Server-Sent Event.

    Fields:
        data: Event payload. May contain newlines — they're split
            into multiple ``data:`` lines on the wire per
            WHATWG §9.2.4.
        event_type: Optional event-type name. Default empty (the
            client default of ``"message"`` applies).
        id: Optional event id (for ``Last-Event-Id`` resumption).
            Default empty.
        retry_ms: Optional reconnection backoff hint, in
            milliseconds. Default ``-1`` (don't emit a ``retry:``
            line).

    Constructors:
        - :meth:`SseEvent.data` — the 80% case (just data).
        - :meth:`SseEvent.named` — typed event with explicit
          event-type.
    """

    var data: String
    var event_type: String
    var id: String
    var retry_ms: Int

    @staticmethod
    def message(payload: String) -> SseEvent:
        """Construct an event with just a ``data`` payload (no
        explicit event-type — the client default ``"message"``
        applies)."""
        return SseEvent(payload, String(""), String(""), -1)

    @staticmethod
    def named(event_type: String, payload: String) -> SseEvent:
        """Construct an event with a named ``event:`` type."""
        return SseEvent(payload, event_type, String(""), -1)


def format_sse_event(event: SseEvent) -> List[UInt8]:
    """Serialise ``event`` to its on-wire byte representation.

    Wire shape (terminated by ``\\n\\n``):

        ``[id: <id>\\n][event: <event_type>\\n][retry: <ms>\\n]
        data: <line0>\\n[data: <line1>\\n]...\\n``

    A ``data`` field containing ``\\n`` is split into multiple
    ``data:`` lines (the WHATWG §9.2.4 parser concatenates them
    back with a single ``\\n`` separator on the receiving side).
    A trailing ``\\n`` inside ``data`` produces a final empty
    ``data:`` line — that is intentional and matches what every
    other SSE library does (Tornado, Sanic, axum-extra).
    """
    var out = String(capacity=event.data.byte_length() + 64)

    if event.id.byte_length() > 0:
        out += "id: "
        out += event.id
        out += "\n"

    if event.event_type.byte_length() > 0:
        out += "event: "
        out += event.event_type
        out += "\n"

    if event.retry_ms >= 0:
        out += "retry: "
        out += String(event.retry_ms)
        out += "\n"

    # Split data on \n; each line gets its own "data:" prefix.
    var n = event.data.byte_length()
    var p = event.data.unsafe_ptr()
    var line_start = 0
    var i = 0
    while i <= n:
        if i == n or Int(p[i]) == ord("\n"):
            out += "data: "
            for k in range(line_start, i):
                out += chr(Int(p[k]))
            out += "\n"
            line_start = i + 1
        i += 1

    out += "\n"  # event terminator

    var bytes = List[UInt8](capacity=out.byte_length())
    var op = out.unsafe_ptr()
    for k in range(out.byte_length()):
        bytes.append(op[k])
    return bytes^


# ── SseChannel ──────────────────────────────────────────────────────────────


struct SseChannel(ChunkSource, Copyable, Movable):
    """An in-memory FIFO of :class:`SseEvent` values + a closed flag.

    Pattern:

    1. Handler creates an :class:`SseChannel`.
    2. Handler ``push``-es events (synchronously or from a
       background pthread; the channel itself is **not**
       thread-safe — wrap with a mutex if you cross threads).
    3. Handler ``close``-s the channel when the stream ends.
    4. Reactor pulls one event per writable edge via
       :meth:`next`; when the buffer is empty AND the channel is
       closed, ``next`` returns ``None`` to signal end-of-stream.

    For an open-ended stream (heartbeat / metric tap / ...), don't
    call ``close`` — the connection lives until either the client
    disconnects (peer FIN ⇒ reactor flips ``cancel``) or the
    request-deadline fires.

    Thread safety:
        Not thread-safe. Push from the reactor's pthread or
        synchronise externally.
    """

    var _events: List[SseEvent]
    var _next_idx: Int
    """Index of the next event to yield. Drains in FIFO order."""

    var _closed: Bool

    def __init__(out self):
        self._events = List[SseEvent]()
        self._next_idx = 0
        self._closed = False

    def push(mut self, var event: SseEvent):
        """Append an event to the FIFO."""
        self._events.append(event^)

    def close(mut self):
        """Mark the channel closed. The reactor's :meth:`next`
        call will return ``None`` once the buffer is drained."""
        self._closed = True

    def is_closed(self) -> Bool:
        return self._closed

    def pending(self) -> Int:
        """Return the count of events buffered but not yet
        yielded."""
        return len(self._events) - self._next_idx

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        """Yield the next event's wire bytes, or ``None`` to
        signal end-of-stream.

        Returns ``None`` immediately if cancel is set OR the
        channel is closed AND the buffer is drained.
        """
        if cancel.cancelled():
            return Optional[List[UInt8]]()
        if self._next_idx >= len(self._events):
            if self._closed:
                return Optional[List[UInt8]]()
            # Open channel with empty buffer: yield a comment-line
            # heartbeat (": keep-alive\n\n") so the reactor still
            # has something to flush. The WHATWG parser ignores
            # comment lines (start with ":"), so this never fires
            # an EventSource event on the client.
            var heartbeat = String(": keep-alive\n\n")
            var bytes = List[UInt8](capacity=heartbeat.byte_length())
            var p = heartbeat.unsafe_ptr()
            for k in range(heartbeat.byte_length()):
                bytes.append(p[k])
            return Optional[List[UInt8]](bytes^)

        var event = self._events[self._next_idx].copy()
        self._next_idx += 1
        return Optional[List[UInt8]](format_sse_event(event))


# ── Response helpers ────────────────────────────────────────────────────────


def _set_sse_headers(mut resp: Response) raises:
    """Apply the spec-correct SSE response headers in place.

    - ``Content-Type: text/event-stream`` (W3C SSE).
    - ``Cache-Control: no-cache`` (caches must not stash the
      half-open stream — RFC 9111 doesn't define a sane shape
      for ``text/event-stream`` revalidation).
    - ``Connection: keep-alive`` (HTTP/1.1 default but SSE
      explicitly requires the connection stays open).
    - ``X-Accel-Buffering: no`` (nginx-specific; tells nginx to
      disable proxy-side buffering, otherwise events trickle in
      4 KiB lumps which defeats the streaming property).
    """
    resp.headers.set("Content-Type", "text/event-stream")
    resp.headers.set("Cache-Control", "no-cache")
    resp.headers.set("Connection", "keep-alive")
    resp.headers.set("X-Accel-Buffering", "no")


def sse_response(channel: SseChannel) raises -> Response:
    """Build a :class:`Response` whose body is a one-shot snapshot
    of every event currently buffered in ``channel``.

    Use this when the handler can produce all events synchronously
    before returning (the typical "metrics endpoint" /
    "history-replay" / "test fixture" shape). For an open-ended
    stream that lives past the handler return, build a
    :class:`SseStreamingResponse` instead.

    Drains the channel synchronously; returns a :class:`Response`
    with the SSE wire bytes inline + the spec-correct headers.
    """
    var resp = Response(status=200)
    _set_sse_headers(resp)
    var snapshot = channel.copy()
    var body = List[UInt8]()
    var sentinel = Cancel.never()
    while True:
        var maybe = snapshot.next(sentinel)
        if not maybe:
            break
        var chunk = maybe.value().copy()
        for i in range(len(chunk)):
            body.append(chunk[i])
        # Bounded by the channel's own end-of-stream signal: an
        # open (un-closed) channel will heartbeat forever, so we
        # only iterate this path when the channel is closed —
        # see assertion below.
        if not snapshot.is_closed() and snapshot.pending() == 0:
            # Caller passed an open-ended channel into the
            # synchronous helper — we'd loop forever on heartbeats.
            # Bail with a clear diagnostic; they want
            # SseStreamingResponse instead.
            raise Error(
                "sse_response: open-ended SseChannel; close the channel"
                " before calling sse_response, or use SseStreamingResponse"
                " for a streaming-body variant."
            )
    resp.body = body^
    resp.headers.set("Content-Length", String(len(resp.body)))
    return resp^


@fieldwise_init
struct SseStreamingResponse(Movable):
    """A streaming-body :class:`Response` analogue for an
    open-ended SSE channel.

    Pairs ``response`` (status + headers) with ``body``
    (:class:`ChunkedBody[SseChannel]`) so the reactor's streaming
    code path can pull one event per writable edge. Unlike
    :func:`sse_response`, this never blocks the handler — it
    captures the channel and returns immediately; events pushed
    to the channel after the handler returns are flushed by the
    reactor on the next writable edge.

    Reactor adoption: the same ``ChunkedBody`` plumbing example 24
    already drives is what the reactor's
    ``serve_streaming(StreamingResponse[B])`` entry point will use
    once the streaming reactor lands.
    """

    var response: Response
    var body: ChunkedBody[SseChannel]

    @staticmethod
    def of(channel: SseChannel) raises -> SseStreamingResponse:
        """Construct a :class:`SseStreamingResponse` carrying
        ``channel`` as its ChunkedBody source."""
        var resp = Response(status=200)
        _set_sse_headers(resp)
        return SseStreamingResponse(
            response=resp^,
            body=ChunkedBody[SseChannel](source=channel.copy()),
        )
