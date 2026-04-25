"""Example 24 — Streaming bodies via ``ChunkSource`` (Server-Sent
Events shape).

Server-Sent Events is the canonical "the body isn't bounded at
handler-return time" case: the server emits ``data: ...\\n\\n``
chunks indefinitely (or until the client disconnects). Building
SSE on top of ``Response.body: List[UInt8]`` would require the
handler to materialise the entire stream up front, which defeats
the point.

The v0.5.0 Step 2 streaming primitives (``ChunkSource`` +
``ChunkedBody``) make SSE a 50-line pattern: the handler implements
a ``ChunkSource`` that yields one event per ``next(cancel)`` call,
wraps it in ``ChunkedBody[Source]``, and the reactor pulls a chunk
on each writable edge. Backpressure is implicit (when the kernel
send buffer fills, the reactor stops calling ``next``). Cancellation
is cooperative (``cancel.cancelled()`` short-circuits the source).

This example drives a ``Counter`` SSE source through the
in-process ``drain_body`` helper to keep the demo self-contained.
The reactor adoption — wiring ``ChunkedBody`` into the
``HttpServer.serve_streaming`` entry point — lands as a follow-up;
when it does the same ``Counter`` source plugs in unchanged.

Run:
    pixi run example-sse
"""

from std.collections import Optional

from flare.http import (
    Cancel,
    CancelCell,
    CancelReason,
    ChunkSource,
    ChunkedBody,
    drain_body,
)


@fieldwise_init
struct Counter(ChunkSource, Copyable, Movable):
    """Yields ``"data: 0\\n\\n"`` ... ``"data: (max_i-1)\\n\\n"`` then
    terminates. Real SSE sources connect to a database / queue /
    websocket / metric stream and emit one event per tick.
    """

    var i: Int
    var max_i: Int

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.i >= self.max_i:
            return Optional[List[UInt8]]()
        var line = "data: " + String(self.i) + "\n\n"
        var bytes = List[UInt8]()
        for b in line.as_bytes():
            bytes.append(b)
        self.i += 1
        return Optional[List[UInt8]](bytes^)


def main() raises:
    print("=== flare Example 24: SSE-shaped streaming body ===")
    print()

    # 1) Bounded source: 5 events, no cancellation.
    print("[1] Counter(0..5) drained without cancellation:")
    var body1 = ChunkedBody[Counter](source=Counter(0, 5))
    var drained1 = drain_body(body1, Cancel.never())
    var s1 = String(unsafe_from_utf8=Span[UInt8, _](drained1))
    print(s1)

    # 2) Same source, but cancel mid-stream after the first chunk.
    print("[2] Counter(0..100) cancelled before draining:")
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var body2 = ChunkedBody[Counter](source=Counter(0, 100))
    var drained2 = drain_body(body2, cell.handle())
    print("    drained", len(drained2), "bytes (expected 0 — cancel was set)")

    # 3) ChunkedBody declares no Content-Length so chunked
    #    Transfer-Encoding framing fires when the reactor adopts
    #    this primitive.
    var body3 = ChunkedBody[Counter](source=Counter(0, 3))
    print(
        "[3] ChunkedBody.content_length() is None:",
        not body3.content_length(),
    )

    print()
    print("Reactor adoption (HttpServer.serve_streaming) is the")
    print("follow-up that wires this into the wire path.")
    print()
    print("=== Example 24 complete ===")
