"""Example 24 -- Server-Sent Events via the K1 streaming path.

Server-Sent Events is the canonical "the body isn't bounded at
handler-return time" case: the server emits ``data: ...\\n\\n`` records
until the client disconnects. Building SSE on ``Response.body:
List[UInt8]`` would force the handler to materialize the whole stream up
front, defeating the point.

Flare ships SSE as a first-class :class:`ChunkSource`
(:class:`SseChannel`) plus the :func:`stream_sse_response` helper. A
normal ``Handler`` / ``Router`` returns::

    def events(req: Request) raises -> Response:
        var ch = SseChannel()
        ch.push(SseEvent.message("hello"))
        ch.close()                      # or keep open for a live stream
        return stream_sse_response(ch^)

and the reactor streams one SSE record per writable edge -- over HTTP/1.1
(chunked transfer-encoding) and HTTP/2 (DATA frames) with no
SSE-specific reactor code. Backpressure is implicit (when the kernel
send buffer fills, the reactor stops calling ``next``); cancellation is
cooperative (``cancel.cancelled()`` ends the source).

This example drives an :class:`SseChannel` through the in-process
``drain`` helper so the demo is self-contained and deterministic; the
same channel plugs straight into ``stream_sse_response`` on a live
server (see ``tests/http/test_sse.mojo`` for the forked e2e).

Run:
    pixi run example-sse
"""

from flare.http import (
    Cancel,
    Response,
    SseChannel,
    SseEvent,
    format_sse_event,
    stream_sse_response,
)


def _drain(var channel: SseChannel) raises -> String:
    """Pull every record out of a closed channel and join the bytes."""
    var out = List[UInt8]()
    var sentinel = Cancel.never()
    while True:
        var maybe = channel.next(sentinel)
        if not maybe:
            break
        var chunk = maybe.value().copy()
        for i in range(len(chunk)):
            out.append(chunk[i])
    return String(unsafe_from_utf8=Span[UInt8, _](out))


def main() raises:
    print("=== flare Example 24: Server-Sent Events (K1) ===")
    print()

    # 1) One event formatted to the SSE wire shape.
    print("[1] format_sse_event(SseEvent.named):")
    var ev = SseEvent.named("tick", "42")
    print(String(unsafe_from_utf8=Span[UInt8, _](format_sse_event(ev))))

    # 2) A closed channel drains to the concatenated records.
    print("[2] SseChannel with 3 events, drained:")
    var ch = SseChannel()
    ch.push(SseEvent.message("alpha"))
    ch.push(SseEvent.message("beta"))
    ch.push(SseEvent.named("done", "bye"))
    ch.close()
    print(_drain(ch^))

    # 3) The canonical Router shape: stream_sse_response wraps a channel
    # as a streaming Response with the spec-correct SSE headers.
    print("[3] stream_sse_response builds the streaming Response:")
    var live = SseChannel()
    live.push(SseEvent.message("hello"))
    live.close()
    var resp = stream_sse_response(live^)
    print(" status           :", resp.status)
    print(" content-type     :", resp.headers.get("content-type"))
    print(" cache-control    :", resp.headers.get("cache-control"))
    print(" body is streaming:", Bool(resp.body_stream))

    print()
    print("=== Example 24 complete ===")
