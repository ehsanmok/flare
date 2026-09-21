"""HTTP/1.1 trailer fields -- gRPC-shaped status trailer demo.

Trailer fields ride after the zero-length chunk of a ``Transfer-
Encoding: chunked`` response (RFC 7230 §4.1.2). They're the
canonical place to surface "the body is what I planned to send,
but here's the post-hoc result" -- the gRPC status protocol uses
them this way, as do checksums computed over a stream and
compute-bound results that the server only learns at end-of-body.

This example walks the server-side emit + the client-side parse
without spinning up a real socket. We:

1. Build a ``StreamingResponse`` carrying both a body and two
   trailer fields (``grpc-status`` and ``grpc-message``).
2. Render to wire bytes via ``serialize_streaming_response`` --
   the serializer auto-emits a ``Trailer:`` header listing the
   declared field names per RFC 7230 §4.4 and writes the
   trailer lines after the zero chunk.
3. Round-trip those wire bytes back through the client decoder
   (``_decode_chunked``) and inspect the populated trailer map.

Run:

    mojo -I . examples/intermediate/trailers.mojo
"""

from std.collections import Optional

from flare.http import HeaderMap
from flare.http.body import Body
from flare.http.cancel import Cancel
from flare.http.client import _decode_chunked
from flare.http.streaming_response import StreamingResponse
from flare.http.streaming_serialize import serialize_streaming_response


@fieldwise_init
struct GreetingBody(Body, Copyable):
    """Minimal one-shot ``Body`` -- one chunk then EOF."""

    var bytes: List[UInt8]
    var done: Bool

    @staticmethod
    def of(s: String) -> GreetingBody:
        var b = List[UInt8]()
        for x in s.as_bytes():
            b.append(x)
        return GreetingBody(bytes=b^, done=False)

    def content_length(self) -> Optional[Int]:
        return Optional[Int]()  # unknown -> chunked framing

    def next_chunk(mut self, cancel: Cancel) -> Optional[List[UInt8]]:
        if self.done:
            return Optional[List[UInt8]]()
        self.done = True
        return Optional[List[UInt8]](self.bytes.copy())


def _wire_str(wire: List[UInt8]) -> String:
    var s = String(capacity_bytes=len(wire) + 1)
    for b in wire:
        s += chr(Int(b))
    return s^


def main() raises:
    print("=== HTTP/1.1 trailers demo ===\n")

    # 1. Build a streaming response with body + two trailer fields.
    var resp = StreamingResponse[GreetingBody](
        status=200,
        body=GreetingBody.of("hello, world"),
        reason="OK",
    )
    resp.trailers.append("grpc-status", "0")
    resp.trailers.append("grpc-message", "ok")

    print("Server-side: emitting", len(resp.trailers._keys), "trailer fields:")
    for i in range(len(resp.trailers._keys)):
        print("  ", resp.trailers._keys[i], "=", resp.trailers._values[i])
    print()

    # 2. Render to wire bytes.
    var wire = serialize_streaming_response(resp^, Cancel.never(), True)
    var wire_str = _wire_str(wire)

    print("--- wire bytes ---")
    print(wire_str)
    print("--- end wire ---\n")

    # 3. Locate the body start (after \r\n\r\n) and re-parse the
    #    chunked body + trailers.
    var body_start = -1
    for i in range(len(wire) - 3):
        if (
            wire[i] == 13
            and wire[i + 1] == 10
            and wire[i + 2] == 13
            and wire[i + 3] == 10
        ):
            body_start = i + 4
            break

    var seen_trailers = HeaderMap()
    var body = _decode_chunked(wire, body_start, seen_trailers)

    print("Client-side: decoded body =", String(unsafe_from_utf8=body))
    print("Client-side: parsed", len(seen_trailers._keys), "trailer fields:")
    for i in range(len(seen_trailers._keys)):
        print("  ", seen_trailers._keys[i], "=", seen_trailers._values[i])
    print()

    print("=== demo complete ===")
