# PLATFORM: any
"""H2-04: the HTTP/2 client accepts a response HEADERS on a stream it
never opened.

Lean: Flare.Bugs.H2_04.bug (counterexample) and Flare.Bugs.H2_04.fixed.
flare/http2/state.mojo:1120 and 1257-1333 @59bda50: the stream-id checks
on HEADERS run only `if ... not self.is_client`, so in client role a
HEADERS on an unknown id goes through _ensure_stream and creates it.

RFC 9113 sec 5.1 (idle): "Receiving any frame other than HEADERS or
PRIORITY on a stream in this state MUST be treated as a connection error";
a client never lets the server open a stream with HEADERS: server push is
disabled (SETTINGS_ENABLE_PUSH = 0, sec 8.4) and server-initiated streams
are even and start with PUSH_PROMISE. sec 5.1.1: "An endpoint that
receives an unexpected stream identifier MUST respond with a connection
error (Section 5.4.1) of type PROTOCOL_ERROR."

Trace: fresh Http2ClientConnection, no request sent. The server sends
HEADERS(stream 2, END_STREAM | END_HEADERS, ":status: 200"), then the same
on stream 3 (odd, never allocated by next_stream_id).

Expected: GOAWAY(PROTOCOL_ERROR). Actual: both are accepted and surface
as ready responses (response_ready(2) and response_ready(3) are True).

Minimal fix: in client role, a HEADERS on a stream id not in conn.streams
is a connection error PROTOCOL_ERROR.
"""

from flare.http2 import Http2ClientConnection, parse_frame


def _headers(sid: Int) -> List[UInt8]:
    var out: List[UInt8] = [
        UInt8(0),
        UInt8(0),
        UInt8(1),
        UInt8(0x1),
        UInt8(0x5),
        UInt8(0),
        UInt8(0),
        UInt8(0),
        UInt8(sid),
        UInt8(0x88),  # :status 200 (static index 8)
    ]
    return out^


def _goaway_code(bytes: List[UInt8]) raises -> Int:
    var off = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            return (
                (Int(f.payload[4]) << 24)
                | (Int(f.payload[5]) << 16)
                | (Int(f.payload[6]) << 8)
                | Int(f.payload[7])
            )
    return -1


def main() raises:
    var client = Http2ClientConnection()
    _ = client.drain()
    client.feed(Span[UInt8, _](_headers(2)))
    var code2 = _goaway_code(client.drain())
    var ready2 = 2 in client.conn.streams and client.response_ready(2)
    var client3 = Http2ClientConnection()
    _ = client3.drain()
    client3.feed(Span[UInt8, _](_headers(3)))
    var code3 = _goaway_code(client3.drain())
    var ready3 = 3 in client3.conn.streams and client3.response_ready(3)
    if code2 < 0 or code3 < 0:
        print(
            "BUG REPRODUCED: HEADERS on never-opened streams accepted:"
            " stream 2 GOAWAY code",
            code2,
            "response_ready",
            ready2,
            "; stream 3 GOAWAY code",
            code3,
            "response_ready",
            ready3,
            "(-1 = no GOAWAY)",
        )
        raise Error("H2-04")
    print("OK: HEADERS on unopened streams 2 and 3 drew GOAWAY", code2, code3)
