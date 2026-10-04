# PLATFORM: any
"""H2-13: after the server resets a stream, the HTTP/2 client's
`send_data` still puts DATA on that closed stream and flips the stream
from CLOSED back to HALF_CLOSED_LOCAL.

Lean: Flare.Bugs.H2_13.bug (counterexample) and Flare.Bugs.H2_13.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g13,
witness Flare.Bugs.H2_Refine.w13_departs) names this step as the H2-13
trigger. flare/http2/client.mojo:869-908 @59bda50 (`send_data`): neither
the empty half-close path (895-901: `CLOSED if HALF_CLOSED_REMOTE else
HALF_CLOSED_LOCAL`) nor `_emit_body_span` (560-585) looks at a CLOSED
state. flare's gRPC client-streaming / bidi calls (flare/grpc/
streaming.mojo:229 and 240) call `send_data` without checking it.

RFC 9113 sec 5.1 (closed): "An endpoint MUST NOT send frames other than
PRIORITY on a closed stream." A closed stream never leaves "closed".

Trace: send_request_open(1); the server sends RST_STREAM(1, CANCEL);
the caller then half-closes with send_data(1, b"", end_stream=True) (what
grpc close_send does) and, on a second connection, sends a body chunk
with send_data(1, b"x", end_stream=True).

Expected: no frame is queued and stream 1 stays CLOSED (or send_data
raises). Actual: a DATA(END_STREAM) frame for stream 1 is queued and the
stream state becomes HALF_CLOSED_LOCAL.

Minimal fix: in `send_data` / `_emit_body_span`, do nothing (or raise)
when the stream is CLOSED.
"""

from flare.http2 import HpackHeader, Http2ClientConnection, parse_frame
from flare.http2.state import StreamState


def _frame(ty: UInt8, flags: UInt8, sid: Int, payload: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    var n = len(payload)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    out.append(ty)
    out.append(flags)
    out.append(UInt8((sid >> 24) & 0x7F))
    out.append(UInt8((sid >> 16) & 0xFF))
    out.append(UInt8((sid >> 8) & 0xFF))
    out.append(UInt8(sid & 0xFF))
    for b in payload:
        out.append(b)
    return out^


def _data_frames(bytes: List[UInt8], sid: Int) raises -> Int:
    var off = 0
    var n = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 0 and f.header.stream_id == sid:
            n += 1
    return n


def _after_reset(body_len: Int) raises -> Tuple[Int, Int]:
    var c = Http2ClientConnection()
    _ = c.drain()
    var sid = c.next_stream_id()
    c.send_request_open(sid, "POST", "http", "example.com", "/", List[HpackHeader]())
    _ = c.drain()
    var cancel: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(8)]
    c.feed(Span[UInt8, _](_frame(0x3, 0x0, sid, cancel)))
    _ = c.drain()
    if sid not in c.conn.streams or c.conn.streams[sid].copy().state.value != StreamState.CLOSED().value:
        print("inconclusive: stream not CLOSED after RST_STREAM")
        raise Error("setup")
    var body = List[UInt8]()
    for _ in range(body_len):
        body.append(0x78)
    c.send_data(sid, Span(body), True)
    var frames = _data_frames(c.drain(), sid)
    return (frames, c.conn.streams[sid].copy().state.value)


def main() raises:
    var e = _after_reset(0)
    var b = _after_reset(1)
    var closed = StreamState.CLOSED().value
    if e[0] > 0 or b[0] > 0 or e[1] != closed or b[1] != closed:
        print(
            "BUG REPRODUCED: after RST_STREAM(CANCEL) the empty half-close"
            " queued",
            e[0],
            "DATA frame(s) and left state",
            e[1],
            "; a 1-byte final chunk queued",
            b[0],
            "DATA frame(s) and left state",
            b[1],
            "(CLOSED =",
            closed,
            ", HALF_CLOSED_LOCAL =",
            StreamState.HALF_CLOSED_LOCAL().value,
            ")",
        )
        raise Error("H2-13")
    print("OK: nothing sent on the closed stream; state stays CLOSED")
