# PLATFORM: any
# RESOLVED: H2-19 fixed on fix/formal-findings
"""H2-19: after a DATA frame with END_STREAM closes a stream, flare still
sends WINDOW_UPDATE on that stream.

Lean: Flare.Bugs.H2_19.bug (trace), Flare.Bugs.H2_19.fixed, and the
refinement theorem Flare.L3.H2.Refine.shipped_classified, which names this
step as the H2-19 trigger. flare/http2/state.mojo:1492-1494 @59bda50
(DATA branch of `handle_frame`):

    if len(f.payload) > 0:
        if credit > 0:
            out.append(Self._window_update_frame(sid, credit))

runs after 1470-1478 has moved a client stream that was HALF_CLOSED_LOCAL
to CLOSED on END_STREAM.

RFC 9113 sec 5.1, closed: "An endpoint MUST NOT send frames other than
PRIORITY on a closed stream." This is the ordinary path for every client
request without a body: `send_request` ends the request with the HEADERS
frame (HALF_CLOSED_LOCAL), and the response's last DATA frame carries
END_STREAM.

Trace: send_request(1, GET, empty body); the server answers
HEADERS(:status 200) and DATA(1, "abc", END_STREAM).

Expected: stream 1 is CLOSED and the reply carries no frame on stream 1
(a connection-level WINDOW_UPDATE on stream 0 is fine). Before the fix: the
reply carries WINDOW_UPDATE(stream 1, 3).

Minimal fix: in the DATA branch, send the stream-level WINDOW_UPDATE only
while the stream is not CLOSED (as `drain_body`, client.mojo:1178-1185,
already does).
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


def _scan(bytes: List[UInt8], sid: Int) raises -> Tuple[Int, Int, Int]:
    """(GOAWAY code or -1, RST_STREAM code on `sid` or -1,
    WINDOW_UPDATE increment on `sid` or -1)."""
    var off = 0
    var ga = -1
    var rst = -1
    var wu = -1
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            ga = Int(f.payload[7])
        if f.header.type.value == 3 and f.header.stream_id == sid:
            rst = Int(f.payload[3])
        if f.header.type.value == 8 and f.header.stream_id == sid:
            wu = (
                (Int(f.payload[0]) & 0x7F) << 24
                | Int(f.payload[1]) << 16
                | Int(f.payload[2]) << 8
                | Int(f.payload[3])
            )
    return (ga, rst, wu)


def main() raises:
    var c = Http2ClientConnection()
    _ = c.drain()
    var settings = List[UInt8]()
    c.feed(Span[UInt8, _](_frame(0x4, 0x0, 0, settings)))
    _ = c.drain()
    var sid = c.next_stream_id()
    var empty = List[UInt8]()
    c.send_request(sid, "GET", "http", "example.com", "/", List[HpackHeader](), Span(empty))
    _ = c.drain()
    if c.conn.streams[sid].copy().state.value != StreamState.HALF_CLOSED_LOCAL().value:
        print("inconclusive: request did not leave the stream HALF_CLOSED_LOCAL")
        raise Error("setup")
    var head: List[UInt8] = [UInt8(0x88)]  # :status 200
    c.feed(Span[UInt8, _](_frame(0x1, 0x4, sid, head)))
    var r1 = _scan(c.drain(), sid)
    if r1[0] >= 0 or r1[1] >= 0:
        print("inconclusive: response HEADERS drew an error")
        raise Error("setup")
    var body: List[UInt8] = [UInt8(0x61), UInt8(0x62), UInt8(0x63)]
    c.feed(Span[UInt8, _](_frame(0x0, 0x1, sid, body)))
    var r2 = _scan(c.drain(), sid)
    if r2[0] >= 0 or r2[1] >= 0:
        print("inconclusive: response DATA drew an error")
        raise Error("setup")
    var st = c.conn.streams[sid].copy().state.value
    if st != StreamState.CLOSED().value:
        print("inconclusive: stream is not CLOSED after the response END_STREAM; state", st)
        raise Error("setup")
    if r2[2] >= 0:
        print(
            "BUG REPRODUCED: DATA(END_STREAM) closed stream",
            sid,
            "(state",
            st,
            "= CLOSED) and the reply still carries WINDOW_UPDATE on stream",
            sid,
            "with increment",
            r2[2],
        )
        raise Error("H2-19")
    print("OK: stream CLOSED and no frame sent on it")
