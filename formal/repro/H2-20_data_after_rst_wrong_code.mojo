# PLATFORM: any
# RESOLVED: H2-20 fixed on fix/formal-findings
"""H2-20: DATA on a client stream the server has reset, before any
response headers, draws GOAWAY(PROTOCOL_ERROR) instead of STREAM_CLOSED.

Lean: Flare.Bugs.H2_20.bug (trace), Flare.Bugs.H2_20.fixed, and the
refinement theorem Flare.L3.H2.Refine.shipped_classified, which names this
step as the H2-20 trigger. flare/http2/state.mojo:1356-1365 @59bda50
(DATA branch of `handle_frame`):

    if self.is_client and not s.headers_complete:
        return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
    var st = s.state.value
    if (st == StreamState.CLOSED().value or ...):
        return self._conn_error(Http2ErrorCode.STREAM_CLOSED().value)

The "no response headers yet" test runs before the closed-stream test, so
a stream the server closed with RST_STREAM before answering takes the
first branch.

RFC 9113 sec 5.1, closed: "An endpoint that receives any frame other than
PRIORITY after receiving a RST_STREAM MUST treat that as a stream error
(Section 5.4.2) of type STREAM_CLOSED." (Escalating to a connection error
is allowed, sec 5.4.1, but the code stays STREAM_CLOSED.)

Trace: client; SETTINGS; send_request(1, GET); the server sends
RST_STREAM(1, CANCEL) and then DATA(1, "x").

Expected: GOAWAY or RST_STREAM with STREAM_CLOSED (5). Before the fix:
GOAWAY(PROTOCOL_ERROR = 1).

Minimal fix: test for CLOSED / HALF_CLOSED_REMOTE before the
headers-complete test.
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
    var cancel: List[UInt8] = [UInt8(0), UInt8(0), UInt8(0), UInt8(8)]
    c.feed(Span[UInt8, _](_frame(0x3, 0x0, sid, cancel)))
    var r1 = _scan(c.drain(), sid)
    if r1[0] >= 0 or r1[1] >= 0:
        print("inconclusive: the server's RST_STREAM drew an error")
        raise Error("setup")
    var st = c.conn.streams[sid].copy().state.value
    if st != StreamState.CLOSED().value:
        print("inconclusive: stream is not CLOSED after RST_STREAM; state", st)
        raise Error("setup")
    var body: List[UInt8] = [UInt8(0x78)]
    c.feed(Span[UInt8, _](_frame(0x0, 0x0, sid, body)))
    var r2 = _scan(c.drain(), sid)
    if r2[0] != 5 and r2[1] != 5:
        print(
            "BUG REPRODUCED: DATA on stream",
            sid,
            "after the server's RST_STREAM (state",
            st,
            "= CLOSED) drew GOAWAY code",
            r2[0],
            "/ RST_STREAM code",
            r2[1],
            "(expected STREAM_CLOSED = 5; 1 = PROTOCOL_ERROR, -1 = none)",
        )
        raise Error("H2-20")
    print("OK: DATA on the reset stream drew STREAM_CLOSED (GOAWAY", r2[0], "/ RST", r2[1], ")")
