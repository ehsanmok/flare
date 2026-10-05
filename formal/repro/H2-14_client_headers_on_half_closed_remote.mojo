# PLATFORM: any
# RESOLVED: H2-14 fixed on fix/formal-findings
"""H2-14: the HTTP/2 client accepts a HEADERS frame on a stream the server
has already ended (half-closed (remote)) and merges it into the response
as an extra trailer section.

Lean: Flare.Bugs.H2_14.bug (counterexample) and Flare.Bugs.H2_14.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g14,
witness Flare.Bugs.H2_Refine.w14) names this step as the H2-14
trigger. flare/http2/state.mojo:1268-1288 @59bda50: the
HALF_CLOSED_REMOTE check on HEADERS runs only `if not self.is_client`;
in client role a HEADERS with END_STREAM on such a stream passes the
trailer checks (851-956) and is committed (958-1003).

RFC 9113 sec 5.1, half-closed (remote): "If an endpoint receives
additional frames, other than WINDOW_UPDATE, PRIORITY, or RST_STREAM, for
a stream that is in this state, it MUST respond with a stream error
(Section 5.4.2) of type STREAM_CLOSED."

Trace: send_request_open(1) (request body still open); the server sends
HEADERS(1, :status 200, END_STREAM), then HEADERS(1, "x-t: 1",
END_STREAM).

Expected: RST_STREAM(1, STREAM_CLOSED) or GOAWAY(STREAM_CLOSED). Before the fix:
no error; the second block is appended to the response headers.

Minimal fix: apply the HALF_CLOSED_REMOTE check to HEADERS in both roles.
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


def _error_code(bytes: List[UInt8], sid: Int) raises -> Int:
    var off = 0
    var rst = -1
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            return Int(f.payload[7])
        if f.header.type.value == 3 and f.header.stream_id == sid:
            rst = Int(f.payload[3])
    return rst


def main() raises:
    var c = Http2ClientConnection()
    _ = c.drain()
    var sid = c.next_stream_id()
    c.send_request_open(sid, "POST", "http", "example.com", "/", List[HpackHeader]())
    _ = c.drain()
    var head: List[UInt8] = [UInt8(0x88)]
    c.feed(Span[UInt8, _](_frame(0x1, 0x5, sid, head)))
    if _error_code(c.drain(), sid) >= 0:
        print("inconclusive: response HEADERS drew an error")
        raise Error("setup")
    var s0 = c.conn.streams[sid].copy()
    if s0.state.value != StreamState.HALF_CLOSED_REMOTE().value:
        print("inconclusive: stream is not HALF_CLOSED_REMOTE")
        raise Error("setup")
    var n0 = len(s0.headers)
    # literal without indexing, new name "x-t", value "1"
    var tr: List[UInt8] = [
        UInt8(0x00), UInt8(3), UInt8(0x78), UInt8(0x2D), UInt8(0x74),
        UInt8(1), UInt8(0x31),
    ]
    c.feed(Span[UInt8, _](_frame(0x1, 0x5, sid, tr)))
    var code = _error_code(c.drain(), sid)
    var s1 = c.conn.streams[sid].copy()
    if code < 0:
        print(
            "BUG REPRODUCED: HEADERS(END_STREAM) on a HALF_CLOSED_REMOTE"
            " stream drew no error (code",
            code,
            "); header count",
            n0,
            "->",
            len(s1.headers),
            "; state",
            s1.state.value,
        )
        raise Error("H2-14")
    print("OK: HEADERS on a HALF_CLOSED_REMOTE stream drew error code", code)
