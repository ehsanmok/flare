# PLATFORM: any
"""H2-12: the HTTP/2 client leaves a stream HALF_CLOSED_LOCAL, not CLOSED,
when it sends END_STREAM on the last DATA chunk of a non-empty body after
the server has already ended its side.

Lean: Flare.Bugs.H2_12.bug (counterexample) and Flare.Bugs.H2_12.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g12,
witness Flare.Bugs.H2_Refine.w12_departs) names this step as the H2-12
trigger. flare/http2/client.mojo:580-585 @59bda50 (`_emit_body_span`):

    if is_last and end_stream:
        sl2.state = StreamState.HALF_CLOSED_LOCAL()

The empty-body path of `send_data` (client.mojo:895-901) maps
HALF_CLOSED_REMOTE to CLOSED; this path does not.

RFC 9113 sec 5.1: "half-closed (remote) ... If an endpoint sends a frame
with the END_STREAM flag set ... the stream transitions to 'closed'". In
flare this path is taken by the WebSocket-over-HTTP/2 client
(flare/ws/client_h2.mojo:182: the CLOSE frame carries END_STREAM) when the
server's CLOSE (with END_STREAM) arrived first.

Trace: send_request_open(1); the server answers HEADERS(:status 200,
END_STREAM) so stream 1 is HALF_CLOSED_REMOTE; the client calls
send_data(1, b"x", end_stream=True); then a server DATA(1, END_STREAM)
arrives.

Expected: stream 1 is CLOSED after the client's END_STREAM, and the late
DATA is a STREAM_CLOSED error (RFC 9113 sec 5.1, closed). Actual: stream 1
is HALF_CLOSED_LOCAL and the DATA after the server's own END_STREAM is
accepted into the response body.

Minimal fix: in `_emit_body_span`, set `CLOSED if sl2.state ==
HALF_CLOSED_REMOTE else HALF_CLOSED_LOCAL`, as the empty-body path does.
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
    """GOAWAY code, else RST_STREAM code on `sid`, else -1."""
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
    var head: List[UInt8] = [UInt8(0x88)]  # :status 200
    c.feed(Span[UInt8, _](_frame(0x1, 0x5, sid, head)))
    if _error_code(c.drain(), sid) >= 0:
        print("inconclusive: response HEADERS drew an error")
        raise Error("setup")
    if c.conn.streams[sid].copy().state.value != StreamState.HALF_CLOSED_REMOTE().value:
        print("inconclusive: stream is not HALF_CLOSED_REMOTE after the response")
        raise Error("setup")
    var body: List[UInt8] = [UInt8(0x78)]
    c.send_data(sid, Span(body), True)
    _ = c.drain()
    var st = c.conn.streams[sid].copy().state.value
    var late: List[UInt8] = [UInt8(0x79)]
    c.feed(Span[UInt8, _](_frame(0x0, 0x1, sid, late)))
    var code = _error_code(c.drain(), sid)
    var n = len(c.conn.streams[sid].copy().data)
    if st != StreamState.CLOSED().value or code < 0:
        print(
            "BUG REPRODUCED: after the client's END_STREAM on a"
            " HALF_CLOSED_REMOTE stream the state is",
            st,
            "(CLOSED =",
            StreamState.CLOSED().value,
            ", HALF_CLOSED_LOCAL =",
            StreamState.HALF_CLOSED_LOCAL().value,
            "); a server DATA after its own END_STREAM drew error code",
            code,
            "(-1 = none) and the body now holds",
            n,
            "byte(s)",
        )
        raise Error("H2-12")
    print("OK: stream CLOSED; late DATA drew error code", code)
