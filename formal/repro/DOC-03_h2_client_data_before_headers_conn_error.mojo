# PLATFORM: any
# RESOLVED: DOC-03 fixed on fix/formal-findings
"""DOC-03: a response that starts with DATA instead of HEADERS is a
malformed response, and the HTTP/2 client answers it with a connection
error, taking every sibling stream down with it.

Lean: Flare.Bugs.DOC_03.counterexample (counterexample) and
Flare.Bugs.DOC_03.fixed (fix meets spec). The branch is modelled as
`Flare.L3.H2.handle` (Conn.lean:664).
flare/http2/state.mojo:1356-1358 @59bda50, in the DATA branch of
`Connection.handle_frame`:

    if self.is_client and not s.headers_complete:
        return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)

Doc claim: docs/features.md:369 "A malformed response is a stream error
per RFC 9113 sec 8.1.1, never a connection error, so one bad stream cannot
take its siblings down".
RFC 9113 sec 8.1: a response is HEADERS, then DATA. sec 8.1.1: "A malformed
request or response is one that is an otherwise valid sequence of HTTP/2
frames but is invalid due to the presence of extraneous frames ...
Malformed requests or responses that are detected MUST be treated as a
stream error (Section 5.4.2) of type PROTOCOL_ERROR." DATA on stream 1
after the client's own HEADERS is valid for the stream state (half-closed
(local)), so it is the malformed-message case, not a framing error.

Trace: GET on streams 1 and 3; the server sends DATA(1, END_STREAM, "x")
before any HEADERS on stream 1, then a complete response on stream 3.
Expected: RST_STREAM(1, PROTOCOL_ERROR), no GOAWAY, and stream 3's
response delivered. Before the fix: GOAWAY(PROTOCOL_ERROR) at the DATA frame.

Minimal fix: replace that `_conn_error` with the stream error the other
malformed-response checks use: RST_STREAM(sid, PROTOCOL_ERROR), mark the
stream CLOSED, and return the frame's connection-level credit
(WINDOW_UPDATE(0, len(payload))), as state.mojo:1384-1398 does for DATA
on a 204.
"""

from flare.http2 import HpackHeader, Http2ClientConnection, parse_frame


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


def _scan(bytes: List[UInt8], want: UInt8, sid: Int) raises -> Int:
    """Error code of the first GOAWAY (want = 7) or of the first RST_STREAM
    on `sid` (want = 3) in `bytes`; -1 when there is none."""
    var off = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value != want:
            continue
        if want == 7 and len(f.payload) >= 8:
            return Int(f.payload[7]) | (Int(f.payload[6]) << 8)
        if want == 3 and f.header.stream_id == sid and len(f.payload) >= 4:
            return Int(f.payload[3]) | (Int(f.payload[2]) << 8)
    return -1


def main() raises:
    var c = Http2ClientConnection()
    _ = c.drain()
    var empty = List[UInt8]()
    var s1 = c.next_stream_id()
    c.send_request(s1, "GET", "http", "example.com", "/a", List[HpackHeader](), Span(empty))
    var s3 = c.next_stream_id()
    c.send_request(s3, "GET", "http", "example.com", "/b", List[HpackHeader](), Span(empty))
    _ = c.drain()
    if s1 != 1 or s3 != 3:
        print("inconclusive: unexpected stream ids", s1, s3)
        raise Error("setup")

    var body: List[UInt8] = [UInt8(0x78)]
    c.feed(Span[UInt8, _](_frame(0x0, 0x1, s1, body)))
    var reply = c.drain()
    var goaway = _scan(reply, 7, 0)
    var rst = _scan(reply, 3, s1)

    # :status 200 on stream 3, END_HEADERS | END_STREAM.
    var hdr: List[UInt8] = [UInt8(0x88)]
    var sibling_ok = False
    if goaway < 0:
        c.feed(Span[UInt8, _](_frame(0x1, 0x5, s3, hdr)))
        _ = c.drain()
        sibling_ok = c.response_ready(s3)

    if goaway < 0 and rst == 1 and sibling_ok:
        print(
            "OK: DATA before HEADERS reset stream 1 (RST_STREAM PROTOCOL_ERROR);"
            " stream 3's response was delivered"
        )
        return
    if goaway >= 0:
        print(
            "BUG REPRODUCED: DATA on stream 1 before its HEADERS drew GOAWAY code",
            goaway,
            "(connection error; RST_STREAM on stream 1:",
            rst,
            ") instead of RST_STREAM(1, PROTOCOL_ERROR), so sibling stream 3 dies",
        )
        raise Error("DOC-03")
    print(
        "inconclusive: no GOAWAY, RST_STREAM code on stream 1 =",
        rst,
        ", stream 3 ready =",
        sibling_ok,
    )
    raise Error("inconclusive")
