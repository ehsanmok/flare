# PLATFORM: any
# RESOLVED: H2-06 fixed on fix/formal-findings
"""H2-06: HEADERS on stream 0 raises out of the server driver instead of
answering GOAWAY(PROTOCOL_ERROR).

Lean: Flare.Bugs.H2_06.bug (counterexample) and Flare.Bugs.H2_06.fixed.
flare/http2/state.mojo:1258-1259 @59bda50:
    if f.header.stream_id == 0:
        raise Error("h2: HEADERS on stream 0")

RFC 9113 sec 6.2: "If a HEADERS frame is received whose Stream Identifier
field is 0x00, the recipient MUST respond with a connection error
(Section 5.4.1) of type PROTOCOL_ERROR." sec 5.4.1: "An endpoint that
encounters a connection error SHOULD first send a GOAWAY frame". flare's
own _conn_error (state.mojo:676-683) exists because "Raising instead drops
the connection with no frame at all".

Trace: Http2Connection.feed(preface, SETTINGS, HEADERS on stream 0).

Expected: feed returns and the outbox carries GOAWAY(PROTOCOL_ERROR).
Before the fix: feed raises "h2: HEADERS on stream 0" and no GOAWAY is queued.

Minimal fix: `return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)`
in place of the raise.
"""

from flare.http2 import Http2Connection, H2_PREFACE, parse_frame


def _frame(mut out: List[UInt8], ty: UInt8, flags: UInt8, sid: Int, payload: List[UInt8]):
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
    var srv = Http2Connection()
    var wire = List[UInt8]()
    for b in String(H2_PREFACE).as_bytes():
        wire.append(b)
    _frame(wire, 0x4, 0x0, 0, List[UInt8]())
    var block: List[UInt8] = [UInt8(0x82), UInt8(0x86), UInt8(0x84)]
    _frame(wire, 0x1, 0x5, 0, block)
    var raised = String("")
    try:
        srv.feed(Span[UInt8, _](wire))
    except e:
        raised = String(e)
    var code = _goaway_code(srv.drain())
    if raised.byte_length() > 0 or code != 1:
        print(
            "BUG REPRODUCED: HEADERS on stream 0 raised '",
            raised,
            "' and queued GOAWAY code",
            code,
            "(expected GOAWAY code 1 = PROTOCOL_ERROR, no raise)",
        )
        raise Error("H2-06")
    print("OK: HEADERS on stream 0 answered with GOAWAY(PROTOCOL_ERROR)")
