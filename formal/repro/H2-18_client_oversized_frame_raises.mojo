# PLATFORM: any
# RESOLVED: H2-18 fixed on fix/formal-findings
"""H2-18: a frame larger than the client's advertised SETTINGS_MAX_FRAME_SIZE
makes `Http2ClientConnection.feed` raise instead of answering
GOAWAY(FRAME_SIZE_ERROR); flare's own callers (flare/http/_client/
h2_send.mojo:146,225,376,403, h2_download.mojo:175, grpc/streaming.mojo)
let the raise propagate, so the connection ends with no GOAWAY at all.

Lean: Flare.Bugs.H2_18.bug (counterexample) and Flare.Bugs.H2_18.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g18,
witness Flare.Bugs.H2_Refine.w18) names this step as the H2-18
trigger. flare/http2/client.mojo:404-414 @59bda50.

RFC 9113 sec 4.2: "An endpoint MUST send an error code of
FRAME_SIZE_ERROR if a frame exceeds the size defined in
SETTINGS_MAX_FRAME_SIZE". The server driver does this
(server.mojo:398-438); the client driver does not. Same class as H2-06.

Trace: fresh client; the server sends a DATA frame header declaring
16385 octets on stream 1.

Expected: feed returns and the outbox holds GOAWAY(FRAME_SIZE_ERROR).
Before the fix: feed raises and nothing is queued.

Minimal fix: queue `_conn_error(FRAME_SIZE_ERROR)` and stop reading
instead of raising.
"""

from flare.http2 import Http2ClientConnection, parse_frame


def _goaway_code(bytes: List[UInt8]) raises -> Int:
    var off = 0
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            return Int(f.payload[7])
    return -1


def main() raises:
    var c = Http2ClientConnection()
    _ = c.drain()
    var n = 16385
    var hdr: List[UInt8] = [
        UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF),
        UInt8(0x0), UInt8(0x0), UInt8(0), UInt8(0), UInt8(0), UInt8(1),
    ]
    var raised = False
    var msg = String("")
    try:
        c.feed(Span[UInt8, _](hdr))
    except e:
        raised = True
        msg = String(e)
    var code = _goaway_code(c.drain())
    if raised or code != 6:
        print(
            "BUG REPRODUCED: oversized frame: feed raised =",
            raised,
            "('",
            msg,
            "') and queued GOAWAY code",
            code,
            "(expected GOAWAY code 6 = FRAME_SIZE_ERROR, no raise)",
        )
        raise Error("H2-18")
    print("OK: oversized frame drew GOAWAY code", code)
