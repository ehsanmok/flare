# PLATFORM: any
"""H2-17: the HTTP/2 client drops a PUSH_PROMISE frame without decoding its
header block, so the HPACK dynamic table falls out of step with the
server's encoder and a later response decodes to a wrong header. The
PUSH_PROMISE itself draws RST_STREAM on the promised id, never the
connection error RFC 9113 requires once push is disabled.

Lean: Flare.Bugs.H2_17.bug (counterexample) and Flare.Bugs.H2_17.fixed;
the composed HPACK theorem Flare.L3.H2.Conn.lookup_sound_conn and
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g17,
witness Flare.Bugs.H2_Refine.w17) name this step as the H2-17
trigger. flare/http2/client.mojo:427-446 @59bda50: a PUSH_PROMISE is
answered with RST_STREAM(promised, PROTOCOL_ERROR) and `continue`d before
`Connection.handle_frame`, so its field block never reaches the HPACK
decoder.

RFC 9113 sec 6.6: "PUSH_PROMISE MUST NOT be sent if the
SETTINGS_ENABLE_PUSH setting of the peer endpoint is set to 0. An
endpoint that has set this setting and has received acknowledgment MUST
treat the receipt of a PUSH_PROMISE frame as a connection error
(Section 5.4.1) of type PROTOCOL_ERROR." sec 4.3: field blocks carry
compression state; a receiver that skips one decodes later blocks against
the wrong dynamic table (RFC 7541 sec 2.3.2, sec 4).

Trace: GET on streams 1 and 3. The server answers stream 1 with
":status 200" and "x-b: 2" (literal with incremental indexing: both
tables now hold x-b: 2 at index 62); sends PUSH_PROMISE(stream 3,
promised 2) whose block inserts "x-a: 1" (server table: 62 = x-a: 1,
63 = x-b: 2); then answers stream 3 with ":status 200" and indexed field
62, meaning "x-a: 1".

Expected: GOAWAY(PROTOCOL_ERROR) at the PUSH_PROMISE (push is disabled
in flare's preface SETTINGS), or at least the field block is decoded so
stream 3 carries "x-a: 1". Actual: RST_STREAM(2) and stream 3's response
carries "x-b: 2", a header the server never sent on it.

Minimal fix: hand PUSH_PROMISE to handle_frame, which already answers
GOAWAY(PROTOCOL_ERROR) (state.mojo:1104-1108).
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


def _reply(bytes: List[UInt8]) raises -> String:
    var off = 0
    var s = String("none")
    while off < len(bytes):
        var got = parse_frame(Span[UInt8, _](bytes)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            return String("GOAWAY code ") + String(Int(f.payload[7]))
        if f.header.type.value == 3:
            s = String("RST_STREAM(") + String(f.header.stream_id) + ") code " + String(Int(f.payload[3]))
    return s


def main() raises:
    var c = Http2ClientConnection()
    _ = c.drain()
    var empty = List[UInt8]()
    var s1 = c.next_stream_id()
    c.send_request(s1, "GET", "http", "example.com", "/", List[HpackHeader](), Span(empty))
    var s3 = c.next_stream_id()
    c.send_request(s3, "GET", "http", "example.com", "/p", List[HpackHeader](), Span(empty))
    _ = c.drain()
    # :status 200, then literal with incremental indexing "x-b: 2"
    var b1: List[UInt8] = [
        UInt8(0x88), UInt8(0x40), UInt8(3), UInt8(0x78), UInt8(0x2D), UInt8(0x62),
        UInt8(1), UInt8(0x32),
    ]
    c.feed(Span[UInt8, _](_frame(0x1, 0x5, s1, b1)))
    if _reply(c.drain()) != "none" or not c.response_ready(s1):
        print("inconclusive: response on stream 1 not accepted")
        raise Error("setup")
    var r1 = c.take_response(s1)
    var saw_b = False
    for h in r1.headers:
        if h.name == "x-b" and h.value == "2":
            saw_b = True
    if not saw_b:
        print("inconclusive: stream 1 response lacks x-b: 2")
        raise Error("setup")
    # PUSH_PROMISE on stream 3, promised stream 2, block inserts "x-a: 1"
    var pp: List[UInt8] = [
        UInt8(0), UInt8(0), UInt8(0), UInt8(2),
        UInt8(0x40), UInt8(3), UInt8(0x78), UInt8(0x2D), UInt8(0x61),
        UInt8(1), UInt8(0x31),
    ]
    c.feed(Span[UInt8, _](_frame(0x5, 0x4, s3, pp)))
    var at_push = _reply(c.drain())
    if at_push.startswith("GOAWAY"):
        print("OK: PUSH_PROMISE drew", at_push)
        return
    # :status 200, indexed field 62 (server table: x-a: 1)
    var b3: List[UInt8] = [UInt8(0x88), UInt8(0xBE)]
    c.feed(Span[UInt8, _](_frame(0x1, 0x5, s3, b3)))
    var at_resp = _reply(c.drain())
    if not c.response_ready(s3):
        print("inconclusive: stream 3 response not ready; reply", at_resp)
        raise Error("setup")
    var r3 = c.take_response(s3)
    var got = String("")
    for h in r3.headers:
        got += h.name + ": " + h.value + "; "
    var wrong = False
    for h in r3.headers:
        if h.name == "x-b":
            wrong = True
    if wrong:
        print(
            "BUG REPRODUCED: PUSH_PROMISE drew",
            at_push,
            "instead of GOAWAY(PROTOCOL_ERROR); its field block was not"
            " decoded, and stream 3's response (server sent index 62 ="
            " x-a: 1) decoded as:",
            got,
        )
        raise Error("H2-17")
    print("inconclusive: no wrong header; stream 3 decoded as:", got, "; reply", at_resp)
    raise Error("inconclusive")
