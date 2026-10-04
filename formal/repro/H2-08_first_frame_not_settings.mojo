# PLATFORM: any
"""H2-08: the server does not require the first frame after the client
preface to be SETTINGS.

Lean: Flare.Bugs.H2_08.bug (counterexample) and Flare.Bugs.H2_08.fixed.
flare/http2/server.mojo:358-391 @59bda50: after the 24-byte magic is
stripped, frames go straight to Connection.handle_frame, which has no
notion of "first frame".

RFC 9113 sec 3.4: "The client connection preface starts with a sequence of
24 octets ... This sequence MUST be followed by a SETTINGS frame". "Clients
and servers MUST treat an invalid connection preface as a connection error
(Section 5.4.1) of type PROTOCOL_ERROR."

Trace: Http2Connection.feed(magic, PING) with no SETTINGS.

Expected: GOAWAY(PROTOCOL_ERROR). Actual: the PING is answered with a PING
ACK and the connection carries on.

Minimal fix: record in Http2Connection whether the peer's first frame has
been seen, and answer anything but a non-ACK SETTINGS there with
GOAWAY(PROTOCOL_ERROR).
"""

from flare.http2 import Http2Connection, H2_PREFACE, parse_frame


def main() raises:
    var srv = Http2Connection()
    var wire = List[UInt8]()
    for b in String(H2_PREFACE).as_bytes():
        wire.append(b)
    # PING, 8-byte payload, stream 0.
    var hdr: List[UInt8] = [
        UInt8(0), UInt8(0), UInt8(8), UInt8(0x6), UInt8(0),
        UInt8(0), UInt8(0), UInt8(0), UInt8(0),
    ]
    for b in hdr:
        wire.append(b)
    for i in range(8):
        wire.append(UInt8(i))
    srv.feed(Span[UInt8, _](wire))
    var out = srv.drain()
    var goaway = -1
    var ping_ack = False
    var off = 0
    while off < len(out):
        var got = parse_frame(Span[UInt8, _](out)[off:])
        if not got:
            break
        var f = got.value().copy()
        off += 9 + f.header.length
        if f.header.type.value == 7:
            goaway = Int(f.payload[7])
        if f.header.type.value == 6 and (f.header.flags.bits & 1) != 0:
            ping_ack = True
    if goaway != 1:
        print(
            "BUG REPRODUCED: first frame after the preface was PING, not"
            " SETTINGS; flare sent PING ACK =",
            ping_ack,
            "and GOAWAY code",
            goaway,
            "(expected GOAWAY code 1 = PROTOCOL_ERROR)",
        )
        raise Error("H2-08")
    print("OK: a non-SETTINGS first frame drew GOAWAY(PROTOCOL_ERROR)")
