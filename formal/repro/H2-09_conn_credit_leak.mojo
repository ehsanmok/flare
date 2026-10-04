# PLATFORM: any
"""H2-09: DATA that ends in a stream reset on the content-length-mismatch
path (and on the stream FLOW_CONTROL_ERROR path) never has its
connection-level credit returned, so the peer's connection window drains.

Lean: Flare.Bugs.H2_09.bug (counterexample) and Flare.Bugs.H2_09.fixed
(returning the credit on every reset path keeps W at 65535).
flare/http2/state.mojo:1457-1470 and 1374-1383 @59bda50: both return
before the WINDOW_UPDATE(0) at 1492-1511. The sibling reset paths at
1397-1398, 1423-1424 and 1445-1446 do return it.

RFC 9113 sec 6.9: "A receiver that receives a flow-controlled frame MUST
always account for its contribution against the connection flow-control
window ... This is necessary even if the frame is in error. The sender
counts the frame toward the flow-control window, but if the receiver does
not, the flow-control window at the sender and receiver can become
different." sec 6.8 likewise: DATA "MUST be counted toward the connection
flow-control window" and failing that lets flow control "become
unsynchronized".

Trace: four POSTs, each declaring content-length 100000 and sending one
DATA frame with END_STREAM (16384, 16384, 16384, 16383 octets). Each is
reset with RST_STREAM(PROTOCOL_ERROR) for the mismatch, as it should be.

Expected: 65535 octets of connection credit come back (one
WINDOW_UPDATE(0) per frame), so the peer's window stays at 65535.
Actual: zero connection credit comes back; the peer's connection window
is 0 and a conforming client can never send DATA on this connection
again.

Minimal fix: append Connection._window_update_frame(0, len(f.payload)) on
both reset paths, as the other reset paths already do.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _post(sid: Int) -> Frame:
    var b: List[UInt8] = [UInt8(0x83), UInt8(0x86), UInt8(0x84)]
    var v = String("100000")
    b.append(0x0F)  # literal w/o indexing, name index 28 = content-length
    b.append(0x0D)
    b.append(UInt8(v.byte_length()))
    for c in v.as_bytes():
        b.append(c)
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.header.stream_id = sid
    f.header.length = len(b)
    f.payload = b^
    return f^


def main() raises:
    var c = Connection()
    var w = 65535
    var sizes: List[Int] = [16384, 16384, 16384, 16383]
    var resets = 0
    for i in range(4):
        var sid = 2 * i + 1
        _ = c.handle_frame(_post(sid))
        var d = Frame()
        d.header.type = FrameType.DATA()
        d.header.flags = FrameFlags(FrameFlags.END_STREAM())
        d.header.stream_id = sid
        d.payload = List[UInt8](length=sizes[i], fill=UInt8(0x61))
        d.header.length = sizes[i]
        w -= sizes[i]
        for f in c.handle_frame(d^):
            if f.header.type.value == FrameType.RST_STREAM().value:
                resets += 1
            if f.header.type.value == FrameType.WINDOW_UPDATE().value and f.header.stream_id == 0:
                w += (
                    (Int(f.payload[0]) << 24)
                    | (Int(f.payload[1]) << 16)
                    | (Int(f.payload[2]) << 8)
                    | Int(f.payload[3])
                )
    if resets != 4:
        raise Error("setup: expected four content-length resets")
    if w < 65535:
        print(
            "BUG REPRODUCED: after 4 content-length resets (65535 DATA"
            " octets) the peer's connection window is",
            w,
            "(no WINDOW_UPDATE(0) credit returned); a conforming peer is"
            " stalled for good",
        )
        raise Error("H2-09")
    print("OK: connection window back at", w, "after four resets")
