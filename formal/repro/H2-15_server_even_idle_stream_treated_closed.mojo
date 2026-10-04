# PLATFORM: any
"""H2-15: the HTTP/2 server treats a never-opened even stream id below the
highest client stream id as closed instead of idle: RST_STREAM and
WINDOW_UPDATE on it are silently accepted, and DATA on it draws
GOAWAY(STREAM_CLOSED) instead of GOAWAY(PROTOCOL_ERROR).

Lean: Flare.Bugs.H2_15.bug (counterexample) and Flare.Bugs.H2_15.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g15,
witness Flare.Bugs.H2_Refine.w15) names these steps as the H2-15
trigger. flare/http2/state.mojo:1099, 1238 and 1351 @59bda50: the idle
test is `sid > self.last_peer_stream_id` for every id. Even ids are
server-initiated; with push disabled the server never opens one, so every
even id stays idle for the life of the connection.

RFC 9113 sec 5.1 (idle): "Receiving any frame other than HEADERS or
PRIORITY on a stream in this state MUST be treated as a connection error
(Section 5.4.1) of type PROTOCOL_ERROR."

Trace: a client opens stream 3 (GET, END_STREAM); then, each on its own
connection, sends WINDOW_UPDATE(stream 2), RST_STREAM(stream 2) and
DATA(stream 2).

Expected: GOAWAY(PROTOCOL_ERROR) for each. Actual: WINDOW_UPDATE and
RST_STREAM draw nothing; DATA draws GOAWAY(STREAM_CLOSED).

Minimal fix: in server role an unknown even id is idle
(`sid > last_peer_stream_id or sid % 2 == 0`).
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _headers3() -> Frame:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS() | FrameFlags.END_STREAM())
    f.header.stream_id = 3
    var b: List[UInt8] = [UInt8(0x82), UInt8(0x86), UInt8(0x84), UInt8(0x41), UInt8(1), UInt8(0x61)]
    f.header.length = len(b)
    f.payload = b^
    return f^


def _raw(ty: Int, sid: Int, var payload: List[UInt8]) -> Frame:
    var f = Frame()
    f.header.type = FrameType(UInt8(ty))
    f.header.stream_id = sid
    f.header.length = len(payload)
    f.payload = payload^
    return f^


def _goaway(r: List[Frame]) -> Int:
    for f in r:
        if f.header.type.value == FrameType.GOAWAY().value:
            return Int(f.payload[7])
    return -1


def _probe(ty: Int, var payload: List[UInt8]) raises -> Int:
    var c = Connection()
    var r0 = c.handle_frame(_headers3())
    if _goaway(r0) >= 0 or 3 not in c.streams:
        print("inconclusive: stream 3 was not opened")
        raise Error("setup")
    return _goaway(c.handle_frame(_raw(ty, 2, payload^)))


def main() raises:
    var wu = _probe(0x8, [UInt8(0), UInt8(0), UInt8(0), UInt8(1)])
    var rst = _probe(0x3, [UInt8(0), UInt8(0), UInt8(0), UInt8(8)])
    var data = _probe(0x0, [UInt8(0x61)])
    if wu != 1 or rst != 1 or data != 1:
        print(
            "BUG REPRODUCED: on never-opened stream 2 (below stream 3):"
            " WINDOW_UPDATE drew GOAWAY code",
            wu,
            ", RST_STREAM drew",
            rst,
            ", DATA drew",
            data,
            "(1 = PROTOCOL_ERROR, 5 = STREAM_CLOSED, -1 = none)",
        )
        raise Error("H2-15")
    print("OK: every frame on idle stream 2 drew GOAWAY(PROTOCOL_ERROR)")
