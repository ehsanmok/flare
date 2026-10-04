# PLATFORM: any
"""H2-07: a GOAWAY frame shorter than its 8 mandatory octets is accepted.

Lean: Flare.Bugs.H2_07.bug (counterexample) and Flare.Bugs.H2_07.fixed.
flare/http2/state.mojo:1063-1065 and 1514-1516 @59bda50: the GOAWAY
shape check tests only the stream id.

RFC 9113 sec 6.8: the GOAWAY payload is Last-Stream-ID (32 bits) and Error
Code (32 bits), plus optional debug data. sec 4.2: "An endpoint MUST send
an error code of FRAME_SIZE_ERROR if a frame ... is too small to contain
mandatory frame data."

Trace: Connection.handle_frame(GOAWAY on stream 0 with an empty payload),
then the same with a 4-byte payload.

Expected: connection error FRAME_SIZE_ERROR (GOAWAY code 6) for both.
Actual: no reply at all, and goaway_received is set as if a well-formed
GOAWAY had arrived.

Minimal fix: `if plen < 8: return self._conn_error(FRAME_SIZE_ERROR)` in
the GOAWAY shape check.
"""

from flare.http2.frame import Frame, FrameType
from flare.http2.state import Connection


def _reply_code(n: Int) raises -> Int:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.GOAWAY()
    f.header.stream_id = 0
    for _ in range(n):
        f.payload.append(0)
    f.header.length = n
    for g in c.handle_frame(f^):
        if g.header.type.value == FrameType.GOAWAY().value:
            return Int(g.payload[7])
    return -1


def main() raises:
    var c0 = _reply_code(0)
    var c4 = _reply_code(4)
    if c0 != 6 or c4 != 6:
        print(
            "BUG REPRODUCED: GOAWAY with 0-byte payload got reply code",
            c0,
            "and with 4-byte payload got",
            c4,
            "(expected 6 = FRAME_SIZE_ERROR; -1 = no reply, frame accepted)",
        )
        raise Error("H2-07")
    print("OK: short GOAWAY frames draw FRAME_SIZE_ERROR")
