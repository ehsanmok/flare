# PLATFORM: any
# RESOLVED: H2-16 fixed on fix/formal-findings
"""H2-16: a PRIORITY frame that makes an idle stream depend on itself (or
a zero-increment WINDOW_UPDATE on an idle stream) makes the HTTP/2 server
send RST_STREAM for that idle stream and remember the id as reset. The
peer can still open the stream, and then every DATA frame on it,
END_STREAM included, is silently discarded: the request never completes.

Lean: Flare.Bugs.H2_16.bug (counterexample) and Flare.Bugs.H2_16.fixed;
the refinement theorem Flare.L3.H2.Refine.shipped_classified (guard g16,
witness Flare.Bugs.H2_Refine.w16) names these steps as the H2-16
trigger. flare/http2/state.mojo:1078-1092 (PRIORITY self-dependency) and
1213-1222 (WINDOW_UPDATE increment 0) @59bda50 call `_rst_stream_frame`,
which appends the id to `_reset_by_us` (587-605), without checking that
the stream exists; HEADERS (1257-1333) never consults `_reset_by_us`;
DATA (1340-1347) drops every frame on an id in `_reset_by_us`.

RFC 9113 sec 5.1 (idle): "RST_STREAM frames MUST NOT be sent for a stream
in the idle state"; sec 5.4.1 lets an endpoint treat a stream error as a
connection error, which is the only way to report one on an idle stream.

Trace: PRIORITY(stream 1, depends on 1); then HEADERS(1, POST, no
END_STREAM); then DATA(1, "abc", END_STREAM).

Expected: GOAWAY(PROTOCOL_ERROR) at the PRIORITY frame (or, if the stream
is opened, the body is delivered). Before the fix: RST_STREAM(1, PROTOCOL_ERROR)
for the idle stream, the HEADERS opens stream 1, and the DATA is dropped:
stream 1 stays OPEN with an empty body and is never completed.

Minimal fix: when the target stream is idle (not in the table and not
below the high-water mark), answer GOAWAY(PROTOCOL_ERROR) instead of
RST_STREAM.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection, StreamState


def _raw(ty: Int, flags: Int, sid: Int, var payload: List[UInt8]) -> Frame:
    var f = Frame()
    f.header.type = FrameType(UInt8(ty))
    f.header.flags = FrameFlags(UInt8(flags))
    f.header.stream_id = sid
    f.header.length = len(payload)
    f.payload = payload^
    return f^


def _kind(r: List[Frame], sid: Int) -> String:
    var s = String("none")
    for f in r:
        if f.header.type.value == FrameType.GOAWAY().value:
            return String("GOAWAY code ") + String(Int(f.payload[7]))
        if f.header.type.value == FrameType.RST_STREAM().value and f.header.stream_id == sid:
            s = String("RST_STREAM code ") + String(Int(f.payload[3]))
    return s


def _run(first: Frame) raises -> Tuple[String, Int, Int, Bool]:
    var c = Connection()
    var k1 = _kind(c.handle_frame(first.copy()), 1)
    if k1.startswith("GOAWAY"):
        return (k1, -1, -1, False)
    # POST /, scheme http, :authority a
    var hb: List[UInt8] = [UInt8(0x83), UInt8(0x86), UInt8(0x84), UInt8(0x41), UInt8(1), UInt8(0x61)]
    var r2 = c.handle_frame(_raw(0x1, 0x4, 1, hb^))
    if _kind(r2, 1) != "none" or 1 not in c.streams:
        print("inconclusive: HEADERS did not open stream 1:", _kind(r2, 1))
        raise Error("setup")
    _ = c.handle_frame(_raw(0x0, 0x1, 1, [UInt8(0x61), UInt8(0x62), UInt8(0x63)]))
    var s = c.streams[1].copy()
    return (k1, s.state.value, len(s.data), s.data_complete)


def main() raises:
    var prio = _run(_raw(0x2, 0x0, 1, [UInt8(0), UInt8(0), UInt8(0), UInt8(1), UInt8(16)]))
    var wu = _run(_raw(0x8, 0x0, 1, [UInt8(0), UInt8(0), UInt8(0), UInt8(0)]))
    if prio[0].startswith("RST") or wu[0].startswith("RST"):
        print(
            "BUG REPRODUCED: on idle stream 1, PRIORITY(self-dependency) drew",
            prio[0],
            "and WINDOW_UPDATE(0) drew",
            wu[0],
            "; after HEADERS opened stream 1, DATA(\"abc\", END_STREAM) left"
            " state",
            prio[1],
            "/",
            wu[1],
            "body bytes",
            prio[2],
            "/",
            wu[2],
            "data_complete",
            prio[3],
            "/",
            wu[3],
            "(OPEN =",
            StreamState.OPEN().value,
            ")",
        )
        raise Error("H2-16")
    print("OK: idle-stream PRIORITY/WINDOW_UPDATE drew", prio[0], "/", wu[0])
