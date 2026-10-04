# PLATFORM: any
"""H2-02: a stream id flare refused with REFUSED_STREAM can be opened again
by a second HEADERS on the same id.

Lean: Flare.Bugs.H2_02.bug (counterexample) and Flare.Bugs.H2_02.fixed
(`<=` rejects every reused id).
flare/http2/state.mojo:1123 @59bda50:
    if sid < self.last_peer_stream_id and sid not in self.streams:

RFC 9113 sec 5.1.1: "The identifier of a newly established stream MUST be
numerically greater than all streams that the initiating endpoint has
opened or reserved. ... An endpoint that receives an unexpected stream
identifier MUST respond with a connection error (Section 5.4.1) of type
PROTOCOL_ERROR." A refused stream is closed (sec 5.1, sec 8.7).

Trace (max_concurrent_streams = 1): HEADERS on stream 1 without
END_STREAM (open); HEADERS on stream 3 is refused with
RST_STREAM(REFUSED_STREAM) and never enters the stream table, but
last_peer_stream_id is now 3; the peer resets stream 1; HEADERS on stream
3 again. sid == last_peer_stream_id, so the `<` test passes it, the slot
is free, and stream 3 opens as a new request.

Expected: GOAWAY(PROTOCOL_ERROR). Actual: stream 3 is accepted as a fresh
request (half-closed remote, ready for dispatch).

The suspected trigger via pruning does not occur: _prune_closed_streams
only runs while a new, higher id is being created, which becomes the new
last_peer_stream_id and is not yet in the table, so the highest id is
never pruned. The refusal path is the reachable one.

Minimal fix: `sid <= self.last_peer_stream_id` at state.mojo:1123.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _headers(sid: Int, end_stream: Bool) -> Frame:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    var fl = FrameFlags.END_HEADERS()
    if end_stream:
        fl |= FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(fl)
    f.header.stream_id = sid
    var b = List[UInt8]()
    b.append(UInt8(0x82) if end_stream else UInt8(0x83))  # GET / POST
    b.append(0x86)
    b.append(0x84)
    f.header.length = len(b)
    f.payload = b^
    return f^


def _code(f: Frame) -> Int:
    var o = 4 if f.header.type.value == FrameType.GOAWAY().value else 0
    return (
        (Int(f.payload[o]) << 24)
        | (Int(f.payload[o + 1]) << 16)
        | (Int(f.payload[o + 2]) << 8)
        | Int(f.payload[o + 3])
    )


def main() raises:
    var c = Connection()
    c.max_concurrent_streams = 1
    _ = c.handle_frame(_headers(1, False))
    var r = c.handle_frame(_headers(3, True))
    var refused = False
    for f in r:
        if f.header.type.value == FrameType.RST_STREAM().value and _code(f) == 7:
            refused = True
    if not refused or 3 in c.streams:
        raise Error("setup: stream 3 was not refused")
    var rst = Frame()
    rst.header.type = FrameType.RST_STREAM()
    rst.header.stream_id = 1
    rst.payload = [UInt8(0), UInt8(0), UInt8(0), UInt8(8)]  # CANCEL
    rst.header.length = 4
    _ = c.handle_frame(rst^)
    var r2 = c.handle_frame(_headers(3, True))
    for f in r2:
        if f.header.type.value == FrameType.GOAWAY().value:
            print("OK: reused stream id 3 drew GOAWAY code", _code(f))
            return
    var st = -1
    if 3 in c.streams:
        st = c.streams[3].copy().state.value
    print(
        "BUG REPRODUCED: stream 3 was refused (RST_STREAM REFUSED_STREAM),"
        " then a second HEADERS on stream 3 opened it as a new request"
        " (state",
        st,
        "= HALF_CLOSED_REMOTE) instead of GOAWAY(PROTOCOL_ERROR)",
    )
    raise Error("H2-02")
