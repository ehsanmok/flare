# PLATFORM: any
# RESOLVED: H2-01 fixed on fix/formal-findings
"""H2-01: the connection-level receive window is never decremented or
checked, so the 64 MiB request-buffer cap does not stop a peer that
ignores the connection window.

Lean: Flare.Bugs.H2_01.bug (counterexample) and Flare.Bugs.H2_01.fixed
(tracking the connection window bounds buffered bytes).
flare/http2/state.mojo:1372-1383 and 1482-1511 @59bda50 (DATA only
touches s.recv_window; Connection.recv_window is never read).

RFC 9113 sec 6.9.1: "The sender MUST NOT send a flow-controlled frame with
a length that exceeds the space available in either of the flow-control
windows advertised by the receiver." sec 6.9: a receiver "MAY respond
with a stream error ... or connection error ... of type
FLOW_CONTROL_ERROR". flare's own design (state.mojo:1485-1491) relies on
withholding connection credit to "stall the peer" once more than
_MAX_BUFFERED_REQUEST_BYTES (64 MiB) are buffered. Without enforcement
that only stalls a peer that chooses to obey.

Trace: POST streams 1, 3, 5, ... each send 16384-byte DATA frames (stream
credit comes straight back). Once 64 MiB are buffered flare withholds
connection credit. The peer keeps sending. W = 65535 + (connection
credit returned) - (DATA received) goes negative after four more frames.

Expected: a GOAWAY(FLOW_CONTROL_ERROR) once W < 0. Before the fix: every frame is
accepted and buffered; the run stops at W = -65537 with no error.

Minimal fix: decrement Connection.recv_window by each DATA payload, treat
a negative value as connection error FLOW_CONTROL_ERROR, and add back
every connection-level WINDOW_UPDATE that is emitted.
"""

from flare.http2.frame import Frame, FrameFlags, FrameType
from flare.http2.state import Connection


def _post(sid: Int) -> Frame:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.header.stream_id = sid
    var b = List[UInt8]()
    b.append(0x83)  # :method POST
    b.append(0x86)  # :scheme http
    b.append(0x84)  # :path /
    f.header.length = len(b)
    f.payload = b^
    return f^


def main() raises:
    var c = Connection()
    var chunk = List[UInt8](length=16384, fill=UInt8(0x61))
    var w = 65535  # receiver-side connection window as the peer sees it
    var sid = 1
    var on_stream = 0
    var per_stream = c.max_request_body_size // 16384
    var r0 = c.handle_frame(_post(sid))
    for f in r0:
        if f.header.type.value == FrameType.GOAWAY().value:
            raise Error("setup: HEADERS rejected")
    var frames = 0
    while w > -65536:
        if on_stream == per_stream:
            sid += 2
            on_stream = 0
            var rh = c.handle_frame(_post(sid))
            for f in rh:
                if f.header.type.value == FrameType.GOAWAY().value:
                    raise Error("setup: HEADERS rejected")
        var d = Frame()
        d.header.type = FrameType.DATA()
        d.header.stream_id = sid
        d.header.length = 16384
        d.payload = chunk.copy()
        var r = c.handle_frame(d^)
        w -= 16384
        frames += 1
        on_stream += 1
        for f in r:
            var ty = f.header.type.value
            if (
                ty == FrameType.GOAWAY().value
                or ty == FrameType.RST_STREAM().value
            ):
                print(
                    "OK: frame",
                    frames,
                    "with W =",
                    w,
                    "was answered with frame type",
                    Int(ty),
                )
                return
            if (
                ty == FrameType.WINDOW_UPDATE().value
                and f.header.stream_id == 0
            ):
                w += (
                    (Int(f.payload[0]) << 24)
                    | (Int(f.payload[1]) << 16)
                    | (Int(f.payload[2]) << 8)
                    | Int(f.payload[3])
                )
    print(
        "BUG REPRODUCED: peer overran the connection window to W =",
        w,
        "with no FLOW_CONTROL_ERROR; buffered_request_bytes =",
        c.buffered_request_bytes,
        "> 64 MiB cap",
        64 * 1024 * 1024,
        "after",
        frames,
        "DATA frames on",
        (sid + 1) // 2,
        "streams; withheld credit",
        c.withheld_conn_credit,
    )
    raise Error("H2-01")
