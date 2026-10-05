# PLATFORM: any
# RESOLVED: NET-04 fixed on fix/formal-findings
"""NET-04: after FrameDemux.feed raises, the frames it already routed
stay in its buffer and are routed again by the next feed.

Lean: Flare.Bugs.NET_04.feed_after_error_duplicates (counterexample) and
Flare.Bugs.NET_04.feedFixed_no_duplicates (fix meets spec).
flare/uds/frame_mux.mojo:176-207 @59bda50.

Expected: every complete frame on the wire reaches its inbox exactly
once, also when a later frame in the same feed is malformed (the
demux raises for the bad frame, the good frames before it are kept).
Before the fix: feed() routes frames while advancing a local `consumed` and
only compacts the buffer after the loop. When a header with a payload
length above MAX_FRAME_PAYLOAD raises mid-loop, the compaction is
skipped: the routed frame's bytes stay at the front of the buffer, and
any later feed() (for example UpstreamChunkSource.next_chunk retried
after the error) routes the same frame a second time.

Minimal fix: compact the consumed prefix before raising (move the
_compact(consumed) call ahead of the raise, or wrap the loop so it runs
on both paths).
"""

from flare.io import ByteWriter
from flare.uds import FrameDemux, FrameKind, encode_frame


def main() raises:
    var w = ByteWriter()
    var payload = List[UInt8](length=3, fill=UInt8(7))
    encode_frame(w, UInt64(5), FrameKind.CHUNK, Span[UInt8, _](payload))
    var wire = w.take()
    # A header claiming a 0xFFFFFFFF-byte payload: protocol error.
    for _ in range(4):
        wire.append(UInt8(0xFF))
    for _ in range(9):
        wire.append(UInt8(0))
    var d = FrameDemux()
    try:
        d.feed(Span[UInt8, _](wire))
    except:
        pass
    var empty = List[UInt8]()
    try:
        d.feed(Span[UInt8, _](empty))
    except:
        pass
    var n = d.pending(UInt64(5))
    if n != 1:
        print(
            "BUG REPRODUCED: one CHUNK frame on the wire, stream 5 has",
            n,
            "queued frames after the protocol error and one more feed()",
        )
        raise Error("NET-04")
    print("OK: stream 5 has exactly one queued frame")
