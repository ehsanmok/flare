# PLATFORM: any
"""QUIC-02: MAX_STREAMS / STREAMS_BLOCKED values above 2^60 are accepted.

Lean: Flare.Bugs.QUIC_02.max_streams_accepted / violates_spec, and
Flare.L3.Quic.Frame.parseFrameFixed_ok for the fix.
flare/quic/frame.mojo:832-840 and 857-867 @59bda50 (value decoded, no bound).

RFC 9000 sec 4.6: a MAX_STREAMS frame with a value greater than 2^60 MUST
close the connection with FRAME_ENCODING_ERROR; sec 19.14: the same for
STREAMS_BLOCKED.

Expected: 12 d0 00 00 00 00 00 00 01 (MAX_STREAMS bidi = 2^60 + 1) raises.
Actual: accepted silently.

Minimal fix: in parse_frame_into, raise when the MAX_STREAMS or
STREAMS_BLOCKED value exceeds 1 << 60.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic import ConnectionId, QuicConnection


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def _frame(t: UInt8) -> List[UInt8]:
    var p = List[UInt8]()
    p.append(t)
    p.append(0xD0)  # 8-byte varint, value 2^60 + 1
    for _ in range(6):
        p.append(0x00)
    p.append(0x01)
    return p^


def main() raises:
    var accepted = List[String]()
    for t in [UInt8(0x12), UInt8(0x16)]:
        var qc = QuicConnection(_cid(1), _cid(0x40))
        var payload = _frame(t)
        try:
            _ = qc.dispatch_plaintext(
                Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
            )
            accepted.append(hex(Int(t)))
        except:
            pass
    if len(accepted) > 0:
        var names = String("")
        for i in range(len(accepted)):
            names += accepted[i] + " "
        print(
            "BUG REPRODUCED: frame types",
            names + "with value 2^60+1 accepted (FRAME_ENCODING_ERROR expected)",
        )
        raise Error("QUIC-02")
    print("OK: MAX_STREAMS / STREAMS_BLOCKED above 2^60 rejected")
