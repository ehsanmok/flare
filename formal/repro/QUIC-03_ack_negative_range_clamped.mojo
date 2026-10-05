# PLATFORM: any
# RESOLVED: QUIC-03 fixed on fix/formal-findings
"""QUIC-03: an ACK whose ranges reach below packet number 0 is clamped,
not rejected.

Lean: Flare.Bugs.QUIC_03.accepted / violates_spec (ACK largest=0,
first_ack_range=5 parses and ackOk = false), and
Flare.L3.Quic.Frame.parseFrameFixed_ok for the fix.
flare/quic/frame.mojo:757-786 @59bda50 (no range check) and
flare/quic/state.mojo:401-436 (expand_ack_ranges clamps lo to 0 and
`break`s on a gap that would go negative).

RFC 9000 sec 19.3.1: "If any computed packet number is negative, an
endpoint MUST generate a connection error of type FRAME_ENCODING_ERROR."

Expected: 02 00 00 00 05 (largest 0, first range 5) raises.
Before the fix: accepted; packet 0 reported acknowledged.

Minimal fix: in parse_frame_into's ACK branch, raise if first > largest,
and for each range if gap + 2 > previous_smallest or length > that largest.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic import ConnectionId, QuicConnection


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def main() raises:
    var qc = QuicConnection(_cid(1), _cid(0x40))
    var payload: List[UInt8] = [0x02, 0x00, 0x00, 0x00, 0x05]
    var raised = False
    var acked = 0
    try:
        var ev = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
        acked = len(ev.acked_packets)
    except:
        raised = True
    if not raised:
        print(
            "BUG REPRODUCED: ACK with largest=0, first_ack_range=5 accepted"
            " (packets reported acked:",
            acked,
            ")",
        )
        raise Error("QUIC-03")
    print("OK: ACK with a negative computed packet number rejected")
