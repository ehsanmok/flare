# PLATFORM: any
"""QUIC-01: an unknown frame type is skipped after its type varint only, so
its body is parsed as further frames.

Lean: Flare.Bugs.QUIC_01.smuggled_close (parsePayload [0x21,0x1c,0,0,0] =
[unknown 0x21, CONNECTION_CLOSE]), Flare.Bugs.QUIC_01.violates_spec, and
Flare.L3.Quic.Frame.parseFrameFixed_ok for the fix.
flare/quic/frame.mojo:956-957 @59bda50 (`handler.on_unknown(raw_type);
return pos`) and flare/quic/state.mojo:769-773 (on_unknown ignores it).

RFC 9000 sec 12.4: "An endpoint MUST treat the receipt of a frame of unknown
type as a connection error of type FRAME_ENCODING_ERROR."

Expected: the 1-RTT payload 21 1c 00 00 00 is rejected (FRAME_ENCODING_ERROR).
Actual: 0x21 is ignored, the next four bytes run as a CONNECTION_CLOSE and the
connection enters DRAINING.

Minimal fix: in parse_frame_into, raise instead of calling on_unknown for an
unrecognised type (or, if extensions are wanted, require negotiation and a
length so the body is skipped, never reparsed).
"""

from std.collections import List
from std.collections.span import Span

from flare.quic import ConnectionId, QuicConnection, CONN_STATE_DRAINING


def _cid(seed: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(seed + i))
    return ConnectionId(bytes=b^)


def main() raises:
    var qc = QuicConnection(_cid(1), _cid(0x40))
    var payload = List[UInt8]()
    payload.append(0x21)  # unknown frame type 0x21
    payload.append(0x1C)  # "body": CONNECTION_CLOSE (transport)
    payload.append(0x00)  # error code
    payload.append(0x00)  # frame type
    payload.append(0x00)  # reason length
    var raised = False
    var closed = False
    try:
        var ev = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
        closed = ev.connection_closed
    except e:
        raised = True
    if not raised:
        print(
            "BUG REPRODUCED: unknown frame type 0x21 accepted; its body ran as"
            " CONNECTION_CLOSE (connection_closed =",
            closed,
            ", draining =",
            qc.conn.state == CONN_STATE_DRAINING,
            ")",
        )
        raise Error("QUIC-01")
    print("OK: unknown frame type rejected")
