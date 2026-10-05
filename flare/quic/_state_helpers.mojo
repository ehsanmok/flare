"""Pure helpers split out of :mod:`flare.quic.state` to keep it under the
per-file size cap: ACK range expansion and the pre-1-RTT frame filter.

Both are re-exported by :mod:`flare.quic.state` (and ``flare.quic``), so
``from flare.quic.state import expand_ack_ranges`` keeps working.
"""

from std.collections import List
from std.collections.span import Span

from .frame import AckFrame


comptime _ACK_EXPAND_CAP: Int = 256
"""Cap how many individual packet numbers one ACK is expanded into.
Bounds the work an adversarial ACK with huge ranges can cause; our
own flows ack a handful of packets per frame. A peer that
genuinely acks more than 256 packets in one frame just gets the
newest 256 retired here -- the rest retire on the next ACK."""


def expand_ack_ranges(ack: AckFrame) -> List[UInt64]:
    """Expand an ACK frame's ranges (RFC 9000 §19.3.1) into the
    explicit list of acknowledged packet numbers, newest first,
    capped at :data:`_ACK_EXPAND_CAP`.

    The first range covers ``[largest - first_ack_range, largest]``;
    each subsequent range starts ``gap + 2`` below the previous
    range's smallest and spans ``length + 1`` packets.
    """
    var out = List[UInt64]()
    var largest = ack.largest_acknowledged
    # Implicit first range.
    var first_len = ack.first_ack_range
    var lo = largest - first_len if largest >= first_len else UInt64(0)
    var pn = largest
    while pn >= lo:
        out.append(pn)
        if len(out) >= _ACK_EXPAND_CAP or pn == UInt64(0):
            return out^
        pn -= UInt64(1)
    var cur_lo = lo
    for i in range(len(ack.ranges)):
        var gap = ack.ranges[i].gap
        var length = ack.ranges[i].length
        # Next range's largest = cur_lo - gap - 2 (RFC 9000 §19.3.1).
        var step = gap + UInt64(2)
        if cur_lo < step:
            break
        var next_largest = cur_lo - step
        var next_lo = (
            next_largest - length if next_largest >= length else UInt64(0)
        )
        var p = next_largest
        while p >= next_lo:
            out.append(p)
            if len(out) >= _ACK_EXPAND_CAP or p == UInt64(0):
                return out^
            p -= UInt64(1)
        cur_lo = next_lo
    return out^


def frame_allowed_before_1rtt(buf: Span[UInt8, _]) -> Bool:
    """Whether the frame at the start of ``buf`` may appear in an
    Initial or Handshake packet (RFC 9000 sec 12.4, table 3).

    Only PADDING, PING, ACK, CRYPTO and the transport CONNECTION_CLOSE
    are permitted there. Every frame type flare knows fits in one varint
    byte, so the first byte is the type.
    """
    if len(buf) == 0:
        return True
    var t = buf[0]
    return (
        t == 0x00  # PADDING
        or t == 0x01  # PING
        or t == 0x02  # ACK
        or t == 0x03  # ACK with ECN counts
        or t == 0x06  # CRYPTO
        or t == 0x1C  # CONNECTION_CLOSE (transport)
    )
