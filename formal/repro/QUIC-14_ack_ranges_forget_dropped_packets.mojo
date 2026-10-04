# PLATFORM: any
"""QUIC-14: once a gap fills, packet numbers from dropped ACK ranges are
accepted again as new.

Lean: Flare.Bugs.QUIC_14.impl_reaccepts (impl),
      Flare.Bugs.QUIC_14.fixed_never_reaccepts (fix).
flare/quic/_server_support.mojo:60-124 @59bda50 (`_ack_contains`,
`_ack_record`), used as the duplicate filter at flare/quic/server.mojo:844-855
("A packet number already received is a duplicate ... drop it").

`_ack_record` keeps at most 32 ranges and drops the lowest. `_ack_contains`
treats a number below every kept range as seen only while the list holds 32
ranges. When a later packet fills the gap between two kept ranges they
merge, the list drops to 31 ranges, and every number in the dropped ranges
reads as never received.

RFC 9000 §13.2.3: "A receiver MUST retain an ACK Range unless it can ensure
that it will not subsequently accept packets with numbers in that range."
§12.3: a packet number MUST NOT be accepted twice ("Endpoints MUST discard
... duplicate packets", RFC 9001 §5.8 / RFC 9000 §21.4 replay). Expected:
after receiving 0, 2, 4, ..., 64 and then 3, packet 0 still reads as
received. Actual: `_ack_contains(flat, 0)` is False, so the server would
dispatch packet 0 a second time.

Minimal fix: when ranges are dropped, remember a floor (one past the
highest dropped number) in an odd trailing slot of `flat` (which every
reader of the pair list already ignores) and treat numbers below it as seen.
"""

from std.collections import List

from flare.quic._server_support import _ack_contains, _ack_record


def main() raises:
    var flat = List[UInt64]()
    for k in range(33):
        _ack_record(flat, UInt64(2 * k))  # 0, 2, ..., 64: 33 ranges
    if not _ack_contains(flat, UInt64(0)):
        print("inconclusive: packet 0 not reported seen right after the cap")
        raise Error("QUIC-14 setup")
    _ack_record(flat, UInt64(3))  # merges [2,2] [3,3] [4,4]
    var pairs = len(flat) // 2
    if _ack_contains(flat, UInt64(0)):
        print("OK: packet 0 still reads as received after the merge (",
              pairs, "ranges )")
        return
    print(
        "BUG REPRODUCED: packet 0 was received, its range was dropped at the"
        " 32-range cap, and after packet 3 merged two ranges (",
        pairs,
        "ranges left) _ack_contains(0) = False, so it would be dispatched"
        " again",
    )
    raise Error("QUIC-14")
