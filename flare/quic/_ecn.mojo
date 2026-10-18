"""ECN validation for a sender that marks ECT(0) (RFC 9000 sec 13.4.2,
appendix A.4) and the congestion signal it yields (RFC 9002 sec 7.1).

Sans-I/O. Every ACK that advances the largest acknowledged packet and
newly acknowledges marked packets must carry ECN counts that did not
fall, report no ECT(1) (we never send it), and grow ECT(0) + CE by at
least the packets it newly acknowledges; otherwise the path or the peer
mangles ECN and marking must stop. A CE count that grew is a congestion
event.
"""

from .frame import EcnCounts


struct EcnValidator(Copyable, Defaultable):
    var ok: Bool
    var counted: Bool
    """An ACK carrying counts has validated."""
    var ect0: UInt64
    var ce: UInt64

    def __init__(out self):
        self.ok = True
        self.counted = False
        self.ect0 = 0
        self.ce = 0

    def on_ack(mut self, newly_acked: Int, counts: List[EcnCounts]) -> Bool:
        """Check an ACK that newly acknowledged ``newly_acked`` marked
        packets and advanced the largest acknowledged (pass 0 otherwise,
        RFC 9000 sec 13.4.2.1: reordered ACKs are not checked). True
        when the peer saw new CE marks."""
        if not self.ok or newly_acked == 0:
            return False
        if len(counts) == 0:
            self.ok = False
            return False
        ref c = counts[len(counts) - 1]
        if (
            c.ect1 != 0
            or c.ect0 < self.ect0
            or c.ce < self.ce
            or (c.ect0 - self.ect0) + (c.ce - self.ce) < UInt64(newly_acked)
        ):
            self.ok = False
            return False
        var more_ce = c.ce > self.ce
        self.counted = True
        self.ect0 = c.ect0
        self.ce = c.ce
        return more_ce
