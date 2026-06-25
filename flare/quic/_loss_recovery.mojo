"""Minimal PTO-based loss recovery for the QUIC client driver.

This is the deliberately small slice of RFC 9002 the v0.9 HTTP/3
client needs to survive packet loss on the request path: track the
ack-eliciting 1-RTT packets we sent, retire them as ACKs arrive, and
when a Probe Timeout (PTO) elapses with data still outstanding,
retransmit the oldest unacked frames in a fresh packet.

Pure bookkeeping -- zero I/O, zero clock, zero socket. The caller
(:class:`flare.quic.client.QuicClientConnection`) feeds it the
monotonic millisecond clock and does the actual encrypt + sendto, so
this module stays sans-I/O and is unit-testable in isolation.

ponytail: this is NOT the full RFC 9002. It omits, by design (tracked
as the v0.9 loss-recovery follow-up):
  - ACK-based loss detection (packet-number + time thresholds); we
    rely solely on the PTO timer.
  - an RTT estimator + congestion controller (NewReno); the PTO is a
    fixed base with exponential backoff, not ``3*smoothed_rtt``.
  - handshake-level (Initial / Handshake CRYPTO) PTO and server-side
    response retransmit; only the client's 1-RTT (request) path is
    covered here.
The upgrade path is to add an RTT sampler keyed off ACK receipt and
swap the fixed base for the RFC 9002 §6.2 PTO formula.

References:
- RFC 9002 §6.2 "Probe Timeout".
- RFC 9002 §A.5 "On Sending a Probe Timeout".
"""

from std.collections import List


comptime _PTO_BACKOFF_CAP: Int = 6
"""Cap the PTO exponential backoff at 2**6 = 64x the base so a long
black-hole does not overflow the shift or stretch the timer past any
reasonable idle timeout (RFC 9002 §6.2 backs off without an explicit
ceiling; we add one because the idle timeout will close the
connection well before then anyway)."""


@fieldwise_init
struct SentPacket(Copyable, Movable):
    """One ack-eliciting 1-RTT packet we sent and have not yet had
    acknowledged: its packet number, the exact plaintext frame bytes
    (so a retransmit re-sends the same frames under a fresh packet
    number per RFC 9002 -- frames are retransmitted, packets are
    not), and the monotonic send time in milliseconds."""

    var pn: UInt64
    var frames: List[UInt8]
    var time_ms: UInt64


struct LossRecovery(Movable):
    """Client-side PTO loss-recovery bookkeeping (RFC 9002 §6.2).

    Holds the in-flight ack-eliciting 1-RTT packets in send order,
    the consecutive-PTO backoff counter, and the base PTO interval.
    """

    var sent: List[SentPacket]
    var pto_count: Int
    var base_pto_ms: UInt64

    def __init__(out self, base_pto_ms: UInt64 = UInt64(250)):
        self.sent = List[SentPacket]()
        self.pto_count = 0
        self.base_pto_ms = base_pto_ms

    def on_sent(mut self, pn: UInt64, var frames: List[UInt8], now_ms: UInt64):
        """Record an ack-eliciting 1-RTT packet as in flight."""
        self.sent.append(SentPacket(pn, frames^, now_ms))

    def outstanding(self) -> Int:
        """Count of in-flight (unacked) ack-eliciting packets."""
        return len(self.sent)

    def on_ack(mut self, acked: List[UInt64]) -> Bool:
        """Retire every in-flight packet whose number appears in
        ``acked`` (the packet numbers an inbound ACK acknowledged).
        Resets the PTO backoff when at least one packet is retired
        (forward progress -- RFC 9002 §6.2). Returns whether anything
        was retired."""
        if len(acked) == 0 or len(self.sent) == 0:
            return False
        var keep = List[SentPacket]()
        var retired = False
        for i in range(len(self.sent)):
            var pn = self.sent[i].pn
            var hit = False
            for j in range(len(acked)):
                if acked[j] == pn:
                    hit = True
                    break
            if hit:
                retired = True
            else:
                keep.append(self.sent[i].copy())
        self.sent = keep^
        if retired:
            self.pto_count = 0
        return retired

    def _oldest_index(self) -> Int:
        """Index of the in-flight packet with the smallest send time
        (the one a PTO would probe first). -1 if none."""
        if len(self.sent) == 0:
            return -1
        var best = 0
        for i in range(1, len(self.sent)):
            if self.sent[i].time_ms < self.sent[best].time_ms:
                best = i
        return best

    def pto_deadline(self) -> UInt64:
        """Absolute monotonic-ms time the PTO fires: the oldest
        in-flight packet's send time plus the base interval scaled by
        the exponential backoff. ``0`` means no timer armed (nothing
        in flight)."""
        var idx = self._oldest_index()
        if idx < 0:
            return UInt64(0)
        var shift = self.pto_count
        if shift > _PTO_BACKOFF_CAP:
            shift = _PTO_BACKOFF_CAP
        var mult = UInt64(1) << UInt64(shift)
        return self.sent[idx].time_ms + self.base_pto_ms * mult

    def fire_pto(mut self) -> List[UInt8]:
        """Probe-timeout action: remove the oldest in-flight packet
        and return its frame bytes for the caller to retransmit in a
        fresh packet (which the caller registers via :meth:`on_sent`
        with the new packet number). Bumps the backoff counter.
        Returns an empty list when nothing is in flight."""
        var idx = self._oldest_index()
        if idx < 0:
            return List[UInt8]()
        var frames = self.sent[idx].frames.copy()
        var keep = List[SentPacket]()
        for i in range(len(self.sent)):
            if i != idx:
                keep.append(self.sent[i].copy())
        self.sent = keep^
        self.pto_count += 1
        return frames^
