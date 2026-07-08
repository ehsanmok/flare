"""RFC 9002 loss recovery + congestion control for the QUIC driver.

Tracks ack-eliciting 1-RTT packets, samples the round-trip time as ACKs
arrive, declares packets lost by the RFC 9002 section 6.1 packet-number
and time thresholds, arms a Probe Timeout (section 6.2) from the smoothed
RTT, and gates / grows the congestion window through a
:trait:`flare.quic.cc.CongestionController` (CUBIC with HyStart++ by
default). The caller
(:class:`flare.quic.client.QuicClientConnection`) feeds it the monotonic
millisecond clock and does the actual encrypt + sendto, so this module
stays sans-I/O and is unit-testable in isolation.

What this covers (RFC 9002):
- RTT estimation (section 5): ``latest_rtt`` / ``min_rtt`` /
  ``smoothed_rtt`` / ``rttvar`` from the largest newly-acked packet.
- ACK-based loss detection (section 6.1): a packet is lost once a
  later-numbered packet is acked and either the packet-number gap
  reaches ``kPacketThreshold`` (3) or its age exceeds the time
  threshold ``9/8 * max(smoothed_rtt, latest_rtt)``.
- PTO (section 6.2): ``smoothed_rtt + max(4*rttvar, kGranularity) +
  max_ack_delay`` with exponential backoff; the oldest unacked packet's
  send time anchors the timer.
- Congestion control (section 7): a CUBIC/HyStart++ controller grows on
  ACK and reduces on loss; ``bytes_in_flight`` is the gate input.

Handshake-level (Initial / Handshake) PTO uses the same 1-RTT
machinery here -- separate per-encryption-level packet-number spaces are
not modelled, because the client retransmits CRYPTO via its handshake
loop, not this struct. Peer ``ack_delay`` is treated as 0 (the client
does not yet plumb it from the ACK frame); under-counting ack_delay only
makes the PTO more conservative, which is safe. The upgrade path is to
thread ack_delay + per-space tracking through ``on_ack``.

References: RFC 9002 sections 5, 6.1, 6.2, 7; RFC 9438 (CUBIC); RFC 9406
(HyStart++).
"""

from std.collections import List

from .cc import CubicController, MAX_DATAGRAM_SIZE


comptime _PTO_BACKOFF_CAP: Int = 6
"""Cap the PTO exponential backoff at 2**6 = 64x the base so a long
black-hole does not overflow the shift or stretch the timer past any
reasonable idle timeout."""

comptime _K_GRANULARITY_MS: UInt64 = 1
"""RFC 9002 kGranularity: timer granularity floor (1 ms)."""

comptime _K_PACKET_THRESHOLD: UInt64 = 3
"""RFC 9002 kPacketThreshold: a packet is lost once 3 later-numbered
packets have been acknowledged."""

comptime _K_TIME_THRESHOLD_NUM: UInt64 = 9
comptime _K_TIME_THRESHOLD_DEN: UInt64 = 8
"""RFC 9002 kTimeThreshold: 9/8 of max(smoothed_rtt, latest_rtt)."""

comptime _DEFAULT_MAX_ACK_DELAY_MS: UInt64 = 25
"""RFC 9000 default max_ack_delay (25 ms) until the peer's value is
decoded from transport parameters."""

comptime _DEFAULT_INITIAL_RTT_MS: UInt64 = 250
"""RFC 9002 kInitialRtt: PTO base before the first RTT sample."""


@fieldwise_init
struct SentPacket(Copyable, Movable):
    """One ack-eliciting 1-RTT packet we sent and have not yet had
    acknowledged: its packet number, the exact plaintext frame bytes
    (so a retransmit re-sends the same frames under a fresh packet
    number per RFC 9002 -- frames are retransmitted, packets are not),
    the monotonic send time in ms, and its size in bytes (for the
    congestion-window in-flight accounting)."""

    var pn: UInt64
    var frames: List[UInt8]
    var time_ms: UInt64
    var size: UInt64


struct LossRecovery(Movable):
    """Client-side RFC 9002 loss-recovery + congestion-control state.

    Holds the in-flight ack-eliciting 1-RTT packets in send order, the
    RTT estimator, the consecutive-PTO backoff counter, the bytes in
    flight, and a CUBIC/HyStart++ congestion controller.
    """

    var sent: List[SentPacket]
    var pto_count: Int
    var base_pto_ms: UInt64
    # RTT estimator (RFC 9002 section 5).
    var has_rtt: Bool
    var latest_rtt: UInt64
    var min_rtt: UInt64
    var smoothed_rtt: UInt64
    var rttvar: UInt64
    var max_ack_delay_ms: UInt64
    # Loss detection.
    var largest_acked: UInt64
    var has_largest_acked: Bool
    # Congestion control.
    var bytes_in_flight: UInt64
    var cc: CubicController

    def __init__(out self, base_pto_ms: UInt64 = _DEFAULT_INITIAL_RTT_MS):
        self.sent = List[SentPacket]()
        self.pto_count = 0
        self.base_pto_ms = base_pto_ms
        self.has_rtt = False
        self.latest_rtt = 0
        self.min_rtt = 0
        self.smoothed_rtt = 0
        self.rttvar = 0
        self.max_ack_delay_ms = _DEFAULT_MAX_ACK_DELAY_MS
        self.largest_acked = 0
        self.has_largest_acked = False
        self.bytes_in_flight = 0
        self.cc = CubicController()

    def on_sent(
        mut self,
        pn: UInt64,
        var frames: List[UInt8],
        now_ms: UInt64,
        size: UInt64 = 0,
    ):
        """Record an ack-eliciting 1-RTT packet as in flight. ``size``
        defaults to the frame byte length when not given."""
        var sz = size if size > 0 else UInt64(len(frames))
        self.bytes_in_flight += sz
        self.sent.append(SentPacket(pn, frames^, now_ms, sz))

    def outstanding(self) -> Int:
        """Count of in-flight (unacked) ack-eliciting packets."""
        return len(self.sent)

    # ── Congestion-window gate ──────────────────────────────────────

    def can_send(self, extra_bytes: UInt64) -> Bool:
        """True if sending ``extra_bytes`` keeps in-flight within the
        congestion window."""
        return self.cc.can_send(self.bytes_in_flight, extra_bytes)

    def window(self) -> UInt64:
        """Current congestion window in bytes."""
        return self.cc.window()

    # ── RTT estimation (RFC 9002 section 5.3) ───────────────────────

    def _update_rtt(mut self, rtt_sample: UInt64):
        if not self.has_rtt:
            self.has_rtt = True
            self.min_rtt = rtt_sample
            self.smoothed_rtt = rtt_sample
            self.rttvar = rtt_sample // 2
            self.latest_rtt = rtt_sample
            return
        self.latest_rtt = rtt_sample
        if rtt_sample < self.min_rtt:
            self.min_rtt = rtt_sample
        # rttvar = 3/4 rttvar + 1/4 |smoothed - sample|
        var diff = (
            self.smoothed_rtt - rtt_sample
        ) if self.smoothed_rtt > rtt_sample else (
            rtt_sample - self.smoothed_rtt
        )
        self.rttvar = (self.rttvar * 3 + diff) // 4
        # smoothed = 7/8 smoothed + 1/8 sample
        self.smoothed_rtt = (self.smoothed_rtt * 7 + rtt_sample) // 8

    # ── ACK handling ────────────────────────────────────────────────

    def on_ack(mut self, acked: List[UInt64], now_ms: UInt64 = 0) -> Bool:
        """Retire every in-flight packet whose number appears in
        ``acked``. Samples the RTT from the largest newly-acked packet,
        feeds the congestion controller, resets the PTO backoff on
        forward progress (RFC 9002 section 6.2). Returns whether
        anything was retired."""
        if len(acked) == 0 or len(self.sent) == 0:
            return False
        # Track the largest acked packet number seen.
        for j in range(len(acked)):
            if not self.has_largest_acked or acked[j] > self.largest_acked:
                self.largest_acked = acked[j]
                self.has_largest_acked = True
        var keep = List[SentPacket]()
        var retired = False
        var newest_acked_time: UInt64 = 0
        var newest_acked_pn: UInt64 = 0
        var have_newest = False
        for i in range(len(self.sent)):
            var pn = self.sent[i].pn
            var hit = False
            for j in range(len(acked)):
                if acked[j] == pn:
                    hit = True
                    break
            if hit:
                retired = True
                self.bytes_in_flight -= self.sent[i].size
                self.cc.on_packet_acked(
                    self.sent[i].size,
                    self.smoothed_rtt if self.has_rtt else self.latest_rtt,
                    now_ms,
                )
                if not have_newest or pn > newest_acked_pn:
                    newest_acked_pn = pn
                    newest_acked_time = self.sent[i].time_ms
                    have_newest = True
            else:
                keep.append(self.sent[i].copy())
        self.sent = keep^
        # RTT sample from the largest newly-acked packet (RFC 9002
        # section 5.1: only the largest-acked drives the sample).
        if have_newest and now_ms > newest_acked_time:
            self._update_rtt(now_ms - newest_acked_time)
        if retired:
            self.pto_count = 0
        return retired

    def detect_lost(mut self, now_ms: UInt64) -> List[List[UInt8]]:
        """Declare packets lost per RFC 9002 section 6.1 and return their
        frame bytes for retransmission in fresh packets.

        A packet is lost if a later-numbered packet has been acked and
        either the packet-number gap reaches ``kPacketThreshold`` or the
        packet's age exceeds ``9/8 * max(smoothed_rtt, latest_rtt)``.
        Lost bytes leave ``bytes_in_flight`` and trigger one congestion
        event (the controller's own in-recovery guard dedupes within a
        round)."""
        var lost = List[List[UInt8]]()
        if not self.has_largest_acked or len(self.sent) == 0:
            return lost^
        var rtt = self.smoothed_rtt
        if self.latest_rtt > rtt:
            rtt = self.latest_rtt
        if rtt == 0:
            rtt = self.base_pto_ms
        var time_thresh = rtt * _K_TIME_THRESHOLD_NUM // _K_TIME_THRESHOLD_DEN
        if time_thresh < _K_GRANULARITY_MS:
            time_thresh = _K_GRANULARITY_MS
        var keep = List[SentPacket]()
        for i in range(len(self.sent)):
            var pn = self.sent[i].pn
            var sent_time = self.sent[i].time_ms
            var is_lost = False
            if pn < self.largest_acked:
                if self.largest_acked - pn >= _K_PACKET_THRESHOLD:
                    is_lost = True
                elif now_ms >= sent_time + time_thresh:
                    is_lost = True
            if is_lost:
                self.bytes_in_flight -= self.sent[i].size
                self.cc.on_congestion_event(sent_time, now_ms)
                lost.append(self.sent[i].frames.copy())
            else:
                keep.append(self.sent[i].copy())
        self.sent = keep^
        return lost^

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

    def _pto_base(self) -> UInt64:
        """The RFC 9002 section 6.2 PTO interval (before backoff):
        ``smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay``,
        or the fixed initial RTT until the first sample."""
        if not self.has_rtt:
            return self.base_pto_ms
        var variance = self.rttvar * 4
        if variance < _K_GRANULARITY_MS:
            variance = _K_GRANULARITY_MS
        return self.smoothed_rtt + variance + self.max_ack_delay_ms

    def pto_deadline(self) -> UInt64:
        """Absolute monotonic-ms time the PTO fires: the oldest
        in-flight packet's send time plus the PTO interval scaled by the
        exponential backoff. ``0`` means no timer armed."""
        var idx = self._oldest_index()
        if idx < 0:
            return UInt64(0)
        var shift = self.pto_count
        if shift > _PTO_BACKOFF_CAP:
            shift = _PTO_BACKOFF_CAP
        var mult = UInt64(1) << UInt64(shift)
        return self.sent[idx].time_ms + self._pto_base() * mult

    def fire_pto(mut self) -> List[UInt8]:
        """Probe-timeout action: remove the oldest in-flight packet and
        return its frame bytes for the caller to retransmit in a fresh
        packet (registered via :meth:`on_sent` with the new packet
        number). Bumps the backoff counter. Returns an empty list when
        nothing is in flight."""
        var idx = self._oldest_index()
        if idx < 0:
            return List[UInt8]()
        var frames = self.sent[idx].frames.copy()
        self.bytes_in_flight -= self.sent[idx].size
        var keep = List[SentPacket]()
        for i in range(len(self.sent)):
            if i != idx:
                keep.append(self.sent[i].copy())
        self.sent = keep^
        self.pto_count += 1
        return frames^
