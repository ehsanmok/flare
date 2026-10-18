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

comptime _PACING_BURST: UInt64 = 10 * 1452
"""Smallest pacer bucket: ten full datagrams may leave back to back, the
initial-window burst RFC 9002 sec 7.7 allows."""

comptime _PACING_MIN_RTT_MS: UInt64 = 4
"""Shortest smoothed RTT that is paced: whole-millisecond RTTs are then
within 25% of the true one."""

comptime _DEFAULT_INITIAL_RTT_MS: UInt64 = 250
"""RFC 9002 kInitialRtt: PTO base before the first RTT sample."""


@fieldwise_init
struct SentPacket(Copyable):
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
    var live: Bool
    """False once acknowledged, declared lost or probed: a tombstone
    until :meth:`LossRecovery._compact` drops it."""


def _in_ranges(ranges: List[UInt64], pn: UInt64) -> Bool:
    """Whether ``pn`` lies in one of the flat ``[lo, hi]`` ranges, which
    are sorted by descending ``hi`` (the ACK-frame order)."""
    var lo_i = 0
    var hi_i = len(ranges) // 2
    while lo_i < hi_i:
        var mid = (lo_i + hi_i) // 2
        if ranges[2 * mid] > pn:
            lo_i = mid + 1
        elif ranges[2 * mid + 1] < pn:
            hi_i = mid
        else:
            return True
    return False


struct LossRecovery(Movable):
    """Client-side RFC 9002 loss-recovery + congestion-control state.

    Holds the in-flight ack-eliciting 1-RTT packets in send order, the
    RTT estimator, the consecutive-PTO backoff counter, the bytes in
    flight, and a CUBIC/HyStart++ congestion controller.
    """

    var sent: List[SentPacket]
    """In-flight packets in send order, which is packet-number order.
    Entries before :attr:`head` and entries with ``live`` False are
    gone; retiring one costs a flag write, not a list rebuild."""
    var head: Int
    var live_count: Int
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
    var last_newly_acked: Int
    """Packets the last :meth:`on_ack_ranges` retired."""
    var last_acked_sent_ms: UInt64
    """Send time of the newest of them, for a congestion event an ECN-CE
    report raises (RFC 9002 sec 7.1)."""
    # Congestion control.
    var bytes_in_flight: UInt64
    var cc: CubicController
    # Pacing (RFC 9002 sec 7.7): a token bucket refilled at the pacing
    # rate, at most :data:`_PACING_BURST` bytes deep.
    var pace_tokens: UInt64
    var pace_last_ms: UInt64

    def __init__(out self, base_pto_ms: UInt64 = _DEFAULT_INITIAL_RTT_MS):
        self.sent = List[SentPacket]()
        self.head = 0
        self.live_count = 0
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
        self.last_newly_acked = 0
        self.last_acked_sent_ms = 0
        self.bytes_in_flight = 0
        self.cc = CubicController()
        self.pace_tokens = _PACING_BURST
        self.pace_last_ms = 0

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
        self.live_count += 1
        self.sent.append(SentPacket(pn, frames^, now_ms, sz, True))

    def outstanding(self) -> Int:
        """Count of in-flight (unacked) ack-eliciting packets."""
        return self.live_count

    def _retire(mut self, i: Int):
        """Take entry ``i`` out of flight (it stays as a tombstone)."""
        self.sent[i].live = False
        self.sent[i].frames = List[UInt8]()
        self.bytes_in_flight -= self.sent[i].size
        self.live_count -= 1

    def _compact(mut self):
        """Skip the dead prefix; drop it once it is half the list, so
        retirement stays amortized O(1) per packet."""
        while self.head < len(self.sent) and not self.sent[self.head].live:
            self.head += 1
        if self.head > 0 and self.head * 2 >= len(self.sent):
            var keep = List[SentPacket](capacity=len(self.sent) - self.head)
            for i in range(self.head, len(self.sent)):
                if self.sent[i].live:
                    var frames = List[UInt8]()
                    swap(frames, self.sent[i].frames)
                    keep.append(
                        SentPacket(
                            self.sent[i].pn,
                            frames^,
                            self.sent[i].time_ms,
                            self.sent[i].size,
                            True,
                        )
                    )
            self.sent = keep^
            self.head = 0

    def _first_at_or_above(self, pn: UInt64) -> Int:
        """Index of the first entry at or after :attr:`head` whose packet
        number is >= ``pn`` (binary search; the list is pn-ordered)."""
        var lo = self.head
        var hi = len(self.sent)
        while lo < hi:
            var mid = (lo + hi) // 2
            if self.sent[mid].pn < pn:
                lo = mid + 1
            else:
                hi = mid
        return lo

    # ── Congestion-window gate ──────────────────────────────────────

    def can_send(self, extra_bytes: UInt64) -> Bool:
        """True if sending ``extra_bytes`` keeps in-flight within the
        congestion window."""
        return self.cc.can_send(self.bytes_in_flight, extra_bytes)

    def window(self) -> UInt64:
        """Current congestion window in bytes."""
        return self.cc.window()

    def pace_admit(mut self, now_ms: UInt64, size: UInt64) -> UInt64:
        """Pacing gate (RFC 9002 sec 7.7): 0 when ``size`` bytes may be
        sent now (and charges them), else the milliseconds until they
        may. The rate is 5/4 of the congestion window per smoothed RTT,
        so a window spreads over most of a round trip instead of leaving
        in one burst. RTTs are kept in whole milliseconds, so below
        :data:`_PACING_MIN_RTT_MS` the rate cannot be known closely
        enough (a 0.2 ms loopback RTT reads as 1 ms and would be paced
        five times too slow); such short paths are not paced."""
        if not self.has_rtt or self.smoothed_rtt < _PACING_MIN_RTT_MS:
            return 0
        var rate = max(self.cc.window() * 5 // 4 // self.smoothed_rtt, 1)
        # Timers tick in whole milliseconds, so the bucket must hold at
        # least two of them at the current rate; a fixed ten-datagram
        # bucket capped the send rate at ten datagrams per millisecond.
        var depth = max(_PACING_BURST, 2 * rate)
        if now_ms > self.pace_last_ms:
            self.pace_tokens = min(
                depth, self.pace_tokens + rate * (now_ms - self.pace_last_ms)
            )
            self.pace_last_ms = now_ms
        if self.pace_tokens >= size:
            self.pace_tokens -= size
            return 0
        return max(UInt64(1), (size - self.pace_tokens + rate - 1) // rate)

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

    def on_ack(
        mut self,
        acked: List[UInt64],
        now_ms: UInt64 = 0,
        next_pn: UInt64 = UInt64.MAX,
    ) -> Bool:
        """Retire every in-flight packet whose number appears in
        ``acked``; see :meth:`on_ack_ranges`."""
        var sorted = acked.copy()
        sort(sorted)
        var ranges = List[UInt64](capacity=2 * len(sorted))
        var i = len(sorted) - 1
        while i >= 0:
            ranges.append(sorted[i])
            ranges.append(sorted[i])
            i -= 1
        return self.on_ack_ranges(ranges, now_ms, next_pn)

    def on_ack_ranges(
        mut self,
        ranges: List[UInt64],
        now_ms: UInt64 = 0,
        next_pn: UInt64 = UInt64.MAX,
    ) -> Bool:
        """Retire every in-flight packet inside the acknowledged ranges
        (flat ``[lo, hi]`` pairs, descending, as an ACK frame carries
        them; RFC 9000 sec 19.3.1). Samples the RTT from the largest
        newly-acked packet, feeds the congestion controller, resets the
        PTO backoff on forward progress (RFC 9002 section 6.2). Returns
        whether anything was retired. The work is the packets the ranges
        cover, not every packet in flight, and nothing is copied: a large
        window used to cost a full copy of every in-flight frame per ACK.

        ``next_pn`` is the next packet number the sender will use. An
        acknowledged number at or past it names a packet never sent,
        and is ignored here. It used to raise ``largest_acked``, and an
        ACK claiming 2^60 then declared every packet in flight lost:
        a retransmission storm on demand."""
        self.last_newly_acked = 0
        if len(ranges) < 2 or self.live_count == 0:
            return False
        var top = ranges[1]
        if top >= next_pn:
            if next_pn == 0:
                return False
            top = next_pn - 1
        if top < ranges[0]:
            return False
        if not self.has_largest_acked or top > self.largest_acked:
            self.largest_acked = top
            self.has_largest_acked = True
        var bottom = ranges[len(ranges) - 2]
        var retired = False
        var newest_acked_time: UInt64 = 0
        var newest_acked_pn: UInt64 = 0
        var have_newest = False
        var i = self._first_at_or_above(bottom)
        while i < len(self.sent) and self.sent[i].pn <= top:
            if self.sent[i].live and _in_ranges(ranges, self.sent[i].pn):
                var pn = self.sent[i].pn
                retired = True
                self.cc.on_packet_acked(
                    self.sent[i].size,
                    self.smoothed_rtt if self.has_rtt else self.latest_rtt,
                    now_ms,
                )
                if not have_newest or pn > newest_acked_pn:
                    newest_acked_pn = pn
                    newest_acked_time = self.sent[i].time_ms
                    have_newest = True
                self.last_newly_acked += 1
                self._retire(i)
            i += 1
        self._compact()
        self.last_acked_sent_ms = newest_acked_time
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
        if not self.has_largest_acked or self.live_count == 0:
            return lost^
        var time_thresh = self._time_threshold()
        # Only packets below the largest acknowledged can be lost; the
        # list is pn-ordered, so the scan stops there.
        var i = self.head
        while i < len(self.sent) and self.sent[i].pn < self.largest_acked:
            if self.sent[i].live:
                var sent_time = self.sent[i].time_ms
                if (
                    self.largest_acked - self.sent[i].pn >= _K_PACKET_THRESHOLD
                    or now_ms >= sent_time + time_thresh
                ):
                    self.cc.on_congestion_event(sent_time, now_ms)
                    var frames = List[UInt8]()
                    swap(frames, self.sent[i].frames)
                    lost.append(frames^)
                    self._retire(i)
            i += 1
        self._compact()
        return lost^

    def _time_threshold(self) -> UInt64:
        """RFC 9002 kTimeThreshold applied: 9/8 of max(smoothed_rtt,
        latest_rtt), at least kGranularity."""
        var rtt = max(self.smoothed_rtt, self.latest_rtt)
        if rtt == 0:
            rtt = self.base_pto_ms
        return max(
            rtt * _K_TIME_THRESHOLD_NUM // _K_TIME_THRESHOLD_DEN,
            _K_GRANULARITY_MS,
        )

    def loss_deadline(self) -> UInt64:
        """When the earliest in-flight packet sent before the largest
        acknowledged one passes the time threshold and becomes lost (RFC
        9002 sec 6.1.2); 0 when none can. Without this timer such a
        packet waited for the PTO, which a tail loss on a small window
        turns into one PTO per lost packet."""
        if not self.has_largest_acked:
            return UInt64(0)
        # Send order is time order: the first live packet below the
        # largest acknowledged is the earliest to cross the threshold.
        var i = self.head
        while i < len(self.sent) and self.sent[i].pn < self.largest_acked:
            if self.sent[i].live:
                return self.sent[i].time_ms + self._time_threshold()
            i += 1
        return UInt64(0)

    def _oldest_index(self) -> Int:
        """Index of the in-flight packet with the smallest send time
        (the one a PTO would probe first): the first live one, since
        send order is time order. -1 if none."""
        var i = self.head
        while i < len(self.sent):
            if self.sent[i].live:
                return i
            i += 1
        return -1

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

    def pto_interval_ms(self) -> UInt64:
        """The current PTO interval including the exponential backoff
        (RFC 9002 sec 6.2.1). The idle timeout is never shorter than
        three of these (RFC 9000 sec 10.1)."""
        var shift = self.pto_count
        if shift > _PTO_BACKOFF_CAP:
            shift = _PTO_BACKOFF_CAP
        return self._pto_base() * (UInt64(1) << UInt64(shift))

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
        var frames = List[UInt8]()
        swap(frames, self.sent[idx].frames)
        self._retire(idx)
        self._compact()
        self.pto_count += 1
        return frames^
