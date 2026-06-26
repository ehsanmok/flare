"""QUIC congestion control (RFC 9002 section 7): Reno + CUBIC (HyStart++).

Sans-I/O, sans-clock controllers: the caller feeds byte counts and the
monotonic millisecond clock; the controller answers "may I send another
``bytes`` right now?" via :meth:`can_send` and grows / shrinks the
congestion window on ACK / loss. No socket, no timer -- the
:mod:`flare.quic._loss_recovery` bookkeeping and the client / server
send paths own those and consult a controller through the
:trait:`CongestionController` contract.

Two algorithms ship:

- :struct:`RenoController` -- the RFC 9002 section 7.3 NewReno reference
  (slow start + AIMD congestion avoidance). Simple, robust, the safe
  default.
- :struct:`CubicController` -- RFC 9438 CUBIC with the RFC 9406
  HyStart++ slow-start exit. Better throughput on high
  bandwidth-delay-product paths (the case HTTP/3 over WAN hits).

:struct:`CcChoice` selects between them. Both share the RFC 9002
constants below and the in-recovery guard (one window reduction per
round-trip, keyed on the lost packet's send time).

ponytail: these controllers model the window only -- they do not pace
egress (no inter-packet send timer). The QUIC send path uses the window
as a gate (burst up to ``cwnd - bytes_in_flight``); add a pacer
(RFC 9002 section 7.7) only if a profile shows bursty loss. The upgrade
path is a ``next_send_time`` accessor here plus a timer in the reactor.
"""

from std.collections import List


# -- Shared RFC 9002 constants ------------------------------------------------

comptime MAX_DATAGRAM_SIZE: UInt64 = 1200
"""Assumed max UDP payload (RFC 9002 kMaxDatagramSize); the window is an
integer multiple of this in spirit, tracked in bytes."""

comptime INITIAL_WINDOW: UInt64 = 10 * MAX_DATAGRAM_SIZE
"""RFC 9002 section 7.2 recommended initial window: ``min(10*MDS,
max(2*MDS, 14720))`` == ``10*1200 == 12000`` here."""

comptime MINIMUM_WINDOW: UInt64 = 2 * MAX_DATAGRAM_SIZE
"""Floor the window never drops below (RFC 9002 kMinimumWindow)."""

comptime _RENO_LOSS_REDUCTION_NUM: UInt64 = 1
comptime _RENO_LOSS_REDUCTION_DEN: UInt64 = 2
"""Reno multiplicative decrease: ssthresh = cwnd * 1/2."""

comptime _CUBIC_BETA_NUM: UInt64 = 7
comptime _CUBIC_BETA_DEN: UInt64 = 10
"""CUBIC multiplicative decrease factor beta == 0.7 (RFC 9438)."""

comptime _CUBIC_C: Float64 = 0.4
"""CUBIC scaling constant C (RFC 9438 section 4.2)."""


# -- HyStart++ constants (RFC 9406) -------------------------------------------

comptime _HS_MIN_RTT_THRESH_MS: UInt64 = 4
comptime _HS_MAX_RTT_THRESH_MS: UInt64 = 16
comptime _HS_N_RTT_SAMPLE: Int = 8
"""HyStart++ needs at least this many RTT samples in a round before it
will conclude the delay has risen and exit slow start early."""


# -- Choice tag ---------------------------------------------------------------


@fieldwise_init
struct CcChoice(Copyable, Movable):
    """Which congestion controller a connection uses.

    ``CcChoice.reno()`` / ``CcChoice.cubic()`` are the two values; the
    QUIC send path reads :attr:`kind` to pick the controller. Kept a
    tiny tagged value (not a Mojo enum) so it round-trips through config
    structs and comparisons cheaply.
    """

    var kind: Int

    comptime RENO: Int = 0
    comptime CUBIC: Int = 1

    @staticmethod
    def reno() -> Self:
        return Self(Self.RENO)

    @staticmethod
    def cubic() -> Self:
        return Self(Self.CUBIC)

    def __eq__(self, other: Self) -> Bool:
        return self.kind == other.kind

    def __ne__(self, other: Self) -> Bool:
        return self.kind != other.kind


# -- Controller contract ------------------------------------------------------


trait CongestionController(Copyable, Movable):
    """The window-management contract the QUIC send path consults.

    A controller owns the congestion window (in bytes) and updates it on
    ACK / loss. It never touches a socket or a clock; the caller passes
    byte counts, RTT samples (ms), and the monotonic clock (ms).
    """

    def window(self) -> UInt64:
        """Current congestion window in bytes."""
        ...

    def can_send(self, bytes_in_flight: UInt64, bytes: UInt64) -> Bool:
        """True if sending ``bytes`` more keeps in-flight <= window."""
        ...

    def on_packet_acked(
        mut self, bytes: UInt64, rtt_ms: UInt64, now_ms: UInt64
    ):
        """Grow the window for ``bytes`` newly acknowledged."""
        ...

    def on_congestion_event(mut self, sent_time_ms: UInt64, now_ms: UInt64):
        """React to loss of a packet sent at ``sent_time_ms`` (one
        window reduction per round-trip)."""
        ...


# -- Reno ---------------------------------------------------------------------


struct RenoController(CongestionController, Copyable, Movable):
    """RFC 9002 section 7.3 NewReno: slow start until ``cwnd`` reaches
    ``ssthresh``, then additive-increase / multiplicative-decrease.
    """

    var cwnd: UInt64
    var ssthresh: UInt64
    var recovery_start_ms: UInt64
    var _recovered: Bool

    def __init__(out self):
        self.cwnd = INITIAL_WINDOW
        self.ssthresh = UInt64.MAX
        self.recovery_start_ms = 0
        self._recovered = False

    def window(self) -> UInt64:
        return self.cwnd

    def can_send(self, bytes_in_flight: UInt64, bytes: UInt64) -> Bool:
        return bytes_in_flight + bytes <= self.cwnd

    def on_packet_acked(
        mut self, bytes: UInt64, rtt_ms: UInt64, now_ms: UInt64
    ):
        if self.cwnd < self.ssthresh:
            # Slow start: exponential growth.
            self.cwnd += bytes
        else:
            # Congestion avoidance: ~1 MDS per RTT.
            self.cwnd += MAX_DATAGRAM_SIZE * bytes // self.cwnd

    def on_congestion_event(mut self, sent_time_ms: UInt64, now_ms: UInt64):
        if self._recovered and sent_time_ms <= self.recovery_start_ms:
            return
        self.recovery_start_ms = now_ms
        self._recovered = True
        self.ssthresh = (
            self.cwnd * _RENO_LOSS_REDUCTION_NUM // _RENO_LOSS_REDUCTION_DEN
        )
        if self.ssthresh < MINIMUM_WINDOW:
            self.ssthresh = MINIMUM_WINDOW
        self.cwnd = self.ssthresh


# -- CUBIC (HyStart++) --------------------------------------------------------


struct CubicController(CongestionController, Copyable, Movable):
    """RFC 9438 CUBIC with the RFC 9406 HyStart++ slow-start exit.

    In slow start the window grows exponentially (like Reno) but
    HyStart++ watches per-round minimum RTT: a sustained delay rise
    means the path queue is filling, so it exits slow start before a
    loss (setting ``ssthresh = cwnd``). In congestion avoidance the
    window follows the CUBIC cubic curve around ``w_max`` (the window at
    the last loss), with a Reno-friendly floor so it never underperforms
    Reno on short-RTT paths.
    """

    var cwnd: UInt64
    var ssthresh: UInt64
    var recovery_start_ms: UInt64
    var _recovered: Bool
    var w_max: Float64
    var epoch_start_ms: UInt64
    var k: Float64
    var _cwnd_at_epoch: Float64
    # Reno-friendly running estimate (TCP-friendly region).
    var _w_est: Float64
    # HyStart++ per-round state.
    var _in_slow_start: Bool
    var _last_round_min_rtt: UInt64
    var _curr_round_min_rtt: UInt64
    var _rtt_sample_count: Int
    var _round_bytes_acked: UInt64
    var _round_end_window: UInt64

    def __init__(out self):
        self.cwnd = INITIAL_WINDOW
        self.ssthresh = UInt64.MAX
        self.recovery_start_ms = 0
        self._recovered = False
        self.w_max = 0.0
        self.epoch_start_ms = 0
        self.k = 0.0
        self._cwnd_at_epoch = 0.0
        self._w_est = 0.0
        self._in_slow_start = True
        self._last_round_min_rtt = UInt64.MAX
        self._curr_round_min_rtt = UInt64.MAX
        self._rtt_sample_count = 0
        self._round_bytes_acked = 0
        self._round_end_window = INITIAL_WINDOW

    def window(self) -> UInt64:
        return self.cwnd

    def can_send(self, bytes_in_flight: UInt64, bytes: UInt64) -> Bool:
        return bytes_in_flight + bytes <= self.cwnd

    def _hystart_round(mut self, rtt_ms: UInt64):
        """Feed one RTT sample into the HyStart++ round tracker; exit
        slow start early if the per-round minimum RTT has risen past the
        clamped threshold over enough samples."""
        if rtt_ms < self._curr_round_min_rtt:
            self._curr_round_min_rtt = rtt_ms
        self._rtt_sample_count += 1
        if (
            self._rtt_sample_count >= _HS_N_RTT_SAMPLE
            and self._last_round_min_rtt != UInt64.MAX
            and self._curr_round_min_rtt != UInt64.MAX
        ):
            var thresh = self._last_round_min_rtt // 8
            if thresh < _HS_MIN_RTT_THRESH_MS:
                thresh = _HS_MIN_RTT_THRESH_MS
            if thresh > _HS_MAX_RTT_THRESH_MS:
                thresh = _HS_MAX_RTT_THRESH_MS
            if self._curr_round_min_rtt >= self._last_round_min_rtt + thresh:
                # Delay rising: leave slow start at the current window.
                self.ssthresh = self.cwnd
                self._in_slow_start = False

    def _maybe_advance_round(mut self, bytes: UInt64):
        """A round-trip's worth of bytes has been acked: roll the
        per-round HyStart++ minimum RTT forward."""
        self._round_bytes_acked += bytes
        if self._round_bytes_acked >= self._round_end_window:
            self._last_round_min_rtt = self._curr_round_min_rtt
            self._curr_round_min_rtt = UInt64.MAX
            self._rtt_sample_count = 0
            self._round_bytes_acked = 0
            self._round_end_window = self.cwnd

    def on_packet_acked(
        mut self, bytes: UInt64, rtt_ms: UInt64, now_ms: UInt64
    ):
        if self.cwnd < self.ssthresh and self._in_slow_start:
            self.cwnd += bytes
            self._hystart_round(rtt_ms)
            self._maybe_advance_round(bytes)
            return
        # Congestion avoidance (CUBIC curve).
        self._in_slow_start = False
        if self.epoch_start_ms == 0:
            self._start_epoch(now_ms)
        var t = Float64(now_ms - self.epoch_start_ms) / 1000.0
        # W_cubic(t) = C*(t-K)^3 + w_max  (bytes).
        var dt = t - self.k
        var target = (
            _CUBIC_C * dt * dt * dt * (MAX_DATAGRAM_SIZE.cast[DType.float64]())
            + self.w_max
        )
        # Reno-friendly estimate: w_est += MDS * acked / cwnd.
        self._w_est += (
            (MAX_DATAGRAM_SIZE.cast[DType.float64]())
            * Float64(bytes)
            / Float64(self.cwnd)
        )
        var next_cwnd: Float64
        if target < self._w_est:
            next_cwnd = self._w_est  # TCP-friendly region.
        else:
            next_cwnd = target
        if next_cwnd > Float64(self.cwnd):
            self.cwnd = UInt64(next_cwnd)

    def _start_epoch(mut self, now_ms: UInt64):
        self.epoch_start_ms = now_ms
        self._cwnd_at_epoch = Float64(self.cwnd)
        self._w_est = Float64(self.cwnd)
        if self.w_max < Float64(self.cwnd):
            # No prior loss this high: K = 0 (already at/over w_max).
            self.w_max = Float64(self.cwnd)
            self.k = 0.0
        else:
            # K = cbrt(w_max*(1-beta)/C) in units of MDS-seconds.
            var mds = MAX_DATAGRAM_SIZE.cast[DType.float64]()
            var w_max_pkts = self.w_max / mds
            var cwnd_pkts = self._cwnd_at_epoch / mds
            var diff = w_max_pkts - cwnd_pkts
            if diff < 0.0:
                diff = 0.0
            self.k = (diff / _CUBIC_C) ** (1.0 / 3.0)

    def on_congestion_event(mut self, sent_time_ms: UInt64, now_ms: UInt64):
        if self._recovered and sent_time_ms <= self.recovery_start_ms:
            return
        self.recovery_start_ms = now_ms
        self._recovered = True
        self.w_max = Float64(self.cwnd)
        var reduced = self.cwnd * _CUBIC_BETA_NUM // _CUBIC_BETA_DEN
        if reduced < MINIMUM_WINDOW:
            reduced = MINIMUM_WINDOW
        self.ssthresh = reduced
        self.cwnd = reduced
        # Force a fresh epoch on the next ack.
        self.epoch_start_ms = 0
        self._in_slow_start = False
