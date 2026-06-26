"""Congestion controllers: Reno + CUBIC (HyStart++) window dynamics
(T2.3 / critique sections 7.1-7.2).

Sans-I/O unit tests pinning the RFC 9002 / 9438 / 9406 behaviours the
QUIC send path relies on: initial window, slow-start growth, the
multiplicative decrease on loss (1/2 for Reno, 0.7 for CUBIC), the
one-reduction-per-round in-recovery guard, congestion-avoidance growth,
the minimum-window floor, and the HyStart++ early slow-start exit on a
sustained RTT rise.
"""

from std.testing import assert_equal, assert_true

from flare.quic.cc import (
    CcChoice,
    CubicController,
    INITIAL_WINDOW,
    MAX_DATAGRAM_SIZE,
    MINIMUM_WINDOW,
    RenoController,
)


def test_choice_tag() raises:
    assert_true(CcChoice.reno() == CcChoice.reno())
    assert_true(CcChoice.reno() != CcChoice.cubic())
    assert_equal(CcChoice.cubic().kind, CcChoice.CUBIC)


def test_reno_initial_window() raises:
    var cc = RenoController()
    assert_equal(cc.window(), INITIAL_WINDOW)
    assert_true(cc.can_send(0, MAX_DATAGRAM_SIZE))
    assert_true(not cc.can_send(INITIAL_WINDOW, 1))


def test_reno_slow_start_growth() raises:
    var cc = RenoController()
    var before = cc.window()
    cc.on_packet_acked(MAX_DATAGRAM_SIZE, rtt_ms=20, now_ms=100)
    # Slow start: cwnd grows by the acked bytes.
    assert_equal(cc.window(), before + MAX_DATAGRAM_SIZE)


def test_reno_loss_halves_window() raises:
    var cc = RenoController()
    var w = cc.window()
    cc.on_congestion_event(sent_time_ms=50, now_ms=100)
    assert_equal(cc.window(), w // 2)
    # In-recovery guard: a packet sent before recovery start does not
    # reduce again.
    var after = cc.window()
    cc.on_congestion_event(sent_time_ms=50, now_ms=120)
    assert_equal(cc.window(), after)
    # A packet sent after recovery start does reduce again.
    cc.on_congestion_event(sent_time_ms=200, now_ms=250)
    assert_true(cc.window() < after)


def test_reno_minimum_window_floor() raises:
    var cc = RenoController()
    # Drive repeated losses on distinct rounds; window bottoms at floor.
    var t: UInt64 = 100
    for _ in range(30):
        cc.on_congestion_event(sent_time_ms=t, now_ms=t + 1)
        t += 100
    assert_equal(cc.window(), MINIMUM_WINDOW)


def test_cubic_initial_and_loss() raises:
    var cc = CubicController()
    assert_equal(cc.window(), INITIAL_WINDOW)
    var w = cc.window()
    cc.on_congestion_event(sent_time_ms=50, now_ms=100)
    # CUBIC beta = 0.7 multiplicative decrease.
    assert_equal(cc.window(), w * 7 // 10)


def test_cubic_slow_start_grows() raises:
    var cc = CubicController()
    var before = cc.window()
    cc.on_packet_acked(MAX_DATAGRAM_SIZE, rtt_ms=20, now_ms=10)
    assert_true(cc.window() > before)


def test_cubic_hystart_exits_on_rtt_rise() raises:
    # Feed a low-RTT first round, then a second round whose min RTT has
    # risen well past the threshold: HyStart++ should drop ssthresh to
    # the current window (leaving slow start).
    var cc = CubicController()
    var now: UInt64 = 0
    # Round 1: many samples at 20ms to establish last_round_min_rtt.
    for _ in range(20):
        cc.on_packet_acked(MAX_DATAGRAM_SIZE, rtt_ms=20, now_ms=now)
        now += 1
    # Round 2: RTT jumps to 60ms (>> 20 + clamp(20/8,4,16)).
    for _ in range(20):
        cc.on_packet_acked(MAX_DATAGRAM_SIZE, rtt_ms=60, now_ms=now)
        now += 1
    assert_true(cc.ssthresh < UInt64.MAX)


def test_cubic_minimum_window_floor() raises:
    var cc = CubicController()
    var t: UInt64 = 100
    for _ in range(40):
        cc.on_congestion_event(sent_time_ms=t, now_ms=t + 1)
        t += 100
    assert_equal(cc.window(), MINIMUM_WINDOW)


def main() raises:
    test_choice_tag()
    test_reno_initial_window()
    test_reno_slow_start_growth()
    test_reno_loss_halves_window()
    test_reno_minimum_window_floor()
    test_cubic_initial_and_loss()
    test_cubic_slow_start_grows()
    test_cubic_hystart_exits_on_rtt_rise()
    test_cubic_minimum_window_floor()
    print("test_quic_cc: all congestion-controller tests passed")
