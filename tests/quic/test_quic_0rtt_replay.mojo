"""Unit tests for the server 0-RTT admission logic (W4a).

Covers the security-sensitive parts of :mod:`flare.quic._server_0rtt`
in isolation (no handshake, no I/O):

* :class:`EarlyDataReplayGuard` -- disabled by default; once enabled it
  admits fresh packet numbers, rejects duplicates and stale (out-of-
  window) numbers, and caps total early-data bytes at the budget.
* :func:`early_data_packet_len` -- returns the on-wire length of a
  coalesced 0-RTT long-header packet so the listener's datagram walk
  can step into it.

The anti-replay window is the only thing standing between a captured
0-RTT flight and the state machine, so these cases are exhaustive about
the boundary conditions (duplicate, just-inside-window, just-outside,
budget edge).
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.quic._server_0rtt import (
    EarlyDataReplayGuard,
    early_data_packet_len,
)
from flare.quic.packet import QUIC_VERSION_1, ConnectionId, encode_long_header


def test_disabled_by_default_rejects_all() raises:
    var g = EarlyDataReplayGuard()  # budget 0 == 0-RTT off
    assert_false(g.enabled())
    assert_false(g.admit(UInt64(0), 10))
    assert_false(g.admit(UInt64(1), 10))


def test_admits_fresh_in_order() raises:
    var g = EarlyDataReplayGuard(max_bytes=UInt64(10_000))
    assert_true(g.enabled())
    assert_true(g.admit(UInt64(0), 100))
    assert_true(g.admit(UInt64(1), 100))
    assert_true(g.admit(UInt64(2), 100))
    assert_equal(Int(g.accepted_bytes), 300)


def test_rejects_duplicate_packet_number() raises:
    var g = EarlyDataReplayGuard(max_bytes=UInt64(10_000))
    assert_true(g.admit(UInt64(5), 50))
    assert_false(g.admit(UInt64(5), 50))  # exact replay
    # The rejected replay must not have consumed budget.
    assert_equal(Int(g.accepted_bytes), 50)


def test_admits_reordered_within_window() raises:
    var g = EarlyDataReplayGuard(max_bytes=UInt64(10_000))
    assert_true(g.admit(UInt64(10), 10))
    assert_true(g.admit(UInt64(7), 10))  # older but inside the 64 window
    assert_false(g.admit(UInt64(7), 10))  # now a duplicate
    assert_true(g.admit(UInt64(9), 10))


def test_rejects_stale_outside_window() raises:
    var g = EarlyDataReplayGuard(max_bytes=UInt64(100_000))
    assert_true(g.admit(UInt64(100), 10))
    # 100 - 30 = 70 >= 64-wide window: indistinguishable from a
    # forgotten pn, so it is rejected as a potential replay.
    assert_false(g.admit(UInt64(30), 10))
    # ...but a number just inside the window is still admitted.
    assert_true(g.admit(UInt64(100 - 63), 10))


def test_byte_budget_enforced() raises:
    var g = EarlyDataReplayGuard(max_bytes=UInt64(250))
    assert_true(g.admit(UInt64(0), 100))
    assert_true(g.admit(UInt64(1), 100))
    assert_false(g.admit(UInt64(2), 100))  # 300 > 250 budget
    # Budget-rejected packet leaves the window untouched, so the
    # same pn can still arrive within budget later (smaller payload).
    assert_true(g.admit(UInt64(2), 50))
    assert_equal(Int(g.accepted_bytes), 250)


def _cid(n: Int) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(n):
        b.append(UInt8(i + 1))
    return ConnectionId(bytes=b^)


def test_early_data_packet_len_matches_total() raises:
    # Build a minimal 0-RTT (type 1) long-header packet: prefix +
    # 1-byte Length varint (value < 64) + that many payload bytes.
    var hdr = encode_long_header(1, QUIC_VERSION_1, _cid(8), _cid(4))
    var pkt = hdr.copy()
    var payload_len = 20
    pkt.append(UInt8(payload_len))  # single-byte varint
    for i in range(payload_len):
        pkt.append(UInt8(i))
    assert_equal(early_data_packet_len(Span[UInt8, _](pkt)), len(pkt))


def main() raises:
    test_disabled_by_default_rejects_all()
    test_admits_fresh_in_order()
    test_rejects_duplicate_packet_number()
    test_admits_reordered_within_window()
    test_rejects_stale_outside_window()
    test_byte_budget_enforced()
    test_early_data_packet_len_matches_total()
    print("test_quic_0rtt_replay: 7 passed")
