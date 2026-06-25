"""Unit tests for the minimal PTO loss-recovery bookkeeping
(:mod:`flare.quic._loss_recovery`, RFC 9002 §6.2) and the ACK-range
expander (:func:`flare.quic.state.expand_ack_ranges`, RFC 9000
§19.3.1).

The recovery logic is pure (no I/O, no clock), so these drive it with
synthetic packet numbers + an injected monotonic clock to assert:

- ack retirement removes only the acked packets and resets the PTO
  backoff (forward progress),
- a gap in the ACK leaves the un-acked (lost) packet outstanding so
  the PTO can probe it,
- the PTO deadline tracks the oldest in-flight packet and backs off
  exponentially across consecutive probes,
- fire_pto returns the oldest packet's frames and removes it (the
  caller re-sends under a fresh packet number).
"""

from std.collections import List
from std.testing import assert_equal, assert_false, assert_true

from flare.quic._loss_recovery import LossRecovery, SentPacket
from flare.quic.frame import AckFrame, AckRange, EcnCounts
from flare.quic.state import expand_ack_ranges


def _frames(tag: UInt8) -> List[UInt8]:
    var f = List[UInt8]()
    f.append(tag)
    f.append(tag)
    return f^


def test_ack_retires_and_resets_backoff() raises:
    var lr = LossRecovery(base_pto_ms=UInt64(100))
    lr.on_sent(UInt64(0), _frames(0xA0), UInt64(1000))
    lr.on_sent(UInt64(1), _frames(0xA1), UInt64(1010))
    lr.on_sent(UInt64(2), _frames(0xA2), UInt64(1020))
    assert_equal(lr.outstanding(), 3)

    # Drive a PTO to bump the backoff counter, then a retiring ACK
    # must reset it.
    _ = lr.fire_pto()
    assert_equal(lr.pto_count, 1)

    var acked = List[UInt64]()
    acked.append(UInt64(1))
    var retired = lr.on_ack(acked)
    assert_true(retired, "acking pn 1 retires it")
    assert_equal(lr.outstanding(), 1)  # pn0 fired+removed, pn1 acked
    assert_equal(lr.pto_count, 0)


def test_ack_gap_leaves_lost_packet_outstanding() raises:
    var lr = LossRecovery(base_pto_ms=UInt64(100))
    lr.on_sent(UInt64(0), _frames(0xB0), UInt64(1000))
    lr.on_sent(UInt64(1), _frames(0xB1), UInt64(1010))
    lr.on_sent(UInt64(2), _frames(0xB2), UInt64(1020))

    # ACK acknowledges only pn 2 (pn 0,1 are a gap -- possibly lost).
    var acked = List[UInt64]()
    acked.append(UInt64(2))
    var retired = lr.on_ack(acked)
    assert_true(retired)
    assert_equal(lr.outstanding(), 2)  # pn0, pn1 still in flight

    var empty = List[UInt64]()
    assert_false(lr.on_ack(empty), "empty ack retires nothing")


def test_pto_deadline_and_backoff() raises:
    var lr = LossRecovery(base_pto_ms=UInt64(100))
    assert_equal(lr.pto_deadline(), UInt64(0))  # nothing armed

    lr.on_sent(UInt64(5), _frames(0xC0), UInt64(2000))
    lr.on_sent(UInt64(6), _frames(0xC1), UInt64(2050))
    # Oldest is pn5 at t=2000; deadline = 2000 + 100*2^0.
    assert_equal(lr.pto_deadline(), UInt64(2100))

    # fire_pto removes the oldest (pn5) and backs off; now oldest is
    # pn6 at t=2050; deadline = 2050 + 100*2^1.
    var f = lr.fire_pto()
    assert_equal(len(f), 2)
    assert_equal(Int(f[0]), 0xC0)
    assert_equal(lr.pto_count, 1)
    assert_equal(lr.outstanding(), 1)
    assert_equal(lr.pto_deadline(), UInt64(2050) + UInt64(200))


def test_fire_pto_empty_is_noop() raises:
    var lr = LossRecovery()
    var f = lr.fire_pto()
    assert_equal(len(f), 0)
    assert_equal(lr.outstanding(), 0)


def _ack(
    largest: UInt64, first: UInt64, var ranges: List[AckRange]
) -> AckFrame:
    return AckFrame(
        largest_acknowledged=largest,
        ack_delay=UInt64(0),
        first_ack_range=first,
        ranges=ranges^,
        ecn=List[EcnCounts](),
    )


def test_expand_ack_single_range() raises:
    # largest=10, first_ack_range=2 -> covers 8,9,10.
    var ack = _ack(UInt64(10), UInt64(2), List[AckRange]())
    var pns = expand_ack_ranges(ack)
    assert_equal(len(pns), 3)
    assert_equal(pns[0], UInt64(10))
    assert_equal(pns[1], UInt64(9))
    assert_equal(pns[2], UInt64(8))


def test_expand_ack_with_gap() raises:
    # largest=10, first range covers just 10 (first_ack_range=0).
    # One extra range: gap=1, length=1 -> next largest = 10 - (1+2)
    # = 7, covers 6,7.
    var ranges = List[AckRange]()
    ranges.append(AckRange(gap=UInt64(1), length=UInt64(1)))
    var ack = _ack(UInt64(10), UInt64(0), ranges^)
    var pns = expand_ack_ranges(ack)
    assert_equal(len(pns), 3)
    assert_equal(pns[0], UInt64(10))
    assert_equal(pns[1], UInt64(7))
    assert_equal(pns[2], UInt64(6))


def main() raises:
    test_ack_retires_and_resets_backoff()
    test_ack_gap_leaves_lost_packet_outstanding()
    test_pto_deadline_and_backoff()
    test_fire_pto_empty_is_noop()
    test_expand_ack_single_range()
    test_expand_ack_with_gap()
    print("test_loss_recovery: 6 passed")
