"""Unit tests for server path-validation policy (W4b).

Covers :mod:`flare.quic._server_migration` in isolation:

* :class:`MigrationProbe` -- re-probe decision, the RFC 9000 sec 8.1
  3x anti-amplification budget (grows with received bytes, lifts on
  validation), and the probe lifecycle.
* :func:`new_path_challenge` -- 8-byte PATH_CHALLENGE frame encoding.

The amplification budget is the anti-reflection control, so its
boundary (exactly 3x, just over 3x, budget growth, post-validation
lift) is tested explicitly.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.quic._server_migration import MigrationProbe, new_path_challenge
from flare.net import SocketAddr


def _addr(port: Int) -> SocketAddr:
    return SocketAddr.localhost(UInt16(port))


def test_idle_probe_allows_and_should_start() raises:
    var p = MigrationProbe()
    assert_true(p.should_start(_addr(5000)), "idle probe should start")
    # Idle (not probing): no amplification limit applies.
    assert_true(p.amplification_allows(10_000))


def test_amplification_budget_3x() raises:
    var p = MigrationProbe()
    p.start(_addr(5000), UInt64(100))  # received 100 bytes on new path
    assert_true(p.amplification_allows(300))  # exactly 3x: allowed
    assert_false(p.amplification_allows(301))  # over 3x: blocked
    p.note_tx(300)  # spend the whole budget
    assert_false(p.amplification_allows(1))  # nothing left
    # More received bytes grow the budget.
    p.note_rx(_addr(5000), UInt64(100))  # now 200 received -> 600 budget
    assert_true(p.amplification_allows(300))  # 300 spent + 300 <= 600


def test_note_rx_only_counts_candidate() raises:
    var p = MigrationProbe()
    p.start(_addr(5000), UInt64(100))
    p.note_rx(_addr(9999), UInt64(1_000))  # different addr: ignored
    assert_false(p.amplification_allows(301))  # budget still just 300


def test_validation_lifts_cap() raises:
    var p = MigrationProbe()
    p.start(_addr(5000), UInt64(10))
    assert_false(p.amplification_allows(1_000))  # tiny budget
    p.on_validated()
    assert_true(p.amplification_allows(1_000_000))  # cap lifted
    assert_false(p.probing, "validated probe is no longer probing")


def test_should_start_on_candidate_change() raises:
    var p = MigrationProbe()
    p.start(_addr(5000), UInt64(100))
    assert_false(p.should_start(_addr(5000)), "same candidate: no re-probe")
    assert_true(p.should_start(_addr(6000)), "new candidate: re-probe")


def test_new_path_challenge_encoding() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i + 1))
    var frame = new_path_challenge(data)
    # PATH_CHALLENGE = 1 type byte + 8 data bytes.
    assert_equal(len(frame), 9)
    for i in range(8):
        assert_equal(Int(frame[1 + i]), i + 1)

    var bad = List[UInt8]()
    bad.append(UInt8(0))  # wrong length
    var raised = False
    try:
        _ = new_path_challenge(bad)
    except:
        raised = True
    assert_true(raised, "non-8-byte challenge must raise")


def main() raises:
    test_idle_probe_allows_and_should_start()
    test_amplification_budget_3x()
    test_note_rx_only_counts_candidate()
    test_validation_lifts_cap()
    test_should_start_on_candidate_change()
    test_new_path_challenge_encoding()
    print("test_quic_migration_probe: 6 passed")
