"""Unit tests for the buffer-ring receive kernel (``flare.http._bufring_ledger``).

``classify_recv`` decides what the io_uring buffer-ring loop does with every
receive completion. The invariant that matters (proved in
``formal/Flare/Kernels/BufLedger.lean``): a completion that took a provided
buffer gives it back exactly once, so the ring never drains. Issue #37 was
the stale-completion path skipping that return.
"""

from std.testing import assert_equal, assert_false, assert_true, TestSuite

from flare.http._bufring_ledger import (
    BufLedger,
    RECV_CLOSE,
    RECV_DROP,
    RECV_STAGE,
    classify_recv,
)


def test_stale_completion_returns_its_buffer() raises:
    var d = classify_recv(False, 100, True)
    assert_equal(d.action, RECV_DROP)
    assert_true(d.return_buf)


def test_data_for_live_connection_is_staged() raises:
    var d = classify_recv(True, 100, True)
    assert_equal(d.action, RECV_STAGE)
    assert_true(d.return_buf)


def test_eof_error_and_bufferless_close() raises:
    var eof = classify_recv(True, 0, True)
    assert_equal(eof.action, RECV_CLOSE)
    assert_true(eof.return_buf)
    var enobufs = classify_recv(True, -105, False)
    assert_equal(enobufs.action, RECV_CLOSE)
    assert_false(enobufs.return_buf)
    var no_buf = classify_recv(True, 100, False)
    assert_equal(no_buf.action, RECV_CLOSE)
    assert_false(no_buf.return_buf)


def test_stale_completions_never_drain_the_ring() raises:
    var led = BufLedger(4)
    for _ in range(1000):
        assert_true(led.on_fill())
        _ = led.on_complete(False, 100, True)
        assert_equal(led.in_ring + led.in_cq, 4)
    assert_equal(led.in_ring, 4)
    assert_equal(led.enobufs, 0)


def test_empty_ring_reports_enobufs() raises:
    var led = BufLedger(1)
    assert_true(led.on_fill())
    assert_false(led.on_fill())
    assert_equal(led.enobufs, 1)
    _ = led.on_complete(True, 8192, True)
    assert_equal(led.in_ring, 1)
    assert_equal(led.in_cq, 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
