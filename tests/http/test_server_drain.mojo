"""Tests for ``HttpServer.drain`` and ``ShutdownReport``.

``HttpServer.close()`` is a hard stop that cuts in-flight handlers
mid-write; ``HttpServer.drain(timeout_ms) -> ShutdownReport`` is the
recommended graceful shutdown.

Covers:

- ``ShutdownReport`` is a value type with the documented four fields
  and a working constructor.
- ``HttpServer.drain(0)`` is a hard stop equivalent to ``close()``:
  ``_stopping`` becomes ``True`` and the listener closes.
- ``HttpServer.drain(timeout_ms > 0)`` returns a report with
  non-negative counts.
- A negative ``timeout_ms`` is clamped to ``0``.
- Re-exports from ``flare.http`` and the root ``flare`` package
  resolve.
- The unified reactor's shutdown tail flips ``Cancel.SHUTDOWN`` on
  live connections before closing them, and reports how many were
  still in flight.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare import ShutdownReport as RootShutdownReport
from flare.http import HttpServer, ServerConfig, ShutdownReport
from flare.http._reactor.tagged_dispatch import KIND_H1, _pack
from flare.http._server_reactor_epoll import _conn_alloc_addr
from flare.http._unified_reactor_impl import _drain_remaining_conns_unified
from flare.net import SocketAddr
from flare.runtime import Reactor, TimerWheel
from flare.tcp import TcpListener, TcpStream


# ── ShutdownReport struct ────────────────────────────────────────────────────


def test_shutdown_report_constructor() raises:
    var r = ShutdownReport(
        drained=3, timed_out=1, in_flight_at_deadline=1, crashed=0
    )
    assert_equal(r.drained, 3)
    assert_equal(r.timed_out, 1)
    assert_equal(r.in_flight_at_deadline, 1)
    assert_equal(r.crashed, 0)


def test_shutdown_report_zero_state() raises:
    var r = ShutdownReport(
        drained=0, timed_out=0, in_flight_at_deadline=0, crashed=0
    )
    assert_equal(r.drained, 0)
    assert_equal(r.timed_out, 0)
    assert_equal(r.in_flight_at_deadline, 0)


# ── HttpServer.drain ─────────────────────────────────────────────────────────


def test_drain_hard_stop_with_zero_timeout() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var report = srv.drain(timeout_ms=0)
    # Zero timeout is a hard stop; drained=0 records that we did
    # not wait for any in-flight work to finish.
    assert_equal(report.drained, 0)
    assert_equal(report.timed_out, 0)
    assert_equal(report.in_flight_at_deadline, 0)
    assert_true(srv._stopping)


def test_drain_negative_timeout_clamped_to_zero() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    # Negative is clamped to 0 inside drain; behaves like a hard
    # stop and does not panic / return garbage.
    var report = srv.drain(timeout_ms=-100)
    assert_equal(report.drained, 0)
    assert_true(srv._stopping)


def test_drain_with_short_timeout_returns_report() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var report = srv.drain(timeout_ms=50)
    # Best-effort report: the single-threaded reactor cannot
    # observe per-conn drain progress without external state, so
    # we only verify the report is well-formed.
    assert_true(report.drained >= 0)
    assert_true(report.timed_out >= 0)
    assert_true(report.in_flight_at_deadline >= 0)
    assert_true(srv._stopping)


def test_drain_marks_stopping_idempotent() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    _ = srv.drain(0)
    assert_true(srv._stopping)
    # Calling drain again is benign — the listener is already
    # closed and ``_stopping`` is already True.
    _ = srv.drain(0)
    assert_true(srv._stopping)


# ── Re-exports resolve from both barrels ────────────────────────────────────


def test_root_package_re_exports_shutdown_report() raises:
    var r = RootShutdownReport(
        drained=2, timed_out=0, in_flight_at_deadline=0, crashed=0
    )
    assert_equal(r.drained, 2)


# ── Reactor shutdown tail flips Cancel.SHUTDOWN ─────────────────────────────


def test_unified_drain_reports_in_flight_and_empties_table() raises:
    """The unified reactor's shutdown tail reports what it closed.

    The legacy epoll loop always flipped ``Cancel.SHUTDOWN`` on live
    connections at shutdown; the unified loop that ``serve()`` actually
    runs used to free them outright, so a cancel-aware handler or a
    streaming body got the socket pulled mid-chunk with no signal. The
    tail now flips first and returns the live count.

    The flip itself is not asserted here: the same call frees the
    handle, and ``CancelCell.__deinit__`` frees the cell, so reading the
    ``Cancel`` afterwards would be a use-after-free. That
    ``signal_drain`` flips every stream cell is covered directly by
    tests/http2/test_h2_per_stream_cancel.mojo; this pins the count
    and the table teardown, which are what the caller observes.
    """
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(listener.local_addr())
    var accepted = listener.accept()

    var reactor = Reactor()
    var conns = Dict[Int, Int]()
    var timers = Dict[Int, UInt64]()

    var fd = Int(accepted._socket.fd)
    conns[fd] = _pack(KIND_H1, _conn_alloc_addr(accepted^))

    var wheel = TimerWheel(now_ms=UInt64(0))
    var still_live = _drain_remaining_conns_unified(
        conns, timers, reactor, wheel
    )

    assert_equal(still_live, 1, "drain must report the live connection")
    assert_equal(len(conns), 0, "drain must empty the conn table")
    client.close()
    listener.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
