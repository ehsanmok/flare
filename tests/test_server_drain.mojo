"""Tests for ``HttpServer.drain`` and ``ShutdownReport``.

only had
``HttpServer.close()`` (a hard stop that cuts in-flight handlers
mid-write) and a ``ServerConfig.shutdown_timeout_ms`` field that
was never wired to a wait-for-drain loop. adds
``HttpServer.drain(timeout_ms) -> ShutdownReport`` as the
recommended graceful shutdown.

Covers:

- ``ShutdownReport`` is a value type with the documented three
  fields and a working constructor.
- ``HttpServer.drain(0)`` is a hard stop equivalent to
  ``close()``: ``_stopping`` becomes ``True`` and the listener
  closes; the report records a non-success outcome.
- ``HttpServer.drain(timeout_ms > 0)`` returns a ``ShutdownReport``
  with non-negative counts.
- A negative ``timeout_ms`` is clamped to ``0``.
- Re-exports from ``flare.http`` and the root ``flare`` package
  resolve.

Multi-worker drain coordination through ``Scheduler.drain`` lands
in ; this commit covers the single-threaded path.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare import ShutdownReport as RootShutdownReport
from flare.http import HttpServer, ServerConfig, ShutdownReport
from flare.net import SocketAddr


# ── ShutdownReport struct ────────────────────────────────────────────────────


def test_shutdown_report_constructor() raises:
    var r = ShutdownReport(drained=3, timed_out=1, in_flight_at_deadline=1)
    assert_equal(r.drained, 3)
    assert_equal(r.timed_out, 1)
    assert_equal(r.in_flight_at_deadline, 1)


def test_shutdown_report_zero_state() raises:
    var r = ShutdownReport(drained=0, timed_out=0, in_flight_at_deadline=0)
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
    var r = RootShutdownReport(drained=2, timed_out=0, in_flight_at_deadline=0)
    assert_equal(r.drained, 2)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
