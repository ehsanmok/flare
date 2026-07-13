"""Tests for ``flare.runtime.scheduler.Scheduler``.

Covers:

- ``default_worker_count`` returns at least 1.
- A Scheduler with N=2 workers starts and shuts down cleanly.
- A Scheduler with N=4 workers starts and shuts down cleanly.
- ``shutdown()`` is idempotent.
- ``is_running`` goes False after shutdown.
- Multiple start/shutdown cycles do not leak.

Runtime-behaviour tests (actual HTTP round-trips across N workers)
live in ``test_server_multicore.mojo`` (Step 10). The tests here are
lifecycle-only, which is what keeps them stable under kqueue +
pthread timing differences between platforms.

The scheduler is :trait:`Frontend`-generic; the tests use a tiny
local ``_NopFrontend`` that runs an idle loop and observes the
stop flag. That keeps the runtime tests free of any
:mod:`flare.http` dependency -- the layering inversion is what
made this possible.
"""

from std.testing import assert_true, assert_equal, TestSuite

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler, default_worker_count
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.scheduler import (
    load_stop_flag,
    store_worker_stat,
    WORKER_STAT_INFLIGHT,
    WORKER_STAT_STATUS,
    WORKER_STATUS_CLEAN,
)


# ── A minimal Frontend whose run_worker idles until stopping flips ──────────


@fieldwise_init
struct _NopFrontend(Copyable, Frontend, Movable):
    """Test-only frontend: spin in 50 ms sleeps until ``stopping``.

    No socket reads, no protocol logic -- the lifecycle tests
    exercise pthread spawn / join, the heap-shared stop flag, and
    the listener bind / cleanup paths that ``Scheduler`` owns.
    """

    var tag: Int

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self, listener_fd: Int, mut stopping: Bool, stats_addr: Int
    ):
        var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
        while not load_stop_flag(stopping_addr):
            store_worker_stat(stats_addr, WORKER_STAT_INFLIGHT, 0)
            _ = libc_nanosleep_ms(50)
        store_worker_stat(stats_addr, WORKER_STAT_STATUS, WORKER_STATUS_CLEAN)


# ── default_worker_count ───────────────────────────────────────────────────


def test_default_worker_count_positive() raises:
    """``default_worker_count`` returns at least 1."""
    var n = default_worker_count()
    assert_true(n >= 1)


# ── Scheduler lifecycle ────────────────────────────────────────────────────


def test_scheduler_start_and_shutdown_n2() raises:
    """Scheduler with 2 workers: start, shut down cleanly."""
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=2, pin_cores=False
    )
    assert_true(s.is_running())
    s.shutdown()
    assert_true(not s.is_running())


def test_scheduler_start_and_shutdown_n4() raises:
    """Scheduler with 4 workers: start, shut down cleanly."""
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=4, pin_cores=False
    )
    assert_true(s.is_running())
    s.shutdown()
    assert_true(not s.is_running())


def test_scheduler_drain_returns_per_worker_reports() raises:
    """``Scheduler.drain`` returns one ``ShutdownReport`` per
    worker; the count matches ``num_workers``."""
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=3, pin_cores=False
    )
    var reports = s.drain(timeout_ms=200)
    assert_equal(len(reports), 3)
    for i in range(len(reports)):
        assert_equal(reports[i].drained, 1)
        assert_equal(reports[i].timed_out, 0)
        assert_equal(reports[i].in_flight_at_deadline, 0)
    assert_true(not s.is_running())
    # D9: idle workers exit cleanly, so no worker is reported crashed.
    assert_equal(s.crashed_worker_count(), 0)


def test_scheduler_drain_zero_timeout_is_hard_stop() raises:
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=2, pin_cores=False
    )
    var reports = s.drain(timeout_ms=0)
    assert_equal(len(reports), 2)
    for i in range(len(reports)):
        assert_equal(reports[i].drained, 0)


def test_scheduler_shutdown_idempotent() raises:
    """``shutdown()`` is safe to call twice."""
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=2, pin_cores=False
    )
    s.shutdown()
    s.shutdown()
    assert_true(not s.is_running())


def test_scheduler_multiple_start_cycles() raises:
    """Two start / shutdown cycles in sequence do not leak."""
    var addr = SocketAddr.localhost(0)
    for _ in range(2):
        var s = Scheduler[_NopFrontend].start(
            addr=addr,
            frontend=_NopFrontend(0),
            num_workers=2,
            pin_cores=False,
        )
        s.shutdown()


def test_scheduler_pin_cores_flag_default_no_crash() raises:
    """``pin_cores=True`` (default on Linux, no-op on macOS) does not crash."""
    var addr = SocketAddr.localhost(0)
    var s = Scheduler[_NopFrontend].start(
        addr=addr, frontend=_NopFrontend(0), num_workers=2, pin_cores=True
    )
    s.shutdown()


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_scheduler.mojo — multicore scheduler lifecycle")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
