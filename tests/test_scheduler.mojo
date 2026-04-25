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
"""

from std.testing import assert_true, assert_equal, TestSuite

from flare.http import Handler, Request, Response, Method, ok
from flare.http.server import ServerConfig
from flare.net import SocketAddr
from flare.runtime.scheduler import Scheduler, default_worker_count


# ── A minimal stateless handler satisfying Handler ─────────────────────────


@fieldwise_init
struct _NopHandler(Copyable, Handler):
    var tag: Int

    def serve(self, req: Request) raises -> Response:
        return ok("nop")


def _config_fast_shutdown() -> ServerConfig:
    """Config tuned so tests exit fast on shutdown."""
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 200
    cfg.write_timeout_ms = 500
    cfg.shutdown_timeout_ms = 300
    return cfg^


# ── default_worker_count ───────────────────────────────────────────────────


def test_default_worker_count_positive() raises:
    """``default_worker_count`` returns at least 1."""
    var n = default_worker_count()
    assert_true(n >= 1)


# ── Scheduler lifecycle ────────────────────────────────────────────────────


def test_scheduler_start_and_shutdown_n2() raises:
    """Scheduler with 2 workers: start, shut down cleanly."""
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=2, pin_cores=False
    )
    assert_true(s.is_running())
    s.shutdown()
    assert_true(not s.is_running())


def test_scheduler_start_and_shutdown_n4() raises:
    """Scheduler with 4 workers: start, shut down cleanly."""
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=4, pin_cores=False
    )
    assert_true(s.is_running())
    s.shutdown()
    assert_true(not s.is_running())


def test_scheduler_drain_returns_per_worker_reports() raises:
    """``Scheduler.drain`` returns one ``ShutdownReport`` per
    worker; the count matches ``num_workers``."""
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=3, pin_cores=False
    )
    var reports = s.drain(timeout_ms=200)
    assert_equal(len(reports), 3)
    # All workers joined inside the budget — drained=1 each.
    for i in range(len(reports)):
        assert_equal(reports[i].drained, 1)
        assert_equal(reports[i].timed_out, 0)
        assert_equal(reports[i].in_flight_at_deadline, 0)
    assert_true(not s.is_running())


def test_scheduler_drain_zero_timeout_is_hard_stop() raises:
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=2, pin_cores=False
    )
    var reports = s.drain(timeout_ms=0)
    assert_equal(len(reports), 2)
    for i in range(len(reports)):
        assert_equal(reports[i].drained, 0)


def test_scheduler_shutdown_idempotent() raises:
    """``shutdown()`` is safe to call twice."""
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=2, pin_cores=False
    )
    s.shutdown()
    s.shutdown()  # must not crash
    assert_true(not s.is_running())


def test_scheduler_multiple_start_cycles() raises:
    """Two start / shutdown cycles in sequence do not leak."""
    var addr = SocketAddr.localhost(0)
    for _ in range(2):
        var h = _NopHandler(0)
        var cfg = _config_fast_shutdown()
        var s = Scheduler[_NopHandler].start(
            addr=addr,
            config=cfg^,
            handler=h^,
            num_workers=2,
            pin_cores=False,
        )
        s.shutdown()


def test_scheduler_pin_cores_flag_default_no_crash() raises:
    """``pin_cores=True`` (default on Linux, no-op on macOS) does not crash."""
    var addr = SocketAddr.localhost(0)
    var h = _NopHandler(0)
    var cfg = _config_fast_shutdown()
    var s = Scheduler[_NopHandler].start(
        addr=addr, config=cfg^, handler=h^, num_workers=2, pin_cores=True
    )
    s.shutdown()


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_scheduler.mojo — multicore scheduler lifecycle")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
