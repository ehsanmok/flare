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

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc
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
struct _NopFrontend(Copyable, Frontend):
    """Test-only frontend: spin in 50 ms sleeps until ``stopping``.

    No socket reads, no protocol logic -- the lifecycle tests
    exercise pthread spawn / join, the heap-shared stop flag, and
    the listener bind / cleanup paths that ``Scheduler`` owns.
    """

    var tag: Int

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self,
        listener_fd: Int,
        mut stopping: Bool,
        stats_addr: Int,
        extra_fds: List[Int] = List[Int](),
    ):
        var stopping_addr = Int(Pointer[Bool, _](to=stopping))
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


def test_shutdown_closes_the_shared_listener_once() raises:
    """Shutdown closed the shared listener fd to wake the workers, then
    freed the TcpListener, whose destructor closed the same number
    again. Anything that reused the number in between was closed."""
    from std.ffi import c_int, external_call
    from std.os import setenv, unsetenv

    # The shared listener is the opt-out shape; per-worker SO_REUSEPORT
    # listeners are the default and are closed once, by their owners.
    _ = setenv("FLARE_REUSEPORT_WORKERS", "0")
    var s = Scheduler[_NopFrontend].start(
        addr=SocketAddr.localhost(0),
        frontend=_NopFrontend(0),
        num_workers=1,
        pin_cores=False,
    )
    var listener_fd = s._shared_listener_fd
    assert_true(listener_fd >= 0)
    s._signal_and_close_listener()
    # Reuse the freed number: the kernel hands out the lowest free fd.
    var opened = List[c_int]()
    var reused = c_int(-1)
    for _ in range(64):
        var fd = external_call["socket", c_int](c_int(2), c_int(1), c_int(0))
        opened.append(fd)
        if Int(fd) == listener_fd:
            reused = fd
            break
    s._join_workers()
    s._record_crash_count()
    s._free_resources()
    var alive = True
    if reused >= c_int(0):
        # F_GETFD fails with EBADF on a closed fd.
        alive = external_call["fcntl", c_int](
            reused, c_int(1), c_int(0)
        ) >= c_int(0)
    for i in range(len(opened)):
        _ = external_call["close", c_int](opened[i])
    s.shutdown()
    _ = unsetenv("FLARE_REUSEPORT_WORKERS")
    assert_true(reused >= c_int(0), "could not reuse the listener's fd")
    assert_true(alive, "shutdown closed an fd it no longer owned")


@fieldwise_init
struct _StubbornFrontend(Copyable, Frontend):
    """Ignores the stop flag for ``hold_ms``, like a worker stuck in a
    handler, then exits."""

    var hold_ms: Int

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self,
        listener_fd: Int,
        mut stopping: Bool,
        stats_addr: Int,
        extra_fds: List[Int] = List[Int](),
    ):
        _ = libc_nanosleep_ms(self.hold_ms)
        store_worker_stat(stats_addr, WORKER_STAT_STATUS, WORKER_STATUS_CLEAN)


def test_drain_returns_at_its_deadline() raises:
    """``drain(timeout_ms)`` joined every worker without a bound, so one
    stuck worker held it for as long as the handler took."""
    from flare.runtime._libc_time import monotonic_now_ms

    var s = Scheduler[_StubbornFrontend].start(
        addr=SocketAddr.localhost(0),
        frontend=_StubbornFrontend(3000),
        num_workers=1,
        pin_cores=False,
    )
    var t0 = monotonic_now_ms()
    var reports = s.drain(timeout_ms=200)
    var took = monotonic_now_ms() - t0
    assert_true(took < 2000, "drain took " + String(took) + " ms")
    assert_equal(len(reports), 1)
    assert_equal(reports[0].drained, 0)


def test_start_raises_when_a_worker_listener_cannot_bind() raises:
    """A failed per-worker bind was skipped, leaving later workers on fd
    -1 or on another address's listener. The fd limit is lowered so the
    probe bind succeeds and the per-worker binds run out."""
    from std.ffi import c_int, external_call
    from std.memory import stack_allocation
    from std.sys.info import CompilationTarget

    # RLIMIT_NOFILE is 7 on Linux, 8 on macOS.
    var res = c_int(7) if CompilationTarget.is_linux() else c_int(8)
    var lim = stack_allocation[2, UInt64]()
    _ = external_call["getrlimit", c_int](res, lim)
    var soft = lim[unsafe_offset=0]
    var probe = external_call["socket", c_int](c_int(2), c_int(1), c_int(0))
    _ = external_call["close", c_int](probe)
    lim[unsafe_offset=0] = UInt64(Int(probe) + 2)
    _ = external_call["setrlimit", c_int](res, lim)
    var raised = False
    try:
        var s = Scheduler[_NopFrontend].start(
            addr=SocketAddr.localhost(0),
            frontend=_NopFrontend(0),
            num_workers=4,
            pin_cores=False,
        )
        s.shutdown()
    except:
        raised = True
    lim[unsafe_offset=0] = soft
    _ = external_call["setrlimit", c_int](res, lim)
    assert_true(raised, "start ran with workers missing their listeners")


# ── CONC-03: drain must not free the stop flag under a detached worker ──────


def _ld(addr: Int) -> Int64:
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](
        p.unsafe_bitcast[Scalar[DType.int64]]()
    )


def _st(addr: Int, v: Int64):
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    Atomic[Int64].store[ordering=Ordering.RELEASE](
        p.unsafe_bitcast[Scalar[DType.int64]](), v
    )


@fieldwise_init
struct _GateFrontend(Copyable, Frontend):
    """One worker that is "stuck in a handler" until the gate opens, then
    returns to an ordinary serve loop that polls the stop flag."""

    var cells: Int  # [0] gate, [1] stop-flag addr seen, [2] outcome

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self,
        listener_fd: Int,
        mut stopping: Bool,
        stats_addr: Int,
        extra_fds: List[Int] = List[Int](),
    ):
        var stop_addr = Int(Pointer[Bool, _](to=stopping))
        _st(self.cells + 8, Int64(stop_addr))
        while _ld(self.cells) == 0:  # the handler that overran drain
            _ = libc_nanosleep_ms(1)
        var spins = 0
        while not load_stop_flag(stop_addr):  # the serve loop
            _ = libc_nanosleep_ms(1)
            spins += 1
            if spins > 2000:
                _st(self.cells + 16, 2)  # never saw the stop
                return
        _st(self.cells + 16, 1)  # saw the stop, exits


def _reissued_within(addr: Int, n: Int) -> Bool:
    """Allocate up to ``n`` stop-flag-sized cells (kept, never freed) and
    report whether one of them is the cell at ``addr``.

    The address goes through an atomic cell first: the optimizer may
    otherwise fold "a fresh allocation equals an older address" to False.
    """
    # 64 bytes: not the stop flag's size class, so it cannot take the cell.
    var scratch = Int(alloc(Layout[Int64](count=8)).unsafe_leak())
    for _ in range(n):
        var q = alloc(Layout[Bool](count=1)).unsafe_leak()
        q.unsafe_write(False)
        _st(scratch, Int64(Int(q)))
        if Int(_ld(scratch)) == addr:
            return True
    return False


def test_drain_keeps_the_stop_flag_allocated_for_a_detached_worker() raises:
    """``drain`` detached a stuck worker, left its context and stats cell
    allocated, and still freed the shared stop flag, which the worker
    re-reads on every serve-loop iteration (use after free).

    The verdict is "the flag cell was freed", observed as the cell being
    handed out again by one of the next allocations on this thread (a
    leaked cell can never come back); the calibration below raises instead
    of passing if the allocator would not reissue a freed cell.
    """
    var c0 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var c1 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var c2 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var cal = Int(c0)
    c0.unsafe_free()
    c1.unsafe_free()
    c2.unsafe_free()
    assert_true(
        _reissued_within(cal, 64),
        "setup: the allocator does not reissue a freed cell",
    )
    var cp = alloc(Layout[Int64](count=3)).unsafe_leak()
    var cells = Int(cp)
    _st(cells, 0)
    _st(cells + 8, 0)
    _st(cells + 16, 0)
    var s = Scheduler[_GateFrontend].start(
        addr=SocketAddr.localhost(0),
        frontend=_GateFrontend(cells),
        num_workers=1,
        pin_cores=False,
    )
    while _ld(cells + 8) == 0:
        _ = libc_nanosleep_ms(1)
    var stop_addr = Int(_ld(cells + 8))
    var reports = s.drain(timeout_ms=50)  # the worker is still in its handler
    assert_equal(reports[0].drained, 0, "setup: the worker was not detached")
    var aliased = _reissued_within(stop_addr, 64)
    _st(cells, 1)  # the handler returns
    while _ld(cells + 16) == 0:
        _ = libc_nanosleep_ms(1)
    var outcome = _ld(cells + 16)
    assert_true(not aliased, "drain freed the stop flag under a live worker")
    assert_equal(Int(outcome), 1, "the detached worker never saw the stop")


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_scheduler.mojo — multicore scheduler lifecycle")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
