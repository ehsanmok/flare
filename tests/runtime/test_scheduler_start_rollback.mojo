"""``Scheduler.start`` rolls back completely when ``pthread_create`` fails.

The default listener mode pre-binds one ``SO_REUSEPORT`` listener per
worker before any thread is spawned. When a later spawn failed, the
rollback freed the worker array, the contexts, the stats cells, the shared
listener and the stop flag, but never the per-worker listeners (CONC-06):
the port stayed held and the kernel kept hashing connections to sockets
nobody accepted on.

``pthread_create`` is made to fail deterministically by filling this
process's thread table with parked threads and releasing exactly one slot,
so worker 0 spawns and worker 1 fails. That exhausts a per-process limit on
macOS (``kern.num_taskthreads``); on Linux the same fill hits the system or
cgroup thread limit and would starve other processes, so the test skips
there (``formal/repro/CONC-06_start_rollback_leaks_per_worker_listeners.mojo``
runs the same scenario and is the end-to-end check on every platform).

Standalone: it owns the whole thread table for a while, so it cannot share
a process with other tests.
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.runtime.scheduler import load_stop_flag

comptime MAX_BLOCKERS = 20000


def _p(addr: Int) -> Pointer[Int64, MutUntrackedOrigin]:
    return Pointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[Scalar[DType.int64]]()


def _ld(addr: Int) -> Int64:
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](_p(addr))


def _st(addr: Int, v: Int64):
    Atomic[Int64].store[ordering=Ordering.RELEASE](_p(addr), v)


def _blocker(arg: _OpaquePtr) -> _OpaquePtr:
    var gate = Int(arg)
    while _ld(gate) == 0:
        _ = libc_nanosleep_ms(100)
    return arg


def _open_fds() -> Int:
    var n = 0
    for fd in range(4096):
        # F_GETFD is 1 on Linux and macOS; it fails with EBADF on a closed fd.
        if external_call["fcntl", c_int](c_int(fd), c_int(1), c_int(0)) >= 0:
            n += 1
    return n


@fieldwise_init
struct _Idle(Copyable, Frontend):
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
        while not load_stop_flag(stop_addr):
            _ = libc_nanosleep_ms(1)


def test_failed_start_releases_the_per_worker_listeners() raises:
    comptime if CompilationTarget.is_linux():
        return
    var gates = Int(alloc(Layout[Int64](count=2)).unsafe_leak())
    var gate_all = gates
    var gate_one = gates + 8
    _st(gate_all, 0)
    _st(gate_one, 0)
    var one = ThreadHandle.spawn_os[_blocker](
        _OpaquePtr(unsafe_from_address=gate_one)
    )
    var parked = 1
    var exhausted = False
    while parked < MAX_BLOCKERS:
        try:
            var th = ThreadHandle.spawn_os[_blocker](
                _OpaquePtr(unsafe_from_address=gate_all)
            )
            th.detach()
            parked += 1
        except:
            exhausted = True
            break
    _st(gate_one, 1)
    one.join()  # exactly one thread slot is free again
    var before = _open_fds()
    var raised = False
    if exhausted:
        try:
            var s = Scheduler[_Idle].start(
                addr=SocketAddr.localhost(0),
                frontend=_Idle(),
                num_workers=2,
                pin_cores=False,
            )
            s.shutdown()
        except:
            raised = True
    var after = _open_fds()
    _st(gate_all, 1)
    _ = libc_nanosleep_ms(500)  # let the blockers exit
    assert_true(exhausted, "the thread table did not fill up")
    assert_true(raised, "pthread_create did not fail inside start")
    assert_equal(after, before, "the failed start left listener fds open")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
