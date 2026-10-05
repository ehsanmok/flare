# PLATFORM: any
# RESOLVED: CONC-06 fixed on fix/formal-findings
"""CONC-06: when pthread_create fails part-way through Scheduler.start,
the rollback leaks every pre-bound per-worker SO_REUSEPORT listener.

Lean: Flare.Bugs.CONC_06.rollback_leaks_listeners (the modelled rollback
ends with the scheduler gone and every per-worker listener still
allocated) and Flare.Bugs.CONC_06.fixed_rollback_clean (the rollback that
also frees `_per_worker_listener_addrs` releases every resource exactly
once and joins every spawned worker).
flare/runtime/scheduler.mojo:591-633 @59bda50 (the `if not spawned:`
rollback frees the worker array, the ctxs, the stats cells, the shared
listener and the stop flag, but never `s._per_worker_listener_addrs`,
which :511-543 filled; `Scheduler` has no destructor, so nothing else
frees them once the Error propagates).

Expected (start's docstring, :337-343): on a pthread_create failure
"partially-started workers are best-effort joined before re-raising";
the failed call leaves nothing of the scheduler behind.
Before the fix: the default listener mode pre-binds one SO_REUSEPORT listener per
worker before spawning. After the rollback those sockets stay open and
bound, for the process lifetime: the port stays held, and the kernel
keeps hashing new connections to listeners nobody accepts on.

Deterministic: pthread_create is made to fail by filling the process's
thread table first (blocker threads until spawn_os raises), then
releasing exactly one slot by joining one blocker. Worker 0 takes that
slot and worker 1 fails (if anything else took the slot, worker 0 fails
instead; the rollback path and the leak are the same). The leak is
measured as the change in the number of open descriptors, which the
allocator cannot influence.

Minimal fix: in the rollback, also destroy and free every entry of
`s._per_worker_listener_addrs` and clear it (as `_free_resources` does).
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime._thread import ThreadHandle, _OpaquePtr
from flare.runtime.scheduler import load_stop_flag


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
        # F_GETFD = 1 on Linux and macOS.
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


def main() raises:
    var cp = alloc(Layout[Int64](count=2)).unsafe_leak()
    var gate_all = Int(cp)
    var gate_one = gate_all + 8
    _st(gate_all, 0)
    _st(gate_one, 0)
    var one = ThreadHandle.spawn_os[_blocker](
        _OpaquePtr(unsafe_from_address=gate_one)
    )
    var parked = 1
    while True:
        try:
            var th = ThreadHandle.spawn_os[_blocker](
                _OpaquePtr(unsafe_from_address=gate_all)
            )
            th.detach()
            parked += 1
        except:
            break
    _st(gate_one, 1)
    one.join()  # exactly one thread slot is free again
    var before = _open_fds()
    var raised = False
    try:
        var s = Scheduler[_Idle].start(
            addr=SocketAddr.localhost(0),
            frontend=_Idle(),
            num_workers=2,
            pin_cores=False,
        )
        s.shutdown()
    except e:
        raised = True
        print("start raised:", e)
    var after = _open_fds()
    _st(gate_all, 1)
    _ = libc_nanosleep_ms(500)  # let the blockers exit before raising
    if not raised:
        raise Error(
            "setup: pthread_create did not fail ("
            + String(parked)
            + " blockers parked)"
        )
    if after > before:
        print(
            "BUG REPRODUCED: the failed Scheduler.start left",
            after - before,
            "listener fds open (",
            before,
            "open before,",
            after,
            "after)",
        )
        raise Error("CONC-06")
    print("OK: the failed Scheduler.start released every fd (", after, "open)")
