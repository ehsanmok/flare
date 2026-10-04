# PLATFORM: any
"""CONC-04: Scheduler.drain leaks the listeners of workers that did join
whenever any one worker had to be detached.

Lean: Flare.Bugs.CONC_04.drain_leaks_joined_listener (counterexample run:
drain finishes with a joined worker's listener still allocated) and
Flare.Bugs.CONC_04.implFixed_noLeak (the fixed drain frees every
joined worker's resources).
flare/runtime/scheduler.mojo:890-897 @59bda50
(`self._per_worker_listener_addrs.clear()` in the stuck-worker branch).

Expected: per drain's docstring only the stuck worker's "context, stats
cell and listeners are left allocated". The listeners of the workers that
returned and were joined are closed and freed, as shutdown() does.
Actual: the stuck-worker branch clears the whole per-worker listener
list, so _free_resources frees none of them. Every joined worker's
SO_REUSEPORT listener fd stays open and bound for the process lifetime;
the kernel keeps hashing new connections to listeners nobody accepts on.

Minimal fix: in that branch keep (for freeing) the listeners of the
non-stuck workers -- primary i and its extras
n_workers + i*n_extra + j -- and drop only the stuck workers' entries.
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.scheduler import load_stop_flag
from flare.tcp import TcpListener


def _p(addr: Int) -> Pointer[Int64, MutUntrackedOrigin]:
    return Pointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[Scalar[DType.int64]]()


@fieldwise_init
struct _OneStuckFrontend(Copyable, Frontend):
    """The first worker to arrive overruns drain (sleeps 1.5 s); the
    others serve an idle loop and exit on the stop flag."""

    var cells: Int  # [0] ticket counter, [1] stuck worker's listener fd

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self,
        listener_fd: Int,
        mut stopping: Bool,
        stats_addr: Int,
        extra_fds: List[Int] = List[Int](),
    ):
        var ticket = Atomic[Int64].fetch_add(_p(self.cells), 1)
        if ticket == 0:
            Atomic[Int64].store[ordering=Ordering.RELEASE](
                _p(self.cells + 8), Int64(listener_fd)
            )
            _ = libc_nanosleep_ms(1500)
            return
        var stop_addr = Int(Pointer[Bool, _](to=stopping))
        while not load_stop_flag(stop_addr):
            _ = libc_nanosleep_ms(1)


def main() raises:
    var cp = alloc(Layout[Int64](count=2)).unsafe_leak()
    var cells = Int(cp)
    cp[unsafe_offset=0] = 0
    cp[unsafe_offset=1] = -1
    var s = Scheduler[_OneStuckFrontend].start(
        addr=SocketAddr.localhost(0),
        frontend=_OneStuckFrontend(cells),
        num_workers=2,
        pin_cores=False,
    )
    if len(s._per_worker_listener_addrs) != 2:
        raise Error("setup: expected two per-worker listeners")
    var fds = List[Int]()
    for i in range(2):
        var lp = Pointer[TcpListener, MutUntrackedOrigin](
            unsafe_from_address=s._per_worker_listener_addrs[i]
        )
        fds.append(Int(lp[].as_raw_fd()))
    while Atomic[Int64].load[ordering=Ordering.ACQUIRE](_p(cells + 8)) < 0:
        _ = libc_nanosleep_ms(1)
    var stuck_fd = Int(
        Atomic[Int64].load[ordering=Ordering.ACQUIRE](_p(cells + 8))
    )
    var reports = s.drain(timeout_ms=100)
    var n_detached = 0
    for i in range(len(reports)):
        if reports[i].drained == 0:
            n_detached += 1
    if n_detached != 1:
        raise Error("setup: expected exactly one detached worker")
    var joined_fd = fds[0] if fds[1] == stuck_fd else fds[1]
    # F_GETFD = 1 on Linux and macOS; -1 means the fd is closed.
    var still_open = (
        external_call["fcntl", c_int](c_int(joined_fd), c_int(1), c_int(0))
        >= c_int(0)
    )
    if still_open:
        print(
            "BUG REPRODUCED: after drain, the joined worker's listener fd",
            joined_fd,
            "is still open (only the stuck worker's fd",
            stuck_fd,
            "should be)",
        )
        raise Error("CONC-04")
    print("OK: drain closed the joined worker's listener fd", joined_fd)
