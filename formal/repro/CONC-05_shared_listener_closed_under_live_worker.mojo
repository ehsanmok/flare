# PLATFORM: any
# RESOLVED: CONC-05 fixed on fix/formal-findings
"""CONC-05: in shared-listener mode the Scheduler closes (and frees) the
shared listener fd while a worker can still accept on it.

Lean: Flare.Bugs.CONC_05.drain_closes_live_listener (a run of the
shared-listener drain reaching a state where a live worker holds a closed
listener fd) and Flare.Bugs.CONC_05.implFixed_safe (closing the shared fd
only after every worker has joined, and leaking it when one is detached,
never closes an fd a live worker can accept on).
flare/runtime/scheduler.mojo:655-668 (`_signal_and_close_listener` closes
the shared fd at the start of shutdown/drain) and :713-724
(`_free_resources` frees the shared TcpListener) @59bda50; the worker
accepts on that fd number in every loop iteration
(flare/http/_server_reactor_epoll.mojo:163-193, `_accept_loop_fd`).

Shared-listener mode is selected with FLARE_REUSEPORT_WORKERS=0
(scheduler.mojo:407-409), which this file sets before Scheduler.start.

Expected: the shared listener is the fd every worker accepts on. Per the
drain docstring (scheduler.mojo:799-803) a detached worker's listeners
"are left allocated, since the thread may still be using them", and no
worker should ever accept on the fd after its number has been released.
Before the fix: drain (and shutdown) close the shared fd in step 1, before any
worker has stopped or been joined, and _free_resources frees the listener
even when a worker was detached. The fd number is released while the
worker still holds it; the next open() in the process reuses the number,
so the worker's next accept_fd(listener_fd) runs on an unrelated file.

Deterministic: the fd close is observed directly with fcntl(F_GETFD)
(no allocator involvement), and the reuse with one open("/dev/null"),
which returns the lowest free descriptor.

Minimal fix: do not close the shared fd in _signal_and_close_listener;
let _free_resources close it once, after the workers have joined; in
drain's stuck-worker branch leak it (`self._shared_listener_addr = 0`)
when any worker was detached, as the per-worker listeners are.
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_char, c_int, external_call
from std.memory import Layout, Pointer, alloc

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler
from flare.runtime._libc_time import libc_nanosleep_ms


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


def _fd_open(fd: Int) -> Bool:
    # F_GETFD = 1 on Linux and macOS; -1 means the descriptor is closed.
    return external_call["fcntl", c_int](
        c_int(fd), c_int(1), c_int(0)
    ) >= c_int(0)


@fieldwise_init
struct _GateShared(Copyable, Frontend):
    """One worker that records its (shared) listener fd and then stays
    "in a handler" until the gate opens."""

    var cells: Int  # [0] gate, [1] listener fd seen (+1), [2] done

    def requires_per_worker_listener(self) -> Bool:
        return False

    def run_worker(
        mut self,
        listener_fd: Int,
        mut stopping: Bool,
        stats_addr: Int,
        extra_fds: List[Int] = List[Int](),
    ):
        _st(self.cells + 8, Int64(listener_fd + 1))
        while _ld(self.cells) == 0:  # the handler that overran drain
            _ = libc_nanosleep_ms(1)
        _st(self.cells + 16, 1)


def main() raises:
    var name = String("FLARE_REUSEPORT_WORKERS")
    var val = String("0")
    _ = external_call["setenv", c_int](
        name.as_c_string_span(), val.as_c_string_span(), c_int(1)
    )
    var cp = alloc(Layout[Int64](count=3)).unsafe_leak()
    var cells = Int(cp)
    _st(cells, 0)
    _st(cells + 8, 0)
    _st(cells + 16, 0)
    var s = Scheduler[_GateShared].start(
        addr=SocketAddr.localhost(0),
        frontend=_GateShared(cells),
        num_workers=1,
        pin_cores=False,
    )
    if s._shared_listener_fd < 0:
        raise Error("setup: shared-listener mode was not selected")
    while _ld(cells + 8) == 0:
        _ = libc_nanosleep_ms(1)
    var lfd = Int(_ld(cells + 8)) - 1
    if lfd != s._shared_listener_fd:
        raise Error("setup: the worker was not handed the shared listener")
    if not _fd_open(lfd):
        raise Error("setup: listener fd closed before drain")
    var reports = s.drain(timeout_ms=50)  # the worker is still in its handler
    if reports[0].drained != 0:
        raise Error("setup: the worker was not detached")
    var closed = not _fd_open(lfd)
    var reused = False
    if closed:
        var path = String("/dev/null")
        var nfd = Int(
            external_call["open", c_int](path.as_c_string_span(), c_int(0))
        )
        reused = nfd == lfd
    _st(cells, 1)  # let the detached worker return
    while _ld(cells + 16) == 0:
        _ = libc_nanosleep_ms(1)
    if closed:
        print(
            "BUG REPRODUCED: drain closed the shared listener fd",
            lfd,
            "while the detached worker still holds it",
            "(the next open() reused the number: " + String(reused) + ")",
        )
        raise Error("CONC-05")
    print("OK: the detached worker's shared listener fd", lfd, "is still open")
