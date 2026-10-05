# PLATFORM: any
# RESOLVED: CONC-03 fixed on fix/formal-findings
"""CONC-03: Scheduler.drain frees the stop flag while a detached worker
still reads it (use-after-free).

Lean: Flare.Bugs.CONC_03.drain_uaf (counterexample run of the impl drain
reaching a worker read of the freed stop flag) and
Flare.Bugs.CONC_03.implFixed_safe (the fixed drain never frees a cell a
live worker can still touch).
flare/runtime/scheduler.mojo:887-900 (stuck-worker carve-out) and
flare/runtime/scheduler.mojo:741-744 (_free_resources frees the flag)
@59bda50; the worker reads the flag on every serve-loop iteration
(flare/runtime/_worker.mojo:150-155, the frontend's
`while not load_stop_flag(stopping_addr)`).

Expected: drain(timeout_ms) detaches a worker stuck past the deadline and,
as its docstring says, leaves everything that worker may still use
allocated. When the worker's handler finally returns, its serve loop
reads the stop flag, sees True, and the thread exits.
Before the fix: the carve-out keeps the stuck worker's ctx, stats cell and
listeners, but _free_resources still frees the shared stop-flag cell.
The detached worker keeps reading that freed byte. The allocator hands
the same cell to a later 1-byte allocation, which stores False, so the
worker never observes the stop and keeps serving after drain returned.

Deterministic: the verdict is "the flag cell was freed", observed as the
cell being handed out again by one of the next 64 same-size allocations
on the thread that called drain (a leaked cell can never be). Mojo's
allocator (the TCMalloc in libKGENCompilerRTShared) keeps a per-thread
LIFO free list per size class, so a freed cell comes back within the
handful of same-class frees drain performs after it. The repro first
calibrates that property and raises "setup:" instead of printing OK if
it does not hold, so it cannot print OK while the cell is freed. The
worker's failure to see the stop is reported as a consequence only.

Minimal fix: in drain's `if len(stuck) > 0:` block, also leak the stop
flag (`self._stopping_addr = 0` before `_free_resources`), the same way
the stuck worker's ctx and stats cell are leaked.
"""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc

from flare.net import SocketAddr
from flare.runtime import Frontend, Scheduler
from flare.runtime._libc_time import libc_nanosleep_ms
from flare.runtime.scheduler import load_stop_flag


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
    """Allocate up to n stop-flag-sized cells (kept, never freed) and
    report whether one of them is the cell at addr.

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


def main() raises:
    # Calibrate: a stop-flag-sized cell freed on this thread, followed by
    # the two same-class frees drain performs after it (its `done` and
    # `stuck` buffers), must come back within 64 allocations. Otherwise
    # "not reissued" below would not mean "not freed".
    var c0 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var c1 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var c2 = alloc(Layout[Bool](count=1)).unsafe_leak()
    var cal = Int(c0)
    c0.unsafe_free()
    c1.unsafe_free()
    c2.unsafe_free()
    if not _reissued_within(cal, 64):
        raise Error(
            "setup: this allocator does not reissue a freed cell within 64"
            " allocations; the free cannot be observed"
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
    if reports[0].drained != 0:
        raise Error("setup: the worker was not detached")
    # The next small allocations of this thread. A leaked cell can never
    # come back; a freed one does, per the calibration above.
    var aliased = _reissued_within(stop_addr, 64)
    _st(cells, 1)  # the handler returns
    while _ld(cells + 16) == 0:
        _ = libc_nanosleep_ms(1)
    var outcome = _ld(cells + 16)
    if aliased or outcome == 2:
        print(
            "BUG REPRODUCED: drain freed the stop flag at",
            hex(stop_addr),
            "under the detached worker (cell reissued:",
            String(aliased) + "; worker saw the stop:",
            String(outcome == 1) + ")",
        )
        raise Error("CONC-03")
    print(
        "OK: drain left the stop flag allocated and the detached worker",
        "saw the stop",
    )
