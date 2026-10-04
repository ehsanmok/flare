# PLATFORM: any
"""RT-07: the blocking-pool thread cap drifts above MAX_POOL_SIZE after a
fail-open acquire.

Lean: Flare.Bugs.RT_07.failOpen_breaks_cap (counterexample) and
Flare.Bugs.RT_07.fixed_cap_invariant (fix meets spec).
flare/runtime/blocking.mojo:177-206 @59bda50.

Expected: at most MAX_POOL_SIZE (32) slots can be held at once, whatever
transient errors occur.
Actual: _pool_try_acquire returns True without decrementing when
sem_open fails (fail-open), but the paired _pool_release posts whenever
its own sem_open succeeds. One acquire made while sem_open fails (here
EMFILE: the fd table is full, i.e. exactly the overload the cap guards
against) followed by a normal release leaves the semaphore at 33, and
the cap is raised for the rest of the process.

On macOS this drift is masked by RT-06 (sem_open never succeeds, so
there is no cap at all); the repro detects that and says so. With the
RT-06 fix applied it reproduces on macOS too (observed: 33 slots).

Minimal fix: fail closed. _pool_try_acquire returns False when sem_open
fails, so a True result always means the semaphore was decremented and
every _pool_release is matched (the Lean model proves the count then
stays in [0, 32]). This needs RT-06 fixed first, or every pool call on
macOS would be refused. Flip check (RT-06 fix + this fix): OK, 32 slots.

On Linux RT-08 masks it the same way from the other side: a failed
sem_open returns NULL there, which the `== -1` test misses, so the
process crashes instead of failing open. With the RT-08 fix applied it
reproduces on Linux (observed: 33 slots).

The fault is injected in a forked child (its own semaphore, since the
name carries the pid), which restores the default SIGSEGV action so a
crash shows as a signal, and reports 100 + the slots it could hold as
its exit status.
"""

from std.ffi import external_call, c_int
from std.memory import stack_allocation
from std.sys.info import CompilationTarget
from flare.utils import exit, fork
from flare.runtime.blocking import (
    MAX_POOL_SIZE,
    _pool_release,
    _pool_reset,
    _pool_try_acquire,
)


def _rlimit_nofile() -> c_int:
    comptime if CompilationTarget.is_macos():
        return c_int(8)
    else:
        return c_int(7)


def _child_held_after_fault() -> Int:
    """One acquire while sem_open fails, its paired release, then count."""
    _ = external_call["signal", Int](c_int(11), Int(0))  # SIG_DFL
    _pool_reset()
    # Lower the soft fd limit so the fd table can be filled quickly.
    var rl = stack_allocation[2, UInt64]()
    _ = external_call["getrlimit", c_int](_rlimit_nofile(), rl)
    var saved_soft = rl[unsafe_offset=0]
    rl[unsafe_offset=0] = UInt64(128)
    _ = external_call["setrlimit", c_int](_rlimit_nofile(), rl)
    var dups = List[c_int]()
    while len(dups) < 1000:
        var d = external_call["dup", c_int](c_int(0))
        if d < 0:
            break
        dups.append(d)
    var took = _pool_try_acquire()  # sem_open fails -> fail-open True
    for i in range(len(dups)):
        _ = external_call["close", c_int](dups[i])
    rl[unsafe_offset=0] = saved_soft
    _ = external_call["setrlimit", c_int](_rlimit_nofile(), rl)
    if took:
        _pool_release()  # paired release, sem_open works again
    var held = 0
    while held < MAX_POOL_SIZE + 8 and _pool_try_acquire():
        held += 1
    for _ in range(held):
        _pool_release()
    _pool_reset()
    return held


def main() raises:
    _pool_reset()
    var base = 0
    while base < MAX_POOL_SIZE + 8 and _pool_try_acquire():
        base += 1
    for _ in range(base):
        _pool_release()
    _pool_reset()
    if base > MAX_POOL_SIZE:
        print(
            "BUG REPRODUCED: no cap at all on this platform (",
            base,
            "slots before any fault injection; RT-06 masks RT-07)",
        )
        raise Error("RT-07")
    var pid = fork()
    if pid < 0:
        print("inconclusive: fork failed")
        raise Error("RT-07")
    if pid == 0:
        exit(100 + _child_held_after_fault())
    var status = stack_allocation[1, c_int]()
    status[0] = c_int(0)
    _ = external_call["waitpid", c_int](
        c_int(pid), Int(status), c_int(0)
    )
    var sig = Int(status[0] & 0x7F)
    var code = Int((status[0] >> 8) & 0xFF)
    if sig == 11:
        print(
            "BUG REPRODUCED: the failed sem_open crashed the process"
            " (SIGSEGV) before the fail-open branch; RT-08 masks RT-07"
        )
        raise Error("RT-07")
    if sig != 0 or code < 100:
        print("inconclusive: child ended with signal", sig, "exit", code)
        raise Error("RT-07")
    var held = code - 100
    if held > MAX_POOL_SIZE:
        print(
            "BUG REPRODUCED: after one fail-open acquire/release pair,",
            held,
            "pool slots could be held at once (cap is",
            MAX_POOL_SIZE,
            ")",
        )
        raise Error("RT-07")
    print("OK: at most", held, "slots held (cap", MAX_POOL_SIZE, ")")
