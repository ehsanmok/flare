# PLATFORM: linux
# RESOLVED: RT-08 fixed on fix/formal-findings
"""RT-08: a failed sem_open crashes the process on Linux.

Lean: Flare.Bugs.RT_08.linux_failure_crashes (counterexample) and
Flare.Bugs.RT_08.never_crashes (shipped code meets spec).
flare/runtime/blocking.mojo:185-206 @59bda50.

Expected: when the pool semaphore cannot be opened the call returns
instead of crashing (RT-07 later made it refuse the slot: False).
Before the fix: _pool_try_acquire and _pool_release test `Int(sem) == -1`, which
is Darwin's SEM_FAILED. glibc's SEM_FAILED is NULL, so on Linux a failed
sem_open (here EMFILE: the fd table is full) passes the check and NULL
goes to sem_trywait, which faults. The process dies with SIGSEGV.

The fault is injected in a forked child, which restores the default
SIGSEGV action first (the Mojo runtime's crash handler would otherwise
turn the signal into exit(1)) and reports through its exit status:
10 = acquire returned False, 11 = returned True, 12 = the fd table could
not be filled.

Minimal fix: compare against the platform's SEM_FAILED (0 on Linux, -1 on
macOS), or treat both 0 and -1 as failure, in both functions. Flip check:
OK, the acquire returned (False since RT-07) and the child exited normally.
"""

from std.ffi import external_call, c_int
from std.memory import stack_allocation
from flare.runtime.blocking import _pool_reset, _pool_try_acquire
from flare.utils import exit, fork

comptime SIGSEGV = 11
comptime RLIMIT_NOFILE_LINUX = 7


def _child() -> Int:
    _ = external_call["signal", Int](c_int(SIGSEGV), Int(0))  # SIG_DFL
    _pool_reset()
    var rl = stack_allocation[2, UInt64]()
    _ = external_call["getrlimit", c_int](c_int(RLIMIT_NOFILE_LINUX), rl)
    rl[unsafe_offset=0] = UInt64(128)
    _ = external_call["setrlimit", c_int](c_int(RLIMIT_NOFILE_LINUX), rl)
    var full = False
    for _ in range(1000):
        if external_call["dup", c_int](c_int(0)) < 0:
            full = True
            break
    if not full:
        return 12
    var took = _pool_try_acquire()
    return 11 if took else 10


def main() raises:
    var pid = fork()
    if pid < 0:
        print("inconclusive: fork failed")
        raise Error("RT-08")
    if pid == 0:
        exit(_child())
    var status = stack_allocation[1, c_int]()
    status[0] = c_int(0)
    _ = external_call["waitpid", c_int](c_int(pid), Int(status), c_int(0))
    var sig = Int(status[0] & 0x7F)
    var code = Int((status[0] >> 8) & 0xFF)
    if sig == SIGSEGV:
        print(
            "BUG REPRODUCED: _pool_try_acquire with the fd table full"
            " (sem_open -> EMFILE, returns NULL) killed the process with"
            " SIGSEGV"
        )
        raise Error("RT-08")
    if sig != 0 or code < 10 or code > 12:
        print("inconclusive: child ended with signal", sig, "exit", code)
        raise Error("RT-08")
    if code == 12:
        print("inconclusive: could not fill the fd table")
        raise Error("RT-08")
    print(
        "OK: _pool_try_acquire returned",
        code == 11,
        "with sem_open failing; no crash",
    )
