# PLATFORM: macos
# RESOLVED: RT-06 fixed on fix/formal-findings
"""RT-06: the MAX_POOL_SIZE thread cap is never enforced on macOS arm64.

Lean: Flare.Bugs.RT_06.persistentFailOpen_unbounded (counterexample) and
Flare.L2.Blocking.paired_cap_invariant (the cap holds once
sem_open works).
flare/runtime/blocking.mojo:177-206 @59bda50.

Expected: at most MAX_POOL_SIZE (32) pool slots can be held at once, so
block_in_pool / resolve_async refuse the 33rd concurrent call.
Before the fix: _pool_try_acquire calls the variadic sem_open(name, O_CREAT,
mode, value) through external_call. On Apple arm64 variadic arguments go
on the stack, external_call passes them in registers, sem_open reads a
garbage initial value and fails with EINVAL every time (observed: errno
22 on every call). The function is fail-open, so every acquire returns
True and the cap does not exist: this repro holds 40 slots.

Minimal fix (verified by the flip check): on macOS, call sem_open with
six dummy register arguments so mode and value land in the first two
8-byte stack slots, where the variadic callee reads them (the same ABI
issue flare already works around for fcntl in tcp/stream.mojo).
"""

from flare.runtime.blocking import (
    MAX_POOL_SIZE,
    _pool_release,
    _pool_reset,
    _pool_try_acquire,
)


def main() raises:
    _pool_reset()
    var held = 0
    while held < MAX_POOL_SIZE + 8 and _pool_try_acquire():
        held += 1
    for _ in range(held):
        _pool_release()
    _pool_reset()
    if held > MAX_POOL_SIZE:
        print(
            "BUG REPRODUCED:",
            held,
            "pool slots acquired at once; the cap is",
            MAX_POOL_SIZE,
        )
        raise Error("RT-06")
    print("OK: cap enforced,", held, "slots acquired (cap", MAX_POOL_SIZE, ")")
