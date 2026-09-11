"""Cross-thread stop flag and per-worker stats cell.

Shared by ``scheduler.mojo`` (which allocates and reads them) and
``_worker.mojo`` (which writes them), so they live here rather than in
either -- importing one from the other would be a cycle.

``scheduler.mojo`` re-exports every name below, so the existing
``from flare.runtime.scheduler import load_stop_flag`` call sites in
the reactor loops keep working unchanged.
"""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer


# ── Atomic stop-flag helpers ─────────────────────────────────────────────────
# The stopping flag is a heap-allocated byte written by the main
# thread and read by every worker. Release-store / acquire-load pair
# gives the workers a proper happens-before edge on shutdown; lowers
# to a plain ``mov`` on x86-64 (TSO) and to ``stlr`` / ``ldar`` on
# ARM64. Callers pass the raw heap address (the same ``Int`` the
# worker ctx carries) so the flag stays valid across struct moves.


@always_inline
def store_stop_flag(addr: Int, value: Bool):
    """Release-store ``value`` into the heap stop-flag byte at ``addr``."""
    if addr == 0:
        return
    var p = Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[Scalar[DType.uint8]]()
    Atomic[DType.uint8].store[ordering=Ordering.RELEASE](
        p, UInt8(1) if value else UInt8(0)
    )


@always_inline
def load_stop_flag(addr: Int) -> Bool:
    """Acquire-load the heap stop-flag byte at ``addr``."""
    if addr == 0:
        return False
    var p = Pointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=addr
    ).unsafe_bitcast[Scalar[DType.uint8]]()
    return Atomic[DType.uint8].load[ordering=Ordering.ACQUIRE](p) != UInt8(0)


# ── Per-worker stats cell (D6 drain accounting + D9 crash visibility) ─────────
# Each worker owns a heap cell of two ``Int64`` slots the worker writes
# and the scheduler (main thread) reads. Slot 0 is the live-connection
# snapshot (updated each reactor iteration); slot 1 is the exit status.
# Release-store / acquire-load makes the worker's writes visible to the
# scheduler after it joins the worker. A ``base_addr`` of 0 disables the
# writes (single-worker / non-scheduler paths pay nothing).

comptime WORKER_STAT_INFLIGHT: Int = 0
"""Slot index: connections still registered on this worker."""
comptime WORKER_STAT_STATUS: Int = 1
"""Slot index: worker exit status (see ``WORKER_STATUS_*``)."""
comptime WORKER_STAT_SLOTS: Int = 2
"""Number of Int64 slots per worker cell."""

comptime WORKER_STATUS_RUNNING: Int = 0
"""Worker has not exited its serve loop yet."""
comptime WORKER_STATUS_CLEAN: Int = 1
"""Worker exited because it observed the stop flag (normal shutdown)."""
comptime WORKER_STATUS_CRASHED: Int = 2
"""Worker exited because its reactor poll failed (unexpected)."""


@always_inline
def store_worker_stat(base_addr: Int, slot: Int, value: Int):
    """Release-store ``value`` into ``slot`` of the worker stats cell."""
    if base_addr == 0:
        return
    var p = Pointer[Int, MutUntrackedOrigin](
        unsafe_from_address=base_addr + slot * 8
    ).unsafe_bitcast[Scalar[DType.int64]]()
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](p, Int64(value))


@always_inline
def load_worker_stat(base_addr: Int, slot: Int) -> Int:
    """Acquire-load ``slot`` of the worker stats cell (0 when disabled)."""
    if base_addr == 0:
        return 0
    var p = Pointer[Int, MutUntrackedOrigin](
        unsafe_from_address=base_addr + slot * 8
    ).unsafe_bitcast[Scalar[DType.int64]]()
    return Int(Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](p))
