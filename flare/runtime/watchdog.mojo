"""Deadline watchdog: a background thread that flips Cancel cells on expiry.

Mojo cannot preempt synchronous code -- a handler that never yields
runs to completion on its worker no matter what. The reactor can only
observe a deadline at the points it owns (request-read edges, streaming
writable edges). To give a *time-based* deadline any teeth against a
handler that at least cooperatively polls its ``Cancel`` token, a
separate OS thread must watch the clock and flip the cell; the worker
thread is busy inside the handler and cannot watch its own deadline.

That is exactly what :struct:`DeadlineWatchdog` does (the K2 mechanism
the assessment names): one background thread polls a fixed table of
``(deadline_ms, cancel_cell_addr)`` slots and, when a slot's deadline
passes, writes ``CancelReason.TIMEOUT`` into that cell with a release
store -- the same cell + ordering :struct:`flare.http.cancel.CancelCell`
uses, so a ``CancelHandler`` polling ``cancel.cancelled()`` observes it.

This is cooperative, not true preemption: a handler that never checks
its cancel token is still not interruptible (a Mojo language limit, not
a design choice) -- for those, ``PostHocDeadline`` still refuses the
too-late response. What the watchdog adds is real mid-flight
cancellation for handlers that *do* cooperate, which the on-worker
reactor cannot deliver by itself.
"""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer, alloc

from ._libc_time import libc_nanosleep_ms, monotonic_now_ms
from ._thread import ThreadHandle, _OpaquePtr


comptime WATCHDOG_MAX_SLOTS: Int = 256
"""Deadline slots (one per worker; matches the scheduler worker cap)."""

# Control-block layout (a flat Int64 array):
#   [0]           running flag (1 = run, 0 = stop)
#   [1]           poll interval (ms)
#   [2 + 2*i]     slot i deadline (monotonic ms; 0 = disarmed)
#   [3 + 2*i]     slot i cancel-cell address (0 = none)
comptime _IDX_RUNNING: Int = 0
comptime _IDX_POLL_MS: Int = 1
comptime _BLOCK_LEN: Int = 2 + 2 * WATCHDOG_MAX_SLOTS
comptime _TIMEOUT_REASON: Int64 = 2  # CancelReason.TIMEOUT


@always_inline
def _slot_deadline_idx(slot: Int) -> Int:
    return 2 + 2 * slot


@always_inline
def _slot_addr_idx(slot: Int) -> Int:
    return 3 + 2 * slot


@always_inline
def _atomic_load(block: Int, idx: Int) -> Int64:
    var p = UnsafePointer[Int64, MutUntrackedOrigin](unsafe_from_address=block)
    return Atomic[DType.int64].load[ordering=Ordering.ACQUIRE](
        (p + idx).bitcast[Scalar[DType.int64]]()
    )


@always_inline
def _atomic_store(block: Int, idx: Int, v: Int64):
    var p = UnsafePointer[Int64, MutUntrackedOrigin](unsafe_from_address=block)
    Atomic[DType.int64].store[ordering=Ordering.RELEASE](
        (p + idx).bitcast[Scalar[DType.int64]](), v
    )


def watchdog_arm(block: Int, slot: Int, budget_ms: Int, cancel_addr: Int):
    """Arm ``slot`` on the watchdog control block at ``block`` to flip
    the cell at ``cancel_addr`` after ``budget_ms``. Address is stored
    before the deadline so the poller never sees a deadline without its
    target."""
    if block == 0 or slot < 0 or slot >= WATCHDOG_MAX_SLOTS:
        return
    _atomic_store(block, _slot_addr_idx(slot), Int64(cancel_addr))
    _atomic_store(
        block, _slot_deadline_idx(slot), Int64(monotonic_now_ms() + budget_ms)
    )


def watchdog_disarm(block: Int, slot: Int):
    """Disarm ``slot`` (deadline -> 0). After this the poller will not
    fire the slot until it is re-armed. A poll already past its
    deadline check may still write once; the reactor resets the cancel
    cell between requests so a late write cannot bleed across."""
    if block == 0 or slot < 0 or slot >= WATCHDOG_MAX_SLOTS:
        return
    _atomic_store(block, _slot_deadline_idx(slot), 0)


def spawn_leaked_watchdog(poll_ms: Int = 1) raises -> Int:
    """Spawn a process-lifetime watchdog thread and return its control-
    block address. The thread + block are intentionally leaked (never
    stopped/freed) -- one background thread for the process life. Use
    the returned address with ``watchdog_arm`` / ``watchdog_disarm``."""
    var wd = DeadlineWatchdog(poll_ms)
    var block = wd._block
    # Drop ``wd`` without ``stop()``: no __del__ joins/frees, so the
    # thread keeps running and the block stays live for the process.
    return block


def _watchdog_main(arg: _OpaquePtr) -> _OpaquePtr:
    """Background-thread entry: poll the deadline table until stopped.

    Must not raise (pthread has no exception channel); every call
    inside is non-raising.
    """
    var block = Int(arg)
    while _atomic_load(block, _IDX_RUNNING) != 0:
        var now = Int64(monotonic_now_ms())
        for slot in range(WATCHDOG_MAX_SLOTS):
            var d = _atomic_load(block, _slot_deadline_idx(slot))
            if d != 0 and now >= d:
                var addr = _atomic_load(block, _slot_addr_idx(slot))
                if addr != 0:
                    # Flip the Cancel cell (release store of TIMEOUT).
                    var cp = UnsafePointer[Int64, MutUntrackedOrigin](
                        unsafe_from_address=Int(addr)
                    )
                    Atomic[DType.int64].store[ordering=Ordering.RELEASE](
                        cp.bitcast[Scalar[DType.int64]](), _TIMEOUT_REASON
                    )
                # Fire once: disarm the slot.
                _atomic_store(block, _slot_deadline_idx(slot), 0)
        var poll = Int(_atomic_load(block, _IDX_POLL_MS))
        if poll < 1:
            poll = 1
        _ = libc_nanosleep_ms(poll)
    return arg


struct DeadlineWatchdog(Movable):
    """One background thread enforcing per-slot deadlines.

    Arm a slot with ``arm(slot, budget_ms, cancel_addr)`` before running
    a cooperative handler and ``disarm(slot)`` after it returns; the
    watchdog flips the cell if the budget elapses first. ``stop()``
    halts and joins the thread. For a process-lifetime server watchdog,
    construct once and leak it (never ``stop``) -- one background thread
    for the process is negligible.
    """

    var _block: Int
    var _thread: ThreadHandle

    def __init__(out self, poll_ms: Int = 1) raises:
        """Allocate the control block and spawn the watchdog thread."""
        var raw = alloc[Int64](_BLOCK_LEN)
        for i in range(_BLOCK_LEN):
            (raw + i).init_pointee_copy(Int64(0))
        self._block = Int(raw)
        _atomic_store(
            self._block, _IDX_POLL_MS, Int64(poll_ms if poll_ms > 0 else 1)
        )
        _atomic_store(self._block, _IDX_RUNNING, Int64(1))
        var arg = _OpaquePtr(unsafe_from_address=self._block)
        self._thread = ThreadHandle.spawn[_watchdog_main](arg)

    def arm(self, slot: Int, budget_ms: Int, cancel_addr: Int):
        """Arm ``slot`` to flip the cell at ``cancel_addr`` in
        ``budget_ms`` from now."""
        watchdog_arm(self._block, slot, budget_ms, cancel_addr)

    def disarm(self, slot: Int):
        """Disarm ``slot`` (the handler finished within budget)."""
        watchdog_disarm(self._block, slot)

    def stop(mut self) raises:
        """Stop the watchdog thread, join it, and free the block."""
        if self._block == 0:
            return
        _atomic_store(self._block, _IDX_RUNNING, 0)
        self._thread.join()
        var p = UnsafePointer[Int64, MutUntrackedOrigin](
            unsafe_from_address=self._block
        )
        p.free()
        self._block = 0
