# PLATFORM: any
"""CONC-01: watchdog_arm stores a non-positive deadline unchecked; a
deadline of -1 is the FIRING sentinel and wedges the slot forever.

Lean: Flare.Bugs.CONC_01.arm_firing_sentinel (a run of the impl that
arms the slot with -1), Flare.Bugs.CONC_01.stuck_closed (from that state
every step keeps the slot at FIRING and the worker inside disarm, so
disarm never returns), and Flare.L5.Watchdog.fixed_safe (clamped,
disarm-first arm meets the spec for every budget).
flare/runtime/watchdog.mojo:107 (`deadline = monotonic_now_ms() +
budget_ms`, no range check) @59bda50; the sentinel at :46, the poller's
`d > 0` guard at :161-165, the settle loop at :81-87.

Expected: arm(slot, budget_ms, cell) with a budget that is already spent
(budget_ms <= 0) flips the cell at the next poll, and disarm returns.
Actual: deadline = now + budget_ms is stored as is. With
budget_ms = -(now + 1) the slot holds -1 == _FIRING: the poller skips it
(d > 0 fails), and every later arm/disarm spins in _settle forever. With
budget_ms <= -now the deadline is <= 0 and the expired budget never
fires (0 even reads as "disarmed").

Minimal fix: clamp the deadline to at least 1 in watchdog_arm
(`if deadline < 1: deadline = 1`).
"""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc

from flare.runtime._libc_time import libc_nanosleep_ms, monotonic_now_ms
from flare.runtime.watchdog import (
    DeadlineWatchdog,
    _atomic_load,
    _slot_deadline_idx,
)


def _cell_get(addr: Int) -> Int64:
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](
        p.unsafe_bitcast[Scalar[DType.int64]]()
    )


def main() raises:
    var wd = DeadlineWatchdog(poll_ms=1)
    var cp = alloc(Layout[Int64](count=1)).unsafe_leak()
    cp[unsafe_offset=0] = 0
    var cell = Int(cp)
    # The clock can tick between reading it and arm reading it: retry.
    for _ in range(50):
        cp[unsafe_offset=0] = 0
        var now = monotonic_now_ms()
        wd.arm(0, -(now + 1), cell)
        var v = _atomic_load(wd._block, _slot_deadline_idx(0))
        if v == -1:
            _ = libc_nanosleep_ms(50)  # 50 polls
            var v2 = _atomic_load(wd._block, _slot_deadline_idx(0))
            if v2 == -1 and _cell_get(cell) == 0:
                print(
                    "BUG REPRODUCED: arm with an expired budget left slot 0 at",
                    "the FIRING sentinel (-1) after 50 polls; the cell was",
                    "never flipped and disarm(0) would spin forever",
                )
                raise Error("CONC-01")
        # Not the sentinel this round: let the poller act, then clear it.
        _ = libc_nanosleep_ms(5)
        if v != -1:
            _ = wd.disarm(0)
    _ = libc_nanosleep_ms(5)
    if _cell_get(cell) == 0:
        print("BUG REPRODUCED: an expired budget never flipped the cell")
        raise Error("CONC-01")
    _ = wd.disarm(0)
    wd.stop()
    print("OK: arm with an expired budget fires at the next poll")
