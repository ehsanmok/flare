# PLATFORM: any
"""CONC-02: arm on a slot that is still armed lets the poller fire the
OLD deadline into the NEW request's cancel cell.

Lean: Flare.Bugs.CONC_02.rearm_hits_new_cell (explicit interleaving of
the impl: arm(cellA, expired) ; arm(cellB, 60 s) stores cellB's address
; poller claims the old deadline and writes TIMEOUT into cellB) and
Flare.L5.Watchdog.fixed_safe (disarm-first arm is safe even when callers
re-arm without disarm).
flare/runtime/watchdog.mojo:98-111 @59bda50 (address stored at :106
before the deadline CAS at :110; the poller reads the address after its
claim at :164-166).

Latent: no caller in flare/ re-arms a still-armed slot (the watchdog has
no production call site at 59bda50; tests/runtime/test_watchdog.mojo
re-arms only after the fire has completed, which is safe). The arm
docstring does not state the "disarm first" precondition.

Expected: arm(slot, 60_000, cellB) never cancels cellB before 60 s.
Actual: between arm's address store and its deadline CAS the slot still
holds the previous, expired deadline; the poller claims it, loads the
new address and writes TIMEOUT into cellB.

Nondeterministic: this drives the real arm against the real poller
thread in a loop (the window cannot be entered from one thread because
the poll loop is not callable one iteration at a time). The loop runs
until the race is seen or 4 s pass; a run that never sees it prints OK,
so OK from this file is evidence, not proof, of a fix.

Minimal fix: begin watchdog_arm with the disarm loop (CAS the current
deadline to 0, waiting out FIRING) before storing the new address, then
CAS 0 -> deadline.
"""

from std.atomic import Atomic, Ordering
from std.memory import Layout, Pointer, alloc

from flare.runtime._libc_time import monotonic_now_ms
from flare.runtime.watchdog import DeadlineWatchdog


def _get(addr: Int) -> Int64:
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    return Atomic[Int64].load[ordering=Ordering.ACQUIRE](
        p.unsafe_bitcast[Scalar[DType.int64]]()
    )


def _set(addr: Int, v: Int64):
    var p = Pointer[Int64, MutUntrackedOrigin](unsafe_from_address=addr)
    Atomic[Int64].store[ordering=Ordering.RELEASE](
        p.unsafe_bitcast[Scalar[DType.int64]](), v
    )


def main() raises:
    var wd = DeadlineWatchdog(poll_ms=1)
    var cp = alloc(Layout[Int64](count=2)).unsafe_leak()
    var cell_a = Int(cp)
    var cell_b = cell_a + 8
    var t0 = monotonic_now_ms()
    var rounds = 0
    while monotonic_now_ms() - t0 < 4000:
        rounds += 1
        _set(cell_a, 0)
        _set(cell_b, 0)
        wd.arm(0, -1, cell_a)  # request A: deadline already passed
        wd.arm(0, 60_000, cell_b)  # request B, without disarming A
        var fired_b = wd.disarm(0)
        if _get(cell_b) != 0:
            print(
                "BUG REPRODUCED: re-arming a still-armed slot cancelled the",
                "new request's cell (60 s budget) in round",
                rounds,
                "; disarm reported fired =",
                fired_b,
            )
            raise Error("CONC-02")
    wd.stop()
    print("OK: no stale fire hit the new cell in", rounds, "rounds")
