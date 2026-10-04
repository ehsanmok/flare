# PLATFORM: linux
"""RT-03: UringReactor.poll can enter its blocking phase with no wakeup
read armed, so a cross-thread wakeup() is not honoured.

Lean: Flare.Bugs.RT_03.poll_blocks_unarmed (counterexample) and
Flare.Bugs.RT_03.pollFixed_never_blocks_unarmed (fix meets spec).
flare/runtime/uring_reactor.mojo:739-846,926-946 @59bda50.

Expected: whenever poll() may block in phase 3 (submit_and_wait(need)),
the eventfd read that turns wakeup() into a CQE is armed, so wakeup()
always releases a blocked poll.
Actual: poll() tries to arm the read before phase 1. If the SQ is full,
_arm_wakeup_recv raises, the exception is swallowed (:799-804) and
_wake_armed stays False. Phase 1 then flushes the SQ (freeing every
slot) but nothing retries the arm, so phase 3 blocks with no read on
the eventfd: a wakeup() from another thread only bumps the eventfd
counter and the poll sleeps until some unrelated CQE arrives.

Run on Linux (repro/linux.sh: a native-arch container with seccomp
unconfined, since Docker's default profile blocks io_uring_setup). Without
io_uring it stops as inconclusive instead of claiming OK. The check is
deterministic and single-threaded:
fill the SQ, call poll(0) (which never blocks), and observe that
_wake_armed is still False after phase 1 freed the SQ. A poll(1) in
the same situation is the one that blocks unarmed.

Minimal fix: after phase 1, if cross-thread wakeup is enabled and
_wake_armed is False, call _arm_wakeup_recv() again (the SQ has room
now) and set _wake_armed = True before phase 3; phase 3's
submit_and_wait(need) then submits the read.
"""

from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.io_uring_sqe import prep_nop
from flare.runtime.uring_reactor import UringCompletion, UringReactor


def main() raises:
    if not is_io_uring_available():
        print("inconclusive: io_uring not available on this host")
        raise Error("RT-03 inconclusive")
    var r = UringReactor(8)
    var filled = 0
    while True:
        var slot = r._driver.next_sqe()
        if Int(slot) == 0:
            break
        prep_nop(slot, UInt64(1000 + filled))
        r._driver.commit_sqe()
        filled += 1
    var out = List[UringCompletion]()
    _ = r.poll(0, out)
    if not r._wake_armed:
        print(
            "BUG REPRODUCED: after poll() flushed a full SQ (",
            filled,
            "SQEs) no wakeup read is armed; a poll(1) here would block"
            " with wakeup() unable to release it",
        )
        raise Error("RT-03")
    print("OK: wakeup read re-armed after the SQ was flushed")
