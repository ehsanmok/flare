"""Setup-flag probe for the io_uring buffer-ring server loop.

Split out of ``_server_reactor_uring.mojo`` to keep that module within the
file-size budget; pure code motion.
"""

from flare.runtime.io_uring import IoUringRing
from flare.runtime.io_uring_sqe import (
    IORING_SETUP_COOP_TASKRUN,
    IORING_SETUP_TASKRUN_FLAG,
    IORING_SETUP_SUBMIT_ALL,
    IORING_SETUP_SINGLE_ISSUER,
    IORING_SETUP_DEFER_TASKRUN,
)


def _probe_bufring_setup_flags(entries: Int = 64) -> UInt32:
    """Probe the host kernel for the best ``IORING_SETUP_*``
    flag mask the bufring dispatch can use.

    The bufring dispatch's throughput is sensitive to how the
    kernel runs task work relative to the dispatch loop's
    CQE-drain rhythm. The kernel scheduler hints introduced in
    5.19 (COOP_TASKRUN + TASKRUN_FLAG + SUBMIT_ALL) and 6.0/6.1
    (SINGLE_ISSUER + DEFER_TASKRUN) batch task work to enter
    boundaries instead of running it IPI-style mid-syscall.

    Probes from highest-impact-first to default:
    1. SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN |
       TASKRUN_FLAG | SUBMIT_ALL  (>= 6.1, the optimal mix)
    2. COOP_TASKRUN | TASKRUN_FLAG | SUBMIT_ALL  (>= 5.19)
    3. SUBMIT_ALL  (>= 5.18)
    4. 0 (default; works on any 5.1+ kernel)

    Returns the first mask the kernel accepts via a no-op
    ``IoUringRing(entries)`` setup; closes the probe ring
    immediately. Called once per worker at bufring loop init.

    Args:
        entries: SQE count for the probe ring; tiny so the
            probe is cheap. Defaults to 64.

    Returns:
        Best-fit setup_flags mask, or 0 if no flag combination
        is accepted (kernel < 5.18 or io_uring unavailable).
    """

    # Probe order: COOP_TASKRUN + TASKRUN_FLAG + SUBMIT_ALL
    # FIRST (5.19+ reliable). DEFER_TASKRUN + SINGLE_ISSUER
    # (6.1+) are tried LAST because they require GETEVENTS-on-
    # every-enter (which we honour in submit_and_wait), but
    # under load the kernel still throttles multishot recv CQE
    # delivery in unpredictable ways with DEFER_TASKRUN. Empirical
    # observation on dev-box (kernel 6.8): bufring throughput is
    # ~60 Hz with DEFER_TASKRUN and significantly higher without.
    # If a future kernel version fixes this, swap the order.
    var t1 = (
        IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_TASKRUN_FLAG
        | IORING_SETUP_SUBMIT_ALL
    )
    var t2 = IORING_SETUP_SUBMIT_ALL
    var t3 = (
        IORING_SETUP_SINGLE_ISSUER
        | IORING_SETUP_DEFER_TASKRUN
        | IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_TASKRUN_FLAG
        | IORING_SETUP_SUBMIT_ALL
    )

    var candidates = [t1, t2, t3]
    for i in range(len(candidates)):
        try:
            var probe = IoUringRing(entries, setup_flags=candidates[i])
            _ = probe^
            return candidates[i]
        except:
            pass
    return UInt32(0)
