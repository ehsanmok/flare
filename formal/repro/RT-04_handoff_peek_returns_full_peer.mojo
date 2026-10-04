# PLATFORM: any
"""RT-04: WorkerHandoffPool.peek_idle_worker returns a peer whose queue is
full.

Lean: Flare.Bugs.RT_04.peek_returns_full_peer (counterexample) and
Flare.Bugs.RT_04.peekFixed_below_capacity (fix meets spec).
flare/runtime/handoff.mojo:312-334 @59bda50.

Expected (docstring): "Returns -1 when the policy is disabled or no peer
queue is below capacity."
Actual: the scan starts from best_size = capacity + 1 and keeps any peer
with size < best_size, so a peer whose queue holds exactly capacity
tokens is returned. choose_handoff_target then picks that peer and the
following try_handoff fails; the caller falls back to local accept, so
the effect is a wasted handoff attempt, not a lost connection.

Minimal fix: start the scan from best_size = capacity (only peers with
size < capacity qualify).
"""

from flare.runtime import HandoffPolicy, WorkerHandoffPool


def main() raises:
    var pool = WorkerHandoffPool(HandoffPolicy(True, 1, 1), 2)
    _ = pool.try_handoff(1, 42)  # worker 1's queue (capacity 1) is now full
    var peer = pool.peek_idle_worker(0)
    if peer != -1:
        print(
            "BUG REPRODUCED: peek_idle_worker returned worker",
            peer,
            "whose queue is full; try_handoff to it returns",
            pool.try_handoff(peer, 43),
        )
        raise Error("RT-04")
    print("OK: no peer below capacity, peek_idle_worker returned -1")
