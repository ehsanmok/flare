"""Example 36: cross-worker connection handoff.

Demonstrates the application-level work-stealing primitive flare's
multicore scheduler uses to even out load skew under
``SO_REUSEPORT``. The full reactor wiring runs across multiple
threads; for the example we drive the queue + policy in-process so
the lifecycle is visible in one file.

Run:
    pixi run example-work-stealing
"""

from os import setenv

from flare.runtime import HandoffPolicy, HandoffQueue, WorkerHandoffPool


def main() raises:
    print("=== flare Example 36: cross-worker handoff ===")
    print()

    # ── 1. Default policy is OFF (SO_REUSEPORT behaviour) ──
    print("── 1. Default HandoffPolicy ──")
    var p0 = HandoffPolicy()
    print(" enabled :", p0.enabled)
    print(" capacity :", p0.capacity)
    print(" steal_threshold :", p0.steal_threshold)
    print()

    # ── 2. Soak knob flips the policy on ──
    print("── 2. FLARE_SOAK_WORKERS=on flips it on ──")
    setenv("FLARE_SOAK_WORKERS", "on", True)
    var p1 = HandoffPolicy.from_env(HandoffPolicy())
    print(" enabled :", p1.enabled)
    print(" steal_threshold :", p1.steal_threshold)
    setenv("FLARE_SOAK_WORKERS", "", True)
    print()

    # ── 3. Bounded MPSC queue: push, pop, refused ──
    print("── 3. HandoffQueue mechanics ──")
    var q = HandoffQueue(4)
    print(
        " push 101..104 :",
        q.push(101),
        q.push(102),
        q.push(103),
        q.push(104),
    )
    print(" push 105 (full) :", q.push(105))
    print(" size :", q.size())
    print(" refused :", q.refused)

    var first = q.pop()
    print(" pop :", first.value())
    print(" size after pop :", q.size())

    var rest = q.drain()
    print(" drain returned :", len(rest), "fds")
    for i in range(len(rest)):
        print(" fd :", rest[i])
    print(" size after drain :", q.size())
    print()

    # ── 4. Wrap-around: FIFO is preserved ──
    print("── 4. Wrap-around preserves FIFO ──")
    var q2 = HandoffQueue(4)
    _ = q2.push(1)
    _ = q2.push(2)
    _ = q2.push(3)
    _ = q2.push(4)
    _ = q2.pop()
    _ = q2.pop()
    _ = q2.push(5)
    _ = q2.push(6)
    var order = q2.drain()
    print(" observed order :", order[0], order[1], order[2], order[3])
    print()

    # ── 5. Per-worker pool: peek the idlest peer, hand off, drain ──
    print()
    print("── 5. WorkerHandoffPool routing ──")
    var pool = WorkerHandoffPool(HandoffPolicy(True, 8, 4), 4)
    print(" size :", pool.size())
    _ = pool.try_handoff(0, 1001)
    _ = pool.try_handoff(0, 1002)
    _ = pool.try_handoff(2, 2001)
    print(" peek_idle from #2 :", pool.peek_idle_worker(2))
    var w0 = pool.drain_local(0)
    var w2 = pool.drain_local(2)
    print(" worker 0 drained :", len(w0), "entries")
    print(" worker 2 drained :", len(w2), "entries")
    print()

    print("=== Example 36 complete ===")
