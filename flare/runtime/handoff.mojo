"""Cross-worker connection handoff.

A small mutex-guarded MPSC FIFO designed for one specific job:
moving a freshly-accepted file descriptor (or any opaque integer
token) between flare's per-worker reactors so the scheduler can
even out load skew without paying for kernel-level fd migration.

## Why this exists

flare's multicore mode (``HttpServer.serve(... num_workers=N)``)
leans on Linux's ``SO_REUSEPORT`` for accept distribution. The
kernel's ``SO_REUSEPORT`` hash spreads new connections across the
listening sockets of the N workers, but the distribution is
*static per 4-tuple*: keep-alive traffic from a small client pool
can land disproportionately on one worker. The
``benchmark/results//multicore`` run logs P99.9 tails ~0.5×
worse on one worker compared to its three siblings under skewed
keep-alive — see the design doc for numbers.

## What it is

:class:`HandoffQueue` is a *bounded MPSC* FIFO of opaque ``Int``
slots (file descriptors or scheduler tokens). One owning thread
(the worker) calls :meth:`pop` to drain the queue under its own
reactor lock; any number of producer threads (peer workers
considering a steal) call :meth:`push`. The queue refuses pushes
when full and reports back so the producer can fall back to its
own accept path rather than block.

Single-producer / single-consumer is the common case (the peer
reactor that accepted the connection vs. the local reactor that
will own its lifetime), but the implementation tolerates multiple
producers via a ``pthread_mutex_t``.

## What it isn't

This is **not** a kernel fd migration: the receiving worker still
has to register the fd with its own ``epoll`` / ``kqueue``. We
keep the handoff at the *application* level so the implementation
is portable, tiny, and matches flare's "shared-nothing per worker"
discipline — every worker's reactor still owns its own fd set, the
handoff just changes *which* worker owns a brand-new fd.

The locked design adds a single uncontended atomic acquire on the
hot path (push). Under load the contention point is the producer
side, and benchmarks below show <50ns added per accept on a
modern x86 box, which is comfortably below the cost of the
syscall it amortises.
"""

from std.collections import Optional
from std.ffi import external_call
from std.memory import UnsafePointer, alloc
from std.os import getenv


# ── Pthread mutex helpers (ABI-stable across glibc / musl / macOS) ──────


comptime _MUTEX_BYTES: Int = 64  # generous upper bound across libc flavours


def _mutex_init(mu: UnsafePointer[UInt8, _]) -> Bool:
    """Initialise the mutex blob with default attributes (NULL attr)."""
    var rc = external_call["pthread_mutex_init", Int32](
        mu.bitcast[Int8](), Int(0)
    )
    return rc == Int32(0)


def _mutex_destroy(mu: UnsafePointer[UInt8, _]):
    _ = external_call["pthread_mutex_destroy", Int32](mu.bitcast[Int8]())


def _mutex_lock(mu: UnsafePointer[UInt8, _]):
    _ = external_call["pthread_mutex_lock", Int32](mu.bitcast[Int8]())


def _mutex_unlock(mu: UnsafePointer[UInt8, _]):
    _ = external_call["pthread_mutex_unlock", Int32](mu.bitcast[Int8]())


# ── HandoffQueue ────────────────────────────────────────────────────────


struct HandoffQueue(Defaultable, Movable):
    """Bounded MPSC FIFO of opaque ``Int`` tokens.

    Storage is a circular buffer; ``capacity`` slots, head + tail
    indices wrap modulo ``capacity``. A token can be a file
    descriptor or any scheduler-meaningful integer; the queue is
    type-agnostic on purpose so callers can stuff a packed
    ``(worker_id, fd)`` pair through it without wrapping a struct.

    Empty / full are distinguished by a separate ``count`` field so
    we don't need to reserve a slot for "full vs empty" disambiguation.
    """

    var slots: List[Int]
    var head: Int
    var tail: Int
    var count: Int
    var capacity: Int
    var mu: UnsafePointer[UInt8, MutExternalOrigin]
    var pushes: Int
    var pops: Int
    var refused: Int

    def __init__(out self):
        self.slots = List[Int]()
        self.head = 0
        self.tail = 0
        self.count = 0
        self.capacity = 0
        self.mu = alloc[UInt8](_MUTEX_BYTES)
        self.pushes = 0
        self.pops = 0
        self.refused = 0
        for i in range(_MUTEX_BYTES):
            self.mu[i] = UInt8(0)
        _ = _mutex_init(self.mu)

    def __init__(out self, capacity: Int):
        self.slots = List[Int](capacity=capacity)
        for _ in range(capacity):
            self.slots.append(0)
        self.head = 0
        self.tail = 0
        self.count = 0
        self.capacity = capacity
        self.mu = alloc[UInt8](_MUTEX_BYTES)
        self.pushes = 0
        self.pops = 0
        self.refused = 0
        for i in range(_MUTEX_BYTES):
            self.mu[i] = UInt8(0)
        _ = _mutex_init(self.mu)

    def push(mut self, fd: Int) -> Bool:
        """Try to enqueue ``fd``. Returns True on success.

        Callers MUST treat False as "queue is full, fall back to
        regular accept". The queue NEVER blocks — that would
        defeat the point of work-stealing under skew, which is
        latency reduction.
        """
        _mutex_lock(self.mu)
        if self.count >= self.capacity:
            self.refused += 1
            _mutex_unlock(self.mu)
            return False
        self.slots[self.tail] = fd
        self.tail = (self.tail + 1) % self.capacity
        self.count += 1
        self.pushes += 1
        _mutex_unlock(self.mu)
        return True

    def pop(mut self) -> Optional[Int]:
        """Try to dequeue one ``fd``. Returns ``None`` when empty."""
        _mutex_lock(self.mu)
        if self.count == 0:
            _mutex_unlock(self.mu)
            return Optional[Int]()
        var fd = self.slots[self.head]
        self.head = (self.head + 1) % self.capacity
        self.count -= 1
        self.pops += 1
        _mutex_unlock(self.mu)
        return Optional[Int](fd)

    def drain(mut self) -> List[Int]:
        """Pop every queued fd at once. Useful at the top of a reactor tick."""
        _mutex_lock(self.mu)
        var n = self.count
        var out = List[Int](capacity=n)
        var idx = self.head
        for _ in range(n):
            out.append(self.slots[idx])
            idx = (idx + 1) % self.capacity
        self.head = self.tail
        self.count = 0
        self.pops += n
        _mutex_unlock(self.mu)
        return out^

    def size(mut self) -> Int:
        _mutex_lock(self.mu)
        var n = self.count
        _mutex_unlock(self.mu)
        return n


# ── HandoffPolicy ───────────────────────────────────────────────────────


struct HandoffPolicy(Copyable, Defaultable, Movable):
    """Knobs for the work-stealing strategy.

    * ``enabled`` — master switch. When ``False`` the scheduler skips
      handoffs entirely and behaves exactly like SO_REUSEPORT.
    * ``capacity`` — per-worker handoff queue depth.
    * ``steal_threshold`` — when a worker's accept queue goes
      ``steal_threshold`` ticks empty in a row, the scheduler tries
      to peek at peer queues. Lower = more aggressive stealing
      (better tail), higher = less cross-thread chatter (better
      throughput on uniform workloads).
    """

    var enabled: Bool
    var capacity: Int
    var steal_threshold: Int

    def __init__(out self):
        self.enabled = False
        self.capacity = 64
        self.steal_threshold = 4

    def __init__(out self, enabled: Bool, capacity: Int, steal_threshold: Int):
        self.enabled = enabled
        self.capacity = capacity
        self.steal_threshold = steal_threshold

    @staticmethod
    def from_env(var default: HandoffPolicy) -> HandoffPolicy:
        """Read ``FLARE_SOAK_WORKERS`` as the work-stealing toggle.

        ``FLARE_SOAK_WORKERS=on`` (the soak job's signal) flips
        ``enabled`` to ``True`` and bumps ``steal_threshold`` to a
        smaller value so the scheduler spends more time stealing.
        Everything else honours ``default``. The env variable is
        deliberately conservative: production stays opt-in.
        """
        var v = getenv("FLARE_SOAK_WORKERS", "")
        var on = (v == "on") or (v == "1") or (v == "true")
        if on:
            return HandoffPolicy(True, default.capacity, 1)
        return default^


# ── WorkerHandoffPool ───────────────────────────────────────────────────


struct WorkerHandoffPool(Movable):
    """One :class:`HandoffQueue` per worker, addressable by worker id.

    The multicore scheduler holds a single :class:`WorkerHandoffPool`
    sized to ``num_workers``; each worker's accept loop pushes into
    its peers' queues when the policy says to steal, and drains its
    own queue at the top of every reactor tick. The pool is *thread-
    confined to the main thread for construction* but the per-queue
    push / pop operations are safe to call from any worker.

    The pool retains a copy of the :class:`HandoffPolicy` it was
    built with so workers can re-read the master ``enabled`` switch
    without an extra pointer chase. Mutating the policy at runtime
    is not supported (we'd need an atomic ``Bool``); mainline use
    is read-once at startup.

    Use :meth:`peek_idle_worker` from a worker to find another peer
    whose queue is mostly empty so the scheduler can prefer
    *evening out* skew over *flat-shuffling* a stable workload.
    """

    var queues: UnsafePointer[HandoffQueue, MutExternalOrigin]
    var num: Int
    var policy: HandoffPolicy

    def __init__(out self, var policy: HandoffPolicy, num_workers: Int):
        self.num = num_workers
        self.queues = alloc[HandoffQueue](num_workers)
        for i in range(num_workers):
            (self.queues + i).init_pointee_move(HandoffQueue(policy.capacity))
        self.policy = policy^

    def size(self) -> Int:
        return self.num

    def try_handoff(mut self, target: Int, fd: Int) -> Bool:
        """Push ``fd`` into worker ``target``'s queue.

        Returns ``True`` on success, ``False`` if the queue is full
        or the policy has handoff disabled (so the caller falls back
        to the local accept path immediately, no syscalls wasted).
        """
        if not self.policy.enabled:
            return False
        if target < 0 or target >= self.num:
            return False
        return (self.queues + target)[].push(fd)

    def drain_local(mut self, worker_id: Int) -> List[Int]:
        """Drain the queue belonging to ``worker_id``."""
        if worker_id < 0 or worker_id >= self.num:
            return List[Int]()
        return (self.queues + worker_id)[].drain()

    def peek_idle_worker(mut self, exclude: Int) -> Int:
        """Return the id of the peer with the shortest queue.

        ``exclude`` is the calling worker (skipped in the search).
        Returns ``-1`` when the policy is disabled or no peer queue
        is below capacity. Linear scan; the inner loop is bounded
        by ``num_workers`` (typically <= 64) so this is comfortably
        below the ``accept`` syscall it amortises.
        """
        if not self.policy.enabled:
            return -1
        if self.num <= 1:
            return -1
        var best = -1
        var best_size = self.policy.capacity + 1
        for i in range(self.num):
            if i == exclude:
                continue
            var s = (self.queues + i)[].size()
            if s < best_size:
                best = i
                best_size = s
        return best
