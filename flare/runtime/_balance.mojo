"""Accept-time connection balancing across the workers of one scheduler.

Per-worker ``SO_REUSEPORT`` listeners let the kernel pick a worker for
each new connection by hashing the 4-tuple. That is cheap and has no
shared state, but it is random: with a few hundred long-lived
connections on four workers the busiest worker routinely ends up with
27-32 % of them instead of 25 %. A worker's CPU is what saturates, so
the busiest one sets the knee of the whole server: p99 jumps to tens of
milliseconds while the others still have headroom.

This module closes that gap without giving up the per-worker listeners.
Each worker publishes how many connections it holds. A worker that has
just accepted one while holding clearly more than the least-loaded peer
hands the new stream to that peer through a small inbox and wakes the
peer's reactor. Balanced traffic never takes the slow path: with loads
within the margin the accepting worker keeps the connection, exactly as
before.

State is one flat ``Int64`` block (the *group*), allocated by
``Scheduler.start`` and shared by every worker. Per worker it holds a
published load, a bounded ring of pending stream addresses guarded by a
spin lock, the reactor's wake fd and a ``live`` flag. Everything is read
and written through ``load_worker_stat`` / ``store_worker_stat``, so
there are no typed pointers to keep alive.

Hand-off protocol:

* A pusher takes the target's lock, checks ``live`` and room, appends the
  address and, when the inbox was empty, writes the target's wake fd
  before it releases the lock (the target closes its reactor only after
  it has cleared ``live`` under that lock, so the fd is still valid).
* The target clears ``live`` under the same lock when it stops, then
  drains the ring. After that no push can succeed, so no stream is left
  behind.
* A refused push (target gone or inbox full) leaves the stream with the
  caller, who keeps it locally.

The wake is ``eventfd_write(3)``, so the group only exists on Linux;
elsewhere ``balance_group_alloc`` returns 0 and every call is a no-op.
``FLARE_BALANCE_ACCEPT=0`` disables the group (``Scheduler.start``
skips allocating it) and every worker behaves as before.
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, external_call
from std.memory import Layout, Pointer, alloc
from std.sys.info import CompilationTarget

from flare.runtime.scheduler_stats import (
    WORKER_STAT_GROUP,
    WORKER_STAT_INDEX,
    load_worker_stat,
    store_worker_stat,
)


# ── Layout of the group block (all slots are Int64) ─────────────────────────

comptime _HEADER_SLOTS: Int = 8
"""Slot 0 of the group holds the worker count; the rest pads the header to
one cache line."""

comptime _INBOX_CAP: Int = 64
"""Streams that can wait in one worker's inbox. A push to a full inbox is
refused and the caller keeps the connection."""

# Slot offsets inside one worker's cell. LOAD sits alone on the first
# cache line: its owner stores it every loop iteration and every peer
# reads it, while the fields below are written by peers.
comptime _W_LOAD: Int = 0
comptime _W_PENDING: Int = 8
comptime _W_WAKE_FD: Int = 9
comptime _W_LIVE: Int = 10
comptime _W_LOCK: Int = 11
comptime _W_HEAD: Int = 12
comptime _W_RING: Int = 16
comptime _W_STRIDE: Int = _W_RING + _INBOX_CAP

# Policy. A worker keeps a new connection unless it holds at least
# ``_FLOOR`` connections and more than one above the least-loaded peer:
# below the floor the counts cannot saturate a core, and a difference of
# one is the best a worker can do (it would only move the surplus
# around).
comptime _FLOOR: Int = 4


def balance_group_alloc(n_workers: Int) -> Int:
    """Allocate and zero the group block for ``n_workers`` workers.

    Args:
        n_workers: Number of workers in the scheduler.

    Returns:
        The block's address, or 0 off Linux; release it with
        ``balance_group_free``.
    """
    comptime if not CompilationTarget.is_linux():
        return 0
    var slots = _HEADER_SLOTS + n_workers * _W_STRIDE
    var p = alloc(Layout[Int64](count=slots)).unsafe_leak()
    for i in range(slots):
        p[unsafe_offset=i] = Int64(0)
    p[unsafe_offset=0] = Int64(n_workers)
    return Int(p)


def balance_group_free(addr: Int):
    """Release a block from ``balance_group_alloc``.

    Call it only after every worker has stopped: workers drain their own
    inbox on the way out, so nothing is left in the ring by then.
    """
    if addr == 0:
        return
    Pointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr).unsafe_free()


@always_inline
def _cell(group: Int, idx: Int) -> Int:
    return group + (_HEADER_SLOTS + idx * _W_STRIDE) * 8


@always_inline
def _lock(cell: Int):
    var p = Pointer[Int64, MutUntrackedOrigin](
        unsafe_from_address=cell + _W_LOCK * 8
    ).unsafe_bitcast[Scalar[DType.int64]]()
    while True:
        var expected = Int64(0)
        if Atomic[Int64].compare_exchange(p, expected, Int64(1)):
            return


@always_inline
def _unlock(cell: Int):
    store_worker_stat(cell, _W_LOCK, 0)


def _wake(fd: Int):
    """Make a sleeping ``Reactor.poll`` on the eventfd ``fd`` return."""
    if fd <= 0:
        return
    # Linux only, like the group: ``eventfd_write`` does not exist on macOS,
    # and an unguarded call leaves it undefined at link time even though no
    # balancer is ever enabled there.
    comptime if CompilationTarget.is_linux():
        _ = external_call["eventfd_write", c_int](c_int(fd), UInt64(1))


struct Balancer(Copyable, ImplicitlyCopyable):
    """One worker's handle on its scheduler's group block.

    A default-built value is disabled: ``enabled`` is False, ``pick``
    always answers -1 and every other call is a no-op, so the single
    worker and non-scheduler paths pay one branch.
    """

    var group: Int
    var idx: Int
    var n: Int

    def __init__(out self):
        self.group = 0
        self.idx = 0
        self.n = 0

    def __init__(out self, group: Int, idx: Int, n: Int):
        self.group = group
        self.idx = idx
        self.n = n

    @staticmethod
    def open(stats_addr: Int, wake_fd: Int) -> Balancer:
        """Join the group named in this worker's stats cell.

        Publishes the reactor's wake fd and marks the worker live, so
        peers may hand it connections from now on.

        Args:
            stats_addr: The worker's stats cell (0 when there is none).
            wake_fd: The worker reactor's wakeup fd.

        Returns:
            A live ``Balancer``, or a disabled one when the scheduler
            started no group.
        """
        var group = load_worker_stat(stats_addr, WORKER_STAT_GROUP)
        if group == 0:
            return Balancer()
        var idx = load_worker_stat(stats_addr, WORKER_STAT_INDEX)
        var n = load_worker_stat(group, 0)
        if idx < 0 or idx >= n:
            return Balancer()
        var c = _cell(group, idx)
        store_worker_stat(c, _W_WAKE_FD, wake_fd)
        store_worker_stat(c, _W_LOAD, 0)
        _lock(c)
        store_worker_stat(c, _W_LIVE, 1)
        _unlock(c)
        return Balancer(group, idx, n)

    @always_inline
    def enabled(self) -> Bool:
        return self.group != 0

    @always_inline
    def publish(self, load: Int):
        """Publish this worker's connection count for its peers."""
        if self.group != 0:
            store_worker_stat(_cell(self.group, self.idx), _W_LOAD, load)

    def pick(self, my_load: Int) -> Int:
        """Choose where a connection this worker just accepted should go.

        Args:
            my_load: Connections this worker holds right now.

        Returns:
            The index of a clearly less-loaded live peer, or -1 to keep
            the connection here.
        """
        if self.group == 0:
            return -1
        var mine = my_load + load_worker_stat(
            _cell(self.group, self.idx), _W_PENDING
        )
        if mine < _FLOOR:
            return -1
        var best = -1
        var best_load = mine
        # Scan from the next worker so equal loads do not all point
        # every accepting worker at worker 0.
        for k in range(1, self.n):
            var w = (self.idx + k) % self.n
            var c = _cell(self.group, w)
            if load_worker_stat(c, _W_LIVE) == 0:
                continue
            var l = load_worker_stat(c, _W_LOAD) + load_worker_stat(
                c, _W_PENDING
            )
            if l < best_load:
                best = w
                best_load = l
        if best < 0:
            return -1
        if mine - best_load <= 1:
            return -1
        return best

    def push(self, target: Int, stream_addr: Int) -> Bool:
        """Queue ``stream_addr`` on ``target`` and wake it.

        Args:
            target: Worker index from ``pick``.
            stream_addr: Address of the boxed stream being handed over.

        Returns:
            True if the target took it. False (target stopped or inbox
            full) leaves ownership with the caller.
        """
        if self.group == 0 or target < 0 or target >= self.n:
            return False
        var c = _cell(self.group, target)
        var ok = False
        _lock(c)
        if load_worker_stat(c, _W_LIVE) != 0:
            var count = load_worker_stat(c, _W_PENDING)
            if count < _INBOX_CAP:
                var head = load_worker_stat(c, _W_HEAD)
                store_worker_stat(
                    c, _W_RING + (head + count) % _INBOX_CAP, stream_addr
                )
                store_worker_stat(c, _W_PENDING, count + 1)
                if count == 0:
                    _wake(load_worker_stat(c, _W_WAKE_FD))
                ok = True
        _unlock(c)
        return ok

    @always_inline
    def pending(self) -> Int:
        """Streams waiting in this worker's inbox (cheap, lock-free)."""
        if self.group == 0:
            return 0
        return load_worker_stat(_cell(self.group, self.idx), _W_PENDING)

    def pop(self) -> Int:
        """Take one waiting stream address from this worker's inbox.

        Returns:
            The address, or 0 when the inbox is empty.
        """
        if self.group == 0:
            return 0
        var c = _cell(self.group, self.idx)
        var addr = 0
        _lock(c)
        var count = load_worker_stat(c, _W_PENDING)
        if count > 0:
            var head = load_worker_stat(c, _W_HEAD)
            addr = load_worker_stat(c, _W_RING + head)
            store_worker_stat(c, _W_HEAD, (head + 1) % _INBOX_CAP)
            store_worker_stat(c, _W_PENDING, count - 1)
        _unlock(c)
        return addr

    def close(self):
        """Stop accepting hand-offs. Drain with ``pop`` afterwards."""
        if self.group == 0:
            return
        var c = _cell(self.group, self.idx)
        _lock(c)
        store_worker_stat(c, _W_LIVE, 0)
        _unlock(c)
        store_worker_stat(c, _W_LOAD, 0)
