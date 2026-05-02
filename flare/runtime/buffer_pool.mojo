"""Per-worker, size-class-bucketed buffer pool (Track B5).

Hands out and returns ``BufferHandle`` byte buffers from one of
four size classes (1 KiB / 4 KiB / 16 KiB / 64 KiB) so the
HTTP/1.1 reactor's read- and write-side temporaries don't pay
``alloc(N)`` / ``free(N)`` per request.

Why this is a Track B subtrack
-------------------------------

flare's reactor reads from each accepted socket into a
``List[UInt8]`` chunk buffer (``ServerConfig.read_buffer_size``,
default 8 KiB) per ``recv(2)`` call, and serialises every
response into a second contiguous ``List[UInt8]`` before the
``send(2)`` (or ``writev(2)``, see Track B4) syscall. Both lists
are constructed-and-destructed once per request on the keep-alive
hot path. At the v0.7 throughput target (220 K req/s, 4 workers)
that's ~1.7 M ``alloc + free`` pairs per second per buffer side —
glibc's malloc is fast but the cache-line eviction it causes for
every small allocation is not free.

The Rust analogues to look at:

* ``hyper`` keeps a per-connection 8 KiB read buffer that is
  reused for the lifetime of the connection (no realloc per
  request, no per-message-frame ``Vec::new``). The buffer is
  owned by the connection state, not pooled across connections.
* ``actix-web`` and ``axum`` (via ``hyper``) inherit the same
  shape; ``actix``'s framework adds a per-worker ``BytesMut``
  freelist for response builders.

Track B5 picks the more conservative shape: a **per-worker pool
of fixed-size-class buffers** that is independent of any
connection. The reactor borrows a buffer for one request, fills
it, drains it, and returns it to the pool; the next request on
any connection (same worker) gets the same buffer back. No
cross-worker handoff, no atomic, no mutex — same per-worker
discipline as ``DateCache`` (B7) and ``ResponsePool`` (B6).

Size classes
------------

Four power-of-two classes pinned at:

* **1 KiB** — tiny payloads (most plaintext / health-check
  responses, the TFB plaintext target itself).
* **4 KiB** — typical JSON responses, typical HTTP/1.1 request
  headers + small body.
* **16 KiB** — moderate payloads (small file responses, a
  typical compressed-body buffer).
* **64 KiB** — large reads / writes (chunked-body single-chunk
  serialisation upper bound, large file-served responses).

The ``acquire(min_capacity)`` API takes a *minimum* capacity and
rounds up to the smallest size class that fits. Requests larger
than 64 KiB fall through to a one-off heap allocation that bypass
the pool — the buffer is destroyed on release rather than
recycled, so giant requests don't cause the pool to grow
unbounded.

What this commit ships
-----------------------

* ``BufferHandle`` — the value moved in / out of the pool. Wraps
  a ``List[UInt8]`` plus an Int recording the size class so the
  matching pool bucket knows which class to push into on
  release. ``Movable`` (not ``Copyable``) for the same reason
  ``Response`` is.
* ``BufferPool`` — per-worker bucketed pool with the four size
  classes above. ``acquire(min_capacity) -> BufferHandle`` /
  ``release(var BufferHandle)`` shape. Each bucket is bounded
  at a small capacity (default 8 per class) so the pool's
  steady-state memory is at most ``8 * (1+4+16+64) KiB ≈
  680 KiB`` per worker.
* ``BufferPool.with_class_capacity(N)`` factory for tests and
  custom workloads.
* ``BufferPool.size_for(min_capacity) -> Int`` helper exposed
  publicly for callers that want to allocate without pooling
  but still snap to the canonical size classes (e.g. on the
  oversize fall-through path).

Storage strategy
----------------

Same as ``ResponsePool`` (B6): ``BufferHandle`` is ``Movable``
but not ``Copyable``, so each per-class bucket is a ``List[Int]``
of heap addresses managed via ``Pool[BufferHandle]``. ``acquire``
pops an address, takes the pointee, frees the cell.
``release`` moves the supplied handle into a fresh cell and
pushes the address. Net allocation cost: one ``Pool.alloc/free``
pair per acquire/release; the actual win is that the **underlying
``List[UInt8]`` capacity is preserved** across the move-in / out.

Wiring into the reactor's accept-and-read path is a follow-up
commit; this commit lands the primitive + tests + re-exports.
"""

from .pool import Pool


# ── Size class table ─────────────────────────────────────────────────────────


comptime _SIZE_CLASS_1K: Int = 1024
comptime _SIZE_CLASS_4K: Int = 4 * 1024
comptime _SIZE_CLASS_16K: Int = 16 * 1024
comptime _SIZE_CLASS_64K: Int = 64 * 1024
comptime _NUM_SIZE_CLASSES: Int = 4
comptime _OVERSIZE_CLASS: Int = -1
"""Sentinel size-class value for buffers larger than 64 KiB. The
``release`` path checks for this and drops the handle on the
floor rather than pushing into a non-existent bucket.
"""


@always_inline
def _class_index_for(min_capacity: Int) -> Int:
    """Return the index (0..3) of the smallest size class that
    fits ``min_capacity``, or ``_OVERSIZE_CLASS`` if none does.
    """
    if min_capacity <= _SIZE_CLASS_1K:
        return 0
    if min_capacity <= _SIZE_CLASS_4K:
        return 1
    if min_capacity <= _SIZE_CLASS_16K:
        return 2
    if min_capacity <= _SIZE_CLASS_64K:
        return 3
    return _OVERSIZE_CLASS


@always_inline
def _capacity_for_class(idx: Int) -> Int:
    """Inverse of :func:`_class_index_for` — return the buffer
    capacity for a size-class index.

    ``idx`` outside ``[0, 3]`` returns 0 (caller error).
    """
    if idx == 0:
        return _SIZE_CLASS_1K
    if idx == 1:
        return _SIZE_CLASS_4K
    if idx == 2:
        return _SIZE_CLASS_16K
    if idx == 3:
        return _SIZE_CLASS_64K
    return 0


# ── BufferHandle ─────────────────────────────────────────────────────────────


struct BufferHandle(Movable):
    """An owned byte buffer with a size-class tag.

    ``buf.bytes`` is the underlying ``List[UInt8]`` — append /
    resize / clear it as a normal List. The ``class_index``
    field is set by ``BufferPool.acquire`` and is consumed by
    ``BufferPool.release`` to find the right bucket on return.

    Fields:
        bytes: The owned byte buffer. Capacity is the size class
               that the pool handed out; ``len(bytes)`` may be 0
               on first acquire and grows / shrinks via the
               caller's ``append`` / ``resize`` / ``clear``.
        class_index: 0..3 for the four standard size classes;
               ``_OVERSIZE_CLASS`` (-1) for one-off oversize
               buffers.
    """

    var bytes: List[UInt8]
    var class_index: Int

    def __init__(out self, capacity: Int, class_index: Int):
        """Construct a fresh handle with the requested capacity.

        Args:
            capacity: Initial capacity to reserve in ``bytes``.
            class_index: 0..3 or ``_OVERSIZE_CLASS``.
        """
        self.bytes = List[UInt8]()
        self.bytes.reserve(capacity)
        self.class_index = class_index

    @staticmethod
    def for_class(class_index: Int) -> BufferHandle:
        """Construct a fresh handle for one of the standard size
        classes.

        Args:
            class_index: 0..3 (1 KiB / 4 KiB / 16 KiB / 64 KiB).

        Returns:
            A handle whose backing ``bytes`` has the matching
            reserved capacity.
        """
        return BufferHandle(
            capacity=_capacity_for_class(class_index),
            class_index=class_index,
        )

    def reset(mut self):
        """Clear the buffer in place without releasing capacity.

        ``BufferPool.acquire`` calls this on every recycled
        handle so the caller sees a length-0 buffer with the
        original size-class capacity intact.
        """
        self.bytes.clear()


# ── BufferPool ───────────────────────────────────────────────────────────────


struct BufferPool(Movable):
    """Per-worker bucketed buffer pool over four size classes.

    Buckets are independent ``List[Int]`` stacks of heap-allocated
    ``BufferHandle`` cell addresses (managed via
    ``Pool[BufferHandle]``). Each bucket is capped at
    ``class_capacity`` (default 8) so the pool's steady-state
    memory is at most ``class_capacity * (1+4+16+64) KiB ≈
    680 KiB`` per worker.

    Fields:
        _buckets: Length-4 list of per-class ``List[Int]`` stacks.
                The outer list is fixed-length (one entry per
                size class); the inner lists grow up to
                ``_class_capacity`` and shrink as buffers are
                acquired.
        _class_capacity: Maximum number of recycled buffers per
                size class. Releases past this cap drop the
                released handle.
    """

    var _buckets: List[List[Int]]
    var _class_capacity: Int

    def __init__(out self):
        """Construct an empty pool with the default per-class
        capacity (8).
        """
        self._buckets = List[List[Int]]()
        for _ in range(_NUM_SIZE_CLASSES):
            self._buckets.append(List[Int]())
        self._class_capacity = 8

    def __del__(deinit self):
        """Free every retained cell across every bucket."""
        for ci in range(_NUM_SIZE_CLASSES):
            for j in range(len(self._buckets[ci])):
                Pool[BufferHandle].free(self._buckets[ci][j])

    @staticmethod
    def with_class_capacity(class_capacity: Int) -> BufferPool:
        """Construct an empty pool with a custom per-class cap.

        Args:
            class_capacity: Maximum recycled buffers per size
                            class. Clamped to ≥ 1.

        Returns:
            A fresh ``BufferPool``.
        """
        var p = BufferPool()
        p._class_capacity = 1 if class_capacity < 1 else class_capacity
        return p^

    @staticmethod
    def size_for(min_capacity: Int) -> Int:
        """Return the canonical size-class capacity for a request,
        or ``min_capacity`` itself if the request exceeds the
        largest class.

        Useful for the oversize fall-through path that bypasses
        the pool but still wants a deterministic capacity.
        """
        var idx = _class_index_for(min_capacity)
        if idx == _OVERSIZE_CLASS:
            return min_capacity
        return _capacity_for_class(idx)

    def acquire(mut self, min_capacity: Int) raises -> BufferHandle:
        """Return a buffer with at least ``min_capacity`` bytes
        of capacity, drawn from the pool if available else
        constructed fresh.

        On a hit the returned handle's ``bytes`` is reset to
        length 0 but retains the size-class capacity. On a miss
        the pool constructs a fresh ``BufferHandle`` for the
        right size class. Requests larger than 64 KiB skip the
        pool and allocate one-off (the returned handle's
        ``class_index`` is ``_OVERSIZE_CLASS``, and ``release``
        will drop it rather than push it into a non-existent
        bucket).

        Args:
            min_capacity: Minimum buffer capacity required.

        Returns:
            A reset-empty ``BufferHandle`` with capacity ≥
            ``min_capacity``.
        """
        debug_assert[assert_mode="safe"](
            min_capacity >= 0,
            "BufferPool.acquire: min_capacity must be non-negative; got ",
            min_capacity,
        )
        var idx = _class_index_for(min_capacity)
        if idx == _OVERSIZE_CLASS:
            return BufferHandle(
                capacity=min_capacity, class_index=_OVERSIZE_CLASS
            )
        if len(self._buckets[idx]) > 0:
            var addr = self._buckets[idx].pop()
            var ptr = Pool[BufferHandle].get_ptr(addr)
            var h = ptr.take_pointee()
            ptr.free()
            h.reset()
            return h^
        return BufferHandle.for_class(idx)

    def release(mut self, var handle: BufferHandle) raises:
        """Return a buffer to its size-class bucket.

        Oversize handles (``class_index == _OVERSIZE_CLASS``) and
        releases past the per-class cap drop the handle on the
        floor (Mojo destructor runs).

        Args:
            handle: Owned ``BufferHandle`` to recycle.
        """
        var idx = handle.class_index
        # Defense-in-depth: any class_index outside the documented
        # set is silently dropped rather than asserted. A
        # hand-constructed BufferHandle with a corrupt tag (e.g.
        # via FFI / unsafe code) shouldn't take the server down.
        # Under `-D ASSERT=all` the explicit invariant is exercised
        # in tests/test_safety_asserts.mojo. See
        # `.cursor/rules/sanitizers-and-bounds-checking.mdc` §4.7
        # for when "fault-tolerant" beats "fail-fast" at API
        # boundaries.
        if idx == _OVERSIZE_CLASS:
            return
        if idx < 0 or idx >= _NUM_SIZE_CLASSES:
            return
        if len(self._buckets[idx]) >= self._class_capacity:
            return
        var addr = Pool[BufferHandle].alloc_move(handle^)
        self._buckets[idx].append(addr)

    def size(self, class_index: Int) -> Int:
        """Return the number of recycled buffers in a class.

        Out-of-range ``class_index`` returns 0.
        """
        if class_index < 0 or class_index >= _NUM_SIZE_CLASSES:
            return 0
        return len(self._buckets[class_index])

    def class_capacity(self) -> Int:
        """Return the per-class capacity cap."""
        return self._class_capacity
