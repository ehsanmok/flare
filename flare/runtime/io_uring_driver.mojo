"""``io_uring`` SQ/CQ ring driver (Track B0 follow-up).

Sits on top of :mod:`flare.runtime.io_uring` (syscall FFI +
ring setup) and :mod:`flare.runtime.io_uring_sqe` (SQE/CQE
codec). Adds the **submission queue** + **completion queue**
ring access via ``mmap(2)``, the atomic head/tail accessors
the kernel-shared SPMC protocol requires, and the high-level
``submit_sqe`` / ``reap_cqe`` API the upcoming ``UringReactor``
calls every poll cycle.

What this commit ships
----------------------

* **``mmap``** + **``munmap``** FFI wrappers (libc constants
  ``PROT_READ``, ``PROT_WRITE``, ``MAP_SHARED``, ``MAP_FAILED``).
* **``IORING_OFF_*``** mmap offsets (``IORING_OFF_SQ_RING = 0``,
  ``IORING_OFF_CQ_RING = 0x8000000``, ``IORING_OFF_SQES =
  0x10000000``).
* **``IoUringDriver(entries)``** — owning wrapper around
  ``IoUringRing`` that performs the three mmaps the kernel ABI
  requires:

  1. The SQ ring control region at ``IORING_OFF_SQ_RING`` of
     length ``sq_off.array + sq_entries * sizeof(__u32)``.
  2. The CQ ring control region at ``IORING_OFF_CQ_RING`` of
     length ``cq_off.cqes + cq_entries * sizeof(io_uring_cqe)``.
  3. The SQE array at ``IORING_OFF_SQES`` of length
     ``sq_entries * sizeof(io_uring_sqe)``.

  All three ``munmap``'d on drop. The ring fd itself is owned
  by the embedded ``IoUringRing`` and closed via its
  destructor.

* **Atomic head/tail accessors** — release-store on SQ tail
  (we're producer), acquire-load on CQ tail (kernel is
  producer), release-store on CQ head (we're consumer). Used
  via ``__atomic_load_n`` / ``__atomic_store_n`` libgcc
  builtins to get the right barriers per CPU; on x86-64 these
  compile to plain mov + a compiler fence.

* **High-level submit/reap API**:

  - ``next_sqe() -> UnsafePointer[UInt8, MutExternalOrigin]``
    — return a writable pointer to the next free SQE slot
    (caller fills via ``prep_*`` helpers from
    :mod:`flare.runtime.io_uring_sqe`).
  - ``commit_sqe()`` — advance the SQ tail (after the caller
    finished writing the SQE).
  - ``submit_and_wait(min_complete: Int) -> Int`` — call
    ``io_uring_enter`` with the new SQ tail; returns the
    number of SQEs the kernel consumed.
  - ``reap_cqe() -> Optional[IoUringCqe]`` — return the next
    pending CQE, or ``None`` if the CQ is empty. Advances
    the CQ head atomically.
  - ``cqe_count() -> Int`` — number of pending CQEs (kernel
    tail - userspace head).
  - ``submit_nop(user_data) -> Int`` — convenience: fill an
    SQE with ``prep_nop``, commit, submit, reap one CQE.
    Used by `test_io_uring_driver` for the SQ→CQ round-trip
    smoke test.

Concurrency contract
--------------------

The kernel-shared SQ/CQ rings are SPSC (single-producer,
single-consumer) per direction:

* SQ direction: userspace is producer, kernel is consumer. We
  release-store on tail; kernel acquire-loads on tail.
* CQ direction: kernel is producer, userspace is consumer.
  Kernel release-stores on tail; we acquire-load tail and
  release-store our consumed-up-to head.

flare's per-worker model means each ``IoUringDriver`` is owned
by exactly one pthread (the worker reactor loop), so there's
no inter-worker locking on the rings themselves. The atomic
ops are only for the userspace-kernel boundary.

References
----------

* ``man 2 io_uring_setup`` — describes the mmap region layout.
* Jens Axboe, *Efficient IO with io_uring*
  (https://kernel.dk/io_uring.pdf) §3 — the SQ/CQ ring protocol.
* ``include/uapi/linux/io_uring.h`` — ``IORING_OFF_*``,
  ``io_uring_sqe``, ``io_uring_cqe`` field layouts.
"""

from std.atomic import Atomic, Ordering
from std.ffi import external_call, c_int, c_uint, c_size_t, c_long, get_errno
from std.memory import UnsafePointer
from std.sys.info import CompilationTarget

from flare.runtime.io_uring import (
    IoUringRing,
    io_uring_enter,
    _IO_URING_PARAMS_BYTES,
    _read_u32_le,
)
from flare.runtime.io_uring_sqe import (
    IO_URING_SQE_BYTES,
    IO_URING_CQE_BYTES,
    IoUringCqe,
    decode_cqe_at,
    prep_nop,
)


# ── mmap FFI ─────────────────────────────────────────────────────────────────


comptime PROT_READ: Int = 1
"""``mmap`` page-protection flag: pages may be read."""
comptime PROT_WRITE: Int = 2
"""``mmap`` page-protection flag: pages may be written."""
comptime MAP_SHARED: Int = 1
"""``mmap`` flag: changes are shared with backing store
(required for io_uring's kernel-shared ring regions)."""
comptime MAP_POPULATE: Int = 0x8000
"""``mmap`` flag (Linux-only): pre-fault page tables to avoid
the per-page minor-fault cost on first access; the io_uring
ring regions are typically a few KB so this is essentially
free."""

# (void*) -1, the sentinel mmap returns on failure. We compare
# against this as an unsigned 64-bit value.
comptime _MAP_FAILED_BITS: UInt64 = 0xFFFF_FFFF_FFFF_FFFF


# io_uring's three named mmap offsets.
comptime IORING_OFF_SQ_RING: UInt64 = 0
"""``mmap`` offset for the SQ ring control region (head, tail,
ring_mask, ring_entries, flags, dropped, array)."""
comptime IORING_OFF_CQ_RING: UInt64 = 0x8000000
"""``mmap`` offset for the CQ ring control region (head, tail,
ring_mask, ring_entries, overflow, cqes, flags). On kernels with
``IORING_FEAT_SINGLE_MMAP`` (5.4+), this region is overlaid on
the SQ region and a single ``mmap(IORING_OFF_SQ_RING, ...)`` for
the larger of the two sizes covers both. flare does the two
mmaps separately for kernel-version-portability simplicity; the
extra page-table entry is negligible."""
comptime IORING_OFF_SQES: UInt64 = 0x10000000
"""``mmap`` offset for the SQE array (the actual 64-byte SQE
slots; the SQ ring's ``array`` field is an indirection table of
``__u32`` indices into this array)."""


@always_inline
def libc_mmap(
    length: Int, prot: Int, flags: Int, fd: Int, offset: UInt64
) -> UnsafePointer[UInt8, MutExternalOrigin]:
    """Wrap ``mmap(2)`` via libc's ``mmap`` symbol.

    Args:
        length: Bytes to map.
        prot: ``PROT_READ | PROT_WRITE`` for the io_uring use.
        flags: ``MAP_SHARED | MAP_POPULATE`` for the io_uring
            use.
        fd: ``IoUringRing.fd()``.
        offset: One of ``IORING_OFF_SQ_RING`` /
            ``IORING_OFF_CQ_RING`` / ``IORING_OFF_SQES``.

    Returns:
        Pointer to the mapped region on success; the
        ``_MAP_FAILED_BITS`` sentinel pointer on failure (caller
        must check via ``Int(rc) == Int(_MAP_FAILED_BITS)``).
    """
    debug_assert[assert_mode="safe"](
        length > 0, "libc_mmap: length must be positive; got ", length
    )
    # ``fd`` is only required to be a valid open fd for the
    # MAP_SHARED io_uring path; for anonymous mappings (the
    # IORING_REGISTER_PBUF_RING path), ``fd`` is conventionally
    # -1 and the kernel ignores it when MAP_ANONYMOUS is in
    # ``flags``. So accept fd >= -1.
    debug_assert[assert_mode="safe"](
        fd >= -1, "libc_mmap: fd must be >= -1; got ", fd
    )
    var null_addr = UnsafePointer[UInt8, MutExternalOrigin](
        unsafe_from_address=0
    )
    var rc = external_call["mmap", UnsafePointer[UInt8, MutExternalOrigin]](
        null_addr,
        c_size_t(length),
        c_int(prot),
        c_int(flags),
        c_int(fd),
        c_long(Int(offset)),
    )
    return rc


@always_inline
def libc_munmap(
    addr: UnsafePointer[UInt8, MutExternalOrigin], length: Int
) -> Int:
    """Wrap ``munmap(2)``. Returns 0 on success, ``-errno`` on
    failure."""
    var rc = external_call["munmap", c_int](addr, c_size_t(length))
    if Int(rc) < 0:
        return -Int(get_errno().value)
    return Int(rc)


# ── atomic head/tail accessors ───────────────────────────────────────────────


@always_inline
def _atomic_load_u32_acquire(
    ptr: UnsafePointer[UInt8, MutExternalOrigin],
) -> UInt32:
    """Acquire-load a 32-bit value out of the kernel-shared SQ/CQ
    ring region.

    Uses Mojo's ``Atomic[DType.uint32].load`` with
    ``Ordering.ACQUIRE``, which lowers to a plain ``mov`` +
    compiler fence on x86-64 (TSO) and to ``ldar`` on ARM64
    (the proper acquire load).

    The kernel guarantees the SQ/CQ head/tail fields are
    4-byte aligned within the ring region.
    """
    debug_assert[assert_mode="safe"](
        Int(ptr) != 0, "_atomic_load_u32_acquire: ptr must be non-NULL"
    )
    var typed = ptr.bitcast[Scalar[DType.uint32]]()
    return Atomic[DType.uint32].load[ordering=Ordering.ACQUIRE](typed)


@always_inline
def _atomic_load_u32_relaxed(
    ptr: UnsafePointer[UInt8, MutExternalOrigin],
) -> UInt32:
    """Relaxed-load a 32-bit value (no ordering guarantees).
    Used for the ring_mask / cached-tail reads where the
    surrounding logic provides the ordering."""
    debug_assert[assert_mode="safe"](
        Int(ptr) != 0, "_atomic_load_u32_relaxed: ptr must be non-NULL"
    )
    var typed = ptr.bitcast[Scalar[DType.uint32]]()
    return Atomic[DType.uint32].load[ordering=Ordering.RELAXED](typed)


@always_inline
def _atomic_store_u32_release(
    ptr: UnsafePointer[UInt8, MutExternalOrigin], value: UInt32
) -> None:
    """Release-store a 32-bit value into the kernel-shared
    SQ/CQ ring region. Pairs with the kernel's acquire-load on
    the same field."""
    debug_assert[assert_mode="safe"](
        Int(ptr) != 0, "_atomic_store_u32_release: ptr must be non-NULL"
    )
    var typed = ptr.bitcast[Scalar[DType.uint32]]()
    Atomic[DType.uint32].store[ordering=Ordering.RELEASE](typed, value)


@always_inline
def _atomic_store_u32_relaxed(
    ptr: UnsafePointer[UInt8, MutExternalOrigin], value: UInt32
) -> None:
    """Relaxed-store a 32-bit value (no ordering guarantees).
    Used for the SQ array's identity-mapping writes where the
    surrounding submit_and_wait release-store on the SQ tail
    provides the publishing barrier."""
    debug_assert[assert_mode="safe"](
        Int(ptr) != 0, "_atomic_store_u32_relaxed: ptr must be non-NULL"
    )
    var typed = ptr.bitcast[Scalar[DType.uint32]]()
    Atomic[DType.uint32].store[ordering=Ordering.RELAXED](typed, value)


# ── params-buffer field offsets (echoes io_uring.mojo IoUringParams) ────────
# These are the fixed byte offsets into the 120-byte
# io_uring_params buffer. Used by the driver to read the
# kernel-filled SQ / CQ region offsets after io_uring_setup.

comptime _SQ_OFF_HEAD_OFF: Int = 40  # u32
comptime _SQ_OFF_TAIL_OFF: Int = 44  # u32
comptime _SQ_OFF_RING_MASK_OFF: Int = 48  # u32
comptime _SQ_OFF_RING_ENTRIES_OFF: Int = 52  # u32
comptime _SQ_OFF_FLAGS_OFF: Int = 56  # u32
comptime _SQ_OFF_DROPPED_OFF: Int = 60  # u32
comptime _SQ_OFF_ARRAY_OFF: Int = 64  # u32

comptime _CQ_OFF_HEAD_OFF: Int = 80  # u32 (40 SQ + 40 CQ start)
comptime _CQ_OFF_TAIL_OFF: Int = 84  # u32
comptime _CQ_OFF_RING_MASK_OFF: Int = 88  # u32
comptime _CQ_OFF_RING_ENTRIES_OFF: Int = 92  # u32
comptime _CQ_OFF_OVERFLOW_OFF: Int = 96  # u32
comptime _CQ_OFF_CQES_OFF: Int = 100  # u32


# ── IoUringDriver ────────────────────────────────────────────────────────────


struct IoUringDriver(Movable):
    """High-level driver for one io_uring ring (one fd, one
    SQ/CQ pair, one SQE array).

    Owns one ``IoUringRing`` (closes ring fd on drop) and three
    ``mmap`` regions (``munmap``'d on drop). Exposes the
    submit/reap API the upcoming ``UringReactor`` calls every
    poll cycle.

    Per-worker ownership: each pthread that runs a reactor loop
    owns exactly one ``IoUringDriver``. The kernel-shared rings
    are SPSC per direction (kernel + this one userspace thread),
    so no inter-worker synchronisation is required.

    Fields:
        _ring: Owning ``IoUringRing`` (substrate; provides fd +
            params).
        _sq_ring_ptr: Mapped SQ ring control region.
        _sq_ring_len: Length of the SQ ring mapping.
        _cq_ring_ptr: Mapped CQ ring control region.
        _cq_ring_len: Length of the CQ ring mapping.
        _sqes_ptr: Mapped SQE array.
        _sqes_len: Length of the SQE array mapping.
        _sq_head_ptr / _sq_tail_ptr / _sq_ring_mask / _sq_array_ptr:
            Cached pointers + values into the SQ ring control
            region (no per-call offset arithmetic).
        _cq_head_ptr / _cq_tail_ptr / _cq_ring_mask / _cq_cqes_ptr:
            Same for the CQ region.
        _sq_local_tail: Userspace-side cached SQ tail; bumped
            by ``commit_sqe``, flushed to the kernel-visible
            tail by ``submit_and_wait``.
    """

    var _ring: IoUringRing
    var _sq_ring_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _sq_ring_len: Int
    var _cq_ring_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _cq_ring_len: Int
    var _sqes_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _sqes_len: Int

    var _sq_head_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _sq_tail_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _sq_array_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _sq_ring_mask: UInt32

    var _cq_head_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _cq_tail_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _cq_cqes_ptr: UnsafePointer[UInt8, MutExternalOrigin]
    var _cq_ring_mask: UInt32

    var _sq_local_tail: UInt32

    def __init__(out self, entries: Int) raises:
        """Set up an io_uring with ``entries`` SQEs and mmap
        the three required regions (SQ ring, CQ ring, SQE array).

        Args:
            entries: Number of SQEs (kernel rounds up to a power
                of two; max 32 768).

        Raises:
            Error: On ``io_uring_setup`` failure or any of the
                three ``mmap`` calls failing.
        """
        comptime if not CompilationTarget.is_linux():
            raise Error(
                "IoUringDriver is a Linux-only feature; this build is not Linux"
            )

        # Set up the underlying ring (raises on syscall failure).
        self._ring = IoUringRing(entries)

        var fd = self._ring.fd()
        var params = self._ring._params_buf

        # Read kernel-filled offsets.
        var sq_array_off = _read_u32_le(params, _SQ_OFF_ARRAY_OFF)
        var sq_ring_entries = _read_u32_le(params, _SQ_OFF_RING_ENTRIES_OFF)
        var sq_head_off = _read_u32_le(params, _SQ_OFF_HEAD_OFF)
        var sq_tail_off = _read_u32_le(params, _SQ_OFF_TAIL_OFF)
        var sq_ring_mask_off = _read_u32_le(params, _SQ_OFF_RING_MASK_OFF)

        var cq_cqes_off = _read_u32_le(params, _CQ_OFF_CQES_OFF)
        var cq_ring_entries = _read_u32_le(params, _CQ_OFF_RING_ENTRIES_OFF)
        var cq_head_off = _read_u32_le(params, _CQ_OFF_HEAD_OFF)
        var cq_tail_off = _read_u32_le(params, _CQ_OFF_TAIL_OFF)
        var cq_ring_mask_off = _read_u32_le(params, _CQ_OFF_RING_MASK_OFF)

        # SQ ring length: array offset + sq_entries * sizeof(__u32).
        var sq_ring_len = sq_array_off + sq_ring_entries * 4
        var cq_ring_len = cq_cqes_off + cq_ring_entries * IO_URING_CQE_BYTES
        var sqes_len = sq_ring_entries * IO_URING_SQE_BYTES

        # mmap SQ ring.
        var sq_ring_ptr = libc_mmap(
            sq_ring_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            IORING_OFF_SQ_RING,
        )
        if Int(sq_ring_ptr) == Int(_MAP_FAILED_BITS):
            raise Error(
                "mmap SQ_RING failed: errno=" + String(get_errno().value)
            )

        # mmap CQ ring.
        var cq_ring_ptr = libc_mmap(
            cq_ring_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            IORING_OFF_CQ_RING,
        )
        if Int(cq_ring_ptr) == Int(_MAP_FAILED_BITS):
            _ = libc_munmap(sq_ring_ptr, sq_ring_len)
            raise Error(
                "mmap CQ_RING failed: errno=" + String(get_errno().value)
            )

        # mmap SQE array.
        var sqes_ptr = libc_mmap(
            sqes_len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            fd,
            IORING_OFF_SQES,
        )
        if Int(sqes_ptr) == Int(_MAP_FAILED_BITS):
            _ = libc_munmap(sq_ring_ptr, sq_ring_len)
            _ = libc_munmap(cq_ring_ptr, cq_ring_len)
            raise Error("mmap SQES failed: errno=" + String(get_errno().value))

        self._sq_ring_ptr = sq_ring_ptr
        self._sq_ring_len = sq_ring_len
        self._cq_ring_ptr = cq_ring_ptr
        self._cq_ring_len = cq_ring_len
        self._sqes_ptr = sqes_ptr
        self._sqes_len = sqes_len

        self._sq_head_ptr = sq_ring_ptr + sq_head_off
        self._sq_tail_ptr = sq_ring_ptr + sq_tail_off
        self._sq_array_ptr = sq_ring_ptr + sq_array_off
        # Read the ring mask once (kernel sets it on setup; never
        # changes for the lifetime of the ring).
        var mask_ptr = sq_ring_ptr + sq_ring_mask_off
        self._sq_ring_mask = _atomic_load_u32_relaxed(mask_ptr)

        self._cq_head_ptr = cq_ring_ptr + cq_head_off
        self._cq_tail_ptr = cq_ring_ptr + cq_tail_off
        self._cq_cqes_ptr = cq_ring_ptr + cq_cqes_off
        var cq_mask_ptr = cq_ring_ptr + cq_ring_mask_off
        self._cq_ring_mask = _atomic_load_u32_relaxed(cq_mask_ptr)

        # Cached SQ tail: starts at the kernel-visible value
        # (typically 0 on a fresh ring).
        self._sq_local_tail = _atomic_load_u32_relaxed(self._sq_tail_ptr)

    def __del__(deinit self):
        """Unmap the three ring regions; the embedded
        ``IoUringRing.__del__`` then closes the ring fd."""
        if Int(self._sqes_ptr) != 0:
            _ = libc_munmap(self._sqes_ptr, self._sqes_len)
        if Int(self._cq_ring_ptr) != 0:
            _ = libc_munmap(self._cq_ring_ptr, self._cq_ring_len)
        if Int(self._sq_ring_ptr) != 0:
            _ = libc_munmap(self._sq_ring_ptr, self._sq_ring_len)

    # ── Accessors ─────────────────────────────────────────────────────────────

    def fd(self) -> Int:
        """Return the underlying ring fd."""
        return self._ring.fd()

    def sq_entries(self) -> Int:
        """Return the kernel-allocated SQ size."""
        return self._ring.sq_entries()

    def cq_entries(self) -> Int:
        """Return the kernel-allocated CQ size."""
        return self._ring.cq_entries()

    def sq_ring_mask(self) -> UInt32:
        """Return the SQ ring index mask (``sq_entries - 1``)."""
        return self._sq_ring_mask

    def cq_ring_mask(self) -> UInt32:
        """Return the CQ ring index mask (``cq_entries - 1``)."""
        return self._cq_ring_mask

    # ── Submit path ───────────────────────────────────────────────────────────

    def next_sqe(self) -> UnsafePointer[UInt8, MutExternalOrigin]:
        """Return a writable 64-byte pointer to the next free
        SQE slot.

        Caller fills the slot via a ``prep_*`` helper from
        :mod:`flare.runtime.io_uring_sqe`, then calls
        :meth:`commit_sqe` to advance the cached SQ tail.
        Multiple ``next_sqe → commit_sqe`` calls may be
        interleaved before ``submit_and_wait`` flushes them to
        the kernel.

        Returns ``UnsafePointer()`` (NULL) if the SQ is full
        (cached tail - kernel head == sq_entries).
        """
        # SQ-full check: cached_tail - kernel_head must be < sq_entries.
        var k_head = _atomic_load_u32_acquire(self._sq_head_ptr)
        var pending = Int(self._sq_local_tail) - Int(k_head)
        if pending >= self.sq_entries():
            return UnsafePointer[UInt8, MutExternalOrigin](
                unsafe_from_address=0
            )
        var idx = Int(self._sq_local_tail & self._sq_ring_mask)
        return self._sqes_ptr + idx * IO_URING_SQE_BYTES

    def commit_sqe(mut self) -> None:
        """Advance the cached SQ tail by one. The kernel-visible
        tail is not updated until :meth:`submit_and_wait` is
        called.

        Caller must have written a fully-formed SQE to the slot
        returned by :meth:`next_sqe` before calling this.
        """
        var idx = Int(self._sq_local_tail & self._sq_ring_mask)
        # The SQ array is an indirection table: array[i] = SQE
        # index. We always set array[i] = i so the kernel reads
        # the SQE at slot i. (Indirection lets you reuse the
        # SQE array for different ordering schemes; flare's
        # in-order submission uses identity.)
        _atomic_store_u32_relaxed(self._sq_array_ptr + idx * 4, UInt32(idx))
        self._sq_local_tail = self._sq_local_tail + UInt32(1)

    def submit_and_wait(mut self, min_complete: Int) -> Int:
        """Flush the cached SQ tail to the kernel and call
        ``io_uring_enter``.

        Args:
            min_complete: 0 = non-blocking submit (kernel may
                process SQEs but the call returns even if no
                CQEs are ready). Positive = block until at least
                this many CQEs are ready.

        Returns:
            On success, the number of SQEs the kernel consumed
            (typically ``cached_tail - kernel_tail`` before the
            store). On failure, ``-errno``.
        """
        # release-store the new tail so the kernel sees the
        # SQEs we wrote.
        var k_tail = _atomic_load_u32_relaxed(self._sq_tail_ptr)
        var to_submit = Int(self._sq_local_tail) - Int(k_tail)
        if to_submit > 0:
            _atomic_store_u32_release(self._sq_tail_ptr, self._sq_local_tail)
        var flags = 0
        if min_complete > 0:
            # IORING_ENTER_GETEVENTS = 0x1
            flags = 1
        return io_uring_enter(self.fd(), to_submit, min_complete, flags)

    # ── Reap path ─────────────────────────────────────────────────────────────

    def cqe_count(self) -> Int:
        """Return the number of pending CQEs (kernel-visible
        tail - userspace head)."""
        var k_tail = _atomic_load_u32_acquire(self._cq_tail_ptr)
        var u_head = _atomic_load_u32_relaxed(self._cq_head_ptr)
        return Int(k_tail) - Int(u_head)

    def reap_cqe(mut self) -> Optional[IoUringCqe]:
        """Return the next pending CQE, or ``None`` if the CQ
        is empty.

        Advances the CQ head with a release store so the kernel
        knows the slot is free for the next CQE.
        """
        var k_tail = _atomic_load_u32_acquire(self._cq_tail_ptr)
        var u_head = _atomic_load_u32_relaxed(self._cq_head_ptr)
        if u_head == k_tail:
            return None
        var idx = Int(u_head & self._cq_ring_mask)
        var slot = self._cq_cqes_ptr + idx * IO_URING_CQE_BYTES
        var cqe = decode_cqe_at(slot)
        _atomic_store_u32_release(self._cq_head_ptr, u_head + UInt32(1))
        return cqe^

    # ── Convenience ───────────────────────────────────────────────────────────

    def submit_nop(mut self, user_data: UInt64) raises -> Int:
        """Submit a single ``IORING_OP_NOP`` SQE and return the
        result-code from ``io_uring_enter``.

        Used by the SQ→CQ round-trip smoke test in
        ``tests/test_io_uring_driver.mojo`` and as the simplest
        sanity check on a fresh driver.
        """
        var slot = self.next_sqe()
        if Int(slot) == 0:
            raise Error("submit_nop: SQ is full")
        prep_nop(slot, user_data)
        self.commit_sqe()
        return self.submit_and_wait(1)
