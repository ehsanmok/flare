"""Provided-buffer-ring memory helpers for :mod:`flare.runtime.uring_reactor`.

Page-aligned anonymous mmap allocation (``_mmap_anon_rw`` / ``_munmap``)
for the kernel-shared ``IORING_REGISTER_PBUF_RING`` ring, plus the
byte-level ``struct io_uring_buf`` accessors (``_pbuf_ring_add`` /
``_pbuf_ring_get_tail`` / ``_pbuf_ring_set_tail``) that publish buffers
to the kernel with the correct acquire/release ordering. Split out of
``uring_reactor.mojo`` to keep that module within the file-size budget;
``uring_reactor`` re-exports every name so existing
``from flare.runtime.uring_reactor import _pbuf_ring_add`` (server
reactor, tests) call sites keep resolving unchanged.
"""

from std.atomic import Atomic, Ordering
from std.memory import UnsafePointer

from flare.runtime.io_uring_driver import libc_mmap, libc_munmap

# ── mmap helpers for kernel-shared buffer ring ───────────────────────────────


@always_inline
def _mmap_anon_rw(size: Int) -> Int:
    """Allocate ``size`` bytes of page-aligned anonymous memory
    (PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS).

    Returns the address as ``Int``, or 0 on failure.

    Used for ``IORING_REGISTER_PBUF_RING`` ring memory which the
    kernel requires to be page-aligned (libc malloc doesn't
    guarantee this for small allocations).

    Routes through :func:`flare.runtime.io_uring_driver.libc_mmap`
    so the FFI signature stays consistent across the codebase
    (Mojo's external_call cache rejects two different signatures
    for the same symbol).
    """
    # PROT_READ=1, PROT_WRITE=2; MAP_PRIVATE=2, MAP_ANONYMOUS=0x20.
    var p = libc_mmap(length=size, prot=3, flags=0x22, fd=-1, offset=0)
    if Int(p) == -1 or Int(p) == 0:
        return 0
    return Int(p)


@always_inline
def _munmap(addr: Int, size: Int) -> None:
    """Release memory previously returned by ``_mmap_anon_rw``."""
    if addr == 0:
        return
    var p = UnsafePointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr)
    _ = libc_munmap(p, size)


# ── PBUF ring helpers (work directly on the registered ring memory) ─────────
#
# Layout (struct io_uring_buf, 16 bytes per slot):
#   offset  0: __u64 addr   (buffer's user-space pointer)
#   offset  8: __u32 len    (buffer length)
#   offset 12: __u16 bid    (buffer id)
#   offset 14: __u16 resv   (reserved -- but for slot index 0 this
#                            field overlaps with the ring's tail
#                            pointer in the union layout the kernel
#                            uses; see io_uring/kbuf.h)
#
# The kernel reads the tail field at slot[0].resv with acquire
# ordering. Userspace writes it with release ordering. Head is
# kernel-private.


@always_inline
def _pbuf_ring_add(
    ring_addr: Int,
    ring_entries: Int,
    buf_addr: UInt64,
    buf_len: UInt32,
    bid: UInt16,
    buf_offset: Int,
    cur_tail: UInt16,
) -> None:
    """Write one ``struct io_uring_buf`` entry into the ring at
    index ``(cur_tail + buf_offset) & (ring_entries - 1)``.

    Does NOT advance the tail; caller calls ``_pbuf_ring_advance``
    after adding all batched entries with the right release
    ordering. This matches liburing's ``io_uring_buf_ring_add``.
    """
    var mask = ring_entries - 1
    var idx = (Int(cur_tail) + buf_offset) & mask
    var entry = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=ring_addr + idx * 16
    )
    # addr (offset 0, u64 LE)
    for i in range(8):
        (entry + i).init_pointee_copy(
            UInt8(Int((buf_addr >> UInt64(8 * i)) & 0xFF))
        )
    # len (offset 8, u32 LE)
    for i in range(4):
        (entry + 8 + i).init_pointee_copy(
            UInt8(Int((buf_len >> UInt32(8 * i)) & 0xFF))
        )
    # bid (offset 12, u16 LE)
    (entry + 12).init_pointee_copy(UInt8(Int(bid) & 0xFF))
    (entry + 13).init_pointee_copy(UInt8((Int(bid) >> 8) & 0xFF))
    # resv left as-is (overwritten by tail-advance for slot 0;
    # ignored by kernel for other slots).


@always_inline
def _pbuf_ring_get_tail(ring_addr: Int) -> UInt16:
    """Load the ring's tail field (kernel-shared u16 at offset 14
    of slot[0]) with relaxed ordering. App-side load only -- the
    kernel reads tail on every recv-buffer-select with acquire
    ordering, which is the publishing barrier."""
    var tail_ptr = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=ring_addr + 14
    )
    var lo = Int(tail_ptr.load())
    var hi = Int((tail_ptr + 1).load())
    return UInt16((hi << 8) | lo)


@always_inline
def _pbuf_ring_set_tail(ring_addr: Int, new_tail: UInt16) -> None:
    """Release-store the ring's tail field. Pairs with the
    kernel's acquire-load on every recv-buffer-select.
    """
    var tail_ptr = UnsafePointer[UInt8, MutUntrackedOrigin](
        unsafe_from_address=ring_addr + 14
    )
    # Use Atomic[u16] release store for cross-platform memory
    # ordering. On x86 this compiles to a regular mov + compiler
    # barrier; on ARM it emits the proper release-store instruction.
    var typed = tail_ptr.bitcast[Scalar[DType.uint16]]()
    Atomic[DType.uint16].store[ordering=Ordering.RELEASE](typed, new_tail)
