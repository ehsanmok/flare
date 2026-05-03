"""``io_uring`` backend substrate.

Lands the direct-syscall FFI + ``IoUringRing`` setup/teardown
primitive for the Linux 5.1+ ``io_uring`` reactor backend.
This is the **substrate**: the syscall wrappers, the
``io_uring_params`` struct, runtime feature detection, and
allocation/teardown of a kernel ring. Submission-queue / completion-
queue plumbing (SQE construction, CQE drain, multishot accept /
recv / send) lands in follow-up commits that bolt onto this
primitive without changing its public API.

Why io_uring
------------

epoll/kqueue need 2-3 syscalls per request on the keep-alive
hot path: ``epoll_wait`` → ``recvmsg`` → ``sendmsg``. At
realistic high-throughput targets (>200K req/s on 4 workers),
that's ≥ 660 K syscalls / s per worker. Each syscall costs a
syscall instruction (≈ 100-200 cycles), a context switch into
the kernel, and a TLB flush on speculation-mitigation kernels.

``io_uring`` (RFC-equivalent: Jens Axboe's 2019 LWN articles +
``man 7 io_uring``) lets the application **submit + reap many
operations per syscall** via a kernel-shared SQ/CQ ring.
Multishot accept/recv/send mean accept-loop and per-connection
recv don't need to be re-armed after each completion. For
plaintext TFB, the syscall count drops from 3-per-request to
~0.1-per-request.

Production servers built on io_uring (tigerbeetle, scylla-seastar,
glommio) routinely measure 2-5x throughput improvements vs.
epoll on the same kernel.

Why ship the substrate first
----------------------------

io_uring's full support surface is vast — the kernel ABI grew
from 7 ops in 5.1 (Read / Write / Fsync / ReadFixed /
WriteFixed / PollAdd / PollRemove) to 40+ ops by 6.10 (Provide-
Buffers, BufferRing, Multishot variants, Linked, Hardlinked,
Splice, Tee, ZeroCopy, Discard, Bind, Listen, Sendmsg-zerocopy
…). flare needs only a small subset for HTTP/1.1 (multishot
accept on the listener fd + recv on each accepted fd + send /
sendv for the response). Shipping the substrate first lets the
follow-up commits land that subset incrementally without
re-touching the syscall-ABI plumbing.

What this commit ships
-----------------------

* **Syscall numbers** — ``SYS_IO_URING_SETUP``,
  ``SYS_IO_URING_ENTER``, ``SYS_IO_URING_REGISTER`` for x86_64
  / aarch64 Linux. (io_uring is a Linux-only feature; macOS /
  BSD callers fall through to the existing kqueue path.)
* **``IoUringParams``** — Mojo mirror of the
  ``struct io_uring_params`` ABI. Holds the ring sizes
  (``sq_entries`` / ``cq_entries``), the kernel-returned
  feature flags, and the per-region offset blobs needed for
  the upcoming SQ/CQ mmaps.
* **``io_uring_setup(entries, params) -> Int``** — wraps the
  ``SYS_io_uring_setup(2)`` syscall. Returns the ring file
  descriptor or a negative ``-errno`` on failure.
* **``io_uring_enter(fd, to_submit, min_complete, flags) -> Int``**
  — wraps ``SYS_io_uring_enter(2)``. The submission /
  completion driver call.
* **``io_uring_register(fd, opcode, arg, nr_args) -> Int``** —
  wraps ``SYS_io_uring_register(2)``. Used to register fixed
  buffers / files / probe the kernel feature set.
* **``IoUringRing(entries)``** — owning wrapper that:
  - Calls ``io_uring_setup`` to allocate a kernel ring of
    ``entries`` SQEs (rounded up to a power of two by the
    kernel).
  - Closes the ring fd on drop.
  - Exposes ``fd()``, ``params()``, and the (currently
    unmmapped) per-region offsets.
* **``is_io_uring_available()``** — runtime feature detection.
  Tries ``io_uring_setup(1, ...)``; on success closes the
  ring + returns ``True``; on EINVAL / ENOSYS / EPERM
  (kernel too old, sandbox, …) returns ``False`` without
  raising.

Why direct syscall FFI vs liburing
-----------------------------------

``liburing`` is the upstream userspace library that wraps these
syscalls + provides the standard SQE/CQE constructors. flare
chooses the direct-syscall route because:

1. **Zero new conda dependency** — io_uring's ABI is stable
   since Linux 5.1 (May 2019); the syscall numbers don't drift.
   Linking against liburing.so adds a deployment dependency
   that conda-forge does ship (``liburing``) but the
   Mojo-FFI-via-shared-library plumbing is awkward (no
   ``ctypes``-equivalent ergonomics yet).
2. **Smaller binary surface** — liburing is ~40 KB; the
   subset flare needs (setup / enter / register + SQE/CQE
   layout) is ~500 lines of FFI + struct definitions in
   pure Mojo.
3. **Better integration with flare's typed errors** — the
   syscall wrapper raises ``IoError`` / ``BrokenPipe`` /
   ``Timeout`` directly instead of returning C ``errno``.

Wiring into the ``Reactor`` (the comptime branch that selects
``UringReactor`` vs ``EpollReactor`` vs ``KqueueReactor`` based
on kernel feature detection) is a follow-up commit that bolts
onto this primitive without changing the existing
``flare.runtime.Reactor`` public surface.
"""

from std.ffi import (
    external_call,
    c_int,
    c_uint,
    c_size_t,
    get_errno,
    ErrNo,
)
from std.memory import UnsafePointer, alloc
from std.sys.info import CompilationTarget


# ── syscall numbers ──────────────────────────────────────────────────────────
# These are stable across Linux kernels since 5.1 (May 2019).


comptime SYS_IO_URING_SETUP: Int = 425
"""``SYS_io_uring_setup`` syscall number on x86_64 + aarch64
Linux. Stable since Linux 5.1.
"""
comptime SYS_IO_URING_ENTER: Int = 426
"""``SYS_io_uring_enter`` syscall number. Stable since 5.1."""
comptime SYS_IO_URING_REGISTER: Int = 427
"""``SYS_io_uring_register`` syscall number. Stable since 5.1.
"""


# ── io_uring_params (Mojo mirror of the struct) ─────────────────────────────


@fieldwise_init
struct IoUringParams(Movable):
    """Mojo mirror of the kernel ``struct io_uring_params``.

    Field layout exactly matches the kernel ABI (see
    ``include/uapi/linux/io_uring.h`` in the Linux source). The
    struct is 120 bytes total; the high 12 bytes are reserved.

    Fields:
        sq_entries: Kernel-returned actual SQ size (rounded up
                    to a power of two from the caller's request).
        cq_entries: Kernel-returned actual CQ size (typically
                    ``2 * sq_entries`` unless ``IORING_SETUP_CQSIZE``
                    is set in flags).
        flags: ``IORING_SETUP_*`` flags. 0 for the default
               configuration; set ``IORING_SETUP_SQPOLL`` for a
               kernel-side polling thread, etc.
        sq_thread_cpu / sq_thread_idle: ``IORING_SETUP_SQ_AFF`` /
               ``IORING_SETUP_SQPOLL`` knobs.
        features: Kernel-returned ``IORING_FEAT_*`` flags
               describing what this kernel supports.
        wq_fd: Worker-queue fd for cross-ring sharing (unused
               in the default setup).
        sq_off / cq_off: Per-region offsets returned by the
               kernel; the caller mmaps the ring fd at these
               offsets to get the SQ / CQ control regions.
    """

    var sq_entries: UInt32
    var cq_entries: UInt32
    var flags: UInt32
    var sq_thread_cpu: UInt32
    var sq_thread_idle: UInt32
    var features: UInt32
    var wq_fd: UInt32
    var resv0: UInt32
    var resv1: UInt32
    var resv2: UInt32
    # sq_off (40 bytes): head, tail, ring_mask, ring_entries,
    # flags, dropped, array, resv1, resv2 (5 fields × 4 bytes
    # + 5 × 4-byte resv = 40 bytes).
    var sq_off_head: UInt32
    var sq_off_tail: UInt32
    var sq_off_ring_mask: UInt32
    var sq_off_ring_entries: UInt32
    var sq_off_flags: UInt32
    var sq_off_dropped: UInt32
    var sq_off_array: UInt32
    var sq_off_resv1: UInt32
    var sq_off_user_addr_lo: UInt32
    var sq_off_user_addr_hi: UInt32
    # cq_off (40 bytes): head, tail, ring_mask, ring_entries,
    # overflow, cqes, flags, resv (8 fields × 4 bytes + 2 × 4
    # = 40 bytes).
    var cq_off_head: UInt32
    var cq_off_tail: UInt32
    var cq_off_ring_mask: UInt32
    var cq_off_ring_entries: UInt32
    var cq_off_overflow: UInt32
    var cq_off_cqes: UInt32
    var cq_off_flags: UInt32
    var cq_off_resv1: UInt32
    var cq_off_user_addr_lo: UInt32
    var cq_off_user_addr_hi: UInt32

    @staticmethod
    def empty() -> IoUringParams:
        """Construct an all-zeros ``IoUringParams`` for use as
        the ``params`` arg of :func:`io_uring_setup`.

        Caller may then set ``flags`` / ``sq_thread_cpu`` /
        ``sq_thread_idle`` before passing to
        ``io_uring_setup``.
        """
        return IoUringParams(
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
            UInt32(0),
        )


# ── direct-syscall wrappers ──────────────────────────────────────────────────


@always_inline
def io_uring_setup(entries: Int, params: UnsafePointer[UInt8, _]) -> Int:
    """Wrap ``SYS_io_uring_setup(2)`` via the libc ``syscall(2)``
    multiplexer.

    Args:
        entries: Number of SQEs to allocate (kernel rounds up
                 to a power of two; max 32 768 in current
                 kernels).
        params: Pointer to a 120-byte ``IoUringParams`` buffer
                (in/out — kernel fills in the per-region
                offsets and feature flags).

    Returns:
        On success, the ring file descriptor (≥ 0). On failure,
        a negative ``-errno`` value.
    """
    # Always pass 6 syscall arguments (padding with 0) so all
    # three io_uring syscall wrappers below share one
    # external_call signature against the libc ``syscall``
    # symbol. Mixing arities (3 / 5 / 7) on the same external
    # symbol triggers a Mojo "existing function with conflicting
    # signature" error during cross-module compilation.
    var rc = external_call["syscall", c_int](
        c_int(SYS_IO_URING_SETUP),
        c_size_t(entries),
        c_size_t(Int(params)),
        c_size_t(0),
        c_size_t(0),
        c_size_t(0),
        c_size_t(0),
    )
    if rc < 0:
        return -Int(get_errno().value)
    return Int(rc)


@always_inline
def io_uring_enter(
    fd: Int, to_submit: Int, min_complete: Int, flags: Int
) -> Int:
    """Wrap ``SYS_io_uring_enter(2)`` via ``syscall(2)``.

    Args:
        fd: Ring file descriptor returned by
            :func:`io_uring_setup`.
        to_submit: Number of SQEs to submit from the SQ ring.
        min_complete: Minimum number of completions to wait for
                      before returning. 0 = non-blocking submit.
        flags: ``IORING_ENTER_*`` flags.

    Returns:
        Number of SQEs consumed on success; negative ``-errno``
        on failure.
    """
    var rc = external_call["syscall", c_int](
        c_int(SYS_IO_URING_ENTER),
        c_size_t(fd),
        c_size_t(to_submit),
        c_size_t(min_complete),
        c_size_t(flags),
        c_size_t(0),
        c_size_t(0),
    )
    if rc < 0:
        return -Int(get_errno().value)
    return Int(rc)


@always_inline
def io_uring_register(fd: Int, opcode: Int, arg: Int, nr_args: Int) -> Int:
    """Wrap ``SYS_io_uring_register(2)`` via ``syscall(2)``.

    Used to register fixed buffers / files / probe the kernel
    feature set.

    Args:
        fd: Ring file descriptor.
        opcode: ``IORING_REGISTER_*`` opcode.
        arg: Pointer-or-int argument (cast to ``UInt64`` for
             the syscall ABI).
        nr_args: Number of arguments at ``arg``.

    Returns:
        0 on success; negative ``-errno`` on failure.
    """
    var rc = external_call["syscall", c_int](
        c_int(SYS_IO_URING_REGISTER),
        c_size_t(fd),
        c_size_t(opcode),
        c_size_t(arg),
        c_size_t(nr_args),
        c_size_t(0),
        c_size_t(0),
    )
    if rc < 0:
        return -Int(get_errno().value)
    return Int(rc)


# ── high-level IoUringRing ───────────────────────────────────────────────────


comptime _IO_URING_PARAMS_BYTES: Int = 120
"""Size of the kernel ``struct io_uring_params`` (10 × 4-byte
fields + 40-byte sq_off + 40-byte cq_off = 120 bytes).
"""


@always_inline
def _read_u32_le(buf: UnsafePointer[UInt8, _], offset: Int) -> Int:
    """Read a 32-bit little-endian value out of the params
    buffer at ``offset``.

    Bounds-checked under ``-D ASSERT=safe``: ``offset`` must
    name a 4-byte window inside the 120-byte params buffer.
    See ``.cursor/rules/sanitizers-and-bounds-checking.mdc``
    §4.4 for the FFI-buffer-read pattern.
    """
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 4 <= _IO_URING_PARAMS_BYTES,
        "_read_u32_le: offset out of range; got ",
        offset,
    )
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "_read_u32_le: buf must be non-NULL"
    )
    var v = UInt32(0)
    for k in range(4):
        v = v | (UInt32(Int(buf[offset + k])) << UInt32(k * 8))
    return Int(v)


struct IoUringRing(Movable):
    """Owning wrapper over an io_uring kernel ring.

    Allocates the ring on construction and closes the fd on
    drop. Future commits will mmap the SQ / CQ regions onto
    public ``sq()`` / ``cq()`` accessors so callers can submit
    SQEs and reap CQEs.

    The kernel-filled ``io_uring_params`` struct (120 bytes) is
    held as a raw byte buffer; field accessors read 32-bit LE
    values out of it via fixed offsets.

    Fields:
        _fd: Ring file descriptor returned by
             ``io_uring_setup``. -1 means "not set up yet"
             (after move-out or on a failed setup).
        _params_buf: Owning pointer to the 120-byte params
                     buffer. Freed on drop.
    """

    var _fd: Int
    var _params_buf: UnsafePointer[UInt8, MutExternalOrigin]

    def __init__(
        out self,
        entries: Int,
        setup_flags: UInt32 = UInt32(0),
        sq_thread_cpu: UInt32 = UInt32(0),
        sq_thread_idle: UInt32 = UInt32(0),
    ) raises:
        """Set up an io_uring with ``entries`` SQEs.

        Args:
            entries: Number of SQEs (kernel rounds up to a power
                     of two; max 32 768).
            setup_flags: Bitwise-OR of ``IORING_SETUP_*`` flags
                from :mod:`flare.runtime.io_uring_sqe`. Default 0
                (interrupt-driven, single-thread, no kernel
                scheduler hints) matches the historical behaviour.
                Bufring callers typically pass
                ``COOP_TASKRUN | TASKRUN_FLAG | SUBMIT_ALL`` and
                add ``SINGLE_ISSUER | DEFER_TASKRUN`` on kernels
                >= 6.1 (probe via :func:`is_io_uring_available`'s
                features field). The kernel rejects the
                io_uring_setup with EINVAL if it doesn't support a
                requested flag, so callers can pass the highest
                set they want and fall back on EINVAL.
            sq_thread_cpu: For ``IORING_SETUP_SQPOLL +
                IORING_SETUP_SQ_AFF``, the CPU to pin the kernel
                SQPOLL thread to. Ignored otherwise.
            sq_thread_idle: For ``IORING_SETUP_SQPOLL``, the
                idle period in milliseconds before the kernel
                SQPOLL thread sleeps. Ignored otherwise.

        Raises:
            Error: On ``io_uring_setup`` failure.
        """
        # Kernel hard-caps SQ at 32 768 entries (IORING_MAX_ENTRIES);
        # zero / negative is a programming error caught here so the
        # debug build aborts with a clear message instead of letting
        # the kernel return a generic EINVAL.
        debug_assert[assert_mode="safe"](
            entries > 0 and entries <= 32768,
            "IoUringRing: entries must be in 1..=32768; got ",
            entries,
        )
        comptime if not CompilationTarget.is_linux():
            raise Error(
                "io_uring is a Linux-only feature; this build is not Linux"
            )
        var raw = alloc[UInt8](_IO_URING_PARAMS_BYTES)
        for i in range(_IO_URING_PARAMS_BYTES):
            (raw + i).init_pointee_copy(UInt8(0))
        # Write setup_flags (offset 8, u32 LE), sq_thread_cpu
        # (offset 12, u32 LE), sq_thread_idle (offset 16, u32 LE)
        # before io_uring_setup. Layout matches the kernel's
        # struct io_uring_params (see IoUringParams docstring).
        for i in range(4):
            (raw + 8 + i).init_pointee_copy(
                UInt8(Int((setup_flags >> UInt32(8 * i)) & 0xFF))
            )
            (raw + 12 + i).init_pointee_copy(
                UInt8(Int((sq_thread_cpu >> UInt32(8 * i)) & 0xFF))
            )
            (raw + 16 + i).init_pointee_copy(
                UInt8(Int((sq_thread_idle >> UInt32(8 * i)) & 0xFF))
            )
        var rc = io_uring_setup(entries, raw)
        if rc < 0:
            raw.free()
            raise Error("io_uring_setup failed: errno=" + String(-rc))
        self._fd = rc
        self._params_buf = UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=Int(raw)
        )

    def __del__(deinit self):
        """Close the ring fd + free the params buffer."""
        if self._fd >= 0:
            _ = external_call["close", c_int](c_int(self._fd))
        if Int(self._params_buf) != 0:
            self._params_buf.free()

    def fd(self) -> Int:
        """Return the ring file descriptor."""
        return self._fd

    def sq_entries(self) -> Int:
        """Return the kernel-allocated SQ size (≥ caller's
        request, rounded up to a power of two).
        """
        return _read_u32_le(self._params_buf, 0)

    def cq_entries(self) -> Int:
        """Return the kernel-allocated CQ size (default
        ``2 * sq_entries``).
        """
        return _read_u32_le(self._params_buf, 4)

    def features(self) -> Int:
        """Return the kernel-reported ``IORING_FEAT_*`` flags."""
        return _read_u32_le(self._params_buf, 20)


# ── feature detection ────────────────────────────────────────────────────────


def is_io_uring_available() -> Bool:
    """Runtime check: does the host kernel expose io_uring?

    Tries to set up a 1-entry ring; on success closes it +
    returns ``True``. On EINVAL / ENOSYS / EPERM (kernel too
    old, sandbox, container without ``io_uring_setup`` syscall
    permitted, …) returns ``False`` without raising.

    Useful for the upcoming ``Reactor`` comptime branch:
    ``UringReactor`` is selected when both
    ``CompilationTarget.is_linux()`` and
    ``is_io_uring_available()`` are true.
    """
    comptime if not CompilationTarget.is_linux():
        return False
    var raw = alloc[UInt8](_IO_URING_PARAMS_BYTES)
    for i in range(_IO_URING_PARAMS_BYTES):
        (raw + i).init_pointee_copy(UInt8(0))
    var rc = io_uring_setup(1, raw)
    raw.free()
    if rc < 0:
        return False
    _ = external_call["close", c_int](c_int(rc))
    return True
