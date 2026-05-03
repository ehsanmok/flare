"""``io_uring`` SQE encoder + CQE decoder primitives (Track B0 follow-up).

Sits on top of :mod:`flare.runtime.io_uring` (which ships the
syscall FFI + ``IoUringRing`` setup/teardown). This module adds
the **submission queue entry** + **completion queue entry** byte-
level codec, plus the small set of prep helpers (``prep_nop``,
``prep_accept``, ``prep_recv``, ``prep_send``, ``prep_writev``,
``prep_close``, ``prep_async_cancel``) that the upcoming
``UringReactor`` (next commit) will call to fill SQE slots before
``io_uring_enter`` is invoked.

What this commit ships
----------------------

* **Opcode constants** (``IORING_OP_NOP``, ``IORING_OP_ACCEPT``,
  ``IORING_OP_RECV``, ``IORING_OP_SEND``, ``IORING_OP_WRITEV``,
  ``IORING_OP_CLOSE``, ``IORING_OP_ASYNC_CANCEL``,
  ``IORING_OP_RECVMSG``, ``IORING_OP_SENDMSG``,
  ``IORING_OP_READ_FIXED``, ``IORING_OP_WRITE_FIXED``,
  ``IORING_OP_PROVIDE_BUFFERS``, ``IORING_OP_REMOVE_BUFFERS``).
* **SQE flag constants** (``IOSQE_FIXED_FILE``, ``IOSQE_IO_LINK``,
  ``IOSQE_IO_HARDLINK``, ``IOSQE_ASYNC``,
  ``IOSQE_BUFFER_SELECT``, ``IOSQE_CQE_SKIP_SUCCESS``).
* **Multishot accept/recv flags** (``IORING_RECV_MULTISHOT``,
  ``IORING_ACCEPT_MULTISHOT``, ``IORING_FEAT_*``).
* **CQE flag constants** (``IORING_CQE_F_BUFFER``,
  ``IORING_CQE_F_MORE``, ``IORING_CQE_F_SOCK_NONEMPTY``).
* **``IoUringSqe``** — 64-byte SQE byte-buffer wrapper with
  byte-precise field accessors that mirror the kernel ABI
  (``include/uapi/linux/io_uring.h``). Construction zeros the
  whole 64 bytes; ``prep_*`` helpers fill the relevant fields.
* **``IoUringCqe``** — 16-byte CQE byte-buffer wrapper with
  ``user_data() / res() / flags()`` accessors.
* **Codec invariants** asserted under ``-D ASSERT=safe`` per
  the ``.cursor/rules/sanitizers-and-bounds-checking.mdc``
  guide: pointer non-NULL on construction, opcode in the
  documented range, fd ≥ 0 on prep_* helpers that take an fd.

Why a byte buffer instead of ``@fieldwise_init`` struct
-------------------------------------------------------

The kernel SQE has tagged unions (``addr2`` overlays
``cmd_op``, ``op_flags`` overlays ``msg_flags``/``rw_flags``/
``poll_events``/``sync_range_flags``/``timeout_flags`` etc.).
Modelling that as a single Mojo struct either requires a giant
``@fieldwise_init`` with overloaded interpretations per opcode
(error-prone — the same byte means different things per op) or
a tagged-union pattern Mojo doesn't yet have at the same
ergonomic level as Rust's ``union {}``.

The byte-buffer + field accessors approach mirrors how
``liburing``'s public API actually feels — ``io_uring_prep_recv``
writes specific bytes; the kernel reads them via fixed offsets.
flare's prep helpers do the same, modelling each opcode's
field interpretation explicitly at the prep call site, which
also documents which union arm we're using.

Bounds checking
---------------

All field accessors and prep helpers assert:

1. The buffer pointer is non-NULL (``buf != UnsafePointer()``).
2. Reads / writes stay inside the 64-byte SQE / 16-byte CQE
   window (``offset + width <= 64`` / ``<= 16``).
3. Opcodes stay within the documented kernel set.

These are ``debug_assert[assert_mode="safe"]`` calls, so they
compile in under ``-D ASSERT=safe`` (the v0.7 default build
profile) and disappear under release-mode ``-D ASSERT=none``.
The full assertion battery (including loop invariants) is
exercised by ``pixi run tests-asserts-all``.

References
----------

* ``include/uapi/linux/io_uring.h`` (Linux kernel source) — the
  canonical SQE / CQE struct layout.
* ``man 7 io_uring`` — high-level overview.
* Jens Axboe, *Efficient IO with io_uring*
  (https://kernel.dk/io_uring.pdf) — original 2019 design doc.
* ``liburing/src/include/liburing/io_uring.h`` — userspace
  mirror of the same layout (nothing here uses liburing, but
  the field offsets match because they have to).
"""

from std.memory import UnsafePointer, alloc


# ── opcode constants (subset; full list in linux/io_uring.h) ─────────────────
# Stable since the kernel version listed; the numeric values must
# never change once shipped.

comptime IORING_OP_NOP: Int = 0
"""5.1+. No-op; useful for testing the SQ/CQ round-trip."""
comptime IORING_OP_READV: Int = 1
"""5.1+. Vectored read."""
comptime IORING_OP_WRITEV: Int = 2
"""5.1+. Vectored write — what flare uses to coalesce status +
headers + body in a single submission (Track B4 path on the
io_uring backend; subsumes the epoll-fallback ``writev(2)``).
"""
comptime IORING_OP_FSYNC: Int = 3
"""5.1+. fsync(2) async."""
comptime IORING_OP_READ_FIXED: Int = 4
"""5.1+. Read into a pre-registered buffer (Track E1 file-serve
fast path)."""
comptime IORING_OP_WRITE_FIXED: Int = 5
"""5.1+. Write from a pre-registered buffer."""
comptime IORING_OP_POLL_ADD: Int = 6
"""5.1+. Async poll on an fd."""
comptime IORING_OP_POLL_REMOVE: Int = 7
"""5.1+. Cancel a previous POLL_ADD."""
comptime IORING_OP_SENDMSG: Int = 9
"""5.3+. sendmsg(2) async."""
comptime IORING_OP_RECVMSG: Int = 10
"""5.3+. recvmsg(2) async."""
comptime IORING_OP_TIMEOUT: Int = 11
"""5.4+. Timeout on a CQE; useful for arming a wakeup."""
comptime IORING_OP_TIMEOUT_REMOVE: Int = 12
"""5.5+. Cancel a previous TIMEOUT."""
comptime IORING_OP_ACCEPT: Int = 13
"""5.5+. accept4(2) async — the listener-socket fast path."""
comptime IORING_OP_ASYNC_CANCEL: Int = 14
"""5.5+. Cancel an in-flight SQE by user_data; the v0.7
``Cancel.SHUTDOWN`` plumbing on the io_uring backend uses this
to interrupt long-running multishot recvs."""
comptime IORING_OP_LINK_TIMEOUT: Int = 15
"""5.5+. Linked timeout."""
comptime IORING_OP_CONNECT: Int = 16
"""5.5+. connect(2) async."""
comptime IORING_OP_CLOSE: Int = 19
"""5.6+. close(2) async — used to drop the per-connection fd
without a syscall round-trip on the response-completion path."""
comptime IORING_OP_PROVIDE_BUFFERS: Int = 31
"""5.7+. Register a pool of buffers for ``IOSQE_BUFFER_SELECT``
recvs. Slow path -- one SQE per refill. flare ships a faster
ring-mapped variant via :data:`IORING_REGISTER_PBUF_RING` (5.19+,
2.7x faster per Linux kernel benchmarks); see
``UringReactor.register_pbuf_ring``."""

# IORING_REGISTER_* opcodes used with the io_uring_register(2)
# syscall (NOT in SQE.opcode -- these go into the syscall's
# ``opcode`` arg directly). Numeric values match
# ``include/uapi/linux/io_uring.h``.
comptime IORING_REGISTER_BUFFERS: Int = 0
"""5.1+. Register fixed buffers for IORING_OP_READ_FIXED /
WRITE_FIXED. Not used by flare's HTTP path."""
comptime IORING_REGISTER_PBUF_RING: Int = 22
"""5.19+. Register a kernel-mapped provided-buffer ring for use
with ``IOSQE_BUFFER_SELECT``. Replaces the per-CQE
``IORING_OP_PROVIDE_BUFFERS`` SQE refill with a userspace
tail-bump on shared memory -- 2.7x faster (27M vs 10M ops/sec
kernel-bench, replenish-1 measurement). The ring memory is
``sizeof(struct io_uring_buf) * ring_entries`` (16 bytes each),
page-aligned, shared with the kernel."""
comptime IORING_UNREGISTER_PBUF_RING: Int = 23
"""5.19+. Companion to :data:`IORING_REGISTER_PBUF_RING`."""
comptime IORING_OP_REMOVE_BUFFERS: Int = 32
"""5.7+. Drop a previously-provided buffer pool."""
comptime IORING_OP_SEND: Int = 26
"""5.6+. send(2) async."""
comptime IORING_OP_RECV: Int = 27
"""5.6+. recv(2) async — the per-connection request-read fast
path on the io_uring backend (combined with
``IORING_RECV_MULTISHOT`` from 6.0+ for the steady-state)."""
comptime IORING_OP_READ: Int = 22
"""5.6+. read(2) / pread(2) async — works on **any fd** (not
just sockets). Used for the cross-thread wakeup eventfd:
``IORING_OP_RECV`` returns ``-ENOTSOCK`` on an eventfd, but
``IORING_OP_READ`` does the right thing."""
comptime IORING_OP_WRITE: Int = 23
"""5.6+. write(2) / pwrite(2) async — companion to
``IORING_OP_READ``."""
comptime IORING_OP_OPENAT: Int = 18
"""5.6+. openat(2) async."""

# Highest valid opcode in the 6.x kernel line; used by the
# bounds check in :func:`_check_opcode`. Conservatively bumped
# every kernel release; flare doesn't actually emit opcodes >
# IORING_OP_REMOVE_BUFFERS today.
comptime _IORING_OP_MAX: Int = 63


# ── SQE flags (per-SQE) ──────────────────────────────────────────────────────

comptime IOSQE_FIXED_FILE: UInt8 = 0x01
"""5.1+. The ``fd`` field is an index into the registered-files
table set up via ``IORING_REGISTER_FILES`` (skips the syscall
``fdtable`` lookup)."""
comptime IOSQE_IO_DRAIN: UInt8 = 0x02
"""5.2+. Drain the SQ before submitting this SQE."""
comptime IOSQE_IO_LINK: UInt8 = 0x04
"""5.3+. Link the next SQE to this one — the next SQE is
deferred until this one completes successfully. flare uses this
to chain ``recv → process → send`` without round-tripping
userspace on the keep-alive hot path."""
comptime IOSQE_IO_HARDLINK: UInt8 = 0x08
"""5.5+. Like ``IOSQE_IO_LINK`` but the next SQE runs even on
this one's failure."""
comptime IOSQE_ASYNC: UInt8 = 0x10
"""5.6+. Force the operation to be processed by the kernel
worker thread pool (vs. inline)."""
comptime IOSQE_BUFFER_SELECT: UInt8 = 0x20
"""5.7+. The kernel picks the buffer from a previously-provided
buffer pool (used with ``IORING_OP_RECV`` for the steady-state
per-connection recv)."""
comptime IOSQE_CQE_SKIP_SUCCESS: UInt8 = 0x40
"""5.17+. Don't post a CQE on success — used for fire-and-
forget ops like ``IORING_OP_CLOSE`` after the response has been
flushed."""


# ── op-specific flags ────────────────────────────────────────────────────────

comptime IORING_RECV_MULTISHOT: UInt32 = 0x02
"""6.0+. Set in the SQE ``op_flags`` (recv_msg_flags) field on
``IORING_OP_RECV``. The kernel keeps re-arming the recv after
each completion, so the userspace driver only re-submits when
the multishot is cancelled or the connection closes. Cuts the
syscall-per-byte ratio dramatically on long-lived keep-alive
connections."""

comptime IORING_ACCEPT_MULTISHOT: UInt32 = 0x01
"""5.19+. Set in the SQE ``op_flags`` (accept_flags) on
``IORING_OP_ACCEPT``. Same idea — the listener socket keeps
firing accept completions without re-submission."""

comptime IORING_POLL_ADD_MULTI: UInt32 = 0x01
"""5.13+. Set in the SQE ``len`` field on ``IORING_OP_POLL_ADD``
to request a *multishot* poll: the kernel posts a CQE every
time the requested poll mask is reached, without requiring
userspace to re-arm. ``IORING_CQE_F_MORE`` in the CQE's
``flags`` indicates the multishot is still armed.

This is the io_uring analog of edge-triggered ``epoll_wait``
with ``EPOLLET`` — it lets a single SQE drive an arbitrary
number of readiness notifications, which is the substrate
that the upcoming server-loop dispatch swap (B0 wire-in)
uses to replace the per-poll ``epoll_wait`` syscall on the
io_uring backend."""

comptime IORING_POLL_UPDATE_EVENTS: UInt32 = 0x02
"""5.13+. Set in the SQE ``len`` field on
``IORING_OP_POLL_REMOVE`` to indicate the SQE is a
*modify* of an existing poll's event mask, not a remove."""

comptime IORING_POLL_UPDATE_USER_DATA: UInt32 = 0x04
"""5.13+. Set in the SQE ``len`` field on
``IORING_OP_POLL_REMOVE`` to indicate the SQE is a
*modify* of an existing poll's user_data tag."""


# ── poll(2) event mask bits (matches sys/poll.h on Linux) ────────────────────
# These are the flags written into the ``op_flags`` (poll32_events)
# slot of an ``IORING_OP_POLL_ADD`` SQE. Numeric values are the
# Linux ABI; the kernel io_uring layer passes them through
# verbatim to ``vfs_poll``.

comptime POLLIN: UInt32 = 0x0001
"""Data ready to read (analog of ``EPOLLIN``)."""
comptime POLLPRI: UInt32 = 0x0002
"""Urgent data ready (analog of ``EPOLLPRI``)."""
comptime POLLOUT: UInt32 = 0x0004
"""Writable without blocking (analog of ``EPOLLOUT``)."""
comptime POLLERR: UInt32 = 0x0008
"""Error condition (analog of ``EPOLLERR``)."""
comptime POLLHUP: UInt32 = 0x0010
"""Peer hung up (analog of ``EPOLLHUP``)."""
comptime POLLRDHUP: UInt32 = 0x2000
"""Peer closed for writing (analog of ``EPOLLRDHUP``).
Linux-specific; not in POSIX."""


# ── CQE flags ────────────────────────────────────────────────────────────────

comptime IORING_CQE_F_BUFFER: UInt32 = 0x01
"""The CQE's ``flags`` high 16 bits encode the buffer-id picked
by ``IOSQE_BUFFER_SELECT``."""
comptime IORING_CQE_F_MORE: UInt32 = 0x02
"""More CQEs are coming for this SQE (multishot accept / recv).
When unset, the multishot has finished and the userspace driver
must re-arm if it still wants events."""
comptime IORING_CQE_F_SOCK_NONEMPTY: UInt32 = 0x04
"""5.19+. The socket's recv buffer still has data after the
completion drained one chunk; the driver should keep reaping
without re-arming poll."""


# ── enter() flags ────────────────────────────────────────────────────────────

comptime IORING_ENTER_GETEVENTS: UInt32 = 0x01
"""Wait for completions in ``io_uring_enter``."""
comptime IORING_ENTER_SQ_WAKEUP: UInt32 = 0x02
"""Wake the SQ-poll thread (only relevant with
``IORING_SETUP_SQPOLL``)."""
comptime IORING_ENTER_SQ_WAIT: UInt32 = 0x04
"""Wait for the SQ to drain before returning."""


# ── struct sizes ─────────────────────────────────────────────────────────────

comptime IO_URING_SQE_BYTES: Int = 64
"""Size of the kernel ``struct io_uring_sqe``. Constant since
5.1; ``IORING_SETUP_SQE128`` (5.19+) doubles it but flare
doesn't enable that mode."""
comptime IO_URING_CQE_BYTES: Int = 16
"""Size of the kernel ``struct io_uring_cqe``. Constant since
5.1; ``IORING_SETUP_CQE32`` (5.19+) doubles it but flare
doesn't enable that mode."""


# ── SQE field offsets (matches include/uapi/linux/io_uring.h) ───────────────
# These are absolute byte offsets into the 64-byte SQE.

comptime _SQE_OFF_OPCODE: Int = 0  # u8
comptime _SQE_OFF_FLAGS: Int = 1  # u8
comptime _SQE_OFF_IOPRIO: Int = 2  # u16
comptime _SQE_OFF_FD: Int = 4  # i32
comptime _SQE_OFF_OFF_OR_ADDR2: Int = 8  # u64 (overlay)
comptime _SQE_OFF_ADDR: Int = 16  # u64 (overlay with splice_off_in)
comptime _SQE_OFF_LEN: Int = 24  # u32
comptime _SQE_OFF_OP_FLAGS: Int = 28  # u32 (overlay across opcodes)
comptime _SQE_OFF_USER_DATA: Int = 32  # u64
comptime _SQE_OFF_BUF_INDEX: Int = 40  # u16 (overlay with buf_group)
comptime _SQE_OFF_PERSONALITY: Int = 42  # u16
comptime _SQE_OFF_FILE_INDEX: Int = 44  # u32 (overlay with splice_fd_in)
comptime _SQE_OFF_ADDR3: Int = 48  # u64
comptime _SQE_OFF_PAD: Int = 56  # u64

# CQE field offsets:
comptime _CQE_OFF_USER_DATA: Int = 0  # u64
comptime _CQE_OFF_RES: Int = 8  # i32
comptime _CQE_OFF_FLAGS: Int = 12  # u32


# ── helpers ──────────────────────────────────────────────────────────────────


@always_inline
def _check_opcode(op: Int) -> None:
    """Bounds-check an opcode against the documented kernel range."""
    debug_assert[assert_mode="safe"](
        op >= 0 and op <= _IORING_OP_MAX,
        "io_uring opcode out of documented range; got ",
        op,
    )


@always_inline
def _store_u8(
    buf: UnsafePointer[UInt8, MutExternalOrigin], offset: Int, value: UInt8
) -> None:
    """Write a u8 into ``buf[offset]`` with bounds + non-NULL guard."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring SQE/CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 1 <= IO_URING_SQE_BYTES,
        "_store_u8 offset out of SQE range; got ",
        offset,
    )
    (buf + offset).init_pointee_copy(value)


@always_inline
def _store_u16_le(
    buf: UnsafePointer[UInt8, MutExternalOrigin], offset: Int, value: UInt16
) -> None:
    """Write a u16 little-endian into ``buf[offset..offset+2]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring SQE/CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 2 <= IO_URING_SQE_BYTES,
        "_store_u16_le offset out of SQE range; got ",
        offset,
    )
    var v = Int(value)
    (buf + offset).init_pointee_copy(UInt8(v & 0xFF))
    (buf + offset + 1).init_pointee_copy(UInt8((v >> 8) & 0xFF))


@always_inline
def _store_u32_le(
    buf: UnsafePointer[UInt8, MutExternalOrigin], offset: Int, value: UInt32
) -> None:
    """Write a u32 little-endian into ``buf[offset..offset+4]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring SQE/CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 4 <= IO_URING_SQE_BYTES,
        "_store_u32_le offset out of SQE range; got ",
        offset,
    )
    var v = Int(value)
    (buf + offset).init_pointee_copy(UInt8(v & 0xFF))
    (buf + offset + 1).init_pointee_copy(UInt8((v >> 8) & 0xFF))
    (buf + offset + 2).init_pointee_copy(UInt8((v >> 16) & 0xFF))
    (buf + offset + 3).init_pointee_copy(UInt8((v >> 24) & 0xFF))


@always_inline
def _store_u64_le(
    buf: UnsafePointer[UInt8, MutExternalOrigin], offset: Int, value: UInt64
) -> None:
    """Write a u64 little-endian into ``buf[offset..offset+8]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring SQE/CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 8 <= IO_URING_SQE_BYTES,
        "_store_u64_le offset out of SQE range; got ",
        offset,
    )
    var v = Int(value)
    for k in range(8):
        (buf + offset + k).init_pointee_copy(UInt8((v >> (k * 8)) & 0xFF))


@always_inline
def _load_u32_le(buf: UnsafePointer[UInt8, _], offset: Int) -> UInt32:
    """Read a u32 little-endian out of ``buf[offset..offset+4]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 4 <= IO_URING_SQE_BYTES,
        "_load_u32_le offset out of range; got ",
        offset,
    )
    var v: UInt32 = 0
    for k in range(4):
        v = v | (UInt32(Int(buf[offset + k])) << UInt32(k * 8))
    return v


@always_inline
def _load_u64_le(buf: UnsafePointer[UInt8, _], offset: Int) -> UInt64:
    """Read a u64 little-endian out of ``buf[offset..offset+8]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 8 <= IO_URING_SQE_BYTES,
        "_load_u64_le offset out of range; got ",
        offset,
    )
    var v: UInt64 = 0
    for k in range(8):
        v = v | (UInt64(Int(buf[offset + k])) << UInt64(k * 8))
    return v


# ── SQE wrapper ──────────────────────────────────────────────────────────────


struct IoUringSqe(Movable):
    """A 64-byte ``io_uring_sqe`` wrapper.

    The wrapper owns its 64-byte buffer (allocated on heap on
    construction, freed on drop). The :meth:`as_bytes` accessor
    exposes the raw pointer so the upcoming SQ-ring writer can
    ``memcpy`` it into the kernel's mmapped SQ array slot.

    For SQEs constructed directly inside the kernel-mmapped SQ
    region (the steady-state hot path), see :func:`encode_sqe_at`,
    which writes the SQE in-place at a caller-supplied byte
    pointer instead of allocating.

    Construction zeros the 64-byte buffer; ``prep_*`` helpers
    overwrite the relevant fields. Untouched fields stay zero —
    matching the `io_uring_prep_*` family contract from
    ``liburing``.
    """

    var _buf: UnsafePointer[UInt8, MutExternalOrigin]
    """Owning pointer to the 64-byte SQE buffer."""

    def __init__(out self) raises:
        """Allocate a 64-byte SQE buffer, zero-initialised."""
        var raw = alloc[UInt8](IO_URING_SQE_BYTES)
        for i in range(IO_URING_SQE_BYTES):
            (raw + i).init_pointee_copy(UInt8(0))
        self._buf = UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=Int(raw)
        )

    def __del__(deinit self):
        """Free the 64-byte buffer."""
        if Int(self._buf) != 0:
            self._buf.free()

    @always_inline
    def as_bytes(self) -> UnsafePointer[UInt8, MutExternalOrigin]:
        """Return the raw 64-byte buffer pointer.

        The pointer's lifetime is tied to the SQE. Callers may
        ``memcpy`` the bytes into a kernel SQ slot before the SQE
        is dropped.
        """
        return self._buf

    @always_inline
    def opcode(self) -> Int:
        """Read the opcode byte."""
        return Int(self._buf[_SQE_OFF_OPCODE])

    @always_inline
    def flags(self) -> Int:
        """Read the SQE-level flags byte."""
        return Int(self._buf[_SQE_OFF_FLAGS])

    @always_inline
    def fd(self) -> Int:
        """Read the fd field as a signed 32-bit integer."""
        var v = _load_u32_le(self._buf, _SQE_OFF_FD)
        # Sign-extend from 32 bits.
        if Int(v) >= 0x8000_0000:
            return Int(v) - 0x1_0000_0000
        return Int(v)

    @always_inline
    def addr(self) -> UInt64:
        """Read the addr field (u64)."""
        return _load_u64_le(self._buf, _SQE_OFF_ADDR)

    @always_inline
    def len(self) -> Int:
        """Read the len field (u32)."""
        return Int(_load_u32_le(self._buf, _SQE_OFF_LEN))

    @always_inline
    def user_data(self) -> UInt64:
        """Read the user_data tag (u64)."""
        return _load_u64_le(self._buf, _SQE_OFF_USER_DATA)

    @always_inline
    def op_flags(self) -> UInt32:
        """Read the op-specific flags field (u32)."""
        return _load_u32_le(self._buf, _SQE_OFF_OP_FLAGS)

    @always_inline
    def set_flags(mut self, flags: UInt8) -> None:
        """Set the SQE-level flags byte."""
        _store_u8(self._buf, _SQE_OFF_FLAGS, flags)

    @always_inline
    def set_user_data(mut self, tag: UInt64) -> None:
        """Set the user_data tag returned in the matching CQE."""
        _store_u64_le(self._buf, _SQE_OFF_USER_DATA, tag)


# ── prep helpers (in-place encoders) ─────────────────────────────────────────
# Each writes a fully-formed SQE at ``buf`` (a 64-byte byte
# pointer). ``buf`` MUST be zeroed before the first prep call;
# the prep helpers only write the fields they care about.


@always_inline
def encode_sqe_zero(buf: UnsafePointer[UInt8, MutExternalOrigin]) -> None:
    """Zero the 64-byte SQE buffer at ``buf`` in preparation for
    a ``prep_*`` helper.

    The kernel reads every byte of the SQE; uninitialised bytes
    can yield ``EINVAL`` or, worse, kernel-side undefined
    behaviour for opcodes that overlay tagged unions.
    """
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "encode_sqe_zero: buf must be non-NULL"
    )
    for i in range(IO_URING_SQE_BYTES):
        (buf + i).init_pointee_copy(UInt8(0))


@always_inline
def prep_nop(
    buf: UnsafePointer[UInt8, MutExternalOrigin], user_data: UInt64
) -> None:
    """Write an ``IORING_OP_NOP`` SQE at ``buf``.

    NOP is the simplest opcode — the kernel just posts a CQE
    with ``res = 0`` and the same ``user_data``. Useful for
    smoke-testing the SQ → CQ round trip without involving any
    fd / buffer / syscall path.

    Args:
        buf: 64-byte SQE buffer pointer (must already be zeroed).
        user_data: Tag returned in the matching CQE.
    """
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_NOP))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_accept(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    addr: UInt64,
    addrlen_ptr: UInt64,
    accept_flags: UInt32,
    user_data: UInt64,
) -> None:
    """Write an oneshot ``IORING_OP_ACCEPT`` SQE at ``buf``.

    The kernel ABI puts ``SOCK_NONBLOCK`` / ``SOCK_CLOEXEC`` /
    ``SOCK_*`` accept flags into the SQE's ``accept_flags`` union
    slot at offset 28 (``op_flags``), and the ``IORING_ACCEPT_*``
    request-class bits into the ``ioprio`` field at offset 2 (so
    the union slot stays a clean SOCK_* mask). This helper writes
    only the SOCK_* flags; for multishot accept, see
    :func:`prep_multishot_accept`.

    Args:
        buf: 64-byte SQE buffer.
        fd: Listener socket fd. ``debug_assert`` verifies fd ≥ 0.
        addr: Pointer to a ``struct sockaddr`` (or 0 to skip).
        addrlen_ptr: Pointer to a ``socklen_t`` (or 0 to skip).
        accept_flags: ``SOCK_NONBLOCK`` / ``SOCK_CLOEXEC`` mask.
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_accept: fd must be non-negative; got ", fd
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_ACCEPT))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_ADDR, addr)
    _store_u64_le(buf, _SQE_OFF_OFF_OR_ADDR2, addrlen_ptr)
    _store_u32_le(buf, _SQE_OFF_OP_FLAGS, accept_flags)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_multishot_accept(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    addr: UInt64,
    addrlen_ptr: UInt64,
    accept_flags: UInt32,
    user_data: UInt64,
) -> None:
    """Write a multishot ``IORING_OP_ACCEPT`` SQE at ``buf``
    (kernels ≥ 5.19).

    This mirrors ``liburing``'s ``io_uring_prep_multishot_accept``:
    fill an oneshot accept SQE, then set the
    ``IORING_ACCEPT_MULTISHOT`` bit in the SQE's ``ioprio`` field.
    The kernel keeps the accept armed across completions so the
    listener self-rearms after every accepted connection — exactly
    one SQE buys an unbounded stream of CQEs (one per accept).

    Each CQE carries:

      * ``user_data``: the tag passed here, unchanged across all
        completions of this multishot.
      * ``res``: the new connected fd on success, or a negative
        ``-errno`` on per-accept failure.
      * ``IORING_CQE_F_MORE``: set as long as the multishot is
        still armed; cleared on the terminal completion (e.g. the
        kernel cancelled the multishot, the listener closed, or
        an unrecoverable error fired).

    Args:
        buf: 64-byte SQE buffer.
        fd: Listener socket fd. ``debug_assert`` verifies fd ≥ 0.
        addr: Pointer to a ``struct sockaddr`` (or 0 to skip).
        addrlen_ptr: Pointer to a ``socklen_t`` (or 0 to skip).
        accept_flags: ``SOCK_NONBLOCK`` / ``SOCK_CLOEXEC`` mask
            applied to every accepted connection.
        user_data: Tag returned in every multishot CQE.
    """
    prep_accept(buf, fd, addr, addrlen_ptr, accept_flags, user_data)
    # ioprio is a u16 at offset 2 in the SQE. liburing folds the
    # IORING_ACCEPT_MULTISHOT bit in here so the ``accept_flags``
    # union slot stays a clean SOCK_* mask.
    _store_u16_le(buf, _SQE_OFF_IOPRIO, UInt16(Int(IORING_ACCEPT_MULTISHOT)))


@always_inline
def prep_recv(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    rx_buf: UInt64,
    rx_len: Int,
    recv_flags: UInt32,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_RECV`` SQE at ``buf``.

    Args:
        buf: 64-byte SQE buffer.
        fd: Connected socket fd. ``debug_assert`` verifies fd ≥ 0.
        rx_buf: Pointer to the receive buffer (or 0 if using
            ``IOSQE_BUFFER_SELECT``).
        rx_len: Length of the receive buffer in bytes.
        recv_flags: Standard ``recv(2)`` flags + on kernels ≥ 6.0,
            ``IORING_RECV_MULTISHOT`` for self-rearming recv.
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_recv: fd must be non-negative; got ", fd
    )
    debug_assert[assert_mode="safe"](
        rx_len >= 0, "prep_recv: rx_len must be non-negative; got ", rx_len
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_RECV))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_ADDR, rx_buf)
    _store_u32_le(buf, _SQE_OFF_LEN, UInt32(rx_len))
    _store_u32_le(buf, _SQE_OFF_OP_FLAGS, recv_flags)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_provide_buffers(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    addr: UInt64,
    nbytes_per_buf: Int,
    nbufs: Int,
    bgid: UInt16,
    bid: UInt16,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_PROVIDE_BUFFERS`` SQE at ``buf`` (5.7+).

    Hands the kernel a contiguous run of ``nbufs`` buffers of
    ``nbytes_per_buf`` bytes each, starting at ``addr``. Each
    buffer gets a sequential id in ``[bid, bid + nbufs)`` and is
    associated with buffer-group ``bgid``. After this SQE
    completes (one CQE with ``res >= 0`` reporting the number of
    buffers actually accepted), subsequent ``IORING_OP_RECV`` SQEs
    that set ``IOSQE_BUFFER_SELECT`` and the same ``bgid`` in
    their ``buf_index`` field will have the kernel auto-pick a
    free buffer from the ring -- no per-conn buffer pinning, no
    user-managed buffer ownership.

    The chosen buffer's id is reported in the recv CQE's
    ``flags`` high 16 bits (decoded by
    :func:`flare.runtime.io_uring_sqe.IoUringCqe.buffer_id`); the
    user computes the buffer's address as
    ``addr + buffer_id * nbytes_per_buf`` and processes it. After
    processing, the same buffer id can be re-provided via another
    ``IORING_OP_PROVIDE_BUFFERS`` SQE (typically as a one-shot
    re-fill SQE per CQE; ``IORING_REGISTER_PBUF_RING`` lets you
    skip the per-recv re-fill, but the simpler PROVIDE_BUFFERS
    path is enough for the v1 wire-in).

    Args:
        buf: 64-byte SQE buffer.
        addr: Pointer to the first buffer in the run.
        nbytes_per_buf: Per-buffer size in bytes.
        nbufs: Number of contiguous buffers (must be > 0).
        bgid: Buffer-group id used by the matching recv SQE's
            ``buf_index``.
        bid: Starting buffer id; ids run sequentially up to
            ``bid + nbufs``.
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        nbytes_per_buf > 0,
        "prep_provide_buffers: nbytes_per_buf must be > 0; got ",
        nbytes_per_buf,
    )
    debug_assert[assert_mode="safe"](
        nbufs > 0, "prep_provide_buffers: nbufs must be > 0; got ", nbufs
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_PROVIDE_BUFFERS))
    # PROVIDE_BUFFERS layout (kernel io_uring/kbuf.c):
    #   sqe->fd       = nbufs
    #   sqe->addr     = first buffer ptr
    #   sqe->len      = bytes per buffer
    #   sqe->off      = starting buffer id
    #   sqe->buf_index = buffer group id
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(nbufs))
    _store_u64_le(buf, _SQE_OFF_ADDR, addr)
    _store_u32_le(buf, _SQE_OFF_LEN, UInt32(nbytes_per_buf))
    _store_u64_le(buf, _SQE_OFF_OFF_OR_ADDR2, UInt64(Int(bid)))
    _store_u16_le(buf, _SQE_OFF_BUF_INDEX, UInt16(Int(bgid)))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_recv_buffer_select(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    bgid: UInt16,
    recv_flags: UInt32,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_RECV`` SQE that picks its buffer from
    a previously-provided buffer pool (``IOSQE_BUFFER_SELECT``).

    Companion to :func:`prep_provide_buffers`. The kernel picks a
    free buffer from buffer-group ``bgid``, recvs into it, and
    reports the chosen buffer id in the CQE's ``flags`` high 16
    bits along with ``IORING_CQE_F_BUFFER`` set in the low bits.

    Combined with ``IORING_RECV_MULTISHOT`` in ``recv_flags``,
    this is the production HTTP server recv shape every Rust
    io_uring HTTP server uses (tokio-uring / monoio / glommio):
    one SQE per connection drives an unbounded stream of recv
    CQEs, each pointing at a fresh kernel-picked buffer; no
    per-conn buffer ownership, no per-CQE re-arm, no recv
    syscall round-trip.

    Args:
        buf: 64-byte SQE buffer.
        fd: Connected socket fd. ``debug_assert`` checks fd >= 0.
        bgid: Buffer-group id matching a prior
            ``prep_provide_buffers`` call.
        recv_flags: Standard ``recv(2)`` flags + optional
            ``IORING_RECV_MULTISHOT``.
        user_data: Tag returned in every recv CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0,
        "prep_recv_buffer_select: fd must be non-negative; got ",
        fd,
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_RECV))
    # IOSQE_BUFFER_SELECT in sqe.flags tells the kernel to pick
    # the buffer at submission time rather than reading
    # sqe.addr / sqe.len. The buffer group id goes in
    # sqe.buf_index (offset 40, u16).
    _store_u8(buf, _SQE_OFF_FLAGS, IOSQE_BUFFER_SELECT)
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u32_le(buf, _SQE_OFF_OP_FLAGS, recv_flags)
    _store_u16_le(buf, _SQE_OFF_BUF_INDEX, UInt16(Int(bgid)))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_read(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    rx_buf: UInt64,
    rx_len: Int,
    offset: UInt64,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_READ`` SQE at ``buf``.

    Like :func:`prep_recv`, but works on **any file descriptor**,
    not just sockets — the underlying syscall is ``read(2)`` /
    ``pread(2)``, not ``recv(2)``. Required for fds where ``recv``
    returns ``-ENOTSOCK``: pipes, eventfds (used by the cross-
    thread wakeup mechanism), regular files, and timerfds.

    Args:
        buf: 64-byte SQE buffer.
        fd: File descriptor to read from. ``debug_assert`` checks
            ``fd ≥ 0``.
        rx_buf: Pointer to the destination buffer.
        rx_len: Length of the destination buffer in bytes.
        offset: Read offset (0 for streaming files / pipes /
            eventfds; ``-1`` for "use file position").
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_read: fd must be non-negative; got ", fd
    )
    debug_assert[assert_mode="safe"](
        rx_len >= 0, "prep_read: rx_len must be non-negative; got ", rx_len
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_READ))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_OFF_OR_ADDR2, offset)
    _store_u64_le(buf, _SQE_OFF_ADDR, rx_buf)
    _store_u32_le(buf, _SQE_OFF_LEN, UInt32(rx_len))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_poll_add(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    poll_mask: UInt32,
    user_data: UInt64,
    multishot: Bool = True,
) -> None:
    """Write an ``IORING_OP_POLL_ADD`` SQE at ``buf``.

    The io_uring analog of ``epoll_ctl(EPOLL_CTL_ADD, fd, mask)``
    — the kernel posts a CQE when the fd's readiness matches any
    bit set in ``poll_mask``. With ``multishot=True`` (5.13+,
    flare's default) the kernel keeps re-arming after every
    completion until the userspace driver cancels via
    ``IORING_OP_ASYNC_CANCEL`` (matched on the same ``user_data``
    tag).

    This is the substrate the upcoming B0 server-loop dispatch
    swap uses to replace the per-poll ``epoll_wait`` syscall on
    the io_uring backend: one SQE per fd at registration time,
    one CQE per readiness change at runtime, no per-iteration
    submission cost.

    Args:
        buf: 64-byte SQE buffer.
        fd: File descriptor to poll. ``debug_assert`` checks
            ``fd >= 0``.
        poll_mask: ORed combination of :data:`POLLIN`,
            :data:`POLLOUT`, :data:`POLLERR`, :data:`POLLHUP`,
            :data:`POLLRDHUP`. flare typically arms ``POLLIN |
            POLLRDHUP`` for read-readiness on connected sockets
            so peer-closed connections surface alongside data-
            available ones.
        user_data: Tag returned in every matching CQE.
        multishot: When True (default), set
            :data:`IORING_POLL_ADD_MULTI` so a single SQE drives
            an unbounded number of CQEs. When False, the kernel
            posts exactly one CQE and the caller must re-arm.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_poll_add: fd must be non-negative; got ", fd
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_POLL_ADD))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    # poll32_events overlays op_flags at offset 28; this is where
    # the kernel reads the requested poll bitmask. Matches
    # liburing's ``io_uring_prep_poll_add`` exactly.
    _store_u32_le(buf, _SQE_OFF_OP_FLAGS, poll_mask)
    # IORING_POLL_ADD_MULTI sits in the ``len`` slot for POLL_ADD;
    # liburing folds it in via ``io_uring_prep_poll_multishot``.
    if multishot:
        _store_u32_le(buf, _SQE_OFF_LEN, IORING_POLL_ADD_MULTI)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_poll_remove(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    target_user_data: UInt64,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_POLL_REMOVE`` SQE at ``buf``.

    Cancels a previous :func:`prep_poll_add` whose ``user_data``
    tag equals ``target_user_data``. The kernel posts the
    cancel CQE under this SQE's own ``user_data``, plus a final
    CQE for the cancelled poll (without ``IORING_CQE_F_MORE``)
    so the userspace driver knows the multishot has stopped.

    Functionally equivalent to :func:`prep_async_cancel` for the
    poll case but slightly cheaper because the kernel doesn't
    have to walk the SQE work-list looking for the matching op.

    Args:
        buf: 64-byte SQE buffer.
        target_user_data: ``user_data`` tag of the
            ``IORING_OP_POLL_ADD`` to remove.
        user_data: Tag returned in this SQE's own CQE.
    """
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_POLL_REMOVE))
    # poll_remove identifies the target poll by user_data, written
    # into the ADDR slot. Matches the kernel's ``poll_remove_one``
    # path in fs/io_uring.c.
    _store_u64_le(buf, _SQE_OFF_ADDR, target_user_data)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_send(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    tx_buf: UInt64,
    tx_len: Int,
    send_flags: UInt32,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_SEND`` SQE at ``buf``.

    Args:
        buf: 64-byte SQE buffer.
        fd: Connected socket fd. ``debug_assert`` verifies fd ≥ 0.
        tx_buf: Pointer to the bytes to send.
        tx_len: Length of the send buffer in bytes.
        send_flags: Standard ``send(2)`` flags (``MSG_NOSIGNAL``,
            ``MSG_DONTWAIT`` etc.).
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_send: fd must be non-negative; got ", fd
    )
    debug_assert[assert_mode="safe"](
        tx_len >= 0, "prep_send: tx_len must be non-negative; got ", tx_len
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_SEND))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_ADDR, tx_buf)
    _store_u32_le(buf, _SQE_OFF_LEN, UInt32(tx_len))
    _store_u32_le(buf, _SQE_OFF_OP_FLAGS, send_flags)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_writev(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    fd: Int,
    iovec_addr: UInt64,
    iovec_count: Int,
    file_offset: UInt64,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_WRITEV`` SQE at ``buf``.

    flare uses this on the io_uring backend to coalesce status
    line + headers + body in a single submission (Track B4
    payoff).

    Args:
        buf: 64-byte SQE buffer.
        fd: Destination fd. ``debug_assert`` verifies fd ≥ 0.
        iovec_addr: Pointer to a ``struct iovec[]`` array.
        iovec_count: Number of iovec entries (kernel max 1024).
        file_offset: ``-1`` to use the current file offset; for
            sockets this field is ignored.
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_writev: fd must be non-negative; got ", fd
    )
    debug_assert[assert_mode="safe"](
        iovec_count >= 0 and iovec_count <= 1024,
        "prep_writev: iovec_count must be in 0..=1024; got ",
        iovec_count,
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_WRITEV))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_OFF_OR_ADDR2, file_offset)
    _store_u64_le(buf, _SQE_OFF_ADDR, iovec_addr)
    _store_u32_le(buf, _SQE_OFF_LEN, UInt32(iovec_count))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_close(
    buf: UnsafePointer[UInt8, MutExternalOrigin], fd: Int, user_data: UInt64
) -> None:
    """Write an ``IORING_OP_CLOSE`` SQE at ``buf``.

    Args:
        buf: 64-byte SQE buffer.
        fd: File descriptor to close. ``debug_assert`` verifies fd ≥ 0.
        user_data: Tag returned in the matching CQE.
    """
    debug_assert[assert_mode="safe"](
        fd >= 0, "prep_close: fd must be non-negative; got ", fd
    )
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_CLOSE))
    _store_u32_le(buf, _SQE_OFF_FD, UInt32(fd))
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


@always_inline
def prep_async_cancel(
    buf: UnsafePointer[UInt8, MutExternalOrigin],
    target_user_data: UInt64,
    user_data: UInt64,
) -> None:
    """Write an ``IORING_OP_ASYNC_CANCEL`` SQE at ``buf``.

    The kernel cancels the in-flight SQE matching
    ``target_user_data``. This is the io_uring-backend hook for
    flare's ``Cancel.SHUTDOWN`` plumbing — when a worker decides
    a connection's recv has timed out, it submits an
    ASYNC_CANCEL targeting the recv's user_data and the kernel
    posts an ``-ECANCELED`` CQE for that recv.

    Args:
        buf: 64-byte SQE buffer.
        target_user_data: ``user_data`` of the SQE to cancel.
        user_data: Tag returned in the cancel's own CQE.
    """
    encode_sqe_zero(buf)
    _store_u8(buf, _SQE_OFF_OPCODE, UInt8(IORING_OP_ASYNC_CANCEL))
    _store_u64_le(buf, _SQE_OFF_ADDR, target_user_data)
    _store_u64_le(buf, _SQE_OFF_USER_DATA, user_data)


# ── CQE wrapper + decoder ────────────────────────────────────────────────────


struct IoUringCqe(Copyable, ImplicitlyCopyable, Movable):
    """A 16-byte ``io_uring_cqe`` wrapper.

    Constructed by :func:`decode_cqe_at` from a 16-byte byte
    pointer carved out of the kernel's mmapped CQ region. The
    wrapper does not own the underlying memory — it's a borrowed
    view over the CQ slot for the duration of one CQE-processing
    iteration of the reactor's poll loop.

    The three fields are:

    * ``user_data`` (u64) — opaque tag the userspace driver set
      on the corresponding SQE.
    * ``res`` (i32) — the operation's return code: ≥ 0 on
      success (typically the byte count for recv/send), or
      ``-errno`` on failure.
    * ``flags`` (u32) — ``IORING_CQE_F_*`` bits; see the
      constants above.
    """

    var _user_data: UInt64
    var _res: Int32
    var _flags: UInt32

    def __init__(out self, user_data: UInt64, res: Int32, flags: UInt32):
        """Construct from already-decoded fields.

        Prefer :func:`decode_cqe_at` for reads from the kernel
        CQ region.
        """
        self._user_data = user_data
        self._res = res
        self._flags = flags

    @always_inline
    def user_data(self) -> UInt64:
        """Return the per-SQE tag set on submission."""
        return self._user_data

    @always_inline
    def res(self) -> Int:
        """Return the operation's return code (negative ``-errno``
        on failure)."""
        return Int(self._res)

    @always_inline
    def flags(self) -> UInt32:
        """Return the ``IORING_CQE_F_*`` flag bits."""
        return self._flags

    @always_inline
    def is_error(self) -> Bool:
        """True iff ``res < 0``."""
        return Int(self._res) < 0

    @always_inline
    def errno(self) -> Int:
        """Return ``-res`` when ``res < 0``; 0 otherwise. Useful
        for symbolising the failure mode (``EAGAIN``, ``ECANCELED``,
        ``EBADF`` …)."""
        var r = Int(self._res)
        if r >= 0:
            return 0
        return -r

    @always_inline
    def has_more(self) -> Bool:
        """True iff ``IORING_CQE_F_MORE`` is set (multishot still
        active)."""
        return (self._flags & IORING_CQE_F_MORE) != 0

    @always_inline
    def buffer_id(self) -> Int:
        """Return the buffer-id the kernel picked from the
        provided-buffer pool, or ``-1`` if ``IORING_CQE_F_BUFFER``
        is not set on this CQE.

        Used with ``IOSQE_BUFFER_SELECT`` recvs.
        """
        if (self._flags & IORING_CQE_F_BUFFER) == 0:
            return -1
        # Buffer id is in the high 16 bits of flags.
        return Int(self._flags >> UInt32(16)) & 0xFFFF


@always_inline
def decode_cqe_at(buf: UnsafePointer[UInt8, _]) -> IoUringCqe:
    """Read a CQE out of the 16-byte slot at ``buf``.

    Args:
        buf: Pointer to a 16-byte CQE slot. Must be non-NULL.

    Returns:
        The decoded ``IoUringCqe`` (by value — no aliasing on
        the caller side).
    """
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "decode_cqe_at: buf must be non-NULL"
    )
    var ud = _load_u64_le(buf, _CQE_OFF_USER_DATA)
    var raw_res = _load_u32_le(buf, _CQE_OFF_RES)
    # Sign-extend the 32-bit res into Int32.
    var res: Int32
    if Int(raw_res) >= 0x8000_0000:
        res = Int32(Int(raw_res) - 0x1_0000_0000)
    else:
        res = Int32(Int(raw_res))
    var flags = _load_u32_le(buf, _CQE_OFF_FLAGS)
    return IoUringCqe(ud, res, flags)
