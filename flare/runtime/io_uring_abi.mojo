"""``flare.runtime.io_uring_abi`` -- io_uring ABI constants + byte codec.

The kernel ABI constant tables (opcodes, SQE/CQE/setup/enter flags,
poll-event bits, struct sizes + field offsets) and the bounds-checked
byte read/write helpers (``_store_*`` / ``_load_*`` / ``_check_opcode``)
that the SQE/CQE codec in :mod:`flare.runtime.io_uring_sqe` builds on.
Split out of ``io_uring_sqe.mojo`` to keep that module within the
file-size budget; ``io_uring_sqe`` re-exports every name here so
existing ``from flare.runtime.io_uring_sqe import IORING_OP_*`` (and
every other constant / helper) call site keeps resolving unchanged.

References: ``include/uapi/linux/io_uring.h`` (canonical layout).
"""

from std.memory import UnsafePointer

# ── opcode constants (subset; full list in linux/io_uring.h) ─────────────────
# Stable since the kernel version listed; the numeric values must
# never change once shipped.

comptime IORING_OP_NOP: Int = 0
"""5.1+. No-op; useful for testing the SQ/CQ round-trip."""
comptime IORING_OP_READV: Int = 1
"""5.1+. Vectored read."""
comptime IORING_OP_WRITEV: Int = 2
"""5.1+. Vectored write — what flare uses to coalesce status +
headers + body in a single submission (the writev(2) path on the
io_uring backend; subsumes the epoll-fallback ``writev(2)``).
"""
comptime IORING_OP_FSYNC: Int = 3
"""5.1+. fsync(2) async."""
comptime IORING_OP_READ_FIXED: Int = 4
"""5.1+. Read into a pre-registered buffer (file-serve
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
"""5.5+. Cancel an in-flight SQE by user_data; the
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

# IORING_SETUP_* flags passed in io_uring_params.flags at
# io_uring_setup() time. Numeric values match
# ``include/uapi/linux/io_uring.h``. flare's bufring path opts
# into the kernel-scheduler hints (COOP_TASKRUN, DEFER_TASKRUN,
# SINGLE_ISSUER, SUBMIT_ALL) to eliminate the ~16 ms / ~60 Hz
# throughput throttle observed when the dispatch loop blocks
# in io_uring_enter without batching.

comptime IORING_SETUP_IOPOLL: UInt32 = 0x01
"""5.1+. Block-IO polling instead of interrupt-driven
completions. Not for network sockets."""

comptime IORING_SETUP_SQPOLL: UInt32 = 0x02
"""5.1+. Kernel polls the SQ; userspace doesn't need to call
``io_uring_enter`` for submission. Trades one always-busy
kernel thread per ring for zero-syscall submission. Useful
for very high SQE rates (> 1 M/s) but requires CAP_SYS_NICE
on some kernels OR registered file descriptors."""

comptime IORING_SETUP_SQ_AFF: UInt32 = 0x04
"""5.1+. Pin the SQPOLL thread to ``sq_thread_cpu``."""

comptime IORING_SETUP_CQSIZE: UInt32 = 0x08
"""5.1+. Use ``params.cq_entries`` to override the default
``2 * sq_entries`` CQ size."""

comptime IORING_SETUP_CLAMP: UInt32 = 0x10
"""5.6+. Clamp ``entries`` / ``cq_entries`` to the kernel max
instead of failing with EINVAL."""

comptime IORING_SETUP_ATTACH_WQ: UInt32 = 0x20
"""5.6+. Share the io-wq workers with another ring (specified
in ``params.wq_fd``)."""

comptime IORING_SETUP_R_DISABLED: UInt32 = 0x40
"""5.10+. Start the ring in disabled state; enable later via
io_uring_register(IORING_REGISTER_ENABLE_RINGS)."""

comptime IORING_SETUP_SUBMIT_ALL: UInt32 = 0x80
"""5.18+. ``io_uring_enter`` continues processing the SQ on a
per-SQE error rather than aborting the batch. Eliminates the
'first SQE in batch errored, rest of batch lost' failure mode
under SQ pressure."""

comptime IORING_SETUP_COOP_TASKRUN: UInt32 = 0x100
"""5.19+. Don't use IPI-driven task work; instead, run task
work cooperatively at io_uring_enter boundaries. Lower CPU
overhead for the common case of a single thread per ring
(which flare's per-worker UringReactor is). Combined with
TASKRUN_FLAG below it tells userspace when to call enter."""

comptime IORING_SETUP_TASKRUN_FLAG: UInt32 = 0x200
"""5.19+. Sets ``IORING_SQ_TASKRUN`` in ``sq_ring->flags``
when there's pending task work. Userspace can poll the flag
to know when to call ``io_uring_enter`` to run pending
completions. Pairs with COOP_TASKRUN."""

comptime IORING_SETUP_SQE128: UInt32 = 0x400
"""5.19+. Doubles SQE size to 128 bytes. flare's SQE codecs
still target 64-byte SQEs; not enabled."""

comptime IORING_SETUP_CQE32: UInt32 = 0x800
"""5.19+. Doubles CQE size to 32 bytes. flare's CQE codecs
still target 16-byte CQEs; not enabled."""

comptime IORING_SETUP_SINGLE_ISSUER: UInt32 = 0x1000
"""6.0+. Promise to the kernel that only one thread will
submit SQEs to this ring. Lets the kernel skip atomic
operations on the SQ submit path. flare's per-worker
UringReactor matches this contract (each worker owns its
own ring + drives it from one pthread). Required by
DEFER_TASKRUN."""

comptime IORING_SETUP_DEFER_TASKRUN: UInt32 = 0x2000
"""6.1+. The kernel runs task work ONLY when the app calls
``io_uring_enter`` (with the GETEVENTS flag). Batches CQE
delivery to enter boundaries; eliminates the IPI-driven
mid-syscall task work that interferes with the dispatch
loop's CQE-drain rhythm. Highest-impact flag for the bufring
throughput throttle when paired with SINGLE_ISSUER."""

comptime IORING_SETUP_NO_MMAP: UInt32 = 0x4000
"""6.5+. Userspace allocates the SQ/CQ rings; kernel mmaps
into them. Not used by flare."""

comptime IORING_SETUP_REGISTERED_FD_ONLY: UInt32 = 0x8000
"""6.5+. Only registered fds can be passed to SQEs. Not
used by flare."""
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
"""Kernel 6.0+. Set in ``sqe->ioprio`` (NOT ``msg_flags``!) to
make an ``IORING_OP_RECV`` rearm itself after each completion.
Each CQE includes ``IORING_CQE_F_MORE`` while the multishot is
still armed; the kernel disarms on terminal errors (EOF, RST,
ENOBUFS, etc) which surface as a CQE without ``F_MORE`` --
userspace re-arms then. The MULTISHOT bit is extracted from
the ``recv_flags`` parameter of :func:`prep_recv` /
:func:`prep_recv_buffer_select` and routed to ``sqe->ioprio``
automatically; callers don't need to handle the split. Kernel
source: ``io_uring/net.c::io_recv_prep`` reads it via
``READ_ONCE(sqe->ioprio)``."""

comptime IORING_RECVSEND_POLL_FIRST: UInt32 = 0x01
"""Kernel 5.19+. Set in ``sqe->ioprio`` to force a poll before
the recv/send is attempted. Like MULTISHOT, this bit is
extracted from ``recv_flags`` / ``send_flags`` and routed to
``sqe->ioprio`` by flare's prep helpers."""

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
    buf: UnsafePointer[UInt8, MutUntrackedOrigin], offset: Int, value: UInt8
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
    buf: UnsafePointer[UInt8, MutUntrackedOrigin], offset: Int, value: UInt16
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
    buf: UnsafePointer[UInt8, MutUntrackedOrigin], offset: Int, value: UInt32
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
    buf: UnsafePointer[UInt8, MutUntrackedOrigin], offset: Int, value: UInt64
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
def _load_u16_le(buf: UnsafePointer[UInt8, _], offset: Int) -> UInt16:
    """Read a u16 little-endian out of ``buf[offset..offset+2]``."""
    debug_assert[assert_mode="safe"](
        Int(buf) != 0, "io_uring CQE buffer must be non-NULL"
    )
    debug_assert[assert_mode="safe"](
        offset >= 0 and offset + 2 <= IO_URING_SQE_BYTES,
        "_load_u16_le offset out of range; got ",
        offset,
    )
    var lo = UInt16(Int(buf[offset]))
    var hi = UInt16(Int(buf[offset + 1]))
    return lo | (hi << UInt16(8))


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
