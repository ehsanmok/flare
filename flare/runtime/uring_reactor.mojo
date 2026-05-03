"""``UringReactor``: io_uring-native event-loop wrapper (Track B0
wire-in).

Sits on top of :mod:`flare.runtime.io_uring_driver` (which owns
the ``io_uring_setup`` + the three SQ/CQ/SQE-array mmaps, the
atomic head/tail accessors, and the raw submit/reap surface) and
adds the **operation-tagged** API that the upcoming uring-backed
server reactor calls:

* ``arm_listener_multishot(fd, conn_id)`` — submit one
  ``IORING_OP_ACCEPT`` SQE with ``IORING_ACCEPT_MULTISHOT`` so
  the kernel keeps re-arming the accept after every completion.
* ``arm_recv_multishot(fd, buf_ptr, buf_len, conn_id)`` — submit
  one ``IORING_OP_RECV`` SQE with ``IORING_RECV_MULTISHOT`` so
  the kernel posts a CQE every time data lands without
  re-arming. (Caller is responsible for buffer ownership; flare
  uses the per-worker BufferHandle pool from Track B5.)
* ``submit_send(fd, buf_ptr, buf_len, conn_id)`` — fire-and-
  forget ``IORING_OP_SEND``. The CQE confirms the kernel
  enqueued the bytes; no per-byte loop.
* ``submit_close(fd, conn_id)`` — graceful close via
  ``IORING_OP_CLOSE``. Posted with ``IOSQE_CQE_SKIP_SUCCESS`` so
  the success case doesn't even round-trip a CQE — close-on-
  success is async fire-and-forget.
* ``cancel_conn(conn_id)`` — submit an
  ``IORING_OP_ASYNC_CANCEL`` targeting any in-flight SQE bearing
  ``conn_id``'s tag. Used by deadline / shutdown paths.
* ``poll(min_complete, out)`` — call
  ``io_uring_enter(min_complete=min_complete)`` then drain the
  CQ into ``out`` as a list of ``UringCompletion`` records.
* ``wakeup()`` — write 1 to a per-reactor eventfd registered as
  a poll target on the ring (so ``poll`` returns from
  ``io_uring_enter`` as soon as any thread calls ``wakeup``).

Operation tagging
-----------------

Each SQE is tagged with a 64-bit ``user_data`` that the kernel
returns verbatim on the matching CQE. We pack two fields into
that 64-bit slot:

    | bits 63..56 | bits 55..0   |
    | op_kind     | conn_id      |

* ``op_kind`` (8 bits) — one of :data:`URING_OP_ACCEPT`,
  :data:`URING_OP_RECV`, :data:`URING_OP_SEND`,
  :data:`URING_OP_CLOSE`, :data:`URING_OP_CANCEL`,
  :data:`URING_OP_WAKEUP`.
* ``conn_id`` (56 bits) — caller-defined connection identifier.
  flare passes a connection-pool slot index.

Two helpers — :func:`pack_user_data` and :func:`unpack_user_data`
— round-trip the encoding and are unit-tested in the dedicated
test module.

Why an operation-tagged surface (not register/poll like epoll)
--------------------------------------------------------------

io_uring's value proposition is the **opposite** of epoll:
instead of "tell me when fd is ready" → "do op manually", it's
"do op for me; tell me when it completed". Flattening that into
an epoll-style ``register(fd, READ); on poll, recv()`` surface
re-introduces the syscall-per-event cost epoll has and
``io_uring`` was built to avoid.

So ``UringReactor`` exposes the io_uring-native submit/reap API
directly. The two backends (``epoll/kqueue`` ``Reactor`` vs
``UringReactor``) are selected at the **server** layer by a
comptime branch — the ``_server_reactor_impl`` state machine
talks to whichever backend is selected via a thin trait surface.
This is the v0.7 design-doc Track B0 wire-in.

Concurrency
-----------

One ``UringReactor`` per worker pthread (matching the existing
``Reactor`` ownership model). All SQ/CQ ring atomics happen on
the single owning thread; the only cross-thread hook is
``wakeup`` which writes 1 byte into the per-reactor eventfd.
"""

from std.atomic import Atomic, Ordering
from std.ffi import c_int, c_uint, c_size_t, get_errno
from std.memory import UnsafePointer, alloc, stack_allocation
from std.os import getenv
from std.sys.info import CompilationTarget

from flare.net._libc import (
    INVALID_FD,
    EFD_NONBLOCK,
    EFD_CLOEXEC,
    _close,
    _eventfd,
    FlareRawIO,
)
from flare.net.error import NetworkError
from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.io_uring_driver import IoUringDriver
from flare.runtime.io_uring_sqe import (
    IORING_ACCEPT_MULTISHOT,
    IORING_RECV_MULTISHOT,
    IORING_CQE_F_MORE,
    IOSQE_CQE_SKIP_SUCCESS,
    POLLERR,
    POLLHUP,
    POLLIN,
    POLLOUT,
    POLLRDHUP,
    IoUringCqe,
    prep_accept,
    prep_async_cancel,
    prep_close,
    prep_multishot_accept,
    prep_poll_add,
    prep_poll_remove,
    prep_provide_buffers,
    prep_read,
    prep_recv,
    prep_recv_buffer_select,
    prep_send,
)


# ── op-kind tag bits ─────────────────────────────────────────────────────────
#
# Eight-bit tag we pack into the high byte of ``user_data`` so the
# CQE handler can dispatch without per-conn state-machine lookup.
# Numeric values are stable; the wire-in commit pins them as
# ``comptime`` so any accidental renumber breaks compilation.

comptime URING_OP_ACCEPT: UInt64 = 1
"""Multishot accept on the listener fd. ``conn_id`` is 0 or the
listener slot id."""
comptime URING_OP_RECV: UInt64 = 2
"""Multishot recv on a connected fd. ``conn_id`` is the
connection slot."""
comptime URING_OP_SEND: UInt64 = 3
"""Single send on a connected fd. ``conn_id`` is the connection
slot."""
comptime URING_OP_CLOSE: UInt64 = 4
"""Async close. ``conn_id`` is the connection slot."""
comptime URING_OP_CANCEL: UInt64 = 5
"""Async cancel of an in-flight op for ``conn_id``."""
comptime URING_OP_WAKEUP: UInt64 = 6
"""Cross-thread wakeup CQE; ``conn_id`` is 0."""
comptime URING_OP_POLL: UInt64 = 7
"""Multishot poll CQE; ``conn_id`` is the registered fd's slot.
The kernel posts one CQE per readiness change (analog of an
``epoll_wait`` event); the userspace driver inspects
``UringCompletion.res`` to see which poll bits fired."""
comptime URING_OP_POLL_REMOVE: UInt64 = 8
"""CQE for an ``IORING_OP_POLL_REMOVE`` we issued ourselves;
the kernel posts it under the remove SQE's own user_data and
the cancelled poll's final CQE arrives separately under
``URING_OP_POLL`` without ``IORING_CQE_F_MORE``."""
comptime URING_OP_PROVIDE_BUFFERS: UInt64 = 9
"""CQE for an ``IORING_OP_PROVIDE_BUFFERS`` we issued ourselves
to seed (or refill) a buffer ring that recv-buffer-select uses.
``conn_id`` is typically the buffer-group id so the dispatch
loop can route refill ACKs to the right ring without a separate
table."""


comptime _OP_SHIFT: UInt64 = 56
comptime _CONN_MASK: UInt64 = (UInt64(1) << _OP_SHIFT) - UInt64(1)


@always_inline
def pack_user_data(op: UInt64, conn_id: UInt64) -> UInt64:
    """Pack ``(op, conn_id)`` into the 64-bit user_data slot.

    ``op`` lives in the top 8 bits, ``conn_id`` in the bottom
    56 bits. ``debug_assert``ed: ``conn_id <= 2^56 - 1``.
    """
    debug_assert[assert_mode="safe"](
        Int(conn_id) <= Int(_CONN_MASK),
        "pack_user_data: conn_id exceeds 56-bit range; got ",
        Int(conn_id),
    )
    debug_assert[assert_mode="safe"](
        Int(op) <= 0xFF,
        "pack_user_data: op_kind exceeds 8-bit range; got ",
        Int(op),
    )
    return (op << _OP_SHIFT) | (conn_id & _CONN_MASK)


@always_inline
def unpack_op(user_data: UInt64) -> UInt64:
    """Return the op_kind portion of a packed user_data."""
    return (user_data >> _OP_SHIFT) & UInt64(0xFF)


@always_inline
def unpack_conn_id(user_data: UInt64) -> UInt64:
    """Return the conn_id portion of a packed user_data."""
    return user_data & _CONN_MASK


# ── Completion record ────────────────────────────────────────────────────────


@fieldwise_init
struct UringCompletion(Copyable, ImplicitlyCopyable, Movable):
    """A decoded io_uring completion, suitable for the
    server reactor's hot-path dispatch.

    Fields:
        op: One of ``URING_OP_*``.
        conn_id: Connection slot id from the original SQE tag.
        res: ``IoUringCqe.res()``; negative on failure
            (``-errno``).
        flags: ``IoUringCqe.flags()``; carries
            ``IORING_CQE_F_MORE`` (multishot still armed) and
            ``IORING_CQE_F_BUFFER`` (kernel-picked buffer id in
            the high 16 bits).
        has_more: True iff the originating multishot is still
            armed.
    """

    var op: UInt64
    var conn_id: UInt64
    var res: Int
    var flags: UInt32
    var has_more: Bool

    @always_inline
    def is_error(self) -> Bool:
        """Convenience: ``res < 0``."""
        return self.res < 0

    @always_inline
    def errno(self) -> Int:
        """Convenience: ``-res`` if it's an error, else 0."""
        if self.res >= 0:
            return 0
        return -self.res


@always_inline
def _cqe_to_completion(cqe: IoUringCqe) -> UringCompletion:
    """Decode an :class:`IoUringCqe` into a high-level
    :class:`UringCompletion` ready for the server reactor."""
    var ud = cqe.user_data()
    return UringCompletion(
        op=unpack_op(ud),
        conn_id=unpack_conn_id(ud),
        res=cqe.res(),
        flags=cqe.flags(),
        has_more=cqe.has_more(),
    )


# ── UringReactor ─────────────────────────────────────────────────────────────


struct UringReactor(Movable):
    """One io_uring ring + a wakeup eventfd, exposed as the
    submit/reap surface flare's per-worker server reactor uses
    on the io_uring backend.

    Per-worker ownership model: each pthread that runs a server
    reactor loop owns exactly one ``UringReactor``; the kernel-
    shared rings are SPSC per direction so no inter-worker
    synchronisation is needed beyond the ``wakeup`` eventfd
    write.

    Fields:
        _driver: The owning ``IoUringDriver`` (closes ring fd +
            unmaps SQ/CQ/SQE on drop).
        _wake_fd: Per-reactor eventfd. ``poll`` arms a
            ``IORING_OP_RECV`` against it (the eventfd's read
            side is byte-stream-shaped) so the next ``wakeup``
            from any thread surfaces a ``URING_OP_WAKEUP`` CQE.
        _wake_buf: Pinned 8-byte buffer the wakeup recv writes
            into.
        _io: Cached ``libflare_tls`` raw-IO handles for the
            ``write`` syscall used by ``wakeup``.
        _wake_armed: True after the first ``poll`` arms the
            wakeup recv; we re-arm lazily after each wakeup CQE.
    """

    var _driver: IoUringDriver
    var _wake_fd: c_int
    # Owning pointer to the 8-byte eventfd recv buffer; pinned for
    # the reactor's lifetime so the multishot recv arming SQE
    # stays valid. Stored under ``MutExternalOrigin`` to match
    # the ``prep_recv`` buf-pointer convention used everywhere
    # in :mod:`flare.runtime.io_uring_sqe`.
    var _wake_buf: UnsafePointer[UInt8, MutExternalOrigin]
    var _io: FlareRawIO
    var _wake_armed: Bool

    def __init__(out self, entries: Int = 256) raises:
        """Set up the ring + wakeup eventfd.

        Args:
            entries: SQE count (kernel rounds up to a power of
                two; default 256 matches the v0.6 epoll
                ``max_events`` budget so the per-worker memory
                footprint is comparable).

        Raises:
            Error: On ``io_uring_setup`` failure (see
                :class:`IoUringDriver`) or ``eventfd`` failure.
        """
        comptime if not CompilationTarget.is_linux():
            raise Error(
                "UringReactor is a Linux-only feature; this build is not Linux"
            )
        self._io = FlareRawIO()
        self._driver = IoUringDriver(entries)
        # NOTE: deliberately *blocking* eventfd (no EFD_NONBLOCK).
        # io_uring's IORING_OP_RECV against a non-blocking eventfd
        # with no pending data immediately posts a -EAGAIN CQE,
        # which spins ``poll(1, ...)`` into a 100 % CPU loop on
        # idle. With the blocking flag clear the kernel actually
        # waits on the eventfd, the CQE only fires when ``wakeup``
        # writes a token, and ``wakeup()`` itself is safe from any
        # thread (the write(2) on the eventfd is atomic + small).
        var efd = _eventfd(c_uint(0), EFD_CLOEXEC)
        if efd < c_int(0):
            raise Error(
                "UringReactor: eventfd failed: errno="
                + String(get_errno().value)
            )
        self._wake_fd = efd
        # 8 bytes is the eventfd read width; we keep the buffer
        # pinned for the reactor's lifetime so the multishot recv
        # arming SQE keeps a stable pointer. Same ``alloc`` →
        # ``MutExternalOrigin`` cast pattern used by
        # ``IoUringRing._params_buf`` in :mod:`io_uring`.
        var raw = alloc[UInt8](8)
        for i in range(8):
            (raw + i).init_pointee_copy(UInt8(0))
        self._wake_buf = UnsafePointer[UInt8, MutExternalOrigin](
            unsafe_from_address=Int(raw)
        )
        self._wake_armed = False

    def __del__(deinit self):
        """Free the wakeup buffer + close the wakeup fd; the
        ``IoUringDriver`` destructor handles ring teardown."""
        if Int(self._wake_buf) != 0:
            self._wake_buf.free()
        if self._wake_fd != INVALID_FD:
            _ = _close(self._wake_fd)

    # ── Introspection ────────────────────────────────────────────────────────

    def fd(self) -> Int:
        """Return the underlying io_uring ring fd."""
        return self._driver.fd()

    def sq_entries(self) -> Int:
        """Kernel-allocated SQ size."""
        return self._driver.sq_entries()

    def cq_entries(self) -> Int:
        """Kernel-allocated CQ size."""
        return self._driver.cq_entries()

    # ── Submit API ───────────────────────────────────────────────────────────

    def arm_listener_multishot(
        mut self, listener_fd: Int, conn_id: UInt64 = 0
    ) raises -> None:
        """Submit one multishot accept SQE so the kernel posts a
        CQE for every accepted connection without re-arming.

        The CQE handler should look at ``cqe.has_more`` — when
        unset, the multishot has terminated (e.g. listener
        closed) and the caller should re-arm.

        Args:
            listener_fd: Listener socket fd (must be non-blocking
                or kernel ≥ 6.0 for blocking-listener support).
            conn_id: Tag returned in every accept CQE; defaults
                to 0 when there's only one listener.

        Raises:
            Error: If the SQ is full (hot-path error; caller
                should ``poll`` to drain CQEs first).
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.arm_listener_multishot: SQ is full")
        var ud = pack_user_data(URING_OP_ACCEPT, conn_id)
        prep_multishot_accept(
            slot, listener_fd, UInt64(0), UInt64(0), UInt32(0), ud
        )
        self._driver.commit_sqe()

    def arm_recv_multishot(
        mut self,
        fd: Int,
        buf: UnsafePointer[UInt8, MutExternalOrigin],
        buf_len: Int,
        conn_id: UInt64,
    ) raises -> None:
        """Submit one multishot recv SQE so the kernel keeps
        firing recv CQEs while the connection has data.

        Args:
            fd: Connected socket fd.
            buf: Receive buffer (caller-owned; flare uses a
                BufferHandle from the per-worker pool).
            buf_len: Buffer capacity in bytes.
            conn_id: Tag returned in each recv CQE.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.arm_recv_multishot: SQ is full")
        var ud = pack_user_data(URING_OP_RECV, conn_id)
        # Multishot recv is signalled via the recv flags slot at
        # offset 28 (op_flags); see io_uring_prep_multishot_recv
        # in liburing.
        prep_recv(
            slot,
            fd,
            UInt64(Int(buf)),
            buf_len,
            IORING_RECV_MULTISHOT,
            ud,
        )
        self._driver.commit_sqe()

    def arm_provide_buffers(
        mut self,
        addr: UInt64,
        nbytes_per_buf: Int,
        nbufs: Int,
        bgid: UInt16,
        bid: UInt16 = UInt16(0),
    ) raises -> None:
        """Submit one ``IORING_OP_PROVIDE_BUFFERS`` SQE that hands
        the kernel a contiguous run of ``nbufs`` buffers of
        ``nbytes_per_buf`` bytes each, starting at ``addr`` with
        ids ``[bid, bid + nbufs)`` in buffer-group ``bgid``.

        After this SQE completes (one CQE tagged
        ``URING_OP_PROVIDE_BUFFERS`` with ``conn_id = bgid`` and
        ``res = number of buffers actually accepted``), subsequent
        ``arm_recv_buffer_select`` calls with the same ``bgid``
        will have the kernel auto-pick a free buffer for each recv.

        flare's recv-buffer-ring dispatch loop typically calls this
        once at startup with N×8 KiB buffers per worker, then
        re-arms the same buffer id after each recv CQE is processed
        (one PROVIDE_BUFFERS SQE with ``nbufs=1`` per recv CQE -- a
        cheap re-fill that amortises into the next ``io_uring_enter``).

        Args:
            addr: Pointer to the first buffer in the run (typically
                  the worker's owned heap allocation, or the slot
                  inside it being re-fed).
            nbytes_per_buf: Per-buffer size in bytes.
            nbufs: Number of contiguous buffers (must be > 0).
            bgid: Buffer-group id; used by the matching recv SQE's
                ``buf_index`` and reported in the CQE's ``conn_id``.
            bid: Starting buffer id (default 0).
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.arm_provide_buffers: SQ is full")
        var ud = pack_user_data(URING_OP_PROVIDE_BUFFERS, UInt64(Int(bgid)))
        prep_provide_buffers(slot, addr, nbytes_per_buf, nbufs, bgid, bid, ud)
        self._driver.commit_sqe()

    def arm_recv_buffer_select(
        mut self,
        fd: Int,
        bgid: UInt16,
        conn_id: UInt64,
        multishot: Bool = True,
    ) raises -> None:
        """Submit one ``IORING_OP_RECV`` SQE with
        ``IOSQE_BUFFER_SELECT`` set; the kernel picks a buffer from
        the ``bgid`` pool at recv time.

        This is the production HTTP server recv shape every Rust
        io_uring HTTP server uses. Combined with ``multishot=True``
        (default), one SQE per accepted connection drives an
        unbounded stream of recv CQEs; each CQE points at a fresh
        kernel-picked buffer (id in the high 16 bits of
        ``UringCompletion.flags``, decoded via
        :func:`IoUringCqe.buffer_id`). No per-conn buffer ownership,
        no per-CQE re-arm, no recv syscall round-trip.

        Args:
            fd: Connected socket fd.
            bgid: Buffer-group id matching a prior
                ``arm_provide_buffers`` call.
            conn_id: Tag returned in every recv CQE; identifies the
                connection this recv belongs to.
            multishot: When True (default), set
                ``IORING_RECV_MULTISHOT`` so the kernel keeps the
                recv armed across CQEs. Only valid in combination
                with ``IOSQE_BUFFER_SELECT`` (which this helper
                always sets), since multishot recv requires a
                buffer-group source.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.arm_recv_buffer_select: SQ is full")
        var ud = pack_user_data(URING_OP_RECV, conn_id)
        var recv_flags: UInt32 = 0
        if multishot:
            recv_flags |= IORING_RECV_MULTISHOT
        prep_recv_buffer_select(slot, fd, bgid, recv_flags, ud)
        self._driver.commit_sqe()

    def submit_send(
        mut self,
        fd: Int,
        buf: UnsafePointer[UInt8, _],
        buf_len: Int,
        conn_id: UInt64,
    ) raises -> None:
        """Submit one ``IORING_OP_SEND`` SQE.

        Args:
            fd: Connected socket fd.
            buf: Send buffer; caller must keep it alive until
                the matching CQE is reaped.
            buf_len: Bytes to send.
            conn_id: Tag returned in the send CQE.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.submit_send: SQ is full")
        var ud = pack_user_data(URING_OP_SEND, conn_id)
        # MSG_NOSIGNAL = 0x4000 prevents SIGPIPE on closed peers.
        prep_send(slot, fd, UInt64(Int(buf)), buf_len, UInt32(0x4000), ud)
        self._driver.commit_sqe()

    def submit_close(mut self, fd: Int, conn_id: UInt64) raises -> None:
        """Submit one ``IORING_OP_CLOSE`` SQE.

        Uses ``IOSQE_CQE_SKIP_SUCCESS`` so the kernel only posts
        a CQE on failure — the typical close path is async
        fire-and-forget.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.submit_close: SQ is full")
        var ud = pack_user_data(URING_OP_CLOSE, conn_id)
        prep_close(slot, fd, ud)
        # Set IOSQE_CQE_SKIP_SUCCESS in the flags byte at offset 1.
        # The IoUringSqe wrapper exposes set_flags but we're
        # writing a raw slot here; use the helper directly.
        # Offset 1 is _SQE_OFF_FLAGS; we OR in the skip-success bit.
        var flag_byte = (slot + 1).load()
        (slot + 1).init_pointee_copy(
            flag_byte | UInt8(Int(IOSQE_CQE_SKIP_SUCCESS))
        )
        self._driver.commit_sqe()

    def arm_poll_readable_multishot(
        mut self,
        fd: Int,
        conn_id: UInt64,
        poll_mask: UInt32 = POLLIN | POLLRDHUP,
    ) raises -> None:
        """Submit a multishot ``IORING_OP_POLL_ADD`` against ``fd``.

        Kernel posts a CQE every time the fd's readiness matches
        any bit in ``poll_mask``, without re-arming. This is the
        io_uring analog of ``epoll_ctl(EPOLL_CTL_ADD, fd, EPOLLIN
        | EPOLLET)`` and is the substrate the upcoming server-loop
        dispatch swap (B0 wire-in) uses to replace ``epoll_wait``
        on the io_uring backend.

        The CQE is tagged ``URING_OP_POLL`` so the dispatch loop
        can route it to the same code path that handles
        ``EVENT_READABLE`` on the epoll backend; the existing
        ``ConnHandle.on_readable`` then runs its own ``recv``
        syscall (no buffer-ring required for the wire-in
        commit; that's the v0.7.x follow-up that swaps to
        ``IORING_OP_RECV`` + ``IORING_RECV_MULTISHOT``).

        Args:
            fd: Connected socket fd. ``debug_assert`` checks
                ``fd >= 0``.
            conn_id: Caller-defined connection slot id (e.g. the
                fd itself when 1:1 with a ConnHandle).
            poll_mask: Defaults to ``POLLIN | POLLRDHUP`` so
                peer-closed connections surface alongside data-
                available ones; pass ``POLLOUT`` for write-side
                readiness or any combination of the ``POLL*``
                constants.

        Raises:
            Error: If the SQ is full (hot-path; caller should
                drain CQEs first).
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.arm_poll_readable_multishot: SQ is full")
        var ud = pack_user_data(URING_OP_POLL, conn_id)
        prep_poll_add(slot, fd, poll_mask, ud, True)
        self._driver.commit_sqe()

    def cancel_poll(mut self, conn_id: UInt64) raises -> None:
        """Submit ``IORING_OP_POLL_REMOVE`` cancelling the
        multishot poll registered for ``conn_id``.

        After the kernel processes the remove SQE, two CQEs
        arrive: one tagged ``URING_OP_POLL_REMOVE`` (this SQE's
        own completion, ``res = 0`` on success or ``-ENOENT`` if
        nothing matched), and one final tagged ``URING_OP_POLL``
        without ``IORING_CQE_F_MORE`` for the cancelled poll
        itself.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.cancel_poll: SQ is full")
        var target = pack_user_data(URING_OP_POLL, conn_id)
        var ud = pack_user_data(URING_OP_POLL_REMOVE, conn_id)
        prep_poll_remove(slot, target, ud)
        self._driver.commit_sqe()

    def cancel_conn(mut self, conn_id: UInt64) raises -> None:
        """Submit an ``IORING_OP_ASYNC_CANCEL`` for any in-flight
        op tagged with ``conn_id`` (the kernel cancels the
        first match).
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor.cancel_conn: SQ is full")
        # The cancel SQE itself uses URING_OP_CANCEL as its
        # op_kind. The recv it's targeting is conn_id with
        # URING_OP_RECV — we cancel by matching the recv's
        # full user_data tag.
        var target = pack_user_data(URING_OP_RECV, conn_id)
        var ud = pack_user_data(URING_OP_CANCEL, conn_id)
        prep_async_cancel(slot, target, ud)
        self._driver.commit_sqe()

    # ── Reap API ─────────────────────────────────────────────────────────────

    def poll(
        mut self,
        min_complete: Int,
        mut out: List[UringCompletion],
        max_completions: Int = 64,
    ) raises -> Int:
        """Submit any pending SQEs, wait for ``min_complete``
        CQEs (0 = non-blocking), then drain up to
        ``max_completions`` CQEs into ``out``.

        Returns the number of completions appended.

        Args:
            min_complete: 0 = non-blocking submit; positive =
                block until this many CQEs are ready.
            out: Output list (cleared on entry).
            max_completions: Per-poll budget so one slow op
                doesn't starve the reactor (matches epoll's
                ``max_events``).
        """
        out.clear()
        if not self._wake_armed:
            # Lazy-arm the wakeup recv on first poll so the
            # eventfd surfaces wakeups via the same drain loop.
            try:
                self._arm_wakeup_recv()
                self._wake_armed = True
            except _e:
                # If arming the wakeup fails (e.g. SQ full on a
                # busy reactor), the poll still works — wakeups
                # just won't be honoured this round. Try again
                # next poll.
                pass

        var rc = self._driver.submit_and_wait(min_complete)
        # rc >= 0 = SQEs consumed; rc < 0 = -errno. EINTR is benign.
        if rc < 0 and rc != -4:  # -EINTR
            raise Error(
                "UringReactor.poll: io_uring_enter failed; rc=" + String(rc)
            )
        var n = 0
        while n < max_completions:
            var maybe = self._driver.reap_cqe()
            if not Bool(maybe):
                break
            var cqe = maybe.value()
            var comp = _cqe_to_completion(cqe)
            # Wakeup CQEs get re-armed lazily and not surfaced.
            if comp.op == URING_OP_WAKEUP:
                self._wake_armed = False
                continue
            out.append(comp)
            n += 1
        return n

    def wakeup(self) raises -> None:
        """Cross-thread wakeup: write 1 to the eventfd. Safe from
        any thread.

        The next ``poll`` will return because the multishot recv
        on the eventfd posts a CQE.
        """
        var one = stack_allocation[8, UInt8]()
        (one + 0).init_pointee_copy(UInt8(1))
        for k in range(1, 8):
            (one + k).init_pointee_copy(UInt8(0))
        _ = self._io.write(self._wake_fd, one, c_size_t(8))

    # ── Private helpers ──────────────────────────────────────────────────────

    def _arm_wakeup_recv(mut self) raises -> None:
        """Submit a read SQE on the wakeup eventfd so the next
        ``wakeup`` write posts a CQE.

        We use ``IORING_OP_READ`` instead of ``IORING_OP_RECV``
        because eventfd is an anon-inode file, not a socket;
        ``IORING_OP_RECV`` returns ``-ENOTSOCK`` immediately on
        an eventfd which would busy-loop ``poll(min_complete=1)``.
        """
        var slot = self._driver.next_sqe()
        if Int(slot) == 0:
            raise Error("UringReactor._arm_wakeup_recv: SQ is full")
        var ud = pack_user_data(URING_OP_WAKEUP, UInt64(0))
        prep_read(
            slot,
            Int(self._wake_fd),
            UInt64(Int(self._wake_buf)),
            8,
            UInt64(0),
            ud,
        )
        self._driver.commit_sqe()


# ── Comptime backend selector ────────────────────────────────────────────────


@always_inline
def use_uring_backend() -> Bool:
    """Comptime+runtime predicate: True iff the host kernel
    exposes io_uring **and** the build target is Linux.

    The flare server's reactor branch consults this once at
    startup to decide whether to construct a ``UringReactor``
    (io_uring path) or fall back to the existing ``Reactor``
    (epoll path on Linux without io_uring, kqueue on macOS).

    The decision is per-process: a long-running server picks
    one backend at boot and never switches. The choice can be
    forced off via the ``FLARE_DISABLE_IO_URING=1`` environment
    variable for A/B benchmarking; flare's default is "use
    io_uring when available".
    """
    comptime if not CompilationTarget.is_linux():
        return False
    # Respect the documented A/B-bench escape hatch. We treat any
    # non-empty value other than "0" / "false" / "no" as "disable"
    # so contributors can ``FLARE_DISABLE_IO_URING=1`` (the
    # documented form) without having to remember the exact spelling.
    var disabled = getenv("FLARE_DISABLE_IO_URING")
    if disabled.byte_length() > 0:
        var d = disabled
        if not (d == "0" or d == "false" or d == "FALSE" or d == "no"):
            return False
    return is_io_uring_available()
