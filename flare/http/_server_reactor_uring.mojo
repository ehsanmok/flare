"""io_uring server reactor loops (static-response + buffer-ring handler).

The ``UringReactor``-backed server event loops: the multishot-poll
static-response twin of the epoll path (``run_uring_reactor_loop_static``)
and the production buffer-ring handler dispatch
(``run_uring_bufring_reactor_loop`` / ``_shared``) with its kernel-managed
``IORING_REGISTER_PBUF_RING`` substrate, generation-stamped conn-id
encoding, setup-flag probe and submit-send drivers. Split out of
``_server_reactor_impl.mojo`` to keep each module within the file-size
budget; ``_server_reactor_impl`` re-exports every public name so existing
call sites keep resolving unchanged. Pure code motion. Linux-only paths
guard themselves with a ``comptime if not is_linux(): raise``.
"""

from std.collections import Dict
from std.ffi import c_int
from std.os import getenv
from std.memory import UnsafePointer, alloc, stack_allocation
from std.sys.info import CompilationTarget

from flare.http.handler import Handler
from flare.http.server import ServerConfig
from flare.http.static_response import StaticResponse
from flare.net import SocketAddr
from flare.net._libc import _close
from flare.tcp import TcpStream, TcpListener
from flare.runtime import Pool
from flare.runtime.uring_reactor import (
    UringReactor,
    _pbuf_ring_add,
    _pbuf_ring_get_tail,
    _pbuf_ring_set_tail,
)
from ._reactor import ConnHandle, StepResult, STATE_READING, STATE_WRITING

# Shared connection-lifecycle helpers live in ``_server_reactor_epoll``
# (the epoll loops own them); imported here for the io_uring teardown path.
from ._server_reactor_epoll import _conn_free_addr, _conn_ptr_from_int


# ── io_uring server-loop dispatch ───────────────────────────────────────────
#
# When ``use_uring_backend()`` is true (Linux kernel exposes io_uring
# AND ``FLARE_DISABLE_IO_URING`` is unset), ``HttpServer.serve_static``
# routes through ``run_uring_reactor_loop_static`` below instead of
# the epoll/kqueue ``run_reactor_loop_static`` above.
#
# How it differs from the epoll path
# -----------------------------------
#
# * Backend: ``UringReactor`` (multishot accept on the listener,
#   multishot poll per connection fd) instead of ``Reactor``
#   (epoll_wait on Linux, kqueue on macOS). One ``io_uring_enter``
#   per loop iteration replaces ``epoll_wait`` + ``epoll_ctl(MOD)``
#   per modify; the multishot accept replaces the
#   ``while True: accept(); EAGAIN`` drain loop with one CQE per
#   accepted connection.
# * Per-conn state machine: **unchanged**. ``ConnHandle.on_readable_static``
#   and ``on_writable`` still do their own non-blocking ``recv`` /
#   ``send`` on the socket fd. The uring path only replaces the
#   *readiness notifier*: the kernel posts a ``URING_OP_POLL`` CQE
#   when the fd becomes readable / writable, and the dispatch loop
#   calls the same on_readable_static / on_writable code that the
#   epoll path runs. This keeps the wire-in surgical: zero changes
#   to the parser / response framer / keep-alive logic.
# * Cleanup: closing the connection fd implicitly cancels the
#   kernel's multishot poll on it. Any final-no-more-events CQE
#   that arrives after cleanup looks like a "conn_id not in dict"
#   miss in the dispatch switch and is silently ignored.
# * Modify (read <-> write): ``cancel_poll(fd) +
#   arm_poll_readable_multishot(fd, mask)`` is the io_uring
#   equivalent of ``epoll_ctl(EPOLL_CTL_MOD, fd, mask)``. We
#   trigger it from ``_apply_step_uring`` only when the new
#   interest mask actually differs from the currently-armed one,
#   matching the epoll path's no-op-skip optimisation.


def _alloc_conn_from_accepted_fd(fd: Int) raises -> Int:
    """Wrap an already-accepted client fd in a ConnHandle and
    return its address.

    Mirrors ``_conn_alloc_addr`` but takes a raw integer fd
    (the kernel returns the accepted fd directly in the
    ``IORING_OP_ACCEPT`` CQE's ``res`` field; we don't get to
    call ``accept(2)`` ourselves on the io_uring multishot
    accept path).

    Sets ``TCP_NODELAY`` + non-blocking on the fd to match the
    contract of :func:`flare.tcp.listener.accept_fd`. The peer
    address is left empty (loopback placeholder) -- the
    multishot-accept path discards it for performance, and the
    static-response path (the only consumer of this helper today)
    doesn't use ``Request.peer``.
    """
    from std.ffi import c_int
    from flare.net.socket import RawSocket
    from flare.net._libc import AF_INET, SOCK_STREAM

    var raw = RawSocket(c_int(fd), AF_INET, SOCK_STREAM, True)
    raw.set_tcp_nodelay(True)
    raw.set_nonblocking(True)
    var stream = TcpStream(raw^, SocketAddr.localhost(0))
    return Pool[ConnHandle].alloc_move(ConnHandle(stream^))


def _cleanup_conn_uring(
    fd: Int,
    mut conns: Dict[Int, Int],
):
    """``_cleanup_conn`` analog for the io_uring backend.

    Closing the fd implicitly cancels every multishot poll the
    kernel holds against it, so we don't bother issuing
    ``cancel_poll`` here -- the kernel auto-posts a final
    no-more-events CQE shortly after close, which the dispatch
    loop drops as a "conn_id not in dict" miss.

    The ConnHandle's destructor (run via ``Pool[ConnHandle].free``)
    closes the underlying ``TcpStream`` socket, which is the
    actual ``close(fd)`` syscall.
    """
    if fd in conns:
        try:
            var addr = conns.pop(fd)
            _conn_free_addr(addr)
        except:
            pass


def run_uring_reactor_loop_static(
    mut listener: TcpListener,
    config: ServerConfig,
    resp: StaticResponse,
    ref stopping: Bool,
) raises:
    """``io_uring``-backed reactor loop for the static-response path.

    Functional twin of :func:`run_reactor_loop_static` but uses
    :class:`flare.runtime.uring_reactor.UringReactor` for both the
    accept path (multishot accept; one SQE arms it, the kernel
    posts an accept CQE per incoming connection) and the per-conn
    readiness path (multishot poll for ``POLLIN | POLLRDHUP`` on
    accepted fds; ``POLLOUT`` after ``on_readable_static``
    transitions the connection to write-mode).

    Per-connection ``ConnHandle.on_readable_static`` /
    ``on_writable`` are unchanged -- the uring path replaces
    *readiness notification*, not the per-conn syscall pattern.
    A separate dispatch loop (``run_uring_bufring_reactor_loop``,
    opt-in via ``FLARE_BUFRING_HANDLER=1``) swaps the in-handle
    ``recv`` for ``IORING_OP_RECV`` + ``IORING_RECV_MULTISHOT``
    against a registered ``IORING_REGISTER_PBUF_RING`` to drop
    the recv syscall entirely.

    Linux-only. Caller is expected to gate this on
    :func:`flare.runtime.uring_reactor.use_uring_backend`.

    Args:
        listener: Bound and listening ``TcpListener`` (caller
            owns it; we borrow for accept / fd access).
        config: Server configuration.
        resp: Pre-encoded static response from
            ``precompute_response(...)``.
        stopping: Checked on every loop iteration; when True the
            loop exits and in-flight connections are closed.
    """
    comptime if not CompilationTarget.is_linux():
        raise Error(
            "run_uring_reactor_loop_static: io_uring path is Linux-only"
        )
    from flare.runtime.uring_reactor import (
        URING_OP_ACCEPT,
        URING_OP_POLL,
        UringCompletion,
        UringReactor,
    )
    from flare.runtime.io_uring_sqe import POLLIN, POLLOUT, POLLRDHUP

    listener._socket.set_nonblocking(True)
    var listener_fd = Int(listener._socket.fd)

    var ureactor = UringReactor(256)
    var conns = Dict[Int, Int]()

    # Multishot accept: one SQE arms it; the kernel posts a CQE per
    # accepted connection with the new fd in ``comp.res``.
    ureactor.arm_listener_multishot(listener_fd, UInt64(0))

    var completions = List[UringCompletion]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutUntrackedOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        completions.clear()
        try:
            # min_complete=1 -> block until at least one CQE arrives.
            # Closing the listener (HttpServer.close()) terminates the
            # multishot accept which posts a final CQE and wakes us up,
            # so the loop exits promptly on graceful-shutdown.
            _ = ureactor.poll(1, completions, 64)
        except:
            break

        for i in range(len(completions)):
            var comp = completions[i]
            if comp.op == URING_OP_ACCEPT:
                # Multishot accept completion. ``comp.res`` is the new
                # client fd on success, or a negative errno on error
                # (typically -EBADF when the listener is closed during
                # graceful shutdown -- we let the outer ``stopping``
                # check handle that).
                if comp.is_error():
                    continue
                var client_fd = Int(comp.res)
                var addr: Int
                try:
                    addr = _alloc_conn_from_accepted_fd(client_fd)
                except:
                    # Fd-allocator failure (rare; OOM); close the
                    # accepted fd to avoid leaking it.
                    var c = c_int(client_fd)
                    _ = _close(c)
                    continue
                conns[client_fd] = addr
                var ch_ptr = _conn_ptr_from_int(addr)
                # Track the initial interest so the no-op-skip in
                # the dispatch path works on the first read->read cycle.
                ch_ptr[].last_interest = Int(POLLIN | POLLRDHUP)
                try:
                    ureactor.arm_poll_readable_multishot(
                        client_fd, UInt64(client_fd), POLLIN | POLLRDHUP
                    )
                except:
                    _cleanup_conn_uring(client_fd, conns)
                continue

            if comp.op != URING_OP_POLL:
                # Wakeup CQEs are filtered inside UringReactor.poll;
                # remove-acks (URING_OP_POLL_REMOVE) + the
                # final-no-more-events poll CQE land here when a
                # re-arm cancelled an existing poll. Both are safe
                # to ignore -- the new poll SQE is already in flight
                # by the time we see them.
                continue

            # URING_OP_POLL completion. ``conn_id`` is the connection
            # fd; ``comp.res`` carries the OR of poll bits that fired.
            var fd = Int(comp.conn_id)
            if fd not in conns:
                # Stale CQE from a connection that was just cleaned up.
                continue

            var ch_ptr = _conn_ptr_from_int(conns[fd])
            var step_done = False
            try:
                var poll_bits = UInt32(comp.res)
                var last_step = StepResult()
                var did_anything = False

                if (poll_bits & POLLIN) != 0:
                    last_step = ch_ptr[].on_readable_static(resp, config)
                    step_done = last_step.done
                    did_anything = True
                    # Inline-cycle keep-alive optimisation, mirroring
                    # the epoll path: while the state machine is still
                    # cycling, drive the next step rather than bouncing
                    # back through the reactor. Cap at 3 cycles.
                    var cycles = 0
                    while (not step_done) and cycles < 3:
                        cycles += 1
                        if (
                            last_step.want_write
                            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
                        ):
                            last_step = ch_ptr[].on_writable(config)
                            step_done = last_step.done
                        elif (
                            last_step.want_read
                            and len(ch_ptr[].read_buf) > 0
                            and ch_ptr[].state == STATE_READING
                        ):
                            last_step = ch_ptr[].on_readable_static(
                                resp, config
                            )
                            step_done = last_step.done
                        else:
                            break

                if (not did_anything) and (poll_bits & POLLOUT) != 0:
                    last_step = ch_ptr[].on_writable(config)
                    step_done = last_step.done

                if not step_done:
                    # Compute the new interest mask + re-arm if it
                    # changed. This is the io_uring equivalent of
                    # _apply_step's ``reactor.modify(fd, interest)``.
                    var new_mask: UInt32 = 0
                    if last_step.want_read:
                        new_mask |= POLLIN | POLLRDHUP
                    if last_step.want_write:
                        new_mask |= POLLOUT
                    if new_mask != 0:
                        var key = Int(new_mask)
                        if key != ch_ptr[].last_interest:
                            if ch_ptr[].last_interest != 0:
                                try:
                                    ureactor.cancel_poll(UInt64(fd))
                                except:
                                    pass
                            try:
                                ureactor.arm_poll_readable_multishot(
                                    fd, UInt64(fd), new_mask
                                )
                                ch_ptr[].last_interest = key
                            except:
                                step_done = True
            except:
                step_done = True
            if step_done:
                _cleanup_conn_uring(fd, conns)

    # Graceful shutdown: drop every in-flight conn. Closing each fd
    # implicitly tears down its kernel-side multishot poll.
    var leftover = List[Int]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_uring(leftover[i], conns)


# ── io_uring buffer-ring dispatch (handler path) ────────────────────────────
#
# Production handler-path io_uring loop using the kernel-managed buffer
# ring substrate: ``IORING_OP_RECV`` + ``IORING_RECV_MULTISHOT`` +
# ``IOSQE_BUFFER_SELECT`` against a registered buffer group (set up via
# ``IORING_REGISTER_PBUF_RING`` on kernels >= 5.19, or
# ``IORING_OP_PROVIDE_BUFFERS`` on older).
#
# How it works
# ------------
#
# This is the same pattern every Rust io_uring HTTP server (tokio-uring,
# monoio, glommio) uses:
#
#   1. At reactor startup, allocate a per-worker buffer pool of
#      N × 8 KiB and register it as a buffer group via
#      ``register_pbuf_ring(bgid, ring_entries)``. The kernel takes
#      ownership of the buffer ring; we keep the backing allocation
#      alive (free at reactor shutdown).
#   2. On each accept CQE, arm one IORING_OP_RECV +
#      IORING_RECV_MULTISHOT + IOSQE_BUFFER_SELECT SQE with
#      buf_group=bgid. The kernel auto-rotates buffers from the
#      pool for every recv on this fd; one SQE per connection
#      drives an unbounded stream of recv CQEs.
#   3. On each recv CQE, the buffer id is in the CQE's flags
#      high 16 bits (IORING_CQE_F_BUFFER set). We compute the
#      buffer's address as ``pool + bid * BUF_SIZE``, feed the
#      bytes into ConnHandle.on_readable_from_buf[H], and recycle
#      the buffer back into the pool via a shared-memory tail bump
#      (PBUF_RING) or a one-shot PROVIDE_BUFFERS SQE (older
#      kernels).
#   4. On step_done, just free the conn (close fd; kernel cancels
#      any pending recv multishot SQE). No per-conn buffer to free
#      -- the buffer was already returned to the pool in step 3
#      (or will be returned by the kernel on the next CQE).
#
# Why MULTISHOT recv requires the buffer ring: without
# ``IOSQE_BUFFER_SELECT``, IORING_RECV_MULTISHOT either errors out,
# fires once and stops, or unsafely reuses the user's single buffer
# across overlapping CQEs. ``IORING_OP_POLL_ADD``'s multishot mode is
# also unsuitable because its edge-triggered semantics race against
# the recv-EAGAIN drain pattern under back-to-back keep-alive.
#
# This eliminates per-conn buffer pinning AND drops the recv
# syscall per request (the kernel hands us bytes via the buffer
# ring), which is the principal io_uring performance unlock for
# the recv-side.
#
# Send path is synchronous ``on_writable`` using non-blocking
# ``_send``. ``UringReactor.submit_send`` is exposed as substrate
# for callers that want to land kernel-async sends on top of
# this dispatch.


comptime _URING_BR_BUF_SIZE: Int = 8192
comptime _URING_BR_NBUFS: Int = 256
comptime _URING_BR_BGID: UInt16 = 1

# Generation-stamped conn_id encoding -- the fix for the
# 9cf97d0 SIGSEGV under concurrent connections.
#
# When connection A on fd=8 closes, the kernel may have a
# trailing recv CQE in flight (the final-no-more-events CQE
# from the cancelled multishot recv) tagged with conn_id=8.
# If a new connection B is accepted on the *same* fd=8 before
# we see that stale CQE, our naive ``conn_id = fd`` scheme
# routes the stale CQE to B's freshly-armed recv state -- which
# either double-arms recv (kernel SIGSEGV territory) or feeds
# stale buffer-id data into B's parser. Generation-stamped
# conn_ids fix this: each accept bumps a per-worker monotonic
# generation counter, packs ``(gen << 24) | fd`` into the
# 56-bit conn_id space, and stores the conn under that full
# packed id. Stale CQEs from connection A carry the OLD gen
# bits and miss the ``if conn_id not in conns`` lookup --
# they're dropped cleanly, never touching connection B's
# state.
#
# 24-bit fd / 32-bit gen split: fd values fit in 24 bits even
# at the kernel's per-process limit (typically 2^20 on a
# default ulimit); 32-bit generation gives 4 billion connections
# per worker before wrap-around (effectively infinite for any
# bench window).

comptime _URING_BR_FD_BITS: Int = 24
comptime _URING_BR_FD_MASK: UInt64 = (
    UInt64(1) << UInt64(_URING_BR_FD_BITS)
) - UInt64(1)


@always_inline
def _br_pack_conn_id(fd: Int, gen: UInt64) -> UInt64:
    """Pack ``(gen, fd)`` into the 56-bit conn_id slot used by
    the buffer-ring dispatch."""
    return (gen << UInt64(_URING_BR_FD_BITS)) | (UInt64(fd) & _URING_BR_FD_MASK)


@always_inline
def _br_unpack_fd(conn_id: UInt64) -> Int:
    """Extract the fd portion of a packed buffer-ring conn_id."""
    return Int(conn_id & _URING_BR_FD_MASK)


def _probe_bufring_setup_flags(entries: Int = 64) -> UInt32:
    """Probe the host kernel for the best ``IORING_SETUP_*``
    flag mask the bufring dispatch can use.

    The bufring dispatch's throughput is sensitive to how the
    kernel runs task work relative to the dispatch loop's
    CQE-drain rhythm. The kernel scheduler hints introduced in
    5.19 (COOP_TASKRUN + TASKRUN_FLAG + SUBMIT_ALL) and 6.0/6.1
    (SINGLE_ISSUER + DEFER_TASKRUN) batch task work to enter
    boundaries instead of running it IPI-style mid-syscall.

    Probes from highest-impact-first to default:
    1. SINGLE_ISSUER | DEFER_TASKRUN | COOP_TASKRUN |
       TASKRUN_FLAG | SUBMIT_ALL  (>= 6.1, the optimal mix)
    2. COOP_TASKRUN | TASKRUN_FLAG | SUBMIT_ALL  (>= 5.19)
    3. SUBMIT_ALL  (>= 5.18)
    4. 0 (default; works on any 5.1+ kernel)

    Returns the first mask the kernel accepts via a no-op
    ``IoUringRing(entries)`` setup; closes the probe ring
    immediately. Called once per worker at bufring loop init.

    Args:
        entries: SQE count for the probe ring; tiny so the
            probe is cheap. Defaults to 64.

    Returns:
        Best-fit setup_flags mask, or 0 if no flag combination
        is accepted (kernel < 5.18 or io_uring unavailable).
    """
    from flare.runtime.io_uring import IoUringRing
    from flare.runtime.io_uring_sqe import (
        IORING_SETUP_COOP_TASKRUN,
        IORING_SETUP_TASKRUN_FLAG,
        IORING_SETUP_SUBMIT_ALL,
        IORING_SETUP_SINGLE_ISSUER,
        IORING_SETUP_DEFER_TASKRUN,
    )

    # Probe order: COOP_TASKRUN + TASKRUN_FLAG + SUBMIT_ALL
    # FIRST (5.19+ reliable). DEFER_TASKRUN + SINGLE_ISSUER
    # (6.1+) are tried LAST because they require GETEVENTS-on-
    # every-enter (which we honour in submit_and_wait), but
    # under load the kernel still throttles multishot recv CQE
    # delivery in unpredictable ways with DEFER_TASKRUN. Empirical
    # observation on dev-box (kernel 6.8): bufring throughput is
    # ~60 Hz with DEFER_TASKRUN and significantly higher without.
    # If a future kernel version fixes this, swap the order.
    var t1 = (
        IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_TASKRUN_FLAG
        | IORING_SETUP_SUBMIT_ALL
    )
    var t2 = IORING_SETUP_SUBMIT_ALL
    var t3 = (
        IORING_SETUP_SINGLE_ISSUER
        | IORING_SETUP_DEFER_TASKRUN
        | IORING_SETUP_COOP_TASKRUN
        | IORING_SETUP_TASKRUN_FLAG
        | IORING_SETUP_SUBMIT_ALL
    )

    var candidates = [t1, t2, t3]
    for i in range(len(candidates)):
        try:
            var probe = IoUringRing(entries, setup_flags=candidates[i])
            _ = probe^
            return candidates[i]
        except:
            pass
    return UInt32(0)


def _alloc_recv_buffer_pool() raises -> Int:
    """Allocate the worker-local recv buffer pool: ``_URING_BR_NBUFS``
    contiguous buffers of ``_URING_BR_BUF_SIZE`` bytes.

    Caller owns the lifetime; the kernel retains pointers via the
    PROVIDE_BUFFERS SQE but the userspace allocation must outlive
    the reactor (released on graceful shutdown via
    ``_free_recv_buffer_pool``).
    """
    var size = _URING_BR_NBUFS * _URING_BR_BUF_SIZE
    var raw = alloc[UInt8](size)
    # Zero-init defensively; kernel will overwrite the prefix of
    # each buffer on every recv, but a stale read of an unused
    # slot (e.g. dump-on-error) shouldn't trip on uninitialised
    # memory.
    for i in range(size):
        (raw + i).init_pointee_copy(UInt8(0))
    return Int(raw)


def _free_recv_buffer_pool(addr: Int):
    """Release the pool previously returned by ``_alloc_recv_buffer_pool``."""
    if addr == 0:
        return
    var p = UnsafePointer[UInt8, MutUntrackedOrigin](unsafe_from_address=addr)
    p.free()


def _cleanup_conn_uring_br(
    conn_id: UInt64,
    mut conns: Dict[UInt64, Int],
    mut ureactor: UringReactor,
):
    """``_cleanup_conn`` for the buffer-ring path.

    Cleanup ordering matters because there's a kernel-level race
    between conn-close and reaccept-on-the-same-fd: if we close
    the fd while the kernel still has an armed multishot recv on
    it, the kernel's implicit cancel of that recv races against
    a potential new accept on the reused fd. Empirically this
    SIGSEGV's our process under sustained conn-churn (sequential
    8 short-lived conns reproduces; sleep(50ms) between conns
    masks it; ASAN's slowdown also masks it).

    The fix: explicitly cancel the multishot recv BEFORE freeing
    the ConnHandle, so the kernel processes the cancel cleanly
    while the fd is still open and the io_uring ring resources
    for that recv are still valid. The cancel CQE arrives a few
    iterations later and is silently dropped (no op tag handler
    for URING_OP_CANCEL); the recv's terminal CQE is dropped via
    the ``conn_id not in conns`` gen-stamp miss.
    """
    if conn_id in conns:
        # Issue the cancel BEFORE freeing the ConnHandle (which
        # closes the fd). cancel_conn uses URING_OP_ASYNC_CANCEL
        # targeting the recv SQE tagged with this conn_id.
        try:
            ureactor.cancel_conn(conn_id)
        except:
            # SQ pressure -- fall back to implicit cancel via fd
            # close. Higher race risk but the only alternative is
            # to drop the cleanup which would leak the conn.
            pass
        try:
            var addr = conns.pop(conn_id)
            _conn_free_addr(addr)
        except:
            pass


def _drive_handler_with_submit_send[
    H: Handler,
](
    fd: Int,
    conn_id: UInt64,
    bytes: Span[UInt8, _],
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutUntrackedOrigin],
    mut ureactor: UringReactor,
) raises -> Bool:
    """Drive one request via parse → handler → submit_send.

    After ``on_readable_from_buf`` parses the request and queues
    the response in ``write_buf``, this helper submits an
    ``IORING_OP_SEND`` SQE pointing at the write_buf bytes
    (instead of the synchronous ``_send`` syscall used in
    ``_drive_handler_after_buf_recv``). The conn is marked
    ``send_in_flight=True``; subsequent recv CQEs for this conn
    just buffer bytes into read_buf without parsing (the next
    request can't be processed until the kernel releases the
    write_buf via the matching send CQE).

    Returns True iff the conn should be cleaned up (handler
    raised, response framing failed, etc.).
    """
    var step_done: Bool
    try:
        var last_step = ch_ptr[].on_readable_from_buf(bytes, handler, config)
        step_done = last_step.done
        # Pipelined-request inline cycle: drain everything in
        # read_buf BEFORE submitting the send (so we batch
        # multiple responses if the client pipelined). Each
        # cycle iter writes to write_buf; the LAST one's bytes
        # are what we submit_send.
        while not step_done:
            if (
                last_step.want_read
                and len(ch_ptr[].read_buf) > 0
                and ch_ptr[].state == STATE_READING
            ):
                # NOTE: we DON'T call on_writable here -- we let
                # write_buf accumulate, then submit_send the
                # whole thing once.
                var empty_buf = stack_allocation[1, UInt8]()
                last_step = ch_ptr[].on_readable_from_buf(
                    Span[UInt8, _](ptr=empty_buf, length=0),
                    handler,
                    config,
                )
                step_done = last_step.done
            else:
                break
        # If we're now in STATE_WRITING with bytes to send, fire
        # off the submit_send + mark in-flight. The send CQE will
        # land later; the dispatch handler will reset state +
        # process any deferred read_buf bytes then.
        if (
            (not step_done)
            and ch_ptr[].state == STATE_WRITING
            and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
        ):
            var write_ptr = ch_ptr[].write_buf.unsafe_ptr() + ch_ptr[].write_pos
            var write_len = len(ch_ptr[].write_buf) - ch_ptr[].write_pos
            try:
                ureactor.submit_send(fd, write_ptr, write_len, conn_id)
                ch_ptr[].send_in_flight = True
            except:
                # SQ full -- can't kick off the send. Drop the
                # conn rather than leaving the response stranded.
                step_done = True
    except:
        step_done = True
    return step_done


def _on_send_cqe_complete[
    H: Handler,
](
    fd: Int,
    conn_id: UInt64,
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutUntrackedOrigin],
    mut ureactor: UringReactor,
) raises -> Bool:
    """Handle a ``URING_OP_SEND`` CQE: clear the send-in-flight
    state, drain any read_buf bytes that were buffered while the
    send was in flight, and start a new request cycle if there
    are buffered bytes.

    Returns True iff the conn should be cleaned up (e.g.,
    ``should_close`` was set on the just-sent response and there
    are no more requests to serve).
    """
    ch_ptr[].send_in_flight = False
    # Reset the write buffer so the next request's response
    # serializes from a clean state.
    ch_ptr[].write_buf.clear()
    ch_ptr[].write_pos = 0
    # Was this the close-after-send response? If so, the conn is
    # done.
    if ch_ptr[].should_close:
        return True
    # Transition back to reading; drain any pipelined bytes that
    # arrived while send was in flight.
    ch_ptr[].state = STATE_READING
    if len(ch_ptr[].read_buf) > 0:
        var empty_buf = stack_allocation[1, UInt8]()
        return _drive_handler_with_submit_send[H](
            fd,
            conn_id,
            Span[UInt8, _](ptr=empty_buf, length=0),
            config,
            handler,
            ch_ptr,
            ureactor,
        )
    return False


def _drive_handler_after_buf_recv[
    H: Handler,
](
    bytes: Span[UInt8, _],
    config: ServerConfig,
    ref handler: H,
    ch_ptr: UnsafePointer[ConnHandle, MutUntrackedOrigin],
) raises -> Bool:
    """Sync-send variant kept as a fallback / reference -- see
    ``_drive_handler_with_submit_send`` for the production io_uring
    path that uses ``submit_send`` instead of synchronous
    ``on_writable``.
    """
    var step_done: Bool
    try:
        var last_step = ch_ptr[].on_readable_from_buf(bytes, handler, config)
        step_done = last_step.done
        while not step_done:
            if (
                last_step.want_write
                and len(ch_ptr[].write_buf) > ch_ptr[].write_pos
            ):
                last_step = ch_ptr[].on_writable(config)
                step_done = last_step.done
                if (not step_done) and last_step.want_write:
                    step_done = True
            elif (
                last_step.want_read
                and len(ch_ptr[].read_buf) > 0
                and ch_ptr[].state == STATE_READING
            ):
                # Pipelined request already in read_buf -- drive the
                # parser without appending more bytes. Use stack-
                # allocated empty span (Span over a temp List would
                # be a use-after-free).
                var empty_buf = stack_allocation[1, UInt8]()
                last_step = ch_ptr[].on_readable_from_buf(
                    Span[UInt8, _](ptr=empty_buf, length=0),
                    handler,
                    config,
                )
                step_done = last_step.done
            else:
                break
    except:
        step_done = True
    return step_done


def run_uring_bufring_reactor_loop[
    H: Handler,
](
    mut listener: TcpListener,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Single-worker io_uring buffer-ring reactor loop.

    Production handler-path io_uring loop. See the module-level
    "io_uring buffer-ring dispatch" comment block above for the
    design rationale and the *Why this finally works* note.
    Linux-only.

    Functionally equivalent to :func:`run_uring_bufring_reactor_loop_shared`
    once the listener fd is extracted -- io_uring's multishot accept
    is already kernel-side fan-out, so there's no
    ``EPOLLEXCLUSIVE``-style register-mode distinction the way the
    epoll/kqueue path needs. This entry sets the listener
    non-blocking, hands off the fd, and delegates to the shared body.
    """
    listener._socket.set_nonblocking(True)
    run_uring_bufring_reactor_loop_shared[H](
        Int(listener._socket.fd), config, handler, stopping
    )


def run_uring_bufring_reactor_loop_shared[
    H: Handler,
](
    listener_fd: Int,
    config: ServerConfig,
    ref handler: H,
    ref stopping: Bool,
) raises:
    """Multi-worker io_uring buffer-ring reactor loop.

    Sharing-listener twin of :func:`run_uring_bufring_reactor_loop`.
    Each pthread worker owns its own UringReactor + per-worker
    buffer pool (no cross-worker sharing -- the buffer ring is
    per-ring, and rings are per-worker). Multishot accept on the
    shared listener fd from each worker; kernel hands each new
    connection to exactly one worker. Linux-only.
    """
    comptime if not CompilationTarget.is_linux():
        raise Error(
            "run_uring_bufring_reactor_loop_shared: io_uring path is Linux-only"
        )
    from flare.runtime.uring_reactor import (
        URING_OP_ACCEPT,
        URING_OP_PROVIDE_BUFFERS,
        URING_OP_RECV,
        URING_OP_SEND,
        UringCompletion,
        UringReactor,
    )
    from flare.runtime.io_uring_sqe import IORING_CQE_F_BUFFER

    # Same setup-flag probe as the single-worker variant;
    # per-worker rings independently negotiate. Each worker is
    # single-issuer (one pthread owns its ring) so the wakeup
    # eventfd is skipped via enable_wakeup=False.
    var ureactor = UringReactor(
        4096,
        setup_flags=_probe_bufring_setup_flags(),
        enable_wakeup=False,
    )
    var conns = Dict[UInt64, Int]()
    var next_gen: UInt64 = 1
    var submit_send = getenv("FLARE_SUBMIT_SEND") == "1"

    var pool_addr = _alloc_recv_buffer_pool()
    var ring_addr = ureactor.register_pbuf_ring(_URING_BR_BGID, _URING_BR_NBUFS)
    for i in range(_URING_BR_NBUFS):
        _pbuf_ring_add(
            ring_addr,
            _URING_BR_NBUFS,
            UInt64(pool_addr + i * _URING_BR_BUF_SIZE),
            UInt32(_URING_BR_BUF_SIZE),
            UInt16(i),
            i,
            UInt16(0),
        )
    _pbuf_ring_set_tail(ring_addr, UInt16(_URING_BR_NBUFS))

    ureactor.arm_listener_multishot(listener_fd, UInt64(0))

    var completions = List[UringCompletion]()
    var stopping_addr = Int(UnsafePointer[Bool, _](to=stopping))
    while not UnsafePointer[Bool, MutUntrackedOrigin](
        unsafe_from_address=stopping_addr
    )[]:
        completions.clear()
        try:
            _ = ureactor.poll(1, completions, 64)
        except:
            break

        for i in range(len(completions)):
            var comp = completions[i]
            if comp.op == URING_OP_ACCEPT:
                if comp.is_error():
                    continue
                var client_fd = Int(comp.res)
                var conn_addr: Int
                try:
                    conn_addr = _alloc_conn_from_accepted_fd(client_fd)
                except:
                    var c = c_int(client_fd)
                    _ = _close(c)
                    continue
                var conn_id = _br_pack_conn_id(client_fd, next_gen)
                next_gen += 1
                conns[conn_id] = conn_addr
                try:
                    ureactor.arm_recv_buffer_select(
                        client_fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            if comp.op == URING_OP_PROVIDE_BUFFERS:
                continue

            if comp.op == URING_OP_SEND:
                var send_conn_id = comp.conn_id
                if send_conn_id not in conns:
                    continue
                var send_fd = _br_unpack_fd(send_conn_id)
                var send_ch_ptr = _conn_ptr_from_int(conns[send_conn_id])
                var send_done = _on_send_cqe_complete[H](
                    send_fd,
                    send_conn_id,
                    config,
                    handler,
                    send_ch_ptr,
                    ureactor,
                )
                if send_done:
                    _cleanup_conn_uring_br(send_conn_id, conns, ureactor)
                continue

            if comp.op != URING_OP_RECV:
                continue

            var conn_id = comp.conn_id
            if conn_id not in conns:
                continue
            if comp.res <= 0:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue
            if (comp.flags & IORING_CQE_F_BUFFER) == UInt32(0):
                _cleanup_conn_uring_br(conn_id, conns, ureactor)
                continue

            var fd = _br_unpack_fd(conn_id)
            var bid = Int(comp.flags >> UInt32(16))
            var n = Int(comp.res)
            var pool_ptr = UnsafePointer[UInt8, MutUntrackedOrigin](
                unsafe_from_address=pool_addr
            )
            var buf = pool_ptr + (bid * _URING_BR_BUF_SIZE)
            var ch_ptr = _conn_ptr_from_int(conns[conn_id])

            # Stage the kernel bytes into the conn's ``read_buf``
            # before the handler runs (Mojo 1.0.0b1 Span-origin
            # narrowing -- see the matching block in the
            # single-worker variant for the full rationale).
            ch_ptr[].read_buf.reserve(len(ch_ptr[].read_buf) + n)
            for i in range(n):
                ch_ptr[].read_buf.append((buf + i).load())

            # Re-fill via shared-memory tail bump (PBUF_RING).
            var cur_tail = _pbuf_ring_get_tail(ring_addr)
            _pbuf_ring_add(
                ring_addr,
                _URING_BR_NBUFS,
                UInt64(Int(buf)),
                UInt32(_URING_BR_BUF_SIZE),
                UInt16(bid),
                0,
                cur_tail,
            )
            _pbuf_ring_set_tail(ring_addr, cur_tail + UInt16(1))

            var step_done = False
            var empty_buf = stack_allocation[1, UInt8]()
            var empty_span = Span[UInt8, _](ptr=empty_buf, length=0)
            if submit_send:
                if not ch_ptr[].send_in_flight:
                    step_done = _drive_handler_with_submit_send[H](
                        fd,
                        conn_id,
                        empty_span,
                        config,
                        handler,
                        ch_ptr,
                        ureactor,
                    )
            else:
                step_done = _drive_handler_after_buf_recv[H](
                    empty_span, config, handler, ch_ptr
                )

            if (not step_done) and (not comp.has_more):
                try:
                    ureactor.arm_recv_buffer_select(
                        fd,
                        _URING_BR_BGID,
                        conn_id,
                        True,
                    )
                except:
                    step_done = True

            if step_done:
                _cleanup_conn_uring_br(conn_id, conns, ureactor)

    # Worker shutdown: close all per-conn fds + free pool +
    # unregister the kernel ring. Shared listener fd stays open
    # -- Scheduler.shutdown closes it.
    var leftover = List[UInt64]()
    for kv in conns.items():
        leftover.append(kv.key)
    for i in range(len(leftover)):
        _cleanup_conn_uring_br(leftover[i], conns, ureactor)
    try:
        ureactor.unregister_pbuf_ring(
            _URING_BR_BGID, ring_addr, _URING_BR_NBUFS
        )
    except:
        pass
    _free_recv_buffer_pool(pool_addr)
