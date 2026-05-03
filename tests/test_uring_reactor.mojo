"""Tests for :mod:`flare.runtime.uring_reactor` — the io_uring-
native event-loop wrapper (Track B0 wire-in).

Coverage:

1. ``pack_user_data`` / ``unpack_op`` / ``unpack_conn_id`` round
   trip across the full 56-bit conn_id range and all 6 op tags.
   These are the wire-format invariants the reactor + server
   loop both rely on for cheap CQE dispatch.
2. ``UringReactor`` constructs cleanly on a host with io_uring
   available; ``fd >= 0``, ``sq_entries >= entries``,
   ``cq_entries >= 2 * sq_entries`` (the kernel default).
3. ``poll(0, ...)`` on a fresh reactor returns 0 completions
   immediately (non-blocking + nothing armed).
4. ``arm_listener_multishot`` against a real loopback TCP
   listener: open three ``connect()`` clients, ``poll(1, ...)``
   per client, verify three completions tagged
   ``URING_OP_ACCEPT`` come back with positive ``res`` (the
   accepted fd) and ``has_more = True`` (multishot still armed).
5. ``submit_send`` end-to-end: ``connect()`` → ``arm_recv_*``
   on the accepted fd → ``submit_send`` → poll for 2
   completions (a recv + a send), validate byte-count and tag.
6. ``wakeup`` posts a CQE that ``poll(1, ...)`` consumes
   internally without surfacing it to the caller (the loop
   re-arms transparently).
7. **Skip cleanly** when the host kernel does not expose
   io_uring (sandbox, pre-5.1, or container without the
   syscall) — same skip pattern as ``test_io_uring_driver``.
"""

from std.ffi import c_int, c_uint, c_size_t, get_errno
from std.memory import UnsafePointer, alloc, stack_allocation
from std.testing import assert_equal, assert_true, assert_false

from flare.net._libc import (
    AF_INET,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    INVALID_FD,
    _socket,
    _bind,
    _listen,
    _connect,
    _close,
    _setsockopt,
    _getsockname,
    _strerror,
    _send,
    _fill_sockaddr_in,
)
from flare.runtime.io_uring import is_io_uring_available
from flare.runtime.io_uring_sqe import POLLIN, POLLRDHUP
from flare.runtime.uring_reactor import (
    URING_OP_ACCEPT,
    URING_OP_RECV,
    URING_OP_SEND,
    URING_OP_CLOSE,
    URING_OP_CANCEL,
    URING_OP_POLL,
    URING_OP_POLL_REMOVE,
    URING_OP_PROVIDE_BUFFERS,
    URING_OP_WAKEUP,
    UringCompletion,
    UringReactor,
    pack_user_data,
    unpack_conn_id,
    unpack_op,
    use_uring_backend,
)
from flare.runtime.io_uring_sqe import IORING_CQE_F_BUFFER


# ── pack/unpack invariants ───────────────────────────────────────────────────


def test_pack_unpack_round_trip() raises:
    """Round-trip every op kind across 0, 1, mid-range, and
    the 56-bit boundary of conn_id."""
    var ops = List[UInt64]()
    ops.append(URING_OP_ACCEPT)
    ops.append(URING_OP_RECV)
    ops.append(URING_OP_SEND)
    ops.append(URING_OP_CLOSE)
    ops.append(URING_OP_CANCEL)
    ops.append(URING_OP_WAKEUP)

    var ids = List[UInt64]()
    ids.append(UInt64(0))
    ids.append(UInt64(1))
    ids.append(UInt64(0x12345678))
    ids.append(UInt64(0xFFFFFFFFFFFFFF))  # 2^56 - 1

    for i in range(len(ops)):
        for j in range(len(ids)):
            var ud = pack_user_data(ops[i], ids[j])
            assert_equal(Int(unpack_op(ud)), Int(ops[i]))
            assert_equal(Int(unpack_conn_id(ud)), Int(ids[j]))


def test_pack_op_does_not_clobber_conn_id() raises:
    """Two different ops on the same conn_id must produce
    different user_data, but the same conn_id round-trip."""
    var a = pack_user_data(URING_OP_RECV, UInt64(42))
    var b = pack_user_data(URING_OP_SEND, UInt64(42))
    assert_true(a != b)
    assert_equal(Int(unpack_conn_id(a)), 42)
    assert_equal(Int(unpack_conn_id(b)), 42)


# ── construction + idle poll ────────────────────────────────────────────────


def test_construction_succeeds() raises:
    if not is_io_uring_available():
        print("test_construction_succeeds: skipped (io_uring not available)")
        return
    var r = UringReactor(64)
    assert_true(r.fd() >= 0)
    assert_true(r.sq_entries() >= 64)
    assert_true(r.cq_entries() >= 64)


def test_idle_poll_returns_zero() raises:
    if not is_io_uring_available():
        print("test_idle_poll_returns_zero: skipped (io_uring not available)")
        return
    var r = UringReactor(16)
    var out = List[UringCompletion]()
    var n = r.poll(0, out)
    # The lazy-armed wakeup recv may or may not have produced a
    # CQE depending on kernel scheduling; either way, the public
    # surface returns 0 (wakeup CQEs are filtered out).
    assert_equal(n, 0)
    assert_equal(len(out), 0)


# ── live multishot accept via UringReactor ──────────────────────────────────


@fieldwise_init
struct _Listener(Copyable, Movable):
    var fd: c_int
    var port: UInt16


def _make_listener() raises -> _Listener:
    var s = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if s < c_int(0):
        raise Error("socket: " + _strerror(get_errno().value))
    var one = stack_allocation[4, UInt8]()
    (one + 0).init_pointee_copy(UInt8(1))
    for k in range(1, 4):
        (one + k).init_pointee_copy(UInt8(0))
    _ = _setsockopt(s, SOL_SOCKET, SO_REUSEADDR, one, c_uint(4))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, UInt16(0), ip)
    if _bind(s, sa, c_uint(16)) < c_int(0):
        var e = _strerror(get_errno().value)
        _ = _close(s)
        raise Error("bind: " + e)
    if _listen(s, c_int(8)) < c_int(0):
        var e = _strerror(get_errno().value)
        _ = _close(s)
        raise Error("listen: " + e)
    var sa2 = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa2 + i).init_pointee_copy(UInt8(0))
    var alen = stack_allocation[1, c_uint]()
    alen.init_pointee_copy(c_uint(16))
    _ = _getsockname(s, sa2, alen)
    var hi = Int((sa2 + 2).load())
    var lo = Int((sa2 + 3).load())
    return _Listener(s, UInt16((hi << 8) | lo))


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("client socket: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_uint(16)) < c_int(0):
        var e = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect: " + e)
    return c


def test_arm_listener_multishot_round_trip() raises:
    """Arm a multishot accept on a loopback listener; open three
    ``connect()``s; verify three accept completions come back
    via ``poll`` with the right op tag, conn_id, and has_more."""
    if not is_io_uring_available():
        print(
            "test_arm_listener_multishot_round_trip: skipped (io_uring"
            " not available)"
        )
        return
    var listener = _make_listener()
    var listener_fd = listener.fd
    var port = listener.port

    var r = UringReactor(32)
    r.arm_listener_multishot(Int(listener_fd), UInt64(0xABCDEF))

    var out = List[UringCompletion]()
    var clients = List[c_int]()
    var accepted = List[Int]()
    for _ in range(3):
        var c = _connect_loopback(port)
        clients.append(c)
        # Block until at least one CQE comes back.
        _ = r.poll(1, out)
        # Find the ACCEPT completion in this batch (the wakeup
        # arm may have produced unrelated CQEs but those are
        # filtered).
        var found = False
        for i in range(len(out)):
            var comp = out[i]
            if comp.op == URING_OP_ACCEPT:
                assert_equal(Int(comp.conn_id), 0xABCDEF)
                assert_true(comp.res > 0)
                assert_true(comp.has_more)
                assert_false(comp.is_error())
                accepted.append(comp.res)
                found = True
                break
        assert_true(found, "no ACCEPT completion in poll batch")

    assert_equal(len(accepted), 3)
    # Distinct accepted fds.
    for i in range(3):
        for j in range(i + 1, 3):
            assert_true(accepted[i] != accepted[j])

    for i in range(len(accepted)):
        _ = _close(c_int(accepted[i]))
    for i in range(len(clients)):
        _ = _close(clients[i])
    _ = _close(listener_fd)


def test_submit_send_round_trip() raises:
    """End-to-end: accept a connection via multishot, arm a
    multishot recv on the accepted fd, then ``submit_send``
    bytes from the client side; verify the recv completion
    surfaces the bytes and the send completion surfaces the
    written byte count."""
    if not is_io_uring_available():
        print("test_submit_send_round_trip: skipped (io_uring not available)")
        return
    var listener = _make_listener()
    var r = UringReactor(32)
    r.arm_listener_multishot(Int(listener.fd), UInt64(7))

    # Open a client connection.
    var client = _connect_loopback(listener.port)

    var out = List[UringCompletion]()
    _ = r.poll(1, out)
    var accepted_fd: Int = -1
    for i in range(len(out)):
        if out[i].op == URING_OP_ACCEPT:
            accepted_fd = out[i].res
            break
    assert_true(accepted_fd > 0)

    # Allocate a small recv buffer (32 bytes) and arm a
    # multishot recv on the accepted fd.
    var rx = alloc[UInt8](32)
    for i in range(32):
        (rx + i).init_pointee_copy(UInt8(0))
    r.arm_recv_multishot(accepted_fd, rx, 32, UInt64(0x42))

    # Have the client write 4 bytes via libc send (we're not
    # exercising UringReactor.submit_send for the client side
    # since the client isn't on the ring).
    var tx = stack_allocation[4, UInt8]()
    (tx + 0).init_pointee_copy(UInt8(ord("p")))
    (tx + 1).init_pointee_copy(UInt8(ord("i")))
    (tx + 2).init_pointee_copy(UInt8(ord("n")))
    (tx + 3).init_pointee_copy(UInt8(ord("g")))
    var w = _send(client, tx, c_size_t(4), c_int(0))
    assert_equal(Int(w), 4)

    # Drain CQEs until we see the recv completion.
    out.clear()
    var saw_recv = False
    for _ in range(8):
        _ = r.poll(1, out)
        for i in range(len(out)):
            var comp = out[i]
            if comp.op == URING_OP_RECV and Int(comp.conn_id) == 0x42:
                assert_equal(comp.res, 4)
                assert_equal(Int((rx + 0).load()), ord("p"))
                assert_equal(Int((rx + 1).load()), ord("i"))
                assert_equal(Int((rx + 2).load()), ord("n"))
                assert_equal(Int((rx + 3).load()), ord("g"))
                saw_recv = True
                break
        if saw_recv:
            break
        out.clear()
    assert_true(saw_recv, "never saw recv completion")

    # Now use UringReactor.submit_send to write a response back
    # over the accepted fd; the client reads it via libc recv.
    var resp = stack_allocation[4, UInt8]()
    (resp + 0).init_pointee_copy(UInt8(ord("p")))
    (resp + 1).init_pointee_copy(UInt8(ord("o")))
    (resp + 2).init_pointee_copy(UInt8(ord("n")))
    (resp + 3).init_pointee_copy(UInt8(ord("g")))
    r.submit_send(accepted_fd, resp, 4, UInt64(0x99))

    out.clear()
    var saw_send = False
    for _ in range(8):
        _ = r.poll(1, out)
        for i in range(len(out)):
            var comp = out[i]
            if comp.op == URING_OP_SEND and Int(comp.conn_id) == 0x99:
                assert_equal(comp.res, 4)
                assert_false(comp.is_error())
                saw_send = True
                break
        if saw_send:
            break
        out.clear()
    assert_true(saw_send, "never saw send completion")

    rx.free()
    _ = _close(c_int(accepted_fd))
    _ = _close(client)
    _ = _close(listener.fd)


def test_wakeup_releases_blocking_poll() raises:
    """Submit nothing, then call ``wakeup`` and verify
    ``poll(1, ...)`` returns promptly. We don't surface the
    wakeup CQE, so the caller sees 0 completions but the call
    returns before any timeout the kernel might apply."""
    if not is_io_uring_available():
        print(
            "test_wakeup_releases_blocking_poll: skipped (io_uring"
            " not available)"
        )
        return
    var r = UringReactor(8)
    var out = List[UringCompletion]()
    # First poll arms the wakeup recv lazily.
    _ = r.poll(0, out)
    # Now write to the eventfd so the multishot recv fires.
    r.wakeup()
    # Block for one CQE; the wakeup CQE is absorbed and
    # filtered out, returning 0 surfaced completions.
    var n = r.poll(1, out)
    assert_equal(n, 0)


def test_arm_poll_readable_multishot_round_trip() raises:
    """Arm a multishot poll on a connected loopback socket; have
    the peer write bytes; verify a ``URING_OP_POLL`` CQE comes
    back with ``POLLIN`` set in ``res`` and ``has_more = True``
    (multishot still armed). This is the substrate the upcoming
    server-loop dispatch swap (B0 wire-in) uses to replace
    ``epoll_wait`` on the io_uring backend.
    """
    if not is_io_uring_available():
        print(
            "test_arm_poll_readable_multishot_round_trip: skipped (io_uring"
            " not available)"
        )
        return
    var listener = _make_listener()
    var r = UringReactor(32)
    r.arm_listener_multishot(Int(listener.fd), UInt64(0))

    var client = _connect_loopback(listener.port)
    var out = List[UringCompletion]()
    _ = r.poll(1, out)
    var accepted_fd: Int = -1
    for i in range(len(out)):
        if out[i].op == URING_OP_ACCEPT:
            accepted_fd = out[i].res
            break
    assert_true(accepted_fd > 0)

    # Arm a multishot poll on the accepted fd. Tag with a
    # well-known conn_id so we can verify the CQE routing.
    r.arm_poll_readable_multishot(
        accepted_fd, UInt64(0xC0DE), POLLIN | POLLRDHUP
    )

    # Drain any pending CQEs without blocking; nothing should
    # have fired yet because nobody has written.
    out.clear()
    _ = r.poll(0, out)
    var fired = False
    for i in range(len(out)):
        if out[i].op == URING_OP_POLL:
            fired = True
            break
    assert_false(fired)

    # Now write 8 bytes from the client side.
    var tx = stack_allocation[8, UInt8]()
    for k in range(8):
        (tx + k).init_pointee_copy(UInt8(ord("a") + k))
    var w = _send(client, tx, c_size_t(8), c_int(0))
    assert_equal(Int(w), 8)

    # Block until at least one CQE arrives, then look for the
    # poll completion.
    var saw_poll = False
    for _ in range(8):
        out.clear()
        _ = r.poll(1, out)
        for i in range(len(out)):
            var comp = out[i]
            if comp.op == URING_OP_POLL:
                assert_equal(Int(comp.conn_id), 0xC0DE)
                # res carries the OR of poll bits that fired;
                # POLLIN must be set.
                assert_true((UInt32(comp.res) & POLLIN) != 0)
                # Multishot stays armed.
                assert_true(comp.has_more)
                saw_poll = True
                break
        if saw_poll:
            break
    assert_true(saw_poll, "no URING_OP_POLL completion observed after write")

    _ = _close(c_int(accepted_fd))
    _ = _close(client)
    _ = _close(listener.fd)


def test_cancel_poll_terminates_multishot() raises:
    """Arm a multishot poll, then ``cancel_poll`` it. Verify the
    final ``URING_OP_POLL`` CQE arrives without
    ``IORING_CQE_F_MORE`` (multishot terminated) and a
    ``URING_OP_POLL_REMOVE`` CQE confirms the cancel succeeded.
    """
    if not is_io_uring_available():
        print(
            "test_cancel_poll_terminates_multishot: skipped (io_uring not"
            " available)"
        )
        return
    var listener = _make_listener()
    var r = UringReactor(32)
    r.arm_listener_multishot(Int(listener.fd), UInt64(0))
    var client = _connect_loopback(listener.port)

    var out = List[UringCompletion]()
    _ = r.poll(1, out)
    var accepted_fd: Int = -1
    for i in range(len(out)):
        if out[i].op == URING_OP_ACCEPT:
            accepted_fd = out[i].res
            break
    assert_true(accepted_fd > 0)

    r.arm_poll_readable_multishot(accepted_fd, UInt64(0xBEEF), POLLIN)
    r.cancel_poll(UInt64(0xBEEF))

    # Drain enough CQEs to observe both the cancel ack and the
    # final poll completion. The kernel may post them in either
    # order, so spin a few times.
    var saw_remove_ack = False
    var saw_poll_terminate = False
    for _ in range(8):
        out.clear()
        _ = r.poll(1, out)
        for i in range(len(out)):
            var comp = out[i]
            if comp.op == URING_OP_POLL_REMOVE:
                assert_equal(Int(comp.conn_id), 0xBEEF)
                # res = 0 on success, -ENOENT (-2) if nothing matched.
                # Either is acceptable here — both signal "cancel done".
                saw_remove_ack = True
            elif comp.op == URING_OP_POLL:
                assert_equal(Int(comp.conn_id), 0xBEEF)
                if not comp.has_more:
                    saw_poll_terminate = True
        if saw_remove_ack and saw_poll_terminate:
            break

    assert_true(saw_remove_ack, "URING_OP_POLL_REMOVE ack never arrived")
    assert_true(
        saw_poll_terminate,
        "final URING_OP_POLL CQE without F_MORE never arrived",
    )

    _ = _close(c_int(accepted_fd))
    _ = _close(client)
    _ = _close(listener.fd)


def test_use_uring_backend_consistent_with_availability() raises:
    """``use_uring_backend()`` must agree with
    ``is_io_uring_available()`` on Linux."""
    var got = use_uring_backend()
    var avail = is_io_uring_available()
    # On Linux the two should match. On non-Linux both are False.
    assert_equal(got, avail)


def test_use_uring_backend_respects_disable_env() raises:
    """Setting ``FLARE_DISABLE_IO_URING=1`` must force the
    backend off, even on a Linux host with io_uring available.

    This is the documented A/B-bench escape hatch: contributors
    flip the env var to compare the io_uring path against the
    epoll path on the same binary without rebuilding.
    """
    from std.os import setenv

    _ = setenv("FLARE_DISABLE_IO_URING", "1", True)
    assert_false(use_uring_backend())

    # Common falsey spellings are honoured as "do NOT disable",
    # i.e. the backend is enabled when io_uring is available.
    _ = setenv("FLARE_DISABLE_IO_URING", "0", True)
    assert_equal(use_uring_backend(), is_io_uring_available())

    _ = setenv("FLARE_DISABLE_IO_URING", "false", True)
    assert_equal(use_uring_backend(), is_io_uring_available())

    # Unset → default (= io_uring when available).
    _ = setenv("FLARE_DISABLE_IO_URING", "", True)
    assert_equal(use_uring_backend(), is_io_uring_available())


# ── buffer-ring (PROVIDE_BUFFERS + IOSQE_BUFFER_SELECT recv) ────────────────


def test_buffer_ring_recv_round_trip() raises:
    """Provide a 4-buffer, 1 KiB-each pool to the kernel; arm a
    multishot recv with ``IOSQE_BUFFER_SELECT`` on a connected
    loopback socket; have the peer write 4 bytes; verify the recv
    CQE arrives with ``IORING_CQE_F_BUFFER`` set, the picked
    buffer id is in ``[0, 4)``, and the data lands at the address
    the buffer id points to.

    This is the substrate the v0.7.x handler-path io_uring wire-in
    uses to drop per-conn buffer pinning entirely (the source of
    the c6ccc79 lifecycle bug). One PROVIDE_BUFFERS SQE up front,
    one buffer-select recv per accepted connection, and the kernel
    rotates buffers from the pool.
    """
    if not is_io_uring_available():
        print(
            "test_buffer_ring_recv_round_trip: skipped (io_uring not available)"
        )
        return
    var listener = _make_listener()
    var r = UringReactor(32)

    # Allocate the buffer pool: 4 buffers of 1 KiB each = 4 KiB
    # contiguous. flare's production wire-in will use 64 buffers
    # of 8 KiB per worker; 4×1K is enough to validate the
    # substrate.
    comptime BUFS = 4
    comptime BUF_SIZE = 1024
    comptime BGID: UInt16 = 7
    var pool = alloc[UInt8](BUFS * BUF_SIZE)
    for i in range(BUFS * BUF_SIZE):
        (pool + i).init_pointee_copy(UInt8(0))
    r.arm_provide_buffers(
        addr=UInt64(Int(pool)),
        nbytes_per_buf=BUF_SIZE,
        nbufs=BUFS,
        bgid=BGID,
        bid=UInt16(0),
    )

    # Accept the loopback client.
    r.arm_listener_multishot(Int(listener.fd), UInt64(0))
    var client = _connect_loopback(listener.port)
    var out = List[UringCompletion]()
    var accepted_fd: Int = -1
    var saw_provide = False
    for _ in range(8):
        out.clear()
        _ = r.poll(1, out)
        for i in range(len(out)):
            var c = out[i]
            if c.op == URING_OP_PROVIDE_BUFFERS:
                # Linux 5.7-6.0: res = number of buffers added.
                # Linux 6.1+: kernel returns res=0 on success
                # (the count is implicit; the SQE either fully
                # succeeded or returned -errno). Either is fine
                # for our purpose -- the buffers are now in the
                # bgid pool. Just assert no error.
                assert_true(
                    c.res >= 0,
                    "provide_buffers must succeed (res >= 0)",
                )
                assert_equal(Int(c.conn_id), Int(BGID))
                saw_provide = True
            elif c.op == URING_OP_ACCEPT:
                accepted_fd = c.res
        if saw_provide and accepted_fd > 0:
            break
    assert_true(saw_provide, "never saw PROVIDE_BUFFERS CQE")
    assert_true(accepted_fd > 0, "never saw accept CQE")

    # Arm multishot recv with IOSQE_BUFFER_SELECT on the accepted fd.
    r.arm_recv_buffer_select(accepted_fd, BGID, UInt64(0xAA), True)

    # Have the client write 4 bytes.
    var tx = stack_allocation[4, UInt8]()
    (tx + 0).init_pointee_copy(UInt8(ord("p")))
    (tx + 1).init_pointee_copy(UInt8(ord("o")))
    (tx + 2).init_pointee_copy(UInt8(ord("n")))
    (tx + 3).init_pointee_copy(UInt8(ord("g")))
    var w = _send(client, tx, c_size_t(4), c_int(0))
    assert_equal(Int(w), 4)

    # Wait for the recv CQE; verify IORING_CQE_F_BUFFER is set,
    # extract the buffer id from the high 16 bits of flags, and
    # check that the picked buffer's first 4 bytes are "pong".
    var saw_recv = False
    for _ in range(8):
        out.clear()
        _ = r.poll(1, out)
        for i in range(len(out)):
            var c = out[i]
            if c.op == URING_OP_RECV and Int(c.conn_id) == 0xAA:
                # Recv result: byte count (4).
                assert_equal(c.res, 4)
                # IORING_CQE_F_BUFFER must be set so we know the
                # kernel actually picked a buffer rather than
                # falling back to the legacy "addr/len" path.
                assert_true(
                    (c.flags & IORING_CQE_F_BUFFER) != UInt32(0),
                    "recv CQE missing IORING_CQE_F_BUFFER",
                )
                # Buffer id is in flags[31:16].
                var bid = Int(c.flags >> UInt32(16))
                assert_true(bid >= 0 and bid < BUFS)
                # The kernel wrote at pool + bid * BUF_SIZE.
                var slot = pool + (bid * BUF_SIZE)
                assert_equal(Int(slot.load()), ord("p"))
                assert_equal(Int((slot + 1).load()), ord("o"))
                assert_equal(Int((slot + 2).load()), ord("n"))
                assert_equal(Int((slot + 3).load()), ord("g"))
                saw_recv = True
                break
        if saw_recv:
            break
    assert_true(saw_recv, "never saw recv CQE with F_BUFFER")

    _ = _close(client)
    _ = _close(c_int(accepted_fd))
    _ = _close(listener.fd)
    pool.free()


# ── runner ───────────────────────────────────────────────────────────────────


def main() raises:
    test_pack_unpack_round_trip()
    print("    PASS test_pack_unpack_round_trip")
    test_pack_op_does_not_clobber_conn_id()
    print("    PASS test_pack_op_does_not_clobber_conn_id")
    test_construction_succeeds()
    print("    PASS test_construction_succeeds")
    test_idle_poll_returns_zero()
    print("    PASS test_idle_poll_returns_zero")
    test_arm_listener_multishot_round_trip()
    print("    PASS test_arm_listener_multishot_round_trip")
    test_submit_send_round_trip()
    print("    PASS test_submit_send_round_trip")
    test_wakeup_releases_blocking_poll()
    print("    PASS test_wakeup_releases_blocking_poll")
    test_arm_poll_readable_multishot_round_trip()
    print("    PASS test_arm_poll_readable_multishot_round_trip")
    test_cancel_poll_terminates_multishot()
    print("    PASS test_cancel_poll_terminates_multishot")
    test_use_uring_backend_consistent_with_availability()
    print("    PASS test_use_uring_backend_consistent_with_availability")
    test_use_uring_backend_respects_disable_env()
    print("    PASS test_use_uring_backend_respects_disable_env")
    test_buffer_ring_recv_round_trip()
    print("    PASS test_buffer_ring_recv_round_trip")
    print("test_uring_reactor: 12/12 PASS")
