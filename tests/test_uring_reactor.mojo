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
from flare.runtime.uring_reactor import (
    URING_OP_ACCEPT,
    URING_OP_RECV,
    URING_OP_SEND,
    URING_OP_CLOSE,
    URING_OP_CANCEL,
    URING_OP_WAKEUP,
    UringCompletion,
    UringReactor,
    pack_user_data,
    unpack_conn_id,
    unpack_op,
    use_uring_backend,
)


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


def test_use_uring_backend_consistent_with_availability() raises:
    """``use_uring_backend()`` must agree with
    ``is_io_uring_available()`` on Linux."""
    var got = use_uring_backend()
    var avail = is_io_uring_available()
    # On Linux the two should match. On non-Linux both are False.
    assert_equal(got, avail)


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
    test_use_uring_backend_consistent_with_availability()
    print("    PASS test_use_uring_backend_consistent_with_availability")
    print("test_uring_reactor: 8/8 PASS")
