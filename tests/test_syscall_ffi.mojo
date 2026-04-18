"""Tests for Stage 1 Phase 1.1 event-loop syscall FFI.

Covers the new FFI wrappers in ``flare/net/_libc.mojo`` that will power the
reactor in Phase 1.2:

- ``epoll_create1`` / ``epoll_ctl`` / ``epoll_wait`` (Linux)
- ``kqueue`` / ``kevent`` (macOS)
- ``eventfd`` (Linux) + ``pipe`` (cross-platform) for cross-thread wakeup
- ``read`` / ``write`` on non-socket fds
- Struct-field helpers (``_epoll_event_set``, ``_kevent_set``, and their
  readers)

All tests run locally with no network dependency. Platform-specific tests
(epoll on Linux, kqueue on macOS) skip gracefully on the other platform.
"""

from std.testing import (
    assert_equal,
    assert_not_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from std.sys.info import CompilationTarget
from std.memory import UnsafePointer, stack_allocation
from std.ffi import c_int, c_uint, c_size_t, get_errno

from flare.net._libc import (
    # Epoll
    EPOLLIN,
    EPOLLOUT,
    EPOLLERR,
    EPOLLHUP,
    EPOLLET,
    EPOLL_CTL_ADD,
    EPOLL_CTL_DEL,
    EPOLL_CTL_MOD,
    EPOLL_CLOEXEC,
    EPOLL_EVENT_SIZE,
    EPOLL_EVENT_DATA_OFF,
    _epoll_create1,
    _epoll_ctl,
    _epoll_wait,
    _epoll_event_set,
    _epoll_event_read_events,
    _epoll_event_read_data,
    # Kqueue
    EVFILT_READ,
    EVFILT_WRITE,
    EVFILT_USER,
    EV_ADD,
    EV_DELETE,
    EV_ENABLE,
    EV_CLEAR,
    NOTE_TRIGGER,
    KEVENT_SIZE,
    _kqueue,
    _kevent,
    _kevent_set,
    _kevent_read_ident,
    _kevent_read_filter,
    _kevent_read_flags,
    _kevent_read_fflags,
    _kevent_read_udata,
    # Wakeup
    EFD_NONBLOCK,
    EFD_CLOEXEC,
    _eventfd,
    _pipe,
    # Raw I/O
    _read_fd,
    _write_fd,
    _close,
    # Socketpair helpers we reuse
    AF_INET,
    SOCK_STREAM,
    INVALID_FD,
)
from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener


# ── Platform gates ────────────────────────────────────────────────────────────


def _is_linux() -> Bool:
    return CompilationTarget.is_linux()


def _is_macos() -> Bool:
    return CompilationTarget.is_macos()


# ── Test helpers ──────────────────────────────────────────────────────────────
#
# Tests that need a connected pair of sockets build it inline using::
#
#     var listener = TcpListener.bind(SocketAddr.localhost(0))
#     var port = listener.local_addr().port
#     var a = TcpStream.connect(SocketAddr.localhost(port))
#     var b = listener.accept()
#     listener.close()
#
# Mojo has no tuple destructuring, so a shared helper that returns two
# sockets cannot be called ergonomically; the inline pattern is fine.


# ── Epoll constant sanity ─────────────────────────────────────────────────────


def test_epoll_constants_distinct_bits() raises:
    """Event bits are distinct powers of two in the low 16 bits."""
    assert_equal(EPOLLIN, UInt32(1))
    assert_equal(EPOLLOUT, UInt32(4))
    assert_equal(EPOLLERR, UInt32(8))
    assert_equal(EPOLLHUP, UInt32(16))
    # ET is bit 31.
    assert_equal(EPOLLET, UInt32(0x80000000))


def test_epoll_ctl_op_constants() raises:
    """ADD / MOD / DEL numeric values match linux headers."""
    assert_equal(EPOLL_CTL_ADD, c_int(1))
    assert_equal(EPOLL_CTL_DEL, c_int(2))
    assert_equal(EPOLL_CTL_MOD, c_int(3))


def test_epoll_event_size_matches_arch() raises:
    """Epoll_event is 12 bytes on x86_64 (packed) and 16 bytes otherwise."""
    if CompilationTarget.is_x86():
        assert_equal(EPOLL_EVENT_SIZE, 12)
        assert_equal(EPOLL_EVENT_DATA_OFF, 4)
    else:
        assert_equal(EPOLL_EVENT_SIZE, 16)
        assert_equal(EPOLL_EVENT_DATA_OFF, 8)


# ── Epoll struct round-trip ───────────────────────────────────────────────────


def test_epoll_event_set_and_read_back() raises:
    """Writing events + data.u64 and reading back yields the same values."""
    var buf = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
    # Zero-initialise for cleanliness
    for i in range(EPOLL_EVENT_SIZE):
        (buf + i).init_pointee_copy(UInt8(0))
    # Re-use the buffer via _set (which reinitialises bytes)
    _epoll_event_set(buf, EPOLLIN | EPOLLET, UInt64(0xDEADBEEFCAFEBABE))
    assert_equal(_epoll_event_read_events(buf), EPOLLIN | EPOLLET)
    assert_equal(_epoll_event_read_data(buf), UInt64(0xDEADBEEFCAFEBABE))


# ── Epoll runtime tests (Linux only) ──────────────────────────────────────────


def test_epoll_create1_and_close() raises:
    """``epoll_create1(0)`` returns a valid fd that ``close(2)`` accepts."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var epfd = _epoll_create1(c_int(0))
    assert_true(epfd >= 0, "epoll_create1 must return non-negative fd")
    _ = _close(epfd)


def test_epoll_create1_with_cloexec() raises:
    """``EPOLL_CLOEXEC`` is accepted (no EINVAL)."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var epfd = _epoll_create1(EPOLL_CLOEXEC)
    assert_true(epfd >= 0, "EPOLL_CLOEXEC must be accepted")
    _ = _close(epfd)


def test_epoll_ctl_add_then_del_ok() raises:
    """Registering then removing an fd via epoll_ctl returns 0 both times."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var a = TcpStream.connect(SocketAddr.localhost(port))
    var b = listener.accept()
    listener.close()
    var epfd = _epoll_create1(c_int(0))
    assert_true(epfd >= 0)
    var ev = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
    for i in range(EPOLL_EVENT_SIZE):
        (ev + i).init_pointee_copy(UInt8(0))
    _epoll_event_set(ev, EPOLLIN, UInt64(42))
    var add = _epoll_ctl(epfd, EPOLL_CTL_ADD, a._socket.fd, ev)
    assert_equal(add, c_int(0), "EPOLL_CTL_ADD returned " + String(add))
    var dele = _epoll_ctl(epfd, EPOLL_CTL_DEL, a._socket.fd, ev)
    assert_equal(dele, c_int(0), "EPOLL_CTL_DEL returned " + String(dele))
    _ = _close(epfd)
    a.close()
    b.close()


def test_epoll_wait_timeout_zero_returns_empty() raises:
    """``epoll_wait`` with timeout 0 on empty set returns 0 immediately."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var epfd = _epoll_create1(c_int(0))
    assert_true(epfd >= 0)
    var out = stack_allocation[EPOLL_EVENT_SIZE * 4, UInt8]()
    var n = _epoll_wait(epfd, out, c_int(4), c_int(0))
    assert_equal(n, c_int(0), "empty epoll should return 0 events")
    _ = _close(epfd)


def test_epoll_wait_detects_readable() raises:
    """Writing on peer makes the watched fd readable."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var a = TcpStream.connect(SocketAddr.localhost(port))
    var b = listener.accept()
    listener.close()
    var epfd = _epoll_create1(c_int(0))
    assert_true(epfd >= 0)
    var ev = stack_allocation[EPOLL_EVENT_SIZE, UInt8]()
    for i in range(EPOLL_EVENT_SIZE):
        (ev + i).init_pointee_copy(UInt8(0))
    var token = UInt64(0xCAFEBABE00000001)
    _epoll_event_set(ev, EPOLLIN, token)
    var rc = _epoll_ctl(epfd, EPOLL_CTL_ADD, a._socket.fd, ev)
    assert_equal(rc, c_int(0))
    # Write a byte on b -> a becomes readable
    var payload = stack_allocation[1, UInt8]()
    payload.init_pointee_copy(UInt8(ord("X")))
    _ = _write_fd(b._socket.fd, payload, c_size_t(1))
    # Wait up to 1s
    var out = stack_allocation[EPOLL_EVENT_SIZE * 4, UInt8]()
    var n = _epoll_wait(epfd, out, c_int(4), c_int(1000))
    assert_true(n >= c_int(1), "expected at least 1 readable event")
    assert_true(
        (_epoll_event_read_events(out) & EPOLLIN) != 0,
        "EPOLLIN must be set in returned events",
    )
    assert_equal(_epoll_event_read_data(out), token, "token must round-trip")
    _ = _close(epfd)
    a.close()
    b.close()


# ── Kqueue constant sanity ────────────────────────────────────────────────────


def test_kqueue_filter_constants() raises:
    """Filter constants have the BSD sign-convention values."""
    assert_equal(EVFILT_READ, Int16(-1))
    assert_equal(EVFILT_WRITE, Int16(-2))
    assert_equal(EVFILT_USER, Int16(-10))


def test_kqueue_flag_constants_distinct_bits() raises:
    """EV_ADD / EV_DELETE / EV_ENABLE / EV_CLEAR are distinct bits."""
    assert_equal(EV_ADD, UInt16(1))
    assert_equal(EV_DELETE, UInt16(2))
    assert_equal(EV_ENABLE, UInt16(4))
    assert_equal(EV_CLEAR, UInt16(0x20))


def test_kevent_size_is_32() raises:
    """Kevent struct is 32 bytes on 64-bit macOS/ARM."""
    assert_equal(KEVENT_SIZE, 32)


# ── Kevent struct round-trip ──────────────────────────────────────────────────


def test_kevent_set_and_read_back_positive_fields() raises:
    """Write all fields, read back identical values."""
    var buf = stack_allocation[KEVENT_SIZE, UInt8]()
    for i in range(KEVENT_SIZE):
        (buf + i).init_pointee_copy(UInt8(0))
    _kevent_set(
        buf,
        ident=UInt64(7),
        filter=EVFILT_READ,
        flags=EV_ADD | EV_CLEAR,
        fflags=UInt32(0),
        data=Int64(0),
        udata=UInt64(0xDEADBEEF),
    )
    assert_equal(_kevent_read_ident(buf), UInt64(7))
    assert_equal(_kevent_read_filter(buf), EVFILT_READ)
    assert_equal(_kevent_read_flags(buf), EV_ADD | EV_CLEAR)
    assert_equal(_kevent_read_fflags(buf), UInt32(0))
    assert_equal(_kevent_read_udata(buf), UInt64(0xDEADBEEF))


def test_kevent_set_filter_negative_roundtrip() raises:
    """Negative filter values (EVFILT_USER = -10) round-trip correctly."""
    var buf = stack_allocation[KEVENT_SIZE, UInt8]()
    for i in range(KEVENT_SIZE):
        (buf + i).init_pointee_copy(UInt8(0))
    _kevent_set(
        buf,
        ident=UInt64(0),
        filter=EVFILT_USER,
        flags=EV_ADD,
        fflags=NOTE_TRIGGER,
        data=Int64(0),
        udata=UInt64(0),
    )
    assert_equal(_kevent_read_filter(buf), EVFILT_USER)
    assert_equal(_kevent_read_fflags(buf), NOTE_TRIGGER)


# ── Kqueue runtime tests (macOS only) ─────────────────────────────────────────


def test_kqueue_create_and_close() raises:
    """``kqueue()`` returns a valid fd that ``close(2)`` accepts."""
    if not _is_macos():
        print("  [SKIP] macOS-only")
        return
    var kq = _kqueue()
    assert_true(kq >= 0, "kqueue must return non-negative fd")
    _ = _close(kq)


def test_kevent_zero_changes_zero_events_timeout_returns_zero() raises:
    """Calling kevent with no changes and a zero timeout returns 0."""
    if not _is_macos():
        print("  [SKIP] macOS-only")
        return
    var kq = _kqueue()
    assert_true(kq >= 0)
    # 16-byte timespec: tv_sec=0, tv_nsec=0
    var ts = stack_allocation[16, UInt8]()
    for i in range(16):
        (ts + i).init_pointee_copy(UInt8(0))
    var dummy = stack_allocation[KEVENT_SIZE, UInt8]()
    var out = stack_allocation[KEVENT_SIZE * 4, UInt8]()
    var n = _kevent(kq, dummy, c_int(0), out, c_int(4), ts)
    assert_equal(n, c_int(0), "no events expected with zero timeout")
    _ = _close(kq)


def test_kevent_detects_readable() raises:
    """Registering a socket and writing to its peer reports an event."""
    if not _is_macos():
        print("  [SKIP] macOS-only")
        return
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    var a = TcpStream.connect(SocketAddr.localhost(port))
    var b = listener.accept()
    listener.close()
    var kq = _kqueue()
    assert_true(kq >= 0)
    # Register a for read
    var changes = stack_allocation[KEVENT_SIZE, UInt8]()
    for i in range(KEVENT_SIZE):
        (changes + i).init_pointee_copy(UInt8(0))
    var token = UInt64(0xCAFEBABE00000002)
    _kevent_set(
        changes,
        ident=UInt64(Int(a._socket.fd)),
        filter=EVFILT_READ,
        flags=EV_ADD,
        fflags=UInt32(0),
        data=Int64(0),
        udata=token,
    )
    # Install the change (zero out wait).
    var ts_zero = stack_allocation[16, UInt8]()
    for i in range(16):
        (ts_zero + i).init_pointee_copy(UInt8(0))
    var out = stack_allocation[KEVENT_SIZE * 4, UInt8]()
    var installed = _kevent(kq, changes, c_int(1), out, c_int(0), ts_zero)
    assert_true(installed >= c_int(0))
    # Write a byte
    var payload = stack_allocation[1, UInt8]()
    payload.init_pointee_copy(UInt8(ord("Y")))
    _ = _write_fd(b._socket.fd, payload, c_size_t(1))
    # Wait up to 1s
    var ts_1s = stack_allocation[16, UInt8]()
    (ts_1s + 0).init_pointee_copy(UInt8(1))  # tv_sec low byte = 1
    for i in range(1, 16):
        (ts_1s + i).init_pointee_copy(UInt8(0))
    var n = _kevent(kq, changes, c_int(0), out, c_int(4), ts_1s)
    assert_true(n >= c_int(1), "expected at least 1 event")
    assert_equal(_kevent_read_filter(out), EVFILT_READ)
    assert_equal(_kevent_read_udata(out), token, "udata must round-trip")
    _ = _close(kq)
    a.close()
    b.close()


# ── Wakeup primitives ─────────────────────────────────────────────────────────


def test_eventfd_write_then_read_counts() raises:
    """Linux: write N increments the counter; read returns the current count."""
    if not _is_linux():
        print("  [SKIP] eventfd is Linux-only")
        return
    var counter = UInt64(7)
    var efd = _eventfd(c_uint(0), EFD_NONBLOCK)
    assert_true(efd >= 0, "eventfd must return non-negative fd")
    # Write one u64 LE.
    var buf = stack_allocation[8, UInt8]()
    for i in range(8):
        (buf + i).init_pointee_copy(UInt8((counter >> UInt64(8 * i)) & 0xFF))
    var w = _write_fd(efd, buf, c_size_t(8))
    assert_equal(w, 8, "write to eventfd must be 8 bytes")
    # Read it back (counter value, then resets to 0)
    var rbuf = stack_allocation[8, UInt8]()
    var r = _read_fd(efd, rbuf, c_size_t(8))
    assert_equal(r, 8, "read from eventfd must be 8 bytes")
    var value: UInt64 = 0
    for i in range(8):
        value |= UInt64((rbuf + i).load()) << UInt64(8 * i)
    assert_equal(value, counter)
    _ = _close(efd)


def test_pipe_round_trip_byte() raises:
    """Write a byte to pipe[1], read it from pipe[0]."""
    var fds = stack_allocation[2, c_int]()
    fds.init_pointee_copy(INVALID_FD)
    (fds + 1).init_pointee_copy(INVALID_FD)
    var rc = _pipe(fds)
    assert_equal(rc, c_int(0), "pipe must return 0 on success")
    var read_end = fds.load()
    var write_end = (fds + 1).load()
    assert_true(read_end >= 0)
    assert_true(write_end >= 0)
    # Write a byte.
    var wbuf = stack_allocation[1, UInt8]()
    wbuf.init_pointee_copy(UInt8(ord("Z")))
    var wn = _write_fd(write_end, wbuf, c_size_t(1))
    assert_equal(wn, 1)
    # Read it back.
    var rbuf = stack_allocation[1, UInt8]()
    rbuf.init_pointee_copy(UInt8(0))
    var rn = _read_fd(read_end, rbuf, c_size_t(1))
    assert_equal(rn, 1)
    assert_equal(rbuf.load(), UInt8(ord("Z")))
    _ = _close(read_end)
    _ = _close(write_end)


# ── Invalid-fd error behaviour ────────────────────────────────────────────────


def test_epoll_wait_on_invalid_fd_returns_negative() raises:
    """``epoll_wait`` on a bogus fd returns -1 (errno set)."""
    if not _is_linux():
        print("  [SKIP] Linux-only")
        return
    var out = stack_allocation[EPOLL_EVENT_SIZE * 4, UInt8]()
    var n = _epoll_wait(c_int(-1), out, c_int(4), c_int(0))
    assert_true(n < c_int(0), "expected failure on invalid epoll fd")


def test_kevent_on_invalid_fd_returns_negative() raises:
    """``kevent`` on a bogus fd returns -1 (errno set)."""
    if not _is_macos():
        print("  [SKIP] macOS-only")
        return
    var ts = stack_allocation[16, UInt8]()
    for i in range(16):
        (ts + i).init_pointee_copy(UInt8(0))
    var dummy = stack_allocation[KEVENT_SIZE, UInt8]()
    var out = stack_allocation[KEVENT_SIZE * 4, UInt8]()
    var n = _kevent(c_int(-1), dummy, c_int(0), out, c_int(4), ts)
    assert_true(n < c_int(0), "expected failure on invalid kqueue fd")


# ── RawSocket.set_nonblocking smoke (already implemented) ─────────────────────


def test_set_nonblocking_toggle_does_not_raise() raises:
    """RawSocket.set_nonblocking flips flags without raising on a fresh socket.
    """
    from flare.net.socket import RawSocket
    from flare.net._libc import AF_INET, SOCK_STREAM

    var sock = RawSocket(AF_INET, SOCK_STREAM)
    sock.set_nonblocking(True)
    sock.set_nonblocking(False)
    sock.close()


def main() raises:
    print("=" * 60)
    print("test_syscall_ffi.mojo — Phase 1.1 FFI layer")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
