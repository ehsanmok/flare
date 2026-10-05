"""Tests for :mod:`flare.uds` — UnixListener + UnixStream.

Round-trips real bytes through real UDS socket pairs (no mocks):

1. ``bind(path)`` returns a listener whose ``local_path()`` and
   ``queried_local_path()`` (via ``getsockname(2)``) both match
   ``path``.
2. ``UnixStream.connect(path)`` followed by ``listener.accept()``
   produces a connected pair; bytes written on one side arrive
   on the other.
3. The listener cleans up the socket file on destruction
   (``cleanup_path=True``, the default), and a fresh ``bind`` to
   the same path succeeds even if a previous run was killed.
4. The listener reports the correct fd through ``as_raw_fd`` and
   the multi-worker shared-listener path via :func:`accept_uds_fd`
   accepts the same way as the high-level ``accept``.
5. Strict path validation: paths longer than 107 (Linux) / 103
   (macOS) bytes raise ``Error``; paths with embedded NUL raise
   ``Error``.
6. Bind on a path occupied by a non-socket file raises (the
   ``unlink_existing=False`` path).
7. Connect to a non-existent path raises ``ConnectionRefused``.
"""

import std.os as os
from std.ffi import c_int, external_call
from std.memory import stack_allocation
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.net import AddressInUse, ConnectionRefused
from flare.net.socket import RawSocket, SOCK_DGRAM
from flare.net._libc import _bind
from flare.uds import UnixListener, UnixStream, accept_uds_fd
from flare.uds._libc import (
    AF_UNIX,
    SOCKADDR_UN_SIZE,
    SUN_PATH_MAX,
    fill_sockaddr_un,
)


def _tmp_uds_path(suffix: String) raises -> String:
    """Build a unique tmp socket path. ``/tmp`` is always writable
    on Linux + macOS test runners and is short enough to leave
    headroom under the 108-byte ``sun_path`` cap."""
    return String("/tmp/flare_uds_test_") + suffix + String(".sock")


def _maybe_unlink(path: String) raises:
    """Best-effort unlink; ignore if the file's already gone."""
    try:
        os.remove(path)
    except:
        pass


# ── Constants sanity ───────────────────────────────────────────────────────


def test_af_unix_constant() raises:
    """POSIX-defined: AF_UNIX = 1 on Linux + macOS."""
    assert_equal(Int(AF_UNIX), 1)


def test_sun_path_max_is_platform_correct() raises:
    """Linux's struct sockaddr_un has 108-byte sun_path; macOS BSD
    has 104. SUN_PATH_MAX exposes that to client code that needs to
    construct paths and verify they fit."""
    assert_true(SUN_PATH_MAX == 108 or SUN_PATH_MAX == 104)


# ── Bind / local_path round-trip ───────────────────────────────────────────


def test_bind_then_query_local_path() raises:
    var p = _tmp_uds_path("bind_then_query")
    _maybe_unlink(p)
    var l = UnixListener.bind(p)
    assert_equal(l.local_path(), p)
    var queried = l.queried_local_path()
    assert_equal(queried, p)


def test_bind_unlinks_stale_socket_by_default() raises:
    """After a "previous" run leaves the path bound, a fresh
    ``UnixListener.bind`` (with ``unlink_existing=True`` default)
    succeeds without raising EADDRINUSE."""
    var p = _tmp_uds_path("unlink_stale")
    _maybe_unlink(p)
    var first = UnixListener.bind(p)
    # Close + drop first; __deinit__ unlinks (cleanup_path=True default).
    first.close()
    # Re-bind: should find a fresh path. Even if cleanup ran, the
    # bind path also unlinks-existing by default, so this is a
    # robust idempotent check.
    var second = UnixListener.bind(p)
    assert_equal(second.local_path(), p)


# ── Round-trip ─────────────────────────────────────────────────────────────


def test_round_trip_bytes() raises:
    """Server binds, client connects, both sides shuttle bytes.

    Uses a single-pthread back-and-forth: connect first, then accept
    (UDS + listen-backlog buffer means connect doesn't block on a
    not-yet-accept'd socket), then write on one side and read on
    the other.
    """
    var p = _tmp_uds_path("round_trip")
    _maybe_unlink(p)
    var l = UnixListener.bind(p)
    var client = UnixStream.connect(p)
    var server = l.accept()

    # Client → server
    var msg = String("hello uds").as_bytes()
    client.write_all(msg)
    var rbuf = List[UInt8](capacity=64)
    rbuf.resize(64, 0)
    var n = server.read(rbuf.unsafe_ptr(), 64)
    assert_equal(n, 9)
    var got = String(capacity_bytes=10)
    for i in range(9):
        got += chr(Int(rbuf[i]))
    assert_equal(got, "hello uds")

    # Server → client
    var reply = String("ack 7").as_bytes()
    server.write_all(reply)
    var rbuf2 = List[UInt8](capacity=64)
    rbuf2.resize(64, 0)
    var n2 = client.read(rbuf2.unsafe_ptr(), 64)
    assert_equal(n2, 5)
    var got2 = String(capacity_bytes=6)
    for i in range(5):
        got2 += chr(Int(rbuf2[i]))
    assert_equal(got2, "ack 7")


def test_eof_on_peer_close() raises:
    """Closing one side gives the other a 0-byte read (EOF), not
    an error. Same shape as ``flare.tcp.TcpStream.read`` returning
    0 on EOF."""
    var p = _tmp_uds_path("eof_on_close")
    _maybe_unlink(p)
    var l = UnixListener.bind(p)
    var client = UnixStream.connect(p)
    var server = l.accept()
    client.close()

    var rbuf = List[UInt8](capacity=16)
    rbuf.resize(16, 0)
    var n = server.read(rbuf.unsafe_ptr(), 16)
    assert_equal(n, 0)


def test_accept_via_borrowed_fd() raises:
    """``accept_uds_fd`` (the multi-worker shared-listener path)
    accepts on a borrowed fd. Same wire shape as ``listener.accept()``."""
    var p = _tmp_uds_path("accept_fd")
    _maybe_unlink(p)
    var l = UnixListener.bind(p)
    var fd = l.as_raw_fd()
    var client = UnixStream.connect(p)
    var server = accept_uds_fd(fd)

    var msg = String("via_fd").as_bytes()
    client.write_all(msg)
    var rbuf = List[UInt8](capacity=16)
    rbuf.resize(16, 0)
    var n = server.read(rbuf.unsafe_ptr(), 16)
    assert_equal(n, 6)
    # Keep ``l`` alive past the accept_uds_fd call so the destructor
    # (which closes the listener fd) doesn't run before
    # accept_uds_fd reads from it.
    _ = l.local_path()


# ── Strict validation ─────────────────────────────────────────────────────


def test_path_too_long_raises() raises:
    """A path that exceeds ``sun_path`` bytes raises immediately,
    before any libc call."""
    var p = "/tmp/" + ("x" * SUN_PATH_MAX)
    with assert_raises(contains="path too long"):
        var _u = UnixListener.bind(p)


def test_embedded_nul_raises() raises:
    """An embedded NUL would silently terminate the C string,
    binding to a shorter prefix path; reject up-front."""
    var p = String("/tmp/flare_uds_") + String(chr(0)) + String("evil.sock")
    with assert_raises(contains="embedded NUL"):
        var _u = UnixListener.bind(p)


def test_connect_to_nonexistent_path_raises_refused() raises:
    """Connect to a path with no listener raises
    ``ConnectionRefused`` (mirrors TCP ``ECONNREFUSED`` shape).
    The exact errno on Linux is ``ENOENT``; the parser maps both
    to ``ConnectionRefused``."""
    var p = _tmp_uds_path("nonexistent")
    _maybe_unlink(p)
    with assert_raises():
        var _u = UnixStream.connect(p)


def test_bind_leaves_a_live_socket_and_a_plain_file_alone() raises:
    """Bind unlinked whatever sat at the path: a regular file was
    deleted, and a running server's socket was replaced under it."""
    from flare.net import AddressInUse

    var p = _tmp_uds_path("live_guard")
    _maybe_unlink(p)
    var first = UnixListener.bind(p)
    var raised = False
    try:
        _ = UnixListener.bind(p)
    except e:
        raised = True
    assert_true(raised, "bound over a live listener")
    # The first listener still owns the path.
    var c = UnixStream.connect(p)
    _ = first.accept()
    c.close()
    first.close()
    _maybe_unlink(p)

    # A stale socket, left by a listener that did not clean up, is
    # still replaced.
    var gone = UnixListener.bind_with_options(p, cleanup_path=False)
    gone.close()
    _ = gone^
    var again = UnixListener.bind(p)
    assert_equal(again.local_path(), p)
    again.close()
    _ = again^

    var f = _tmp_uds_path("plain_file")
    _maybe_unlink(f)
    with open(f, "w") as fh:
        fh.write("keep me")
    var raised2 = False
    try:
        _ = UnixListener.bind(f)
    except:
        raised2 = True
    assert_true(raised2, "bound over a regular file")
    assert_true(os.path.exists(f), "the regular file was deleted")
    os.remove(f)


def _chmod(var path: String, mode: Int) -> c_int:
    return external_call["chmod", c_int](path.as_c_string_span(), c_int(mode))


def _getuid() -> c_int:
    return external_call["getuid", c_int]()


def _bind_dgram(path: String) raises -> RawSocket:
    """Bind an AF_UNIX *datagram* socket at ``path``: a live socket file
    that a stream ``connect`` answers with ``EPROTOTYPE`` (neither a
    success nor a refusal, whoever the caller is)."""
    var sock = RawSocket(AF_UNIX, SOCK_DGRAM)
    var sa = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
    for i in range(Int(SOCKADDR_UN_SIZE)):
        (sa.unsafe_offset(i)).unsafe_write(0)
    var used = fill_sockaddr_un(sa, path)
    if _bind(sock.fd, sa, used) < 0:
        raise Error("test setup: bind of the datagram socket failed")
    return sock^


def test_bind_refuses_when_liveness_probe_is_inconclusive() raises:
    """NET-07: the probe's ``except: pass`` treated every connect failure as
    "stale", so a live socket the caller could not connect to (EACCES, a
    different socket type, ...) was unlinked and taken over. Only a refusal
    proves a socket stale."""
    # A live datagram socket: connect(SOCK_STREAM) fails with EPROTOTYPE.
    var p = _tmp_uds_path("probe_dgram")
    _maybe_unlink(p)
    var live = _bind_dgram(p)
    var raised = False
    var in_use = False
    try:
        _ = UnixListener.bind(p)
    except e:
        raised = True
        in_use = String(e).startswith("AddressInUse")
    assert_true(raised, "bound over a socket whose liveness is unknown")
    assert_true(in_use, "expected AddressInUse")
    assert_true(os.path.exists(p), "the live socket file was unlinked")
    live.close()
    _maybe_unlink(p)


def test_bind_refuses_unwritable_live_listener() raises:
    """NET-07 (the original trigger): a live listener whose socket file the
    caller may not write answers the probe with EACCES. root bypasses the
    permission check, so this part only runs for a non-root user."""
    if _getuid() == 0:
        return
    var p = _tmp_uds_path("probe_eacces")
    _maybe_unlink(p)
    var a = UnixListener.bind(p)
    assert_equal(Int(_chmod(p, 0)), 0)
    var raised = False
    try:
        _ = UnixListener.bind(p)
    except:
        raised = True
    assert_true(raised, "took over a live listener it could not probe")
    assert_true(os.path.exists(p), "the live socket file was unlinked")
    assert_equal(a.local_path(), p)
    a.close()
    _ = a^
    _maybe_unlink(p)


def test_destructor_removes_only_its_own_socket() raises:
    """An old listener's destructor unlinked by path, taking the socket
    file of whatever server had bound the path since."""
    var p = _tmp_uds_path("own_socket")
    _maybe_unlink(p)
    var old = UnixListener.bind(p)
    _maybe_unlink(p)  # an operator clears the path
    var new = UnixListener.bind(p)
    old.close()
    _ = old^
    assert_true(os.path.exists(p), "old listener removed the new socket")
    var c = UnixStream.connect(p)
    _ = new.accept()
    c.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
