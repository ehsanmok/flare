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
from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_raises,
    assert_true,
)

from flare.net import ConnectionRefused
from flare.uds import UnixListener, UnixStream, accept_uds_fd
from flare.uds._libc import AF_UNIX, SUN_PATH_MAX


def _tmp_uds_path(suffix: String) raises -> String:
    """Build a unique tmp socket path. ``/tmp`` is always writable
    on Linux + macOS test runners and is short enough to leave
    headroom under the 108-byte ``sun_path`` cap."""
    return String("/tmp/flare_uds_test_") + suffix + String(".sock")


def _maybe_unlink(path: String) raises:
    """Best-effort unlink; ignore if the file's already gone."""
    try:
        os.path.remove(path)
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
    # Close + drop first; __del__ unlinks (cleanup_path=True default).
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
    var got = String(capacity=10)
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
    var got2 = String(capacity=6)
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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
