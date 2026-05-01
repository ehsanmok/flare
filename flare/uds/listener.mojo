"""AF_UNIX listener — bound + listening Unix domain socket.

``UnixListener`` is the UDS sibling of
:class:`flare.tcp.TcpListener`. Same lifecycle (``bind`` → 0..N
``accept`` → automatic ``close`` on destruction), same
``accept_uds_fd`` shape for the multi-worker shared-listener
scheduler. The differences:

- ``bind`` takes a filesystem path, not a :class:`SocketAddr`.
- A previous socket file at the same path is unlinked before
  ``bind(2)`` (controllable via ``unlink_existing=False``).
- ``UnixListener.__del__`` unlinks the socket file on destruction
  by default — opt out via ``cleanup_path=False`` for the
  shared-listener case where one fd is being passed to many
  workers and the path lifecycle is owned externally.
- ``SO_REUSEADDR`` is not set (UDS has no port concept; the path
  collision is handled by the unlink step).
"""

from std.ffi import c_int, c_uint, get_errno, ErrNo
from std.memory import stack_allocation

from ..net import (
    AddressInUse,
    NetworkError,
)
from ..net.socket import RawSocket, SOCK_STREAM
from ..net._libc import (
    _accept,
    _bind,
    _getsockname,
    _listen,
    _strerror,
)

from ._libc import (
    AF_UNIX,
    SOCKADDR_UN_SIZE,
    fill_sockaddr_un,
    read_path_from_sockaddr_un,
    unlink_path,
)
from .stream import UnixStream


struct UnixListener(Movable):
    """A bound + listening AF_UNIX socket.

    Lifecycle: ``bind(path)`` then 0..N ``accept()`` calls then an
    automatic close + (optional) ``unlink(path)`` when the struct
    is destroyed.

    Thread safety:
        Not thread-safe. Do not call ``accept()`` concurrently.
        For the multi-worker shared-listener case, hand out the
        listener fd via :meth:`as_raw_fd` and have each worker
        call :func:`accept_uds_fd`; that mirrors
        :func:`flare.tcp.accept_fd`.
    """

    var _socket: RawSocket
    var _path: String
    var _cleanup_path: Bool

    def __init__(
        out self,
        var socket: RawSocket,
        path: String,
        cleanup_path: Bool,
    ):
        """Wrap an already-bound, listening ``RawSocket``.

        Safety: ``socket`` must be in the listening state and
        bound to ``path``.
        """
        self._socket = socket^
        self._path = path
        self._cleanup_path = cleanup_path

    def __del__(deinit self):
        """Close the socket. If ``cleanup_path`` is ``True`` (the
        :meth:`bind` default), also ``unlink(2)`` the socket file
        so the next ``bind(path)`` doesn't have to fight a stale
        file. Failure to unlink is silent (the file may already
        have been moved / deleted by an admin)."""
        self._socket.close()
        if self._cleanup_path and self._path.byte_length() > 0:
            _ = unlink_path(self._path)

    # ── Factory ───────────────────────────────────────────────────────────

    @staticmethod
    def bind(path: String) raises -> UnixListener:
        """Bind a UDS listener at ``path`` with default options.

        Cleans up a stale socket at ``path`` (``unlink(2)``) before
        ``bind(2)`` so a crashed-and-restarted server can come
        back without manual intervention. The backlog is 128.
        """
        return UnixListener.bind_with_options(path)

    @staticmethod
    def bind_with_options(
        path: String,
        backlog: Int = 128,
        unlink_existing: Bool = True,
        cleanup_path: Bool = True,
    ) raises -> UnixListener:
        """Bind with explicit backlog + path-cleanup control.

        Args:
            path: Filesystem path for the socket. Must fit the
                platform's ``sun_path`` field (108 bytes on
                Linux, 104 on macOS, including NUL); paths longer
                than that raise ``Error``.
            backlog: ``listen(2)`` backlog.
            unlink_existing: ``unlink(path)`` before ``bind(2)``.
                Defaults ``True`` so a crashed-then-restarted
                process recovers cleanly. Set ``False`` if you
                want a hard ``EADDRINUSE`` when a previous
                instance is still running.
            cleanup_path: ``unlink(path)`` on destruction.
                Defaults ``True``. Set ``False`` for the
                multi-worker shared-listener case where the path
                lifecycle is owned externally (e.g. by systemd).

        Raises:
            AddressInUse: ``EADDRINUSE`` on bind.
            NetworkError: Other libc failures.
        """
        var sock = RawSocket(AF_UNIX, SOCK_STREAM)
        if unlink_existing:
            # Best-effort: ignore failure (file might not exist).
            _ = unlink_path(path)

        var sa = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_UN_SIZE)):
            (sa + i).init_pointee_copy(0)
        var used = fill_sockaddr_un(sa, path)

        var rc = _bind(sock.fd, sa, used)
        if rc < 0:
            var e = get_errno()
            if e == ErrNo.EADDRINUSE:
                raise AddressInUse(path, Int(e.value))
            raise NetworkError(
                _strerror(e.value) + " (bind " + path + ")",
                Int(e.value),
            )

        var lr = _listen(sock.fd, c_int(backlog))
        if lr < 0:
            var e = get_errno()
            raise NetworkError(_strerror(e.value) + " (listen)", Int(e.value))

        return UnixListener(sock^, path, cleanup_path)

    # ── Accept ────────────────────────────────────────────────────────────

    def accept(self) raises -> UnixStream:
        """Block until an incoming connection arrives and return it.

        Returns a connected :class:`UnixStream` whose ``peer_path``
        is the empty string — UDS clients are anonymous unless they
        explicitly bind() a path before connect() (rare).
        """
        var peer_buf = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_UN_SIZE)):
            (peer_buf + i).init_pointee_copy(0)
        var peer_len = stack_allocation[1, c_uint]()
        peer_len.init_pointee_copy(SOCKADDR_UN_SIZE)

        var client_fd = _accept(self._socket.fd, peer_buf, peer_len)
        if client_fd < 0:
            var e = get_errno()
            raise NetworkError(_strerror(e.value) + " (accept)", Int(e.value))

        var client_sock = RawSocket(client_fd, AF_UNIX, SOCK_STREAM, True)
        # Anonymous client (typical) — empty path.
        return UnixStream(client_sock^, String(""))

    # ── Introspection ────────────────────────────────────────────────────

    def local_path(self) -> String:
        """Return the path the listener was bound to."""
        return self._path

    def queried_local_path(self) raises -> String:
        """Round-trip the path through ``getsockname(2)`` —
        primarily for the test suite (proves we built a
        correctly-shaped ``sockaddr_un``). Most callers want
        :meth:`local_path` instead."""
        var sa = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_UN_SIZE)):
            (sa + i).init_pointee_copy(0)
        var len_buf = stack_allocation[1, c_uint]()
        len_buf.init_pointee_copy(SOCKADDR_UN_SIZE)
        var rc = _getsockname(self._socket.fd, sa, len_buf)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (getsockname)", Int(e.value)
            )
        return read_path_from_sockaddr_un(sa, len_buf[])

    def as_raw_fd(self) -> c_int:
        """Return the underlying file descriptor.

        Same contract as :meth:`flare.tcp.TcpListener.as_raw_fd`:
        the fd is borrowed, its lifetime is tied to ``self``,
        callers must not ``close(fd)`` themselves.
        """
        return self._socket.fd

    def close(mut self):
        """Close the listening socket. Idempotent.

        Does **not** unlink the path; that happens in
        :meth:`__del__` if ``cleanup_path`` was set."""
        self._socket.close()


def accept_uds_fd(listener_fd: c_int) raises -> UnixStream:
    """Accept one connection on a borrowed listener fd.

    Functionally equivalent to :meth:`UnixListener.accept` but
    takes the listener as a raw integer fd, so the multi-worker
    scheduler can share a single listener across worker pthreads
    without any one worker owning the :class:`UnixListener`
    object. Mirror of :func:`flare.tcp.accept_fd`.
    """
    var peer_buf = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
    for i in range(Int(SOCKADDR_UN_SIZE)):
        (peer_buf + i).init_pointee_copy(0)
    var peer_len = stack_allocation[1, c_uint]()
    peer_len.init_pointee_copy(SOCKADDR_UN_SIZE)

    var client_fd = _accept(listener_fd, peer_buf, peer_len)
    if client_fd < 0:
        var e = get_errno()
        raise NetworkError(_strerror(e.value) + " (accept)", Int(e.value))

    var client_sock = RawSocket(client_fd, AF_UNIX, SOCK_STREAM, True)
    return UnixStream(client_sock^, String(""))
