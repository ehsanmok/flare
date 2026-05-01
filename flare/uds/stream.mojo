"""Connected AF_UNIX byte stream.

``UnixStream`` is the UDS sibling of :class:`flare.tcp.TcpStream`.
The wire shape is identical (``read`` / ``write`` / ``write_all``
/ ``shutdown`` / ``close``); the differences are limited to the
address-family layer:

- Peer address is a path string (or empty when the peer side
  didn't bind).
- ``TCP_NODELAY`` doesn't apply (no Nagle on UDS); the constructor
  skips it.
- ``MSG_NOSIGNAL`` still applies — a writer to a peer that has
  closed must not get ``SIGPIPE`` on Linux. macOS uses
  ``SO_NOSIGPIPE`` which the underlying ``RawSocket`` already
  sets in :class:`flare.net.socket.RawSocket.__init__`.
"""

from std.ffi import (
    c_int,
    c_size_t,
    c_ssize_t,
    get_errno,
    ErrNo,
)
from std.memory import stack_allocation

from ..net import (
    BrokenPipe,
    ConnectionRefused,
    ConnectionReset,
    NetworkError,
)
from ..net.socket import RawSocket, SOCK_STREAM
from ..net._libc import (
    _close,
    _connect,
    _recv,
    _send,
    _shutdown,
    _strerror,
    MSG_NOSIGNAL,
    SHUT_RD,
    SHUT_RDWR,
    SHUT_WR,
)

from ._libc import AF_UNIX, SOCKADDR_UN_SIZE, fill_sockaddr_un


struct UnixStream(Movable):
    """A connected AF_UNIX byte stream.

    Owns a ``RawSocket`` (kind = ``SOCK_STREAM``, family =
    ``AF_UNIX``). ``Movable`` but not ``Copyable`` — same
    rationale as :class:`flare.tcp.TcpStream`: a connection is a
    single owned resource, duplicating it without tracking both
    fds leads to double-close.

    Closed automatically when the struct is destroyed.

    Thread safety:
        Not thread-safe. Do not share across threads without
        external synchronisation.

    Example:
        ```mojo
        from flare.uds import UnixStream

        var s = UnixStream.connect("/tmp/sidecar.sock")
        s.write_all("ping".as_bytes())
        s.close()
        ```
    """

    var _socket: RawSocket
    var _peer_path: String
    """Filesystem path of the peer side of the connection. Empty
    string when the peer didn't bind a path (the standard
    accept-side shape — server-accepted streams have no peer
    address since the client side is anonymous)."""

    def __init__(out self, var socket: RawSocket, peer_path: String):
        """Wrap an already-connected ``RawSocket``.

        Safety: ``socket`` must be connected (kind = SOCK_STREAM,
        family = AF_UNIX) before calling this constructor.
        """
        self._socket = socket^
        self._peer_path = peer_path

    def __del__(deinit self):
        self._socket.close()

    # ── Factory ───────────────────────────────────────────────────────────

    @staticmethod
    def connect(path: String) raises -> UnixStream:
        """Connect to an AF_UNIX listener bound at ``path``.

        Raises :class:`ConnectionRefused` if no listener is bound
        at the path (mirrors TCP's ``ECONNREFUSED`` shape).
        Raises :class:`NetworkError` for other connect(2) errors.
        """
        var sock = RawSocket(AF_UNIX, SOCK_STREAM)
        var sa = stack_allocation[Int(SOCKADDR_UN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_UN_SIZE)):
            (sa + i).init_pointee_copy(0)
        var used = fill_sockaddr_un(sa, path)
        var rc = _connect(sock.fd, sa, used)
        if rc < 0:
            var e = get_errno()
            var msg = _strerror(e.value) + " (connect " + path + ")"
            if e == ErrNo.ECONNREFUSED or e == ErrNo.ENOENT:
                raise ConnectionRefused(path, Int(e.value))
            raise NetworkError(msg, Int(e.value))
        return UnixStream(sock^, path)

    # ── I/O ──────────────────────────────────────────────────────────────

    def read(self, buf: UnsafePointer[UInt8, _], n: Int) raises -> Int:
        """Read up to ``n`` bytes into ``buf``. Returns 0 on EOF.

        Retries transparently on ``EINTR``. Raises
        :class:`ConnectionReset` on ``ECONNRESET``,
        :class:`NetworkError` on every other failure.
        """
        while True:
            var got = _recv(self._socket.fd, buf, c_size_t(n), c_int(0))
            if got >= 0:
                return Int(got)
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e == ErrNo.ECONNRESET:
                raise ConnectionReset(self._peer_path, Int(e.value))
            raise NetworkError(_strerror(e.value) + " (recv)", Int(e.value))

    def write(self, buf: UnsafePointer[UInt8, _], n: Int) raises -> Int:
        """Write at most ``n`` bytes from ``buf``. Returns the byte
        count actually written (may be less than ``n``).

        Retries on ``EINTR``. Raises :class:`BrokenPipe` on
        ``EPIPE``, :class:`NetworkError` on every other failure.
        """
        while True:
            var sent = _send(self._socket.fd, buf, c_size_t(n), MSG_NOSIGNAL)
            if sent >= 0:
                return Int(sent)
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue
            if e == ErrNo.EPIPE:
                raise BrokenPipe(self._peer_path, Int(e.value))
            raise NetworkError(_strerror(e.value) + " (send)", Int(e.value))

    def write_all(self, data: Span[UInt8, _]) raises:
        """Write every byte of ``data``, looping until done."""
        var p = data.unsafe_ptr()
        var remaining = len(data)
        while remaining > 0:
            var got = self.write(p, remaining)
            p = p + got
            remaining -= got

    def shutdown_read(self) raises:
        """Half-close the read side (``SHUT_RD``)."""
        var rc = _shutdown(self._socket.fd, SHUT_RD)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (shutdown rd)", Int(e.value)
            )

    def shutdown_write(self) raises:
        """Half-close the write side (``SHUT_WR``)."""
        var rc = _shutdown(self._socket.fd, SHUT_WR)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (shutdown wr)", Int(e.value)
            )

    def shutdown(self) raises:
        """Half-close both directions (``SHUT_RDWR``)."""
        var rc = _shutdown(self._socket.fd, SHUT_RDWR)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (shutdown rdwr)", Int(e.value)
            )

    def close(mut self):
        """Close the connection. Idempotent."""
        self._socket.close()

    # ── Introspection ────────────────────────────────────────────────────

    def peer_path(self) -> String:
        """Return the filesystem path of the peer side, or ``""``
        when the peer didn't bind a path."""
        return self._peer_path

    def as_raw_fd(self) -> c_int:
        """Return the underlying file descriptor.

        The returned fd is borrowed; its lifetime is tied to
        ``self``. Callers must not ``close(fd)`` themselves; let
        ``UnixStream`` own the close. Same contract as
        :meth:`flare.tcp.TcpStream.as_raw_fd`."""
        return self._socket.fd
