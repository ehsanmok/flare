"""Raw POSIX socket wrapper — the single point where flare touches the OS.

Every higher-level type (``TcpStream``, ``UdpSocket``, etc.) is built on
top of ``RawSocket``. No module above ``flare.net`` calls libc directly.

Safety contracts for this module:
1. ``fd >= 0`` iff the socket is open. After ``close()`` or ``__del__``
   sets ``fd = INVALID_FD``.
2. Every libc call that returns -1 reads ``errno`` immediately (before any
   subsequent libc call) and maps it to a typed error.
3. ``TCP_NODELAY`` is set by the caller, not here — ``RawSocket`` is
   transport-agnostic and does not know whether it carries TCP or UDP.
"""

from ffi import external_call, OwnedDLHandle, c_int, c_uint, get_errno, ErrNo
from memory import UnsafePointer, stack_allocation, alloc
from os import getenv
from sys.info import CompilationTarget

from .address import SocketAddr, IpAddr
from .error import (
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    AddressInUse,
    BrokenPipe,
)
from ._libc import (
    AF_INET,
    AF_INET6,
    SOCK_STREAM,
    SOCK_DGRAM,
    SOL_SOCKET,
    SO_REUSEADDR,
    SO_REUSEPORT,
    SO_KEEPALIVE,
    SO_RCVTIMEO,
    SO_SNDTIMEO,
    TCP_NODELAY,
    IPPROTO_TCP,
    F_GETFL,
    F_SETFL,
    O_NONBLOCK,
    INVALID_FD,
    SOCKADDR_IN_SIZE,
    TIMEVAL_SIZE,
    _fill_sockaddr_in,
    _read_port_from_sockaddr,
    _read_ip_from_sockaddr,
    _os_error,
    _strerror,
    _socket,
    _close,
    _bind,
    _listen,
    _accept,
    _connect,
    _getsockname,
    _getpeername,
    _setsockopt,
    _fcntl2,
    _inet_pton,
    _htons,
    _ntohs,
)


fn _find_flare_lib() -> String:
    """Return the path to ``libflare_tls.so``.

    Search order:
    1. ``$FLARE_LIB`` — set by the pixi activation script; always points to the
       freshly-built ``build/libflare_tls.so`` and avoids any path ambiguity.
    2. ``$CONDA_PREFIX/lib/libflare_tls.so`` — installed via a conda/pixi package.
    3. ``build/libflare_tls.so`` — bare checkout without a conda environment.
    """
    var explicit = getenv("FLARE_LIB", "")
    if explicit:
        return explicit
    var prefix = getenv("CONDA_PREFIX", "")
    if prefix:
        return prefix + "/lib/libflare_tls.so"
    return "build/libflare_tls.so"


struct RawSocket(Movable):
    """A thin, owning wrapper around a POSIX socket file descriptor.

    ``RawSocket`` is ``Movable`` but intentionally **not** ``Copyable``.
    Duplicating a file descriptor without tracking both copies leads to
    double-close bugs and hard-to-find resource leaks.

    Lifecycle:
    - ``__init__``: calls ``socket(2)``; raises on failure.
    - ``__del__``:  calls ``close(2)`` when ``fd >= 0``.
    - ``__moveinit__``: transfers ownership; source ``fd`` becomes ``INVALID_FD``.
    - ``close()``:  explicit, idempotent close.

    Fields:
        fd:     The OS file descriptor. ``INVALID_FD`` means closed/invalid.
        family: Address family (``AF_INET`` or ``AF_INET6``).
        kind:   Socket type (``SOCK_STREAM`` or ``SOCK_DGRAM``).

    Example:
        ```mojo
        var sock = RawSocket(AF_INET, SOCK_STREAM)
        sock.set_reuse_addr(True)
        # ... use sock.fd ...
        sock.close()  # or let it fall out of scope
        ```
    """

    var fd: c_int
    var family: c_int
    var kind: c_int

    fn __init__(out self, family: c_int, kind: c_int) raises:
        """Create a new socket via ``socket(2)``.

        Args:
            family: Address family (``AF_INET`` or ``AF_INET6``).
            kind:   Socket type (``SOCK_STREAM`` for TCP, ``SOCK_DGRAM`` for UDP).

        Raises:
            NetworkError: If ``socket(2)`` returns -1, with the OS errno and
                          ``strerror`` message included.

        Example:
            ```mojo
            var tcp = RawSocket(AF_INET, SOCK_STREAM)
            var udp = RawSocket(AF_INET, SOCK_DGRAM)
            ```
        """
        var fd = _socket(family, kind, c_int(0))
        if fd < 0:
            var e = get_errno()
            raise NetworkError(_strerror(e.value) + " (socket)", Int(e.value))
        self.fd = fd
        self.family = family
        self.kind = kind

    fn __init__(out self, fd: c_int, family: c_int, kind: c_int, _wrap: Bool):
        """Wrap an existing file descriptor without calling ``socket(2)``.

        Args:
            fd:     An already-open file descriptor (from ``accept(2)`` etc.).
            family: Address family (``AF_INET`` or ``AF_INET6``).
            kind:   Socket type (``SOCK_STREAM`` or ``SOCK_DGRAM``).
            _wrap:  Dummy parameter that disambiguates this overload from the
                    public ``__init__(family, kind)`` constructor.

        Safety:
            ``fd`` must be a valid, open file descriptor. The caller
            transfers ownership — ``RawSocket.__del__`` will call
            ``close(fd)`` exactly once.
        """
        self.fd = fd
        self.family = family
        self.kind = kind

    fn __moveinit__(out self, deinit take: RawSocket):
        """Transfer ownership from ``take``.

        After the move, the source fd is set to ``INVALID_FD``, so its
        destructor will not call ``close()`` again.

        Args:
            take: The socket to move from (left in a closed/invalid state).
        """
        self.fd = take.fd
        self.family = take.family
        self.kind = take.kind

    fn __del__(deinit self):
        """Close the file descriptor if it is open.

        Safety: safe to call even after a move because ``fd`` is set to
        ``INVALID_FD`` by the move constructor.
        """
        if self.fd >= 0:
            _ = _close(self.fd)

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    fn close(mut self):
        """Close the socket explicitly. Idempotent.

        Sets ``fd = INVALID_FD`` so subsequent calls and the destructor
        are no-ops.
        """
        if self.fd >= 0:
            _ = _close(self.fd)
            self.fd = INVALID_FD

    # ── Socket options ────────────────────────────────────────────────────────

    fn set_reuse_addr(self, enabled: Bool) raises:
        """Set ``SO_REUSEADDR`` so the port can be reused immediately after
        the socket is closed.

        Should be called before ``bind()``. This is the default for all
        ``TcpListener`` instances.

        Args:
            enabled: ``True`` to enable address reuse, ``False`` to disable.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.

        Example:
            ```mojo
            sock.set_reuse_addr(True)
            ```
        """
        self._set_bool_opt(SOL_SOCKET, SO_REUSEADDR, enabled)

    fn set_reuse_port(self, enabled: Bool) raises:
        """Set ``SO_REUSEPORT`` for multi-process listener load balancing.

        Allows multiple processes or threads to bind the same port. Each
        accept loop gets a fair share of incoming connections from the kernel.

        Args:
            enabled: ``True`` to enable port reuse.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        self._set_bool_opt(SOL_SOCKET, SO_REUSEPORT, enabled)

    fn set_keepalive(self, enabled: Bool) raises:
        """Enable or disable ``SO_KEEPALIVE``.

        When enabled, the kernel sends TCP keepalive probes on idle
        connections to detect dead peers.

        Args:
            enabled: ``True`` to send keepalive probes.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.

        Example:
            ```mojo
            stream._socket.set_keepalive(True)
            ```
        """
        self._set_bool_opt(SOL_SOCKET, SO_KEEPALIVE, enabled)

    fn set_tcp_nodelay(self, enabled: Bool) raises:
        """Disable Nagle's algorithm via ``TCP_NODELAY``.

        Must be called on all TCP sockets in flare. Nagle coalesces small
        writes, which introduces latency that surprises virtually every
        networking caller.

        Args:
            enabled: ``True`` to disable Nagle (send immediately).

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.

        Example:
            ```mojo
            sock.set_tcp_nodelay(True)
            ```
        """
        self._set_bool_opt(IPPROTO_TCP, TCP_NODELAY, enabled)

    fn set_recv_timeout(self, ms: Int) raises:
        """Set a receive timeout via ``SO_RCVTIMEO``.

        After the timeout expires, ``recv``/``recvfrom`` returns ``EAGAIN``.

        Args:
            ms: Timeout in milliseconds. ``0`` disables the timeout.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.

        Example:
            ```mojo
            sock.set_recv_timeout(5_000)  # 5 seconds
            ```
        """
        self._set_timeval_opt(SO_RCVTIMEO, ms)

    fn set_send_timeout(self, ms: Int) raises:
        """Set a send timeout via ``SO_SNDTIMEO``.

        Args:
            ms: Timeout in milliseconds. ``0`` disables the timeout.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        self._set_timeval_opt(SO_SNDTIMEO, ms)

    fn set_nonblocking(self, enabled: Bool) raises:
        """Toggle non-blocking mode on the socket.

        Delegates to ``flare_set_nonblocking`` in ``libflare_tls.so``, which
        calls ``fcntl(F_GETFL)`` / ``fcntl(F_SETFL)`` from C.  The C helper
        avoids a Mojo ABI bug where ``external_call`` silently corrupts the
        third argument of variadic C functions (like ``fcntl``) when called
        across a Mojo function boundary.

        Args:
            enabled: ``True`` to enable non-blocking I/O; ``False`` to restore
                blocking mode.

        Raises:
            NetworkError: If the underlying ``fcntl(F_SETFL)`` call fails.
        """
        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_nb = lib.get_function[fn(c_int, c_int) -> c_int](
            "flare_set_nonblocking"
        )
        var rc = fn_nb(self.fd, c_int(1) if enabled else c_int(0))
        if rc < c_int(0):
            var e = get_errno()
            raise NetworkError(_os_error("fcntl F_SETFL"), Int(e.value))

    # ── Local / peer address ──────────────────────────────────────────────────

    fn local_addr(self) raises -> SocketAddr:
        """Return the local address assigned by the OS.

        Returns:
            The local ``SocketAddr`` (IP + port). Useful after ``bind()``
            with port 0 to discover the ephemeral port chosen by the kernel.

        Raises:
            NetworkError: If ``getsockname(2)`` fails.

        Example:
            ```mojo
            var addr = sock.local_addr()
            print(addr)  # e.g. 127.0.0.1:54321
            ```
        """
        var buf = stack_allocation[16, UInt8]()
        for i in range(16):
            (buf + i).init_pointee_copy(0)
        var len_ptr = stack_allocation[1, c_uint]()
        len_ptr.init_pointee_copy(16)
        var rc = _getsockname(self.fd, buf, len_ptr)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(_os_error("getsockname"), Int(e.value))
        return _sockaddr_to_socket_addr(buf)

    fn peer_addr(self) raises -> SocketAddr:
        """Return the remote address of the connected peer.

        Returns:
            The peer ``SocketAddr``.

        Raises:
            NetworkError: If ``getpeername(2)`` fails (e.g. not connected).
        """
        var buf = stack_allocation[16, UInt8]()
        for i in range(16):
            (buf + i).init_pointee_copy(0)
        var len_ptr = stack_allocation[1, c_uint]()
        len_ptr.init_pointee_copy(16)
        var rc = _getpeername(self.fd, buf, len_ptr)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(_os_error("getpeername"), Int(e.value))
        return _sockaddr_to_socket_addr(buf)

    # ── Private helpers ───────────────────────────────────────────────────────

    fn _set_bool_opt(self, level: c_int, opt: c_int, value: Bool) raises:
        """Helper: call ``setsockopt`` with an ``Int32`` boolean value.

        Args:
            level: Option level (e.g. ``SOL_SOCKET``).
            opt:   Option name (e.g. ``SO_REUSEADDR``).
            value: ``True`` to enable, ``False`` to disable.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        var v = stack_allocation[1, c_int]()
        v.init_pointee_copy(c_int(1) if value else c_int(0))
        var rc = _setsockopt(self.fd, level, opt, v.bitcast[UInt8](), c_uint(4))
        if rc < 0:
            var e = get_errno()
            raise NetworkError(_os_error("setsockopt"), Int(e.value))

    fn _set_timeval_opt(self, opt: c_int, ms: Int) raises:
        """Helper: call ``setsockopt`` with a ``timeval`` for timeout options.

        ``timeval`` layout (64-bit platforms): 8 bytes ``tv_sec`` +
        8 bytes ``tv_usec`` = 16 bytes total.

        Args:
            opt: ``SO_RCVTIMEO`` or ``SO_SNDTIMEO``.
            ms:  Timeout in milliseconds. 0 = disable timeout.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        # timeval: Int64 tv_sec, Int64 tv_usec (16 bytes on 64-bit)
        var tv = stack_allocation[16, UInt8]()
        for i in range(16):
            (tv + i).init_pointee_copy(0)
        var sec = ms // 1000
        var usec = (ms % 1000) * 1000
        # Write tv_sec as Int64 little-endian at offset 0
        var sec_ptr = tv.bitcast[Int64]()
        sec_ptr.init_pointee_copy(Int64(sec))
        # Write tv_usec as Int64 little-endian at offset 8
        var usec_ptr = (tv + 8).bitcast[Int64]()
        usec_ptr.init_pointee_copy(Int64(usec))
        var rc = _setsockopt(self.fd, SOL_SOCKET, opt, tv, c_uint(16))
        if rc < 0:
            var e = get_errno()
            raise NetworkError(_os_error("setsockopt timeval"), Int(e.value))


# ── Module-level helpers ──────────────────────────────────────────────────────


fn _build_sockaddr_in(
    addr: SocketAddr,
) raises -> Tuple[type_of(alloc[UInt8](0)), c_uint]:
    """Allocate and populate a heap ``sockaddr_in`` buffer for ``addr``.

    The caller is responsible for freeing the returned pointer via
    ``ptr.free()`` once the buffer is no longer needed (i.e., after the
    syscall that consumes it). Only IPv4 addresses are supported.

    Args:
        addr: The socket address to encode.

    Returns:
        A tuple of ``(heap_pointer_to_buf, buf_size_bytes)``.

    Raises:
        AddressParseError: If the IP string is not a valid IPv4 address.
        NetworkError:      If ``inet_pton`` returns an unexpected error.
    """
    from .error import AddressParseError

    var ip_buf = alloc[UInt8](4)
    for i in range(4):
        (ip_buf + i).init_pointee_copy(0)

    var rc = _inet_pton(AF_INET, String(addr.ip), ip_buf)
    if rc != 1:
        ip_buf.free()
        raise AddressParseError(String(addr.ip))

    var sa = alloc[UInt8](16)
    for i in range(16):
        (sa + i).init_pointee_copy(0)

    _fill_sockaddr_in(sa, addr.port, ip_buf)
    ip_buf.free()
    return Tuple(sa, SOCKADDR_IN_SIZE)


fn _sockaddr_to_socket_addr(buf: UnsafePointer[UInt8]) raises -> SocketAddr:
    """Extract a ``SocketAddr`` from a 16-byte ``sockaddr_in`` buffer.

    Args:
        buf: Pointer to 16 bytes returned by ``getsockname`` / ``getpeername``.

    Returns:
        The decoded ``SocketAddr``.

    Raises:
        NetworkError: If ``inet_ntop`` fails.
    """
    var port = _read_port_from_sockaddr(buf)
    var ip_str = _read_ip_from_sockaddr(buf)
    return SocketAddr(IpAddr(ip_str, is_v6=False), port)


fn _raise_net_error(op: String) raises:
    """Read ``errno`` and raise an appropriate typed error.

    Maps common socket errno values to typed errors; falls back to
    ``NetworkError`` for all others.

    Args:
        op: Name of the failing operation for context (e.g. ``"connect"``).

    Raises:
        ConnectionRefused:  On ``ECONNREFUSED``.
        ConnectionTimeout:  On ``ETIMEDOUT``.
        ConnectionReset:    On ``ECONNRESET``.
        AddressInUse:       On ``EADDRINUSE``.
        BrokenPipe:         On ``EPIPE``.
        NetworkError:       For all other errors.
    """
    var e = get_errno()
    var msg = _strerror(e.value) + " (" + op + ")"
    if e == ErrNo.ECONNREFUSED:
        raise ConnectionRefused(msg, Int(e.value))
    if e == ErrNo.ETIMEDOUT:
        raise ConnectionTimeout(msg, Int(e.value))
    if e == ErrNo.ECONNRESET:
        raise ConnectionReset(msg, Int(e.value))
    if e == ErrNo.EADDRINUSE:
        raise AddressInUse(msg, Int(e.value))
    if e == ErrNo.EPIPE:
        raise BrokenPipe(msg, Int(e.value))
    raise NetworkError(msg, Int(e.value))
