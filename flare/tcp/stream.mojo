"""TCP stream: a connected, bidirectional byte stream.

``TcpStream`` owns a ``RawSocket`` and exposes blocking read/write
operations. ``TCP_NODELAY`` is set automatically on every new stream so
callers get low-latency behaviour by default (Nagle's algorithm is
disabled).

Design rules enforced here:
- ``write`` retries transparently on ``EINTR``.
- ``write_all`` loops until every byte is sent.
- ``read`` returning 0 means EOF — it is never converted to an error.
- ``connect_timeout`` delegates to ``flare_connect_timeout`` in
  ``libflare_tls.so``, which does non-blocking connect + ``poll(POLLOUT)``
  + ``getsockopt(SO_ERROR)`` entirely in C, sidestepping a Mojo ABI bug
  with variadic functions on macOS/arm64.
"""

from ffi import (
    OwnedDLHandle,
    c_int,
    c_uint,
    c_size_t,
    c_ssize_t,
    get_errno,
    ErrNo,
)
from memory import alloc

from ..net import (
    SocketAddr,
    NetworkError,
    ConnectionRefused,
    ConnectionTimeout,
    ConnectionReset,
    BrokenPipe,
    Timeout,
    DnsError,
)
from ..net.socket import (
    RawSocket,
    AF_INET,
    SOCK_STREAM,
    _build_sockaddr_in,
    _sockaddr_to_socket_addr,
    _find_flare_lib,
)
from ..net._libc import (
    _connect,
    _recv,
    _send,
    _shutdown,
    _strerror,
    MSG_NOSIGNAL,
    SHUT_RD,
    SHUT_WR,
)


struct TcpStream(Movable):
    """A connected TCP socket.

    Owns a ``RawSocket`` and exposes blocking read/write operations.
    ``TCP_NODELAY`` is set automatically on every new stream so callers
    get low-latency behaviour without any configuration.

    This type is ``Movable`` but not ``Copyable`` — a TCP connection
    cannot be duplicated without tracking both file descriptors.

    The connection is closed automatically when the struct is destroyed.

    Thread safety:
        Not thread-safe in v0.1.0. Do not share a ``TcpStream`` across
        threads without external synchronisation.

    Example:
        ```mojo
        from flare.tcp import TcpStream
        from flare.net import SocketAddr

        var stream = TcpStream.connect(SocketAddr.localhost(8080))
        stream.write_all("hello".as_bytes())
        var buf = List[UInt8](capacity=1024)
        buf.resize(1024, 0)
        var n = stream.read(buf.unsafe_ptr(), len(buf))
        stream.close()
        ```
    """

    var _socket: RawSocket
    var _peer: SocketAddr

    fn __init__(out self, var socket: RawSocket, peer: SocketAddr):
        """Wrap an already-connected ``RawSocket``.

        Args:
            socket: An open, connected file descriptor (ownership transferred).
            peer:   The remote address.

        Safety:
            ``socket`` must be connected before calling this constructor.
            ``TCP_NODELAY`` should already be set by the factory functions.
        """
        self._socket = socket^
        self._peer = peer

    fn __moveinit__(out self, deinit take: TcpStream):
        self._socket = take._socket^
        self._peer = take._peer

    fn __del__(deinit self):
        self._socket.close()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn connect(addr: SocketAddr) raises -> TcpStream:
        """Open a blocking TCP connection to ``addr``.

        Sets ``TCP_NODELAY`` automatically.

        Args:
            addr: The remote socket address to connect to.

        Returns:
            A connected ``TcpStream``.

        Raises:
            ConnectionRefused:  If the remote port actively refuses.
            ConnectionTimeout:  If the OS connect timeout expires.
            ConnectionReset:    If the peer sends a TCP RST during connect.
            NetworkError:       For any other OS error.

        Example:
            ```mojo
            var stream = TcpStream.connect(SocketAddr.localhost(8080))
            ```
        """
        var sock = RawSocket(AF_INET, SOCK_STREAM)
        var sa = _build_sockaddr_in(addr)
        var rc = _connect(sock.fd, sa[0], sa[1])
        sa[0].free()
        if rc < 0:
            var e = get_errno()
            var s = String(addr)
            if e == ErrNo.ECONNREFUSED:
                raise ConnectionRefused(s, Int(e.value))
            if e == ErrNo.ETIMEDOUT:
                raise ConnectionTimeout(s, Int(e.value))
            if e == ErrNo.ECONNRESET:
                raise ConnectionReset(s, Int(e.value))
            raise NetworkError(
                _strerror(e.value) + " (connect " + s + ")", Int(e.value)
            )
        sock.set_tcp_nodelay(True)
        return TcpStream(sock^, addr)

    @staticmethod
    fn connect_timeout(addr: SocketAddr, timeout_ms: Int) raises -> TcpStream:
        """Open a TCP connection, failing if it takes longer than ``timeout_ms``.

        Delegates the non-blocking connect + ``poll(POLLOUT)`` +
        ``getsockopt(SO_ERROR)`` sequence to ``flare_connect_timeout`` in
        ``libflare_tls.so``.  Using a C helper avoids a Mojo ABI bug where
        ``external_call`` silently corrupts variadic-function arguments (like
        the third argument of ``fcntl``) when they cross a Mojo function
        boundary on macOS/arm64.

        ``flare_connect_timeout`` returns:
        - ``0``  on success,
        - ``-1`` if ``fcntl`` or ``getsockopt`` failed (errno set),
        - ``-2`` if the poll deadline expired (timeout),
        - positive errno value on connect failure.

        Args:
            addr:       The remote socket address.
            timeout_ms: Maximum time to wait in milliseconds (must be > 0).

        Returns:
            A connected ``TcpStream``.

        Raises:
            ConnectionTimeout: If the deadline expires before connecting.
            ConnectionRefused: If the port actively refuses.
            NetworkError:      For any other OS error.

        Example:
            ```mojo
            var stream = TcpStream.connect_timeout(SocketAddr.localhost(8080), 5000)
            ```
        """
        var sock = RawSocket(AF_INET, SOCK_STREAM)
        var sa = _build_sockaddr_in(addr)

        var lib = OwnedDLHandle(_find_flare_lib())
        var fn_ct = lib.get_function[fn(c_int, Int, c_uint, c_int) -> c_int](
            "flare_connect_timeout"
        )
        var rc = fn_ct(sock.fd, Int(sa[0]), sa[1], c_int(timeout_ms))
        sa[0].free()

        if rc == c_int(-2):
            raise ConnectionTimeout(String(addr), timeout_ms)
        if rc != c_int(0):
            var s = String(addr)
            var rc_int = Int(rc)
            if rc_int == Int(ErrNo.ECONNREFUSED.value):
                raise ConnectionRefused(s, rc_int)
            if rc_int == Int(ErrNo.ETIMEDOUT.value):
                raise ConnectionTimeout(s, rc_int)
            if rc_int == -1:
                var e = get_errno()
                raise NetworkError(
                    _strerror(e.value) + " (connect " + s + ")", Int(e.value)
                )
            raise NetworkError(_strerror(rc) + " (connect " + s + ")", rc_int)

        sock.set_tcp_nodelay(True)
        return TcpStream(sock^, addr)

    @staticmethod
    fn connect(host: String, port: UInt16) raises -> TcpStream:
        """Resolve ``host`` via DNS and open a blocking TCP connection.

        Convenience overload that performs DNS resolution then calls
        ``TcpStream.connect(SocketAddr(...))`` automatically.

        Args:
            host: Hostname or IP address string (e.g. ``"example.com"``).
            port: TCP port number.

        Returns:
            A connected ``TcpStream``.

        Raises:
            DnsError:          If ``host`` cannot be resolved.
            ConnectionRefused: If the remote port actively refuses.
            ConnectionTimeout: If the OS connect timeout expires.
            NetworkError:      For any other OS error.

        Example:
            ```mojo
            var stream = TcpStream.connect("example.com", 80)
            ```
        """
        from ..dns import resolve_v4

        var addrs = resolve_v4(host)
        if len(addrs) == 0:
            raise DnsError("DNS resolution returned no results for: " + host)
        return TcpStream.connect(SocketAddr(addrs[0], port))

    @staticmethod
    fn connect(host: String, port: UInt16, timeout_ms: Int) raises -> TcpStream:
        """Resolve ``host`` via DNS and connect with a timeout.

        Convenience overload that performs DNS resolution then calls
        ``TcpStream.connect_timeout(SocketAddr(...), timeout_ms)``.

        Args:
            host:       Hostname or IP address string.
            port:       TCP port number.
            timeout_ms: Maximum time to wait in milliseconds.

        Returns:
            A connected ``TcpStream``.

        Raises:
            DnsError:          If ``host`` cannot be resolved.
            ConnectionTimeout: If the deadline expires.
            ConnectionRefused: If the remote port actively refuses.
            NetworkError:      For any other OS error.

        Example:
            ```mojo
            var stream = TcpStream.connect("example.com", 80, 5000)
            ```
        """
        from ..dns import resolve_v4

        var addrs = resolve_v4(host)
        if len(addrs) == 0:
            raise DnsError("DNS resolution returned no results for: " + host)
        return TcpStream.connect_timeout(SocketAddr(addrs[0], port), timeout_ms)

    # ── Context manager ───────────────────────────────────────────────────────

    fn __enter__(var self) -> TcpStream:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``TcpStream`` (moved).
        """
        return self^

    # ── I/O ───────────────────────────────────────────────────────────────────

    fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
        """Read up to ``size`` bytes from the stream into ``buf``.

        Retries transparently on ``EINTR``. Returns 0 on EOF (the peer
        closed the connection) — this is not an error.

        Args:
            buf:  Destination buffer; the caller must provide at least
                  ``size`` bytes of valid storage.
            size: Maximum number of bytes to read.

        Returns:
            Number of bytes placed in ``buf``. **0 means EOF.**

        Raises:
            ConnectionReset: If the peer sent a TCP RST.
            Timeout:         If a recv timeout was set and expired.
            NetworkError:    For any other OS read error.

        Example:
            ```mojo
            var buf = List[UInt8](capacity=4096)
            buf.resize(4096, 0)
            var n = stream.read(buf.unsafe_ptr(), len(buf))
            if n == 0:
                print("connection closed")
            ```
        """
        if size == 0:
            return 0
        while True:
            var got = _recv(self._socket.fd, buf, c_size_t(size), c_int(0))
            if got > 0:
                return Int(got)
            if got == 0:
                return 0  # EOF — peer closed connection
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue  # signal interrupted — retry
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                raise Timeout("recv")
            if e == ErrNo.ECONNRESET:
                raise ConnectionReset(String(self._peer), Int(e.value))
            raise NetworkError(_strerror(e.value) + " (recv)", Int(e.value))

    fn read_exact(mut self, buf: UnsafePointer[UInt8], size: Int) raises:
        """Read exactly ``size`` bytes into ``buf``.

        Loops over ``read()`` until ``size`` bytes have been received.

        Args:
            buf:  Destination buffer; must have at least ``size`` bytes.
            size: Exact number of bytes to read.

        Raises:
            NetworkError: If EOF is reached before ``size`` bytes are received,
                or on any other I/O error.

        Example:
            ```mojo
            var exact = List[UInt8](capacity=8)
            exact.resize(8, 0)
            stream.read_exact(exact.unsafe_ptr(), 8)
            ```
        """
        var received = 0
        while received < size:
            var n = self.read(buf + received, size - received)
            if n == 0:
                raise NetworkError(
                    "read_exact: EOF after "
                    + String(received)
                    + "/"
                    + String(size)
                    + " bytes"
                )
            received += n

    fn write(self, data: Span[UInt8]) raises -> Int:
        """Write up to ``len(data)`` bytes to the stream.

        A single call may write fewer bytes than requested (partial write).
        Use ``write_all`` to guarantee all bytes are sent. Retries on
        ``EINTR``.

        Args:
            data: The bytes to send.

        Returns:
            Number of bytes actually written (>= 1 if data is non-empty).

        Raises:
            BrokenPipe:  If the peer has closed the read end.
            Timeout:     If a send timeout was set and expired.
            NetworkError: For any other OS write error.

        Example:
            ```mojo
            var n = stream.write("hello".as_bytes())
            ```
        """
        var n = len(data)
        if n == 0:
            return 0
        var ptr = data.unsafe_ptr()
        while True:
            var sent = _send(self._socket.fd, ptr, c_size_t(n), MSG_NOSIGNAL)
            if sent > 0:
                return Int(sent)
            if sent == 0:
                return 0
            var e = get_errno()
            if e == ErrNo.EINTR:
                continue  # signal interrupted — retry
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                raise Timeout("send")
            if e == ErrNo.EPIPE:
                raise BrokenPipe(String(self._peer), Int(e.value))
            if e == ErrNo.ECONNRESET:
                raise ConnectionReset(String(self._peer), Int(e.value))
            raise NetworkError(_strerror(e.value) + " (send)", Int(e.value))

    fn write_all(self, data: Span[UInt8]) raises:
        """Write all of ``data``, looping until every byte is sent.

        Args:
            data: The bytes to send completely.

        Raises:
            BrokenPipe:  If the peer closes before all bytes are sent.
            NetworkError: For any other OS write error.

        Example:
            ```mojo
            stream.write_all("Hello, server!".as_bytes())
            ```
        """
        var total = len(data)
        var ptr = data.unsafe_ptr()
        var sent = 0
        while sent < total:
            var chunk = Span[UInt8](ptr=ptr + sent, length=total - sent)
            var n = self.write(chunk)
            sent += n

    # ── Introspection ─────────────────────────────────────────────────────────

    fn peer_addr(self) -> SocketAddr:
        """Return the remote socket address.

        Returns:
            The ``SocketAddr`` this stream is connected to.
        """
        return self._peer

    fn local_addr(self) raises -> SocketAddr:
        """Return the local socket address assigned by the OS.

        Returns:
            The local ``SocketAddr`` (IP + ephemeral port).

        Raises:
            NetworkError: If ``getsockname(2)`` fails.
        """
        return self._socket.local_addr()

    # ── Control ───────────────────────────────────────────────────────────────

    fn shutdown_read(self) raises:
        """Shut down the read half of the connection.

        After this call, any subsequent ``read()`` returns 0 (EOF). The
        peer will receive a FIN indicating no more data will be read.

        Raises:
            NetworkError: If ``shutdown(2)`` fails.
        """
        var rc = _shutdown(self._socket.fd, SHUT_RD)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (shutdown_read)", Int(e.value)
            )

    fn shutdown_write(self) raises:
        """Shut down the write half of the connection.

        Sends a FIN to the peer, signalling that no more data will be
        written. The peer will see EOF on their next ``read()``.

        Raises:
            NetworkError: If ``shutdown(2)`` fails.
        """
        var rc = _shutdown(self._socket.fd, SHUT_WR)
        if rc < 0:
            var e = get_errno()
            raise NetworkError(
                _strerror(e.value) + " (shutdown_write)", Int(e.value)
            )

    fn close(mut self):
        """Close the connection explicitly. Idempotent."""
        self._socket.close()

    # ── Options ───────────────────────────────────────────────────────────────

    fn set_nodelay(self, enabled: Bool) raises:
        """Toggle ``TCP_NODELAY`` (Nagle's algorithm).

        Args:
            enabled: ``True`` disables Nagle (low-latency); ``False`` re-enables it.
        """
        self._socket.set_tcp_nodelay(enabled)

    fn set_keepalive(self, enabled: Bool) raises:
        """Toggle ``SO_KEEPALIVE``.

        Args:
            enabled: ``True`` to send keepalive probes on idle connections.
        """
        self._socket.set_keepalive(enabled)

    fn set_recv_timeout(self, ms: Int) raises:
        """Set a per-read timeout.

        After the timeout expires, ``read()`` raises ``Timeout``.

        Args:
            ms: Timeout in milliseconds. 0 disables the timeout.
        """
        self._socket.set_recv_timeout(ms)

    fn set_send_timeout(self, ms: Int) raises:
        """Set a per-write timeout.

        After the timeout expires, ``write()`` raises ``Timeout``.

        Args:
            ms: Timeout in milliseconds. 0 disables the timeout.
        """
        self._socket.set_send_timeout(ms)
