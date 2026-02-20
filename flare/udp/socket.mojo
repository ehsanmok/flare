"""UDP socket: connectionless datagrams.

``UdpSocket`` wraps a ``RawSocket`` in ``SOCK_DGRAM`` mode and exposes
``send_to`` / ``recv_from`` operations. Use ``bind()`` for a receiving
socket and ``unbound()`` for a send-only socket.

Platform notes:
- Maximum UDP payload: 65507 bytes (65535 − 8-byte UDP header − 20-byte
  IP header). Larger datagrams must be rejected by the caller.
- ``SO_BROADCAST`` must be explicitly enabled to send to broadcast
  addresses (e.g. ``255.255.255.255``).
"""

from ffi import c_int, c_uint, c_size_t, c_ssize_t, get_errno, ErrNo
from memory import stack_allocation

from format import Writable, Writer
from ..net import (
    SocketAddr,
    NetworkError,
    AddressInUse,
    Timeout,
)
from ..net.socket import (
    RawSocket,
    AF_INET,
    SOCK_DGRAM,
    _build_sockaddr_in,
    _sockaddr_to_socket_addr,
)
from ..net._libc import (
    _bind,
    _sendto,
    _recvfrom,
    _setsockopt,
    _strerror,
    SOL_SOCKET,
    SO_BROADCAST,
    SOCKADDR_IN_SIZE,
)


# Maximum safe UDP payload — any datagram larger than this must be rejected
# before calling sendto() to avoid a silent truncation.
comptime UDP_MAX_PAYLOAD: Int = 65507


struct DatagramTooLarge(Copyable, Movable, Stringable, Writable):
    """Raised when a UDP datagram exceeds the maximum allowed payload size.

    Fields:
        size:     The datagram size in bytes that was rejected.
        max_size: The platform maximum (``65507`` bytes).

    Example:
        ```mojo
        raise DatagramTooLarge(70000)
        ```
    """

    var size: Int
    var max_size: Int

    fn __init__(out self, size: Int, max_size: Int = UDP_MAX_PAYLOAD):
        """Initialise a DatagramTooLarge error.

        Args:
            size:     The requested datagram size.
            max_size: The allowed maximum. Defaults to ``65507``.
        """
        self.size = size
        self.max_size = max_size

    fn write_to[W: Writer](self, mut writer: W):
        """Write the error description to ``writer``.

        Args:
            writer: Destination writer.
        """
        writer.write(
            "DatagramTooLarge: ",
            self.size,
            " bytes (max ",
            self.max_size,
            ")",
        )

    fn __str__(self) -> String:
        """Return a human-readable error message.

        Returns:
            ``"DatagramTooLarge: N bytes (max M)"``.
        """
        return (
            "DatagramTooLarge: "
            + String(self.size)
            + " bytes (max "
            + String(self.max_size)
            + ")"
        )


struct UdpSocket(Movable):
    """A UDP socket for sending and receiving datagrams.

    ``UdpSocket`` is ``Movable`` but not ``Copyable`` — a socket file
    descriptor cannot be shared without tracking both copies.

    Use ``bind()`` to receive datagrams from any sender, or ``unbound()``
    to create a send-only socket that the OS assigns a source port to.

    Thread safety:
        Not thread-safe in v0.1.0.

    Example:
        ```mojo
        from flare.udp import UdpSocket
        from flare.net import SocketAddr

        # Receiver
        var recv = UdpSocket.bind(SocketAddr.localhost(5000))
        var buf  = List[UInt8]()
        buf.resize(1024, 0)
        var (n, from_addr) = recv.recv_from(Span[UInt8](buf))
        print("received", n, "bytes from", String(from_addr))

        # Sender
        var sender = UdpSocket.unbound()
        sender.send_to("hello".as_bytes(), SocketAddr.localhost(5000))
        ```
    """

    var _socket: RawSocket
    var _local: SocketAddr

    fn __init__(out self, var socket: RawSocket, local: SocketAddr):
        """Wrap an existing ``RawSocket`` (internal use only).

        Args:
            socket: An open UDP socket (ownership transferred).
            local:  The bound address; use ``SocketAddr(IpAddr.unspecified(), 0)``
                    for an unbound socket.

        Safety:
            The caller must not use ``socket`` after this constructor.
        """
        self._socket = socket^
        self._local = local

    fn __moveinit__(out self, deinit take: UdpSocket):
        self._socket = take._socket^
        self._local = take._local

    fn __del__(deinit self):
        self._socket.close()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn bind(addr: SocketAddr) raises -> UdpSocket:
        """Create a UDP socket bound to ``addr``.

        After this call, ``recv_from()`` will receive datagrams sent to
        the bound address.

        Args:
            addr: The local address to bind. Use port ``0`` for an
                  OS-assigned ephemeral port.

        Returns:
            A bound ``UdpSocket``.

        Raises:
            AddressInUse: If the port is already in use.
            NetworkError: For any other OS bind error.

        Example:
            ```mojo
            var s = UdpSocket.bind(SocketAddr.localhost(5000))
            ```
        """
        var sock = RawSocket(AF_INET, SOCK_DGRAM)
        sock.set_reuse_addr(True)

        var sa = _build_sockaddr_in(addr)
        var rc = _bind(sock.fd, sa[0], sa[1])
        sa[0].free()

        if rc < 0:
            var e = get_errno()
            if e == ErrNo.EADDRINUSE:
                raise AddressInUse(String(addr), Int(e.value))
            raise NetworkError(
                _strerror(e.value) + " (bind " + String(addr) + ")",
                Int(e.value),
            )

        var local = sock.local_addr()
        return UdpSocket(sock^, local)

    @staticmethod
    fn unbound() raises -> UdpSocket:
        """Create a send-only UDP socket without binding to a specific port.

        The OS assigns an ephemeral source port on the first ``send_to()``.

        Returns:
            An unbound ``UdpSocket``.

        Raises:
            NetworkError: If ``socket(2)`` fails.

        Example:
            ```mojo
            var s = UdpSocket.unbound()
            var n = s.send_to("hello".as_bytes(), SocketAddr.localhost(5000))
            ```
        """
        from ..net.address import IpAddr, SocketAddr as SA

        var sock = RawSocket(AF_INET, SOCK_DGRAM)
        var unspec = SA(IpAddr.unspecified(), 0)
        return UdpSocket(sock^, unspec)

    # ── Context manager ───────────────────────────────────────────────────────

    fn __enter__(var self) -> UdpSocket:
        """Transfer ownership of ``self`` into the ``with`` block.

        Returns:
            This ``UdpSocket`` (moved).
        """
        return self^

    # ── I/O ───────────────────────────────────────────────────────────────────

    fn send_to(self, data: Span[UInt8], addr: SocketAddr) raises -> Int:
        """Send a datagram to ``addr``.

        Args:
            data: The payload bytes to send.
            addr: The destination socket address.

        Returns:
            Number of bytes sent (equals ``len(data)`` for UDP or raises).

        Raises:
            DatagramTooLarge: If ``len(data) > 65507``.
            NetworkError:     For any OS send error.

        Example:
            ```mojo
            var n = s.send_to("hello".as_bytes(), SocketAddr.localhost(9000))
            ```
        """
        var n = len(data)
        if n > UDP_MAX_PAYLOAD:
            raise DatagramTooLarge(n)

        var sa = _build_sockaddr_in(addr)
        var sent = _sendto(
            self._socket.fd,
            data.unsafe_ptr(),
            c_size_t(n),
            c_int(0),
            sa[0],
            sa[1],
        )
        sa[0].free()

        if sent < 0:
            var e = get_errno()
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                raise Timeout("sendto")
            raise NetworkError(_strerror(e.value) + " (sendto)", Int(e.value))
        return Int(sent)

    fn recv_from(
        mut self, buf: Span[UInt8, _]
    ) raises -> Tuple[Int, SocketAddr]:
        """Receive a datagram, returning the byte count and sender address.

        Blocks until a datagram arrives or a timeout expires.

        Args:
            buf: Destination span; at most ``len(buf)`` bytes are written.
                 For UDP, this should be large enough for the expected
                 datagram (up to 65507 bytes).

        Returns:
            ``(n, sender_addr)`` where ``n`` is the number of bytes received.

        Raises:
            Timeout:     If a recv timeout was set and expired.
            NetworkError: For any other OS error.

        Example:
            ```mojo
            var buf = List[UInt8]()
            buf.resize(1024, 0)
            var (n, sender) = s.recv_from(Span[UInt8](buf))
            print("got", n, "bytes from", String(sender))
            ```
        """
        var peer_buf = stack_allocation[Int(SOCKADDR_IN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_IN_SIZE)):
            (peer_buf + i).init_pointee_copy(0)
        var peer_len = stack_allocation[1, c_uint]()
        peer_len.init_pointee_copy(SOCKADDR_IN_SIZE)

        var got = _recvfrom(
            self._socket.fd,
            buf.unsafe_ptr(),
            c_size_t(len(buf)),
            c_int(0),
            peer_buf,
            peer_len,
        )

        if got < 0:
            var e = get_errno()
            if e == ErrNo.EAGAIN or e == ErrNo.EWOULDBLOCK:
                raise Timeout("recvfrom")
            raise NetworkError(_strerror(e.value) + " (recvfrom)", Int(e.value))

        var sender = _sockaddr_to_socket_addr(peer_buf)
        return Tuple(Int(got), sender)

    # ── Options ───────────────────────────────────────────────────────────────

    fn set_recv_timeout(self, ms: Int) raises:
        """Set a receive timeout via ``SO_RCVTIMEO``.

        After the timeout expires, ``recv_from()`` raises ``Timeout``.

        Args:
            ms: Timeout in milliseconds. 0 disables the timeout.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        self._socket.set_recv_timeout(ms)

    fn set_broadcast(self, enabled: Bool) raises:
        """Enable or disable sending to broadcast addresses.

        Must be enabled before ``send_to()`` can send to ``255.255.255.255``
        or a subnet broadcast (e.g. ``192.168.1.255``).

        Args:
            enabled: ``True`` to allow broadcast sends.

        Raises:
            NetworkError: If ``setsockopt(2)`` fails.
        """
        self._socket._set_bool_opt(SOL_SOCKET, SO_BROADCAST, enabled)

    fn local_addr(self) -> SocketAddr:
        """Return the local address the socket is bound to.

        Returns:
            The bound ``SocketAddr``. Port is 0 for unbound sockets.
        """
        return self._local

    fn close(mut self):
        """Close the socket. Idempotent."""
        self._socket.close()
