"""TCP listener: a socket bound and listening for incoming connections.

``TcpListener`` wraps a ``RawSocket`` in the listening state. Call
``accept()`` to receive incoming connections as ``TcpStream`` instances.

Design rules enforced here:
- ``SO_REUSEADDR`` is set before every ``bind()`` call.
- ``TCP_NODELAY`` is set on every accepted ``TcpStream``.
- ``accept()`` sets ``TCP_NODELAY`` on the client socket automatically.
"""

from ffi import c_int, c_uint, get_errno, ErrNo
from memory import stack_allocation

from ..net import (
    SocketAddr,
    NetworkError,
    AddressInUse,
)
from ..net.socket import (
    RawSocket,
    AF_INET,
    SOCK_STREAM,
    _build_sockaddr_in,
    _sockaddr_to_socket_addr,
)
from ..net._libc import (
    _bind,
    _listen,
    _accept,
    _strerror,
    SOCKADDR_IN_SIZE,
)
from .stream import TcpStream


struct TcpListener(Movable):
    """A TCP socket in the listening state.

    ``TcpListener`` accepts incoming TCP connections and returns each one
    as a ``TcpStream``. ``SO_REUSEADDR`` is always set before ``bind()``.

    The listener is closed automatically when the struct is destroyed.

    Thread safety:
        Not thread-safe in v0.1.0. Do not call ``accept()`` concurrently.

    Example:
        ```mojo
        from flare.tcp import TcpListener, TcpStream
        from flare.net import SocketAddr

        var listener = TcpListener.bind(SocketAddr.localhost(8080))
        var stream = listener.accept()  # blocks until a client connects
        stream.write_all("welcome".as_bytes())
        ```
    """

    var _socket: RawSocket
    var _local: SocketAddr

    fn __init__(out self, var socket: RawSocket, local: SocketAddr):
        """Wrap an already-bound, listening ``RawSocket``.

        Args:
            socket: Open, listening socket (ownership transferred).
            local:  The address the socket was bound to.

        Safety:
            ``socket`` must already be in the listening state (``listen(2)``
            was called). The caller must not close ``socket`` after this.
        """
        self._socket = socket^
        self._local = local

    fn __moveinit__(out self, deinit take: TcpListener):
        self._socket = take._socket^
        self._local = take._local

    fn __del__(deinit self):
        self._socket.close()

    # ── Factory ───────────────────────────────────────────────────────────────

    @staticmethod
    fn bind(addr: SocketAddr) raises -> TcpListener:
        """Bind a TCP listener to ``addr`` with default options.

        ``SO_REUSEADDR`` is set before binding. The backlog is 128.

        Args:
            addr: The local address to bind (use port 0 for OS-assigned port).

        Returns:
            A ``TcpListener`` ready to call ``accept()``.

        Raises:
            AddressInUse: If the port is already in use.
            NetworkError: For any other OS bind/listen error.

        Example:
            ```mojo
            var l = TcpListener.bind(SocketAddr.localhost(8080))
            ```
        """
        return TcpListener.bind_with_options(addr)

    @staticmethod
    fn bind_with_options(
        addr: SocketAddr,
        backlog: Int = 128,
        reuse_port: Bool = False,
    ) raises -> TcpListener:
        """Bind with explicit backlog and ``SO_REUSEPORT`` control.

        Args:
            addr:       The local address to bind.
            backlog:    Maximum length of the pending-connections queue.
            reuse_port: If ``True``, set ``SO_REUSEPORT`` (useful for
                        multi-process load balancing).

        Returns:
            A ``TcpListener`` ready to call ``accept()``.

        Raises:
            AddressInUse: If the port is already in use.
            NetworkError: For any other OS error.

        Example:
            ```mojo
            var l = TcpListener.bind_with_options(
                SocketAddr.localhost(8080), backlog=1024, reuse_port=True
            )
            ```
        """
        var sock = RawSocket(AF_INET, SOCK_STREAM)

        # SO_REUSEADDR must be set before bind — mandatory by spec
        sock.set_reuse_addr(True)
        if reuse_port:
            sock.set_reuse_port(True)

        var sa = _build_sockaddr_in(addr)
        var rc = _bind(sock.fd, sa[0], sa[1])
        sa[0].free()

        if rc < 0:
            var e = get_errno()
            var s = String(addr)
            if e == ErrNo.EADDRINUSE:
                raise AddressInUse(s, Int(e.value))
            raise NetworkError(
                _strerror(e.value) + " (bind " + s + ")", Int(e.value)
            )

        var lr = _listen(sock.fd, c_int(backlog))
        if lr < 0:
            var e = get_errno()
            raise NetworkError(_strerror(e.value) + " (listen)", Int(e.value))

        # Query the actual local address (handles port 0 → OS-assigned port)
        var local = sock.local_addr()
        return TcpListener(sock^, local)

    # ── Accept ────────────────────────────────────────────────────────────────

    fn accept(self) raises -> TcpStream:
        """Block until an incoming connection arrives and return it.

        Sets ``TCP_NODELAY`` on the accepted socket automatically.

        Returns:
            A connected ``TcpStream`` for the new client.

        Raises:
            NetworkError: If ``accept(2)`` fails.

        Example:
            ```mojo
            while True:
                var client = listener.accept()
                client.write_all("hello".as_bytes())
                client.close()
            ```
        """
        var peer_buf = stack_allocation[Int(SOCKADDR_IN_SIZE), UInt8]()
        for i in range(Int(SOCKADDR_IN_SIZE)):
            (peer_buf + i).init_pointee_copy(0)
        var peer_len = stack_allocation[1, c_uint]()
        peer_len.init_pointee_copy(SOCKADDR_IN_SIZE)

        var client_fd = _accept(self._socket.fd, peer_buf, peer_len)
        if client_fd < 0:
            var e = get_errno()
            raise NetworkError(_strerror(e.value) + " (accept)", Int(e.value))

        var peer = _sockaddr_to_socket_addr(peer_buf)

        # Wrap the accepted fd without calling socket() again
        var client_sock = RawSocket(client_fd, AF_INET, SOCK_STREAM, True)
        client_sock.set_tcp_nodelay(True)

        return TcpStream(client_sock^, peer)

    # ── Introspection ─────────────────────────────────────────────────────────

    fn local_addr(self) -> SocketAddr:
        """Return the local address the listener is bound to.

        Returns:
            The bound ``SocketAddr`` (useful when port 0 was requested).
        """
        return self._local

    fn close(mut self):
        """Close the listening socket. Idempotent."""
        self._socket.close()
