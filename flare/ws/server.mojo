"""WebSocket server: upgrades HTTP connections to WebSocket."""

from .frame import WsFrame, WsOpcode, WsCloseCode
from ..http import Request, Response, Status
from ..tcp import TcpListener, TcpStream
from ..net import SocketAddr


struct WsConnection(Movable):
    """An accepted WebSocket connection (server side).

    Server-side frames MUST NOT be masked (RFC 6455 §5.3).

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _stream: The underlying TCP stream.
        _peer:   The remote socket address.
    """

    var _stream: TcpStream
    var _peer: SocketAddr

    fn __init__(out self, var stream: TcpStream, peer: SocketAddr):
        self._stream = stream^
        self._peer = peer

    fn __moveinit__(out self, deinit take: WsConnection):
        self._stream = take._stream^
        self._peer = take._peer

    fn __del__(deinit self):
        self._stream.close()

    fn send_text(self, msg: String) raises:
        """Send a UTF-8 text message to the client.

        Args:
            msg: The UTF-8 string to send.

        Raises:
            WsError:     If the connection has been closed.
            NetworkError: On I/O failure.
        """
        raise Error("WsConnection.send_text: not yet implemented")

    fn send_binary(self, data: List[UInt8]) raises:
        """Send a binary message to the client.

        Args:
            data: The raw binary payload.

        Raises:
            WsError:     If the connection has been closed.
            NetworkError: On I/O failure.
        """
        raise Error("WsConnection.send_binary: not yet implemented")

    fn recv(self) raises -> WsFrame:
        """Receive the next message from the client.

        Unmasks client frames automatically. Responds to PING with PONG.

        Returns:
            The next complete data frame (TEXT or BINARY).

        Raises:
            WsCloseError:    If the client sends a CLOSE frame.
            WsProtocolError: If the client violates RFC 6455 (e.g. unmasked frame).
            NetworkError:    On I/O failure.
        """
        raise Error("WsConnection.recv: not yet implemented")

    fn close(
        self,
        code: UInt16 = WsCloseCode.NORMAL,
        reason: String = "",
    ) raises:
        """Send CLOSE and wait for the client's CLOSE response.

        Args:
            code:   Close status code (see ``WsCloseCode.*``).
            reason: Optional UTF-8 reason phrase (≤123 bytes).
        """
        raise Error("WsConnection.close: not yet implemented")

    fn peer_addr(self) -> SocketAddr:
        """Return the remote socket address.

        Returns:
            The client's ``SocketAddr``.
        """
        return self._peer


struct WsServer(Movable):
    """A WebSocket server that upgrades incoming HTTP connections.

    Accepts TCP connections, performs the HTTP Upgrade handshake, and
    calls ``handler`` once per established WebSocket connection.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _listener: The bound TCP listener.
    """

    var _listener: TcpListener

    fn __init__(out self, var listener: TcpListener):
        self._listener = listener^

    fn __moveinit__(out self, deinit take: WsServer):
        self._listener = take._listener^

    fn __del__(deinit self):
        self._listener.close()

    @staticmethod
    fn bind(addr: SocketAddr) raises -> WsServer:
        """Bind a WebSocket server on ``addr``.

        Args:
            addr: Local address to accept connections on.

        Returns:
            A ``WsServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return WsServer(listener^)

    fn serve(self, handler: fn(WsConnection) raises -> None) raises:
        """Accept WebSocket connections in a loop.

        Performs the HTTP Upgrade handshake for each accepted TCP connection,
        then calls ``handler`` with the resulting ``WsConnection``.

        Validates the ``Sec-WebSocket-Accept`` header before handing off.

        Args:
            handler: Callback invoked once per successfully upgraded connection.

        Raises:
            NetworkError: On fatal accept-loop errors.
        """
        # TODO:
        # while True:
        #     var stream = self._listener.accept()
        #     var peer = stream.peer_addr()
        #     var req = parse_http_request(stream)
        #     var conn = WsConnection(stream^, peer)
        #     validate_upgrade_request(req)
        #     send_upgrade_response(conn, req)
        #     handler(conn^)
        raise Error("WsServer.serve: not yet implemented")

    fn close(mut self):
        """Stop accepting connections. Idempotent."""
        self._listener.close()
