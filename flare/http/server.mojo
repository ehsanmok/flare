"""HTTP/1.1 server with per-connection handler callbacks."""

from .request import Request
from .response import Response, Status
from ..net import SocketAddr
from ..tcp import TcpListener, TcpStream


struct HttpServer(Movable):
    """A blocking HTTP/1.1 server that calls a handler for each request.

    Each accepted connection is handled in the calling thread (v0.1.0).
    Async and thread-pool models are planned for v0.2.0.

    This type is ``Movable`` but not ``Copyable``.

    Fields:
        _listener:   The bound TCP listener.
        _max_header_size: Maximum bytes for all request headers combined.
        _max_body_size:   Maximum bytes for the request body.

    Example:
        ```mojo
        fn handle(req: Request) raises -> Response:
            return Response(Status.OK, body="hello".as_bytes())

        var srv = HttpServer.bind(SocketAddr.localhost(8080))
        srv.serve(handle)
        ```
    """

    var _listener: TcpListener
    var _max_header_size: Int
    var _max_body_size: Int

    fn __init__(
        out self,
        var listener: TcpListener,
        max_header_size: Int = 8_192,
        max_body_size: Int = 10 * 1024 * 1024,
    ):
        self._listener = listener^
        self._max_header_size = max_header_size
        self._max_body_size = max_body_size

    fn __moveinit__(out self, deinit take: HttpServer):
        self._listener = take._listener^
        self._max_header_size = take._max_header_size
        self._max_body_size = take._max_body_size

    fn __del__(deinit self):
        self._listener.close()

    @staticmethod
    fn bind(addr: SocketAddr) raises -> HttpServer:
        """Bind an HTTP server on ``addr``.

        Args:
            addr: Local address to listen on.

        Returns:
            An ``HttpServer`` ready to call ``serve()``.

        Raises:
            AddressInUse: If the port is already bound.
            NetworkError: For any other OS error.
        """
        var listener = TcpListener.bind(addr)
        return HttpServer(listener^)

    fn serve(self, handler: fn(Request) raises -> Response) raises:
        """Accept connections in a loop, calling ``handler`` for each request.

        Blocks indefinitely. Call ``close()`` from another thread (or
        SIGTERM) to break the accept loop.

        Args:
            handler: Callback invoked once per parsed HTTP request.

        Raises:
            NetworkError: If the accept loop encounters a fatal error.
        """
        # TODO:
        # while True:
        #     var stream = self._listener.accept()
        #     var req = parse_request(stream, self._max_header_size, self._max_body_size)
        #     var resp = handler(req)
        #     write_response(stream, resp)
        raise Error("HttpServer.serve: not yet implemented")

    fn close(mut self):
        """Stop accepting new connections. Idempotent."""
        self._listener.close()
