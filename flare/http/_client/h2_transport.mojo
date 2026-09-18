"""Owned TCP/TLS transport shared by the HTTP and gRPC stream readers."""

from ...io.buf_reader import Readable
from ...runtime.pool import Pool
from ...tcp import TcpStream
from ...tls import TlsStream


struct _H2Transport(Movable, Readable):
    """A live transport: either a cleartext ``TcpStream`` or a TLS
    ``TlsStream``, stored in a heap cell (:class:`Pool`) so the move-only
    stream can be re-borrowed mutably for each read and write.

    Exactly one of ``_tcp_addr`` / ``_tls_addr`` is non-zero. The cell is
    freed -- closing the socket -- by :meth:`close`, or by the destructor
    as a backstop.

    Conforms to :trait:`Readable` so a ``BufReader`` can wrap it without
    caring which of the two wires is underneath.
    """

    var _tcp_addr: Int
    """Heap cell holding the ``TcpStream``, or 0 when this is a TLS
    transport."""

    var _tls_addr: Int
    """Heap cell holding the ``TlsStream``, or 0 when this is a cleartext
    transport."""

    def __init__(out self, tcp_addr: Int, tls_addr: Int):
        """Take ownership of whichever cell address is non-zero.

        Args:
            tcp_addr: Heap cell of a ``TcpStream``, or 0.
            tls_addr: Heap cell of a ``TlsStream``, or 0.
        """
        self._tcp_addr = tcp_addr
        self._tls_addr = tls_addr

    def __deinit__(deinit self):
        Pool[TcpStream].free(self._tcp_addr)
        Pool[TlsStream].free(self._tls_addr)

    @staticmethod
    def from_tcp(var s: TcpStream) raises -> _H2Transport:
        """Wrap a cleartext stream.

        Args:
            s: The connected stream (ownership transferred).

        Returns:
            A transport reading and writing over ``s``.
        """
        return _H2Transport(Pool[TcpStream].alloc_move(s^), 0)

    @staticmethod
    def from_tls(var s: TlsStream) raises -> _H2Transport:
        """Wrap a TLS stream.

        Args:
            s: The handshaken stream (ownership transferred).

        Returns:
            A transport reading and writing over ``s``.
        """
        return _H2Transport(0, Pool[TlsStream].alloc_move(s^))

    def read(mut self, buf: Pointer[UInt8, _], size: Int) raises -> Int:
        """Read up to ``size`` bytes from whichever wire is live.

        Args:
            buf: Destination pointer with at least ``size`` bytes.
            size: Maximum number of bytes to read.

        Returns:
            Bytes written into ``buf``; 0 means EOF.

        Raises:
            NetworkError: On any I/O error.
        """
        if self._tcp_addr != 0:
            return Pool[TcpStream].get_ptr(self._tcp_addr)[].read(buf, size)
        return Pool[TlsStream].get_ptr(self._tls_addr)[].read(buf, size)

    def write_all(self, data: Span[UInt8, _]) raises:
        """Write every byte of ``data``, retrying short writes.

        Args:
            data: The bytes to send.

        Raises:
            NetworkError: On any I/O error.
        """
        if self._tcp_addr != 0:
            Pool[TcpStream].get_ptr(self._tcp_addr)[].write_all(data)
        else:
            Pool[TlsStream].get_ptr(self._tls_addr)[].write_all(data)

    def close(mut self):
        """Close the underlying socket and release the heap cell.

        Idempotent: both addresses are zeroed, so a later destructor run
        is a no-op.
        """
        Pool[TcpStream].free(self._tcp_addr)
        Pool[TlsStream].free(self._tls_addr)
        self._tcp_addr = 0
        self._tls_addr = 0
