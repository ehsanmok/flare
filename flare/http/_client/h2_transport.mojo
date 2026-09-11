"""Owned TCP/TLS transport shared by the HTTP and gRPC stream readers."""

from ...io.buf_reader import Readable
from ...runtime.pool import Pool
from ...tcp import TcpStream
from ...tls import TlsStream


struct _H2Transport(Movable, Readable):
    var _tcp_addr: Int
    var _tls_addr: Int
    var _is_h2: Bool

    def __init__(out self, tcp_addr: Int, tls_addr: Int):
        self._tcp_addr = tcp_addr
        self._tls_addr = tls_addr
        self._is_h2 = False

    def __deinit__(deinit self):
        Pool[TcpStream].free(self._tcp_addr)
        Pool[TlsStream].free(self._tls_addr)

    @staticmethod
    def from_tcp(var s: TcpStream) raises -> _H2Transport:
        return _H2Transport(Pool[TcpStream].alloc_move(s^), 0)

    @staticmethod
    def from_tls(var s: TlsStream) raises -> _H2Transport:
        return _H2Transport(0, Pool[TlsStream].alloc_move(s^))

    def read(mut self, buf: UnsafePointer[UInt8, _], size: Int) raises -> Int:
        if self._tcp_addr != 0:
            return Pool[TcpStream].get_ptr(self._tcp_addr)[].read(buf, size)
        return Pool[TlsStream].get_ptr(self._tls_addr)[].read(buf, size)

    def write_all(self, data: Span[UInt8, _]) raises:
        if self._tcp_addr != 0:
            Pool[TcpStream].get_ptr(self._tcp_addr)[].write_all(data)
        else:
            Pool[TlsStream].get_ptr(self._tls_addr)[].write_all(data)

    def close(mut self):
        Pool[TcpStream].free(self._tcp_addr)
        Pool[TlsStream].free(self._tls_addr)
        self._tcp_addr = 0
        self._tls_addr = 0
