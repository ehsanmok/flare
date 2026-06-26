"""gRPC streaming calls over a long-lived HTTP/2 stream (W6).

The unary :class:`flare.grpc.GrpcClient.call` path buffers the whole
response and pops it in one shot. Streaming RPCs instead keep one HTTP/2
stream open and pump length-prefix-message (LPM) frames incrementally:

- **server-streaming**: one request message, then N reply messages
  surfaced one at a time via :meth:`GrpcServerStream.recv` as the
  server's DATA frames arrive (bounded memory -- only one message and
  the partial-frame reassembly buffer are held, never the whole
  response).
- **client-streaming / bidi**: the request stream stays OPEN so the
  caller pumps request messages with :meth:`GrpcBidiStream.send` and
  half-closes with :meth:`GrpcBidiStream.close_send`, then drains reply
  messages with :meth:`GrpcBidiStream.recv`.

Both ride the existing :class:`flare.http2.client.Http2ClientConnection`
driver -- the unary fast path in ``http2/client.mojo`` is untouched;
streaming only uses the additive incremental accessors
(``send_request_open`` / ``drain_body`` / ``stream_ended`` /
``response_headers``).

The transport is held behind :class:`_H2Transport` (a TCP or TLS stream
in a heap cell) so a single concrete stream type serves both h2c and h2
without leaking a transport type parameter through the public API.
"""

from std.collections import List, Optional
from std.memory import Span, UnsafePointer

from ..http2.client import Http2ClientConnection
from ..http2.hpack import HpackHeader
from ..http.url import Url
from ..net import NetworkError
from ..runtime.pool import Pool
from ..tcp import TcpStream
from ..tls import TlsStream
from .framing import decode_grpc_message, encode_grpc_message
from .metadata import GrpcMetadata
from .status import GRPC_STATUS_OK, GRPC_STATUS_UNKNOWN, GrpcStatus

comptime _READ_BUF_SIZE: Int = 16384
"""Per-syscall recv buffer for the streaming read pump (RFC 9113
§6.5.2 default max_frame_size)."""


# ── _H2Transport ──────────────────────────────────────────────────────────


struct _H2Transport(Movable):
    """A live HTTP/2 transport: either a cleartext ``TcpStream`` or a
    TLS ``TlsStream``, stored in a heap cell (:class:`Pool`) so the
    move-only stream can be re-borrowed mutably for each read/write.

    Exactly one of ``_tcp_addr`` / ``_tls_addr`` is non-zero. The cell
    is freed (closing the socket) by :meth:`close` or, as a backstop,
    by the destructor.
    """

    var _tcp_addr: Int
    var _tls_addr: Int

    def __init__(out self, tcp_addr: Int, tls_addr: Int):
        self._tcp_addr = tcp_addr
        self._tls_addr = tls_addr

    def __del__(deinit self):
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
        if self._tcp_addr != 0:
            Pool[TcpStream].get_ptr(self._tcp_addr)[].close()
            Pool[TcpStream].free(self._tcp_addr)
            self._tcp_addr = 0
        if self._tls_addr != 0:
            Pool[TlsStream].get_ptr(self._tls_addr)[].close()
            Pool[TlsStream].free(self._tls_addr)
            self._tls_addr = 0


# ── header helpers ──────────────────────────────────────────────────────────


def _hdr_value(hdrs: List[HpackHeader], name: String) -> String:
    """Return the value of header ``name`` (already lowercased on the
    wire) or the empty string if absent."""
    for i in range(len(hdrs)):
        if hdrs[i].name == name:
            return hdrs[i].value
    return String("")


def _status_from_headers(hdrs: List[HpackHeader]) -> GrpcStatus:
    """Build a :class:`GrpcStatus` from the ``grpc-status`` /
    ``grpc-message`` header (or trailer) values."""
    var code_str = _hdr_value(hdrs, "grpc-status")
    var msg = _hdr_value(hdrs, "grpc-message")
    var code = GRPC_STATUS_UNKNOWN
    if code_str.byte_length() > 0:
        try:
            code = Int(code_str)
        except:
            code = GRPC_STATUS_UNKNOWN
    if code == GRPC_STATUS_OK:
        return GrpcStatus.ok()
    return GrpcStatus.err(code, msg)


# ── GrpcServerStream ────────────────────────────────────────────────────────


struct GrpcServerStream(Movable):
    """A live server-streaming RPC: pull reply messages one at a time.

    Returned by :meth:`flare.grpc.GrpcClient.call_server_streaming`.
    Call :meth:`recv` until it returns ``None`` (end of stream), then
    :meth:`status` for the final ``grpc-status``.
    """

    var _t: _H2Transport
    var _conn: Http2ClientConnection
    var _sid: Int
    var _lpm: List[UInt8]
    """Reassembly buffer of received-but-not-yet-decoded body bytes; a
    partial LPM frame straddling DATA frames lives here until complete."""
    var _ended: Bool

    def __init__(
        out self, var t: _H2Transport, var conn: Http2ClientConnection, sid: Int
    ):
        self._t = t^
        self._conn = conn^
        self._sid = sid
        self._lpm = List[UInt8]()
        self._ended = False

    def _try_decode(mut self) raises -> Optional[List[UInt8]]:
        """Decode one LPM frame from :attr:`_lpm` if a full one is
        buffered, popping the consumed prefix. ``None`` => need more."""
        if len(self._lpm) < 5:
            return None
        var dec = decode_grpc_message(Span[UInt8, _](self._lpm))
        if dec.needs_more:
            return None
        var payload = dec.message.payload.copy()
        var rest = List[UInt8](capacity=len(self._lpm) - dec.consumed)
        for i in range(dec.consumed, len(self._lpm)):
            rest.append(self._lpm[i])
        self._lpm = rest^
        return Optional[List[UInt8]](payload^)

    def _pump(mut self) raises -> Bool:
        """Flush outbound bytes, read one socket batch, feed it. Returns
        ``False`` on a clean EOF (no more bytes will arrive)."""
        var out = self._conn.drain()
        if len(out) > 0:
            self._t.write_all(Span[UInt8, _](out))
        var buf = List[UInt8](capacity=_READ_BUF_SIZE)
        buf.resize(_READ_BUF_SIZE, UInt8(0))
        var n = self._t.read(buf.unsafe_ptr(), _READ_BUF_SIZE)
        if n == 0:
            return False
        self._conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack = self._conn.drain()
        if len(ack) > 0:
            self._t.write_all(Span[UInt8, _](ack))
        return True

    def recv(mut self) raises -> Optional[List[UInt8]]:
        """Return the next reply message payload, or ``None`` once the
        server has ended the stream and no full frame remains.

        Raises:
            NetworkError: if the peer resets the stream or closes the
                connection mid-message.
        """
        while True:
            var msg = self._try_decode()
            if msg:
                return msg^
            var chunk = self._conn.drain_body(self._sid)
            if len(chunk) > 0:
                for i in range(len(chunk)):
                    self._lpm.append(chunk[i])
                continue
            var err = self._conn.stream_error(self._sid)
            if err:
                raise NetworkError(
                    "grpc(server-stream): peer sent RST_STREAM (error code "
                    + String(err.value())
                    + ")"
                )
            if self._conn.stream_ended(self._sid):
                self._ended = True
                return None
            if not self._pump():
                self._ended = True
                # One last drain in case the final DATA arrived with EOF.
                var tail = self._conn.drain_body(self._sid)
                if len(tail) > 0:
                    for i in range(len(tail)):
                        self._lpm.append(tail[i])
                    continue
                if self._conn.stream_ended(self._sid):
                    return None
                raise NetworkError(
                    "grpc(server-stream): connection closed mid-stream"
                )

    def status(mut self) raises -> GrpcStatus:
        """Return the final RPC status (``grpc-status`` /
        ``grpc-message`` trailer). Call after :meth:`recv` has returned
        ``None``. Discards the stream's per-connection state."""
        var hdrs = self._conn.response_headers(self._sid)
        var st = _status_from_headers(hdrs)
        self._conn.discard_stream(self._sid)
        return st^

    def close(mut self):
        """Release the underlying connection (closes the socket)."""
        self._t.close()


# ── GrpcBidiStream ──────────────────────────────────────────────────────────


struct GrpcBidiStream(Movable):
    """A live client-streaming or bidirectional RPC.

    Returned by :meth:`flare.grpc.GrpcClient.call_client_streaming` and
    :meth:`flare.grpc.GrpcClient.call_bidi`. Pump request messages with
    :meth:`send`, half-close the request side with :meth:`close_send`,
    and drain reply messages with :meth:`recv` (then :meth:`status`).
    """

    var _t: _H2Transport
    var _conn: Http2ClientConnection
    var _sid: Int
    var _lpm: List[UInt8]
    var _send_closed: Bool

    def __init__(
        out self, var t: _H2Transport, var conn: Http2ClientConnection, sid: Int
    ):
        self._t = t^
        self._conn = conn^
        self._sid = sid
        self._lpm = List[UInt8]()
        self._send_closed = False

    def send(mut self, message: Span[UInt8, _]) raises:
        """Send one request message (LPM-framed) on the open stream."""
        if self._send_closed:
            raise NetworkError("grpc(client-stream): send after close_send()")
        var frame = List[UInt8]()
        encode_grpc_message(message, frame)
        self._conn.send_data(self._sid, Span[UInt8, _](frame), False)
        var out = self._conn.drain()
        if len(out) > 0:
            self._t.write_all(Span[UInt8, _](out))

    def close_send(mut self) raises:
        """Half-close the request side (empty DATA + END_STREAM). After
        this the caller may only :meth:`recv`."""
        if self._send_closed:
            return
        var empty = List[UInt8]()
        self._conn.send_data(self._sid, Span[UInt8, _](empty), True)
        var out = self._conn.drain()
        if len(out) > 0:
            self._t.write_all(Span[UInt8, _](out))
        self._send_closed = True

    def _try_decode(mut self) raises -> Optional[List[UInt8]]:
        if len(self._lpm) < 5:
            return None
        var dec = decode_grpc_message(Span[UInt8, _](self._lpm))
        if dec.needs_more:
            return None
        var payload = dec.message.payload.copy()
        var rest = List[UInt8](capacity=len(self._lpm) - dec.consumed)
        for i in range(dec.consumed, len(self._lpm)):
            rest.append(self._lpm[i])
        self._lpm = rest^
        return Optional[List[UInt8]](payload^)

    def _pump(mut self) raises -> Bool:
        var out = self._conn.drain()
        if len(out) > 0:
            self._t.write_all(Span[UInt8, _](out))
        var buf = List[UInt8](capacity=_READ_BUF_SIZE)
        buf.resize(_READ_BUF_SIZE, UInt8(0))
        var n = self._t.read(buf.unsafe_ptr(), _READ_BUF_SIZE)
        if n == 0:
            return False
        self._conn.feed(Span[UInt8, _](ptr=buf.unsafe_ptr(), length=n))
        var ack = self._conn.drain()
        if len(ack) > 0:
            self._t.write_all(Span[UInt8, _](ack))
        return True

    def recv(mut self) raises -> Optional[List[UInt8]]:
        """Return the next reply message, or ``None`` at end of stream.

        Servers typically deliver replies only after the request side is
        half-closed; for a true bidi server, replies may interleave with
        :meth:`send` calls."""
        while True:
            var msg = self._try_decode()
            if msg:
                return msg^
            var chunk = self._conn.drain_body(self._sid)
            if len(chunk) > 0:
                for i in range(len(chunk)):
                    self._lpm.append(chunk[i])
                continue
            var err = self._conn.stream_error(self._sid)
            if err:
                raise NetworkError(
                    "grpc(bidi): peer sent RST_STREAM (error code "
                    + String(err.value())
                    + ")"
                )
            if self._conn.stream_ended(self._sid):
                return None
            if not self._pump():
                var tail = self._conn.drain_body(self._sid)
                if len(tail) > 0:
                    for i in range(len(tail)):
                        self._lpm.append(tail[i])
                    continue
                if self._conn.stream_ended(self._sid):
                    return None
                raise NetworkError("grpc(bidi): connection closed mid-stream")

    def status(mut self) raises -> GrpcStatus:
        """Return the final RPC status. Call after :meth:`recv` returns
        ``None``."""
        var hdrs = self._conn.response_headers(self._sid)
        var st = _status_from_headers(hdrs)
        self._conn.discard_stream(self._sid)
        return st^

    def close(mut self):
        self._t.close()


# ── dial helpers (shared by GrpcClient) ─────────────────────────────────────


def _grpc_request_headers(
    metadata: GrpcMetadata,
) raises -> List[HpackHeader]:
    """Build the gRPC request header list (lowercased) for an h2 stream:
    the fixed gRPC headers plus any text metadata entries."""
    var hh = List[HpackHeader]()
    hh.append(HpackHeader("content-type", "application/grpc+proto"))
    hh.append(HpackHeader("te", "trailers"))
    hh.append(HpackHeader("grpc-encoding", "identity"))
    hh.append(HpackHeader("grpc-accept-encoding", "identity"))
    var entries = metadata.entries()
    for i in range(len(entries)):
        if entries[i].is_binary:
            continue
        var key = entries[i].key
        var val = String(unsafe_from_utf8=Span[UInt8, _](entries[i].value))
        hh.append(HpackHeader(key.lower(), val^))
    return hh^


def _authority(u: Url) -> String:
    var a = u.host
    if (u.scheme == "http" and u.port != 80) or (
        u.scheme == "https" and u.port != 443
    ):
        a = a + ":" + String(Int(u.port))
    return a^
