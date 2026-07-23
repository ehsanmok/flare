"""Smoke + round-trip tests for ``flare.http._h2_conn_handle.Http2ConnHandle``.

Exercises the reactor-shaped HTTP/2 per-connection state machine
that the unified :class:`flare.http.server.HttpServer` will dispatch
to when the first 24 bytes on an accepted TCP stream match the H2
connection preface.

Each test pairs a real TCP socketpair (one side hand-driven, one
side wrapped in :class:`Http2ConnHandle`) so the
non-blocking ``recv`` / ``send`` syscalls inside the handle exercise
the same code path the live reactor would. The "H2 client" half is
driven via :class:`flare.http2.Http2ClientConnection` so we exchange
real wire-format frames.
"""

from std.collections import Optional
from std.ffi import c_int, c_size_t, c_uint

from flare.utils import usleep
from std.memory import UnsafePointer, stack_allocation
from std.testing import assert_equal, assert_true

from flare.http import Request, Response, ServerConfig, ok, stream_response
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.handler import FnHandler
from flare.net._libc import AF_INET, SOCK_STREAM
from flare.http2 import (
    HpackHeader,
    Http2ClientConnection,
    Http2Config,
)
from flare.http._h2_conn_handle import Http2ConnHandle
from flare.net import SocketAddr
from flare.net._libc import _close, _recv, _send, MSG_NOSIGNAL
from flare.tcp import TcpListener, TcpStream


@fieldwise_init
struct _TaggedSource(ChunkSource, Copyable, Movable):
    """Test chunk source: yields ``count`` chunks of four ``tag`` bytes
    each, then end-of-stream. Distinct tags per concurrent stream let the
    test assert each stream received exactly its own body (no cross-stream
    interleaving corruption)."""

    var remaining: Int
    var tag: UInt8

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.remaining == 0:
            return Optional[List[UInt8]]()
        self.remaining -= 1
        var b = List[UInt8](capacity=4)
        for _ in range(4):
            b.append(self.tag)
        return Optional[List[UInt8]](b^)


def _streaming_by_path(req: Request) raises -> Response:
    """Return a chunked streaming response whose body byte is derived
    from the request path (``/a`` -> 'A', ``/b`` -> 'B', else 'C')."""
    var tag = UInt8(ord("C"))
    if req.url == "/a":
        tag = UInt8(ord("A"))
    elif req.url == "/b":
        tag = UInt8(ord("B"))
    return stream_response(_TaggedSource(remaining=3, tag=tag))


def _set_nonblocking(fd: c_int) raises:
    """Toggle non-blocking on a raw fd via the existing
    :meth:`flare.net.RawSocket.set_nonblocking` helper."""
    from flare.net import RawSocket

    var s = RawSocket(fd, AF_INET, SOCK_STREAM, _wrap=True)
    s.set_nonblocking(True)
    # Detach so the destructor doesn't close the borrowed fd.
    s.fd = c_int(-1)


def _hello(req: Request) raises -> Response:
    return ok("hello h2 reactor")


def test_h2_conn_handle_init_smoke() raises:
    """Smoke: constructing an Http2ConnHandle over an accepted stream
    produces a valid handle with no inbox/outbox content yet."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    var client_fd = client._socket.fd
    client._socket.fd = c_int(-1)
    _ = client^

    var handle = Http2ConnHandle(server^, Http2Config())
    assert_true(Int(handle.fd()) > 0)
    assert_equal(handle.write_pos, 0)
    assert_equal(len(handle.write_buf), 0)
    _ = _close(client_fd)


def test_h2_conn_handle_get_round_trip() raises:
    """End-to-end: client sends preface + GET, Http2ConnHandle dispatches
    handler, response frames flow back to the client."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    var client_stream = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    var client_fd = client_stream._socket.fd
    client_stream._socket.fd = c_int(-1)
    _ = client_stream^
    _set_nonblocking(server._socket.fd)
    _set_nonblocking(client_fd)

    var handle = Http2ConnHandle(server^, Http2Config())

    # Client side: drive an Http2ClientConnection. Send preface +
    # SETTINGS + a GET request.
    var client = Http2ClientConnection()
    var sid = client.next_stream_id()
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    client.send_request(
        sid,
        "GET",
        "http",
        "127.0.0.1",
        "/",
        no_extra,
        Span[UInt8, _](no_body),
    )
    var first = client.drain()
    var n = _send(
        client_fd,
        first.unsafe_ptr(),
        c_size_t(len(first)),
        c_int(MSG_NOSIGNAL),
    )
    assert_true(Int(n) == len(first))

    # Server reactor step: on_readable should pull all the bytes
    # out of the socket, dispatch the handler, queue a response.
    # On non-Linux loopback (macOS in particular) the just-sent
    # bytes may not yet be visible to the server's recv on the
    # very first attempt -- loop with a short usleep until
    # on_readable sees data (mirrors the live reactor's poll
    # cadence).
    var cfg = ServerConfig()
    var h = FnHandler(_hello)
    var step_pump = handle.on_readable(h, cfg)
    var pump_attempts = 0
    while (not step_pump.want_write) and pump_attempts < 50:
        pump_attempts += 1
        usleep(2000)
        step_pump = handle.on_readable(h, cfg)
    assert_true(
        step_pump.want_write,
        "on_readable did not surface a writable step after pumping",
    )
    # Step 2: on_writable flushes the response bytes.
    var step2 = handle.on_writable(cfg)
    assert_true(step2.want_read)

    # Pump the client side to receive the response.
    var got = List[UInt8]()
    var attempts = 0
    while not client.response_ready(sid) and attempts < 50:
        attempts += 1
        var buf = stack_allocation[8192, UInt8]()
        var got_n = _recv(client_fd, buf, c_size_t(8192), c_int(0))
        if Int(got_n) > 0:
            for i in range(Int(got_n)):
                got.append(buf[i])
            client.feed(Span[UInt8, _](got))
            got.clear()
        else:
            # Socket may be EAGAIN; let the server pump again.
            var step_extra = handle.on_writable(cfg)
            _ = step_extra
            var step_extra2 = handle.on_readable(h, cfg)
            _ = step_extra2

    assert_true(client.response_ready(sid), "h2 response did not arrive")
    var resp = client.take_response(sid)
    assert_equal(resp.status, 200)
    var body_str = String(unsafe_from_utf8=Span[UInt8, _](resp.body))
    assert_equal(body_str, "hello h2 reactor")

    _ = _close(client_fd)


def test_h2_conn_handle_concurrent_streaming() raises:
    """Three streaming responses multiplex concurrently on one h2
    connection: the per-stream ``_stream_out`` map pumps each source
    fairly (one chunk per stream per writable edge). Before the
    per-stream refactor only ONE streaming response could be active at a
    time (a second was drained synchronously), so this exercises the new
    concurrent path — each stream must receive exactly its own tagged
    body with no cross-stream corruption."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    var client_stream = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    var client_fd = client_stream._socket.fd
    client_stream._socket.fd = c_int(-1)
    _ = client_stream^
    _set_nonblocking(server._socket.fd)
    _set_nonblocking(client_fd)

    var handle = Http2ConnHandle(server^, Http2Config())
    var client = Http2ClientConnection()

    # Open three concurrent streams (paths /a, /b, /c) in a single
    # outbound buffer so the server sees all three completed requests in
    # one on_readable batch and begins streaming all three at once.
    var no_extra = List[HpackHeader]()
    var no_body = List[UInt8]()
    var sid_a = client.next_stream_id()
    client.send_request(
        sid_a,
        "GET",
        "http",
        "127.0.0.1",
        "/a",
        no_extra,
        Span[UInt8, _](no_body),
    )
    var sid_b = client.next_stream_id()
    client.send_request(
        sid_b,
        "GET",
        "http",
        "127.0.0.1",
        "/b",
        no_extra,
        Span[UInt8, _](no_body),
    )
    var sid_c = client.next_stream_id()
    client.send_request(
        sid_c,
        "GET",
        "http",
        "127.0.0.1",
        "/c",
        no_extra,
        Span[UInt8, _](no_body),
    )
    var first = client.drain()
    var sent = _send(
        client_fd, first.unsafe_ptr(), c_size_t(len(first)), c_int(MSG_NOSIGNAL)
    )
    assert_true(Int(sent) == len(first))

    var cfg = ServerConfig()
    var h = FnHandler(_streaming_by_path)

    var attempts = 0
    while (
        not (
            client.response_ready(sid_a)
            and client.response_ready(sid_b)
            and client.response_ready(sid_c)
        )
    ) and attempts < 400:
        attempts += 1
        _ = handle.on_readable(h, cfg)
        _ = handle.on_writable(cfg)
        var buf = stack_allocation[8192, UInt8]()
        var got_n = _recv(client_fd, buf, c_size_t(8192), c_int(0))
        if Int(got_n) > 0:
            var got = List[UInt8]()
            for i in range(Int(got_n)):
                got.append(buf[i])
            client.feed(Span[UInt8, _](got))
            # Flush any client-side control frames (WINDOW_UPDATE / acks)
            # back to the server so flow control stays healthy.
            var cout = client.drain()
            if len(cout) > 0:
                _ = _send(
                    client_fd,
                    cout.unsafe_ptr(),
                    c_size_t(len(cout)),
                    c_int(MSG_NOSIGNAL),
                )
        else:
            usleep(1000)

    assert_true(client.response_ready(sid_a), "stream /a did not complete")
    assert_true(client.response_ready(sid_b), "stream /b did not complete")
    assert_true(client.response_ready(sid_c), "stream /c did not complete")

    var ra = client.take_response(sid_a)
    var rb = client.take_response(sid_b)
    var rc = client.take_response(sid_c)
    assert_equal(ra.status, 200)
    assert_equal(rb.status, 200)
    assert_equal(rc.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](ra.body)), "AAAAAAAAAAAA"
    )
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](rb.body)), "BBBBBBBBBBBB"
    )
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](rc.body)), "CCCCCCCCCCCC"
    )

    _ = _close(client_fd)


def main() raises:
    test_h2_conn_handle_init_smoke()
    test_h2_conn_handle_get_round_trip()
    test_h2_conn_handle_concurrent_streaming()
    print("test_h2_conn_handle: 3 passed")
