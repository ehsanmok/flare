"""Smoke + round-trip tests for ``flare.http._h2_conn_handle.H2ConnHandle``.

Exercises the reactor-shaped HTTP/2 per-connection state machine
that the unified :class:`flare.http.server.HttpServer` will dispatch
to when the first 24 bytes on an accepted TCP stream match the H2
connection preface.

Each test pairs a real TCP socketpair (one side hand-driven, one
side wrapped in :class:`H2ConnHandle`) so the
non-blocking ``recv`` / ``send`` syscalls inside the handle exercise
the same code path the live reactor would. The "H2 client" half is
driven via :class:`flare.http2.Http2ClientConnection` so we exchange
real wire-format frames.
"""

from std.ffi import c_int, c_uint, c_size_t, external_call
from std.memory import UnsafePointer, stack_allocation
from std.testing import assert_equal, assert_true

from flare.http import Request, Response, ServerConfig, ok
from flare.http.handler import FnHandler
from flare.net._libc import AF_INET, SOCK_STREAM
from flare.http2 import (
    HpackHeader,
    Http2ClientConnection,
    Http2Config,
)
from flare.http._h2_conn_handle import H2ConnHandle
from flare.net import SocketAddr
from flare.net._libc import _close, _recv, _send, MSG_NOSIGNAL
from flare.tcp import TcpListener, TcpStream


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
    """Smoke: constructing an H2ConnHandle over an accepted stream
    produces a valid handle with no inbox/outbox content yet."""
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server = listener.accept()
    var client_fd = client._socket.fd
    client._socket.fd = c_int(-1)
    _ = client^

    var handle = H2ConnHandle(server^, Http2Config())
    assert_true(Int(handle.fd()) > 0)
    assert_equal(handle.write_pos, 0)
    assert_equal(len(handle.write_buf), 0)
    _ = _close(client_fd)


def test_h2_conn_handle_get_round_trip() raises:
    """End-to-end: client sends preface + GET, H2ConnHandle dispatches
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

    var handle = H2ConnHandle(server^, Http2Config())

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
        _ = external_call["usleep", c_int](c_int(2000))
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


def main() raises:
    test_h2_conn_handle_init_smoke()
    test_h2_conn_handle_get_round_trip()
    print("test_h2_conn_handle: 2 passed")
