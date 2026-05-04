"""Unified HttpServer auto-dispatch test (HTTP/1.1 + HTTP/2 on the same port).

The whole point of the unified reactor loop in
:mod:`flare.http._unified_reactor_impl` is that one
:class:`flare.http.server.HttpServer` accepting on a single port
auto-detects the wire protocol per connection (preface peek for
cleartext) and dispatches each connection to the right per-conn
state machine -- without the application handler knowing or
caring which wire is talking to it. These tests verify exactly
that:

- An HTTP/1.1 client (raw TCP request bytes) round-trips through
  the same handler.
- An HTTP/2 client (``flare.http2.Http2Client``) round-trips
  through the same handler over the same port.

Topology mirrors the existing tests/test_h2_server_handler.mojo:
fork a child running ``HttpServer.serve(handler)``, drive both
client variants from the parent, SIGKILL on test-end.
"""

from std.ffi import c_int, c_size_t, external_call
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true

from flare.http import HttpServer, Request, Response, ok
from flare.http2 import Http2Client
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    _close,
    _connect,
    _fill_sockaddr_in,
    _recv,
    _send,
    _socket,
    _strerror,
    get_errno,
)


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


comptime _SIGKILL: c_int = c_int(9)


def _connect_loopback(port: UInt16) raises -> c_int:
    """Open a blocking loopback TCP connection and return the fd."""
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_int(16).cast[DType.uint32]()) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


def _hello(req: Request) raises -> Response:
    return ok("hello unified")


def test_unified_server_http1_request() raises:
    """HTTP/1.1 client over the unified server gets the handler's
    response unchanged."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var raised = False
    var got = String("")
    try:
        var fd = _connect_loopback(port)
        var req = String(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        var rb = req.as_bytes()
        var sent = _send(
            fd,
            rb.unsafe_ptr(),
            c_size_t(req.byte_length()),
            c_int(MSG_NOSIGNAL),
        )
        if Int(sent) != req.byte_length():
            raise Error("short send")
        var buf = stack_allocation[4096, UInt8]()
        var attempts = 0
        while attempts < 20 and "hello unified" not in got:
            attempts += 1
            var n = _recv(fd, buf, c_size_t(4096), c_int(0))
            if Int(n) <= 0:
                break
            for i in range(Int(n)):
                got += chr(Int(buf[i]))
        _ = _close(fd)
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "HTTP/1.1 round-trip raised")
    assert_true(
        "hello unified" in got, "HTTP/1.1 response missing body; got: " + got
    )


def test_unified_server_http2_request() raises:
    """HTTP/2 client over the unified server (same port) gets the
    same handler's response."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got_status = -1
    var got_body = String("")
    var raised = False
    try:
        with Http2Client() as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "HTTP/2 round-trip raised")
    assert_equal(got_status, 200)
    assert_equal(got_body, "hello unified")


def _by_path_dispatcher(req: Request) raises -> Response:
    """Tiny in-test path router proving the same handler dispatch
    logic runs for both wires (HTTP/1.1 and HTTP/2). The dispatch
    is intentionally inline (not via flare.http.Router) so the
    test stays portable across the Router's evolving Copyable /
    multi-worker constraints."""
    if req.url == "/a":
        return ok("route-a-body")
    if req.url == "/b":
        return ok("route-b-body")
    return Response(status=404, reason="Not Found")


def test_unified_server_router_dispatch_both_protocols() raises:
    """A path-dispatching handler serves the same routes over both
    wire protocols on the same port."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_by_path_dispatcher)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    # HTTP/2: hit /a then /b on the same client.
    var base = String("http://127.0.0.1:") + String(Int(port))
    var got_a = String("")
    var got_b = String("")
    try:
        with Http2Client(base_url=base) as c:
            got_a = c.get("/a").text()
            got_b = c.get("/b").text()
    except:
        pass

    # HTTP/1.1: independent connection on the same port for /a.
    var got_a_h1 = String("")
    try:
        var fd = _connect_loopback(port)
        var req = String(
            "GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        var rb = req.as_bytes()
        _ = _send(
            fd,
            rb.unsafe_ptr(),
            c_size_t(req.byte_length()),
            c_int(MSG_NOSIGNAL),
        )
        var buf = stack_allocation[4096, UInt8]()
        var attempts = 0
        while attempts < 20 and "route-a-body" not in got_a_h1:
            attempts += 1
            var n = _recv(fd, buf, c_size_t(4096), c_int(0))
            if Int(n) <= 0:
                break
            for i in range(Int(n)):
                got_a_h1 += chr(Int(buf[i]))
        _ = _close(fd)
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_equal(got_a, "route-a-body")
    assert_equal(got_b, "route-b-body")
    assert_true("route-a-body" in got_a_h1)


def main() raises:
    test_unified_server_http1_request()
    test_unified_server_http2_request()
    test_unified_server_router_dispatch_both_protocols()
    print("test_unified_http_server: 3 passed")
