"""Integration test for the io_uring server-loop dispatch (Track B0
wire-in).

When ``flare.runtime.uring_reactor.use_uring_backend()`` returns True,
``HttpServer.serve_static`` routes through
``run_uring_reactor_loop_static`` (in ``flare.http._server_reactor_impl``)
instead of the epoll/kqueue ``run_reactor_loop_static``. This file
boots a real server on the io_uring path, fires a real HTTP/1.1 GET
over loopback, and asserts the response carries the precomputed body.

Topology (mirrors ``tests/test_tls.mojo`` so we reuse the same
fork(2)-based pattern):

    Parent: TCP client (assertions live here).
    Child:  ``HttpServer.serve_static`` (exits via ``_exit(0)`` after
            the parent sends ``SIGKILL`` post-assertion).

Linux + io_uring-only. On macOS or on Linux kernels that pre-date
io_uring, the lone test is skipped (logged, not asserted) so the
test-server battery still passes everywhere.
"""

from std.testing import assert_equal, assert_true, TestSuite
from std.ffi import c_int, c_uint, c_size_t, c_ssize_t, external_call
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget

from flare.http import HttpServer, precompute_response
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    SOCK_STREAM,
    MSG_NOSIGNAL,
    _socket,
    _connect,
    _send,
    _recv,
    _close,
    _fill_sockaddr_in,
    _strerror,
    get_errno,
)
from flare.runtime.uring_reactor import use_uring_backend


# ── POSIX shims (same shape as test_tls.mojo) ────────────────────────────────


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
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


comptime _SIGKILL: c_int = c_int(9)


# ── Loopback client helper (same shape as
# tests/test_io_uring_multishot_accept.mojo._connect_loopback) ───────────────


def _connect_loopback(port: UInt16) raises -> c_int:
    """Open a blocking AF_INET socket and ``connect()`` it to
    ``127.0.0.1:port``. Returns the connected client fd."""
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("client socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_uint(16)) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


# ── Integration test ─────────────────────────────────────────────────────────


def test_serve_static_io_uring_round_trip() raises:
    """End-to-end: io_uring serve_static returns the precomputed
    response on a real loopback HTTP/1.1 GET.

    The test is a no-op skip on non-Linux hosts and on Linux hosts
    where ``use_uring_backend()`` is False (kernel too old, or the
    contributor set ``FLARE_DISABLE_IO_URING=1`` to A/B-bench the
    epoll path). Skipping rather than raising keeps the test-server
    battery green on every supported platform.
    """
    comptime if not CompilationTarget.is_linux():
        print("(skipped: io_uring is Linux-only)")
        return
    if not use_uring_backend():
        print(
            "(skipped: kernel lacks io_uring or FLARE_DISABLE_IO_URING is set)"
        )
        return

    # Bind in the parent on an ephemeral port. After fork(), both
    # parent and child share the listening fd; the child runs the
    # serve loop, the parent connects in as a client.
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    # Pre-encode the body the child will memcpy on every request.
    var body = "Hello, io_uring!"
    var resp = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body=body,
    )

    var pid = _fork()
    if pid == 0:
        # Child: drive the reactor loop forever. Parent kills us
        # with SIGKILL after asserting on the response. Use
        # ``_exit_child`` rather than ``return`` so we don't run
        # Mojo atexit hooks (same rationale as test_tls.mojo's
        # ``_spawn_echo_server``).
        try:
            srv.serve_static(resp)
        except:
            pass
        _exit_child()
    # Parent: give the child time to enter ``poll(min_complete=1)``.
    # 80ms matches test_tls.mojo's ``_spawn_echo_server`` budget;
    # the io_uring submit + the multishot accept arming together
    # take << 1ms, so this is very conservative.
    _usleep(c_int(80000))

    # Open a TCP client and fire one keep-alive GET.
    var client_fd = _connect_loopback(port)
    try:
        var req = String(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
        var rc_send = _send(
            client_fd,
            req.unsafe_ptr(),
            c_size_t(req.byte_length()),
            c_int(MSG_NOSIGNAL),
        )
        assert_true(
            Int(rc_send) == req.byte_length(),
            "send() must write the full request",
        )

        # Drain the response. The static path writes the entire
        # precomputed buffer in one ``send(2)`` so a single recv
        # is sufficient at this size; we still loop a few times
        # to be robust against TCP segmentation.
        var buf = stack_allocation[4096, UInt8]()
        var got = String(capacity=4096)
        var attempts = 0
        while attempts < 8 and got.byte_length() < 64:
            attempts += 1
            var rc_recv = _recv(client_fd, buf, c_size_t(4096), c_int(0))
            if Int(rc_recv) <= 0:
                break
            for i in range(Int(rc_recv)):
                got += chr(Int(buf[i]))

        # Assertions on the wire form. We don't assert on the exact
        # ``Connection`` header since the static path picks
        # keep-alive vs close based on the request, and either is a
        # correct response — we only need to confirm the server
        # actually served the request (i.e. the io_uring poll →
        # on_readable_static → on_writable dispatch worked
        # end-to-end).
        assert_true(
            got.startswith("HTTP/1.1 200 OK"),
            String("response must start with HTTP/1.1 200 OK; got: ") + got,
        )
        assert_true(
            String("Content-Length: ") + String(body.byte_length()) in got,
            "response must carry the precomputed Content-Length",
        )
        assert_true(
            body in got,
            "response must contain the precomputed body",
        )
    finally:
        _ = _close(client_fd)

    # Tear down the child process. SIGKILL because serve_static is
    # an infinite loop — the parent has no in-band way to flip
    # ``_stopping`` in the child's address space.
    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)


# ── Test runner ──────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_uring_serve_static.mojo — Track B0 wire-in integration")
    print("=" * 60)
    var suite = TestSuite()
    suite.test[test_serve_static_io_uring_round_trip]()
    suite^.run()
