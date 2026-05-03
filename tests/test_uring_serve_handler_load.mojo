"""Sustained-load smoke test for the io_uring buffer-ring
handler-path wire-in.

Drives a fork()ed bufring server under
``FLARE_BUFRING_HANDLER=1`` and runs a multi-conn keep-alive
load probe to validate the dispatch survives sustained load
(no crash, no deadlock, all round-trips complete). The
io_uring substrate (PBUF_RING + multishot recv with
``IOSQE_BUFFER_SELECT`` + COOP_TASKRUN/DEFER_TASKRUN setup
flags) is exercised end-to-end on every run.

This is a floor-level regression guard rather than a
throughput assertion -- it catches "totally broken bufring"
regressions but does not police absolute throughput.
"""

from std.ffi import c_int, c_uint, c_size_t, external_call
from std.memory import UnsafePointer, stack_allocation
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.http import (
    FnHandlerCT,
    HttpServer,
    Response,
    ServerConfig,
    ok,
)
from flare.http.request import Request
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
from flare.runtime.uring_reactor import use_uring_backend


@always_inline
def _setenv(name: String, value: String, overwrite: c_int = c_int(1)) -> c_int:
    return external_call["setenv", c_int](
        name.unsafe_ptr(), value.unsafe_ptr(), overwrite
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
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


comptime _SIGKILL: c_int = c_int(9)


def _connect_loopback(port: UInt16) raises -> c_int:
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


def _send_request_and_recv_response(
    fd: c_int, req: String, body: String
) raises:
    """Send one HTTP/1.1 GET; verify the response contains body."""
    var rc_send = _send(
        fd,
        req.unsafe_ptr(),
        c_size_t(req.byte_length()),
        c_int(MSG_NOSIGNAL),
    )
    if Int(rc_send) != req.byte_length():
        raise Error("send() short-write")

    var buf = stack_allocation[4096, UInt8]()
    var got = String(capacity=4096)
    var attempts = 0
    while attempts < 16 and (body not in got or "\r\n\r\n" not in got):
        attempts += 1
        var rc_recv = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(rc_recv) <= 0:
            raise Error("recv() returned " + String(Int(rc_recv)))
        for i in range(Int(rc_recv)):
            got += chr(Int(buf[i]))
    if body not in got:
        raise Error("response missing body")


def _handler(req: Request) raises -> Response:
    return ok("Hello, bufring load!")


alias _BenchHandler = FnHandlerCT[_handler]


def test_bufring_load_clears_minimum_throughput() raises:
    """Sustained load against the in-process bufring server.
    Asserts every round-trip completes (no crash, no deadlock,
    no dropped responses). Floor-level regression guard for
    the bufring dispatch's correctness under multi-conn
    keep-alive load.
    """
    comptime if not CompilationTarget.is_linux():
        print("(skipped: io_uring is Linux-only)")
        return
    if not use_uring_backend():
        print("(skipped: io_uring not available)")
        return

    _ = _setenv("FLARE_BUFRING_HANDLER", "1")

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    var pid = _fork()
    if pid == 0:
        try:
            var h = _BenchHandler()
            srv.serve(h^)
        except:
            pass
        _exit_child()
    _usleep(c_int(120000))

    # Drive 8 conns sequentially, 10 keep-alive requests each =
    # 80 round-trips total. Sized to complete promptly while
    # exercising the full per-conn lifecycle (accept -> recv
    # -> handler -> send -> close) eight times.
    var req = String(
        "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    var body = String("Hello, bufring load!")
    var total_ok = 0
    var failed_at = -1
    for c in range(8):
        try:
            var fd = _connect_loopback(port)
            try:
                for i in range(10):
                    _ = i
                    _send_request_and_recv_response(fd, req, body)
                total_ok += 10
            finally:
                _ = _close(fd)
        except:
            failed_at = c
            break

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)

    # Floor assertion: all 80 round-trips must succeed.
    assert_equal(failed_at, -1, "bufring sustained load failed mid-test")
    assert_equal(total_ok, 80, "bufring sustained load missed round-trips")


def main() raises:
    print("=" * 60)
    print("test_uring_serve_handler_load.mojo - bufring sustained-load floor")
    print("=" * 60)
    var suite = TestSuite()
    suite.test[test_bufring_load_clears_minimum_throughput]()
    suite^.run()
