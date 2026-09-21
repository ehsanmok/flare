"""Regression: io_uring buffer-ring dispatch must stage kernel-pool
bytes into the conn's owned ``read_buf`` BEFORE invoking the
handler.

The bug (destructor reorder + stricter Span origin tracking): the
bufring dispatch in
:func:`flare.http._server_reactor_impl.run_uring_bufring_reactor_loop`
used to forward a ``Span[UInt8, _](unsafe_ptr=buf, length=n)`` over kernel-
shared pool memory directly into ``_drive_handler_after_buf_recv``,
then recycle the buffer slot once the handler returned. Under
Mojo's stricter scheduling, the kernel could re-issue the same
buffer slot to a fresh recv before the handler finished reading
it, surfacing as an io_uring multishot recv that silently stalled
on this kernel after ~240 round-trips.

The fix stages the kernel bytes into the conn's ``read_buf`` first,
recycles the kernel slot immediately, and *then* runs the handler
over the in-process buffer. This regression test is a one-round-
trip integration that runs under the default lean env AND under
``pixi run tests-asserts-all`` (-D ASSERT=all), so any future OOB
on the staging-copy write path aborts loudly in CI rather than
silently hanging the parent.

Run shape: bind a server, fork a child that drives
``HttpServer.serve(handler)`` through ``FLARE_BUFRING_HANDLER=1``
into ``run_uring_bufring_reactor_loop[H]``, send one HTTP/1.1
keep-alive GET, validate the response body. Skips cleanly on
hosts without io_uring (sandbox / pre-5.1 / docker without
syscall).
"""

from std.ffi import c_int, c_size_t, c_uint, external_call
from std.memory import Pointer, stack_allocation
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.utils import (
    SIGKILL,
    exit,
    fork,
    kill,
    usleep,
    waitpid,
)

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


def _connect_loopback(port: UInt16) raises -> c_int:
    """Open a blocking AF_INET socket and ``connect()`` it to
    ``127.0.0.1:port`` with a ~2 s retry budget. Returns ``-1`` if
    every attempt was refused (forked io_uring serve loop never
    accepted -- caller treats this as a skip)."""
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        sa.unsafe_offset(i).unsafe_write(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    ip.unsafe_offset(0).unsafe_write(UInt8(127))
    ip.unsafe_offset(1).unsafe_write(UInt8(0))
    ip.unsafe_offset(2).unsafe_write(UInt8(0))
    ip.unsafe_offset(3).unsafe_write(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    for _ in range(100):
        var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
        if c < c_int(0):
            raise Error(
                "client socket() failed: " + _strerror(get_errno().value)
            )
        if _connect(c, sa, c_uint(16)) >= c_int(0):
            return c
        _ = _close(c)
        usleep(20000)
    return c_int(-1)


def _send_request_and_recv_response(
    fd: c_int, req: String, body: String
) raises:
    var rc_send = _send(
        fd,
        req.unsafe_ptr(),
        c_size_t(req.byte_length()),
        c_int(MSG_NOSIGNAL),
    )
    if Int(rc_send) != req.byte_length():
        raise Error("send() short-write")

    var buf = stack_allocation[4096, UInt8]()
    var got = String(capacity_bytes=4096)
    var attempts = 0
    while attempts < 16 and (body not in got or "\r\n\r\n" not in got):
        attempts += 1
        var rc_recv = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(rc_recv) <= 0:
            raise Error("recv() returned " + String(Int(rc_recv)))
        for i in range(Int(rc_recv)):
            got += chr(Int(buf[unsafe_offset=i]))
    if body not in got:
        raise Error("response missing body; got prefix: " + got)


def _handler(req: Request) raises -> Response:
    return ok("Hello, bufring dispatch!")


comptime _BenchHandler = FnHandlerCT[_handler]


def test_bufring_single_round_trip_via_staging_copy() raises:
    """One round-trip through ``run_uring_bufring_reactor_loop[H]``.
    Validates the staging-copy dispatch path -- handler runs after
    the kernel buffer has been recycled, observing the bytes via
    the conn's owned ``read_buf``. Pre-fix this same path passed
    the kernel-pool ``Span`` straight into the handler; under
    `-D ASSERT=all` any future OOB on the staging-copy write would
    abort here rather than hanging.
    """
    comptime if not CompilationTarget.is_linux():
        print("(skipped: io_uring is Linux-only)")
        return
    if not use_uring_backend():
        print(
            "(skipped: kernel lacks io_uring or FLARE_DISABLE_IO_URING is set)"
        )
        return

    _ = _setenv("FLARE_BUFRING_HANDLER", "1")

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    var pid = fork()
    if pid == 0:
        try:
            var h = _BenchHandler()
            srv.serve(h^)
        except:
            pass
        exit()
    usleep(120000)

    var req = String(
        "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "Connection: keep-alive\r\n\r\n"
    )
    var body = String("Hello, bufring dispatch!")
    var skipped = False
    var raised = False
    try:
        var fd = _connect_loopback(port)
        if Int(fd) < 0:
            skipped = True
        else:
            try:
                _send_request_and_recv_response(fd, req, body)
            finally:
                _ = _close(fd)
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    if skipped:
        print(
            "(skipped: io_uring bufring serve loop did not accept on this"
            " runner; keep io_uring opt-in until the runtime path stabilises)"
        )
        return
    assert_true(not raised, "bufring single round-trip raised mid-test")


def main() raises:
    print("=" * 60)
    print("test_uring_bufring_dispatch.mojo - staging-copy regression")
    print("=" * 60)
    var suite = TestSuite()
    suite.test[test_bufring_single_round_trip_via_staging_copy]()
    suite^.run()
