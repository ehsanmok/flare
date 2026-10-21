"""Regression: the io_uring buffer-ring loop must give every provided
buffer back, including the ones carried by receive completions whose
connection is already gone.

The bug: the loop skipped a receive completion whose ``conn_id`` was no
longer in ``conns`` *before* returning the provided buffer. A completion
with ``IORING_CQE_F_BUFFER`` has already taken one of the 256 buffers out
of the ring, so every such stale completion shrank the pool by one. After
a few hundred of them the ring was empty, every new receive failed with
``-ENOBUFS`` and the server stopped answering new connections.

Stale completions are common once a peer sends in two writes and the loop
closes after the first: the second write lands after the loop freed the
connection. This test opens that shape of connection (an HTTP/2
prior-knowledge opening that the HTTP/1.1 buffer-ring loop answers and
closes, then one more frame in a separate write) well past the pool size
and checks, after every batch of connections, that a plain GET on a new
connection is still answered.

Run shape: parent runs the clients; a forked child runs
``HttpServer.serve(handler)`` with ``FLARE_BUFRING_HANDLER=1`` and is
SIGKILL'd at the end. A 2 s receive timeout turns a hung server into a
failed assertion instead of a hung test. Linux + io_uring only; skips
cleanly elsewhere.
"""

from std.ffi import c_int, c_size_t, c_uint, external_call
from std.memory import stack_allocation
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.http import ServerConfig, FnHandlerCT, HttpServer, Response, ok
from flare.http.request import Request
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_RCVTIMEO,
    TIMEVAL_SIZE,
    _close,
    _connect,
    _fill_sockaddr_in,
    _recv,
    _send,
    _setsockopt,
    _socket,
    _strerror,
    get_errno,
)
from flare.runtime.uring_reactor import use_uring_backend


def _bufring_config() -> ServerConfig:
    """A config the buffer-ring loop serves: it arms no timers, so a
    config with any timeout set is served by the reactor loop instead."""
    return ServerConfig(
        idle_timeout_ms=0,
        write_timeout_ms=0,
        read_body_timeout_ms=0,
        request_timeout_ms=0,
    )


comptime _ROUNDS: Int = 20
comptime _CONNS_PER_ROUND: Int = 64
"""20 x 64 = 1280 connections, five times the 256-buffer pool. Each round
opens its connections together and sends every first write before any second
write, so the loop is still busy with the first batch when the second writes
land. That is what makes stale completions frequent (hundreds per run), so
an unfixed server runs out of buffers within the first few rounds."""


@always_inline
def _setenv(name: String, value: String, overwrite: c_int = c_int(1)) -> c_int:
    return external_call["setenv", c_int](
        name.unsafe_ptr(), value.unsafe_ptr(), overwrite
    )


def _connect_loopback(port: UInt16) raises -> c_int:
    """Connect to ``127.0.0.1:port`` with a 2 s receive timeout armed.

    Returns ``-1`` if every attempt was refused (the forked server never
    accepted); the caller treats that as a skip.
    """
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
            var tv = stack_allocation[16, UInt8]()
            for i in range(16):
                tv.unsafe_offset(i).unsafe_write(UInt8(0))
            tv.unsafe_offset(0).unsafe_write(UInt8(2))
            _ = _setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, tv, TIMEVAL_SIZE)
            return c
        _ = _close(c)
        usleep(20000)
    return c_int(-1)


def _send_bytes(fd: c_int, data: List[UInt8]):
    """Best-effort send; a peer that already closed is part of the shape
    under test, so errors are ignored."""
    _ = _send(
        fd,
        data.unsafe_ptr(),
        c_size_t(len(data)),
        c_int(MSG_NOSIGNAL),
    )


def _drain(fd: c_int):
    """Read until EOF, error or the receive timeout, then close."""
    var buf = stack_allocation[4096, UInt8]()
    while Int(_recv(fd, buf, c_size_t(4096), c_int(0))) > 0:
        pass
    _ = _close(fd)


def _h2_opening() -> List[UInt8]:
    """Connection preface + empty SETTINGS + a HEADERS frame."""
    var b = List[UInt8]()
    for ch in "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_bytes():
        b.append(ch)
    # SETTINGS (empty), stream 0.
    var settings: List[UInt8] = [0, 0, 0, 4, 0, 0, 0, 0, 0]
    b.extend(settings^)
    # HEADERS, END_HEADERS, stream 1, two indexed fields.
    var headers: List[UInt8] = [0, 0, 2, 1, 4, 0, 0, 0, 1, 0x83, 0x86]
    b.extend(headers^)
    return b^


def _h2_data_frame() -> List[UInt8]:
    """One-byte DATA frame, END_STREAM, stream 1."""
    return [0, 0, 1, 0, 1, 0, 0, 0, 1, UInt8(ord("x"))]


def _get_is_answered(port: UInt16) raises -> Bool:
    """Plain HTTP/1.1 GET on a new connection; True iff it gets a 200."""
    var fd = _connect_loopback(port)
    if Int(fd) < 0:
        return False
    var req = String("GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    var raw = List[UInt8]()
    for ch in req.as_bytes():
        raw.append(ch)
    _send_bytes(fd, raw)
    var buf = stack_allocation[4096, UInt8]()
    var got = String()
    while True:
        var n = Int(_recv(fd, buf, c_size_t(4096), c_int(0)))
        if n <= 0:
            break
        for i in range(n):
            got += chr(Int(buf[unsafe_offset=i]))
    _ = _close(fd)
    return got.startswith("HTTP/1.1 200")


def _handler(req: Request) raises -> Response:
    return ok("hi")


comptime _Handler = FnHandlerCT[_handler]


def test_stale_recv_completions_return_their_buffers() raises:
    """1280 two-write connections in batches of 64, probed after every batch,
    must never starve the buffer ring."""
    comptime if not CompilationTarget.is_linux():
        print("(skipped: io_uring is Linux-only)")
        return
    if not use_uring_backend():
        print(
            "(skipped: kernel lacks io_uring or FLARE_DISABLE_IO_URING is set)"
        )
        return

    _ = _setenv("FLARE_BUFRING_HANDLER", "1")
    var srv = HttpServer.bind(SocketAddr.localhost(0), _bufring_config())
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")

    var pid = fork()
    if pid == 0:
        try:
            var h = _Handler()
            srv.serve(h^)
        except:
            pass
        exit()
    usleep(120000)

    var opening = _h2_opening()
    var frame = _h2_data_frame()
    var skipped = False
    var failed_round = -1
    try:
        if Int(_connect_loopback(port)) < 0:
            skipped = True
        else:
            for r in range(1, _ROUNDS + 1):
                var fds = List[c_int]()
                for _ in range(_CONNS_PER_ROUND):
                    var fd = _connect_loopback(port)
                    if Int(fd) >= 0:
                        fds.append(fd)
                for i in range(len(fds)):
                    _send_bytes(fds[i], opening)
                for i in range(len(fds)):
                    _send_bytes(fds[i], frame)
                for i in range(len(fds)):
                    _drain(fds[i])
                if not _get_is_answered(port):
                    failed_round = r
                    break
    except:
        failed_round = 0

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    if skipped:
        print("(skipped: io_uring bufring serve loop did not accept)")
        return
    assert_equal(
        failed_round,
        -1,
        (
            "a plain GET stopped being answered in this round: the buffer ring"
            " ran out of provided buffers"
        ),
    )


def main() raises:
    print("=" * 60)
    print("test_uring_bufring_buffers.mojo - stale completions keep buffers")
    print("=" * 60)
    var suite = TestSuite()
    suite.test[test_stale_recv_completions_return_their_buffers]()
    suite^.run()
