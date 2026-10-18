"""A server at ``ServerConfig.max_connections`` must sleep, not spin.

At the cap the accept loops stop accepting. If the listener stayed
registered with the (level-triggered) reactor, a client waiting in the
accept queue would keep it readable and every ``poll`` would return at
once, pinning a core until a connection closed. The loops pause their
listener at the cap and resume it when a slot frees.

fork(2) topology as in ``test_accept_balance.mojo``: the child runs the
server, the parent runs the clients, reads the child's CPU time from
``/proc`` and SIGKILLs it at the end. For each serving path:

1. Fill the cap with two keep-alive connections and open a third that
   waits.
2. Over one second the server's CPU time stays far below a core.
3. Closing one held connection frees a slot and the waiting client is
   served (the paused listener is resumed).
"""

from std.ffi import c_int, c_size_t, c_uint, external_call
from std.memory import stack_allocation
from std.os import setenv
from std.sys.info import CompilationTarget
from std.testing import assert_equal, assert_true, TestSuite

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpServer, Handler, Request, Response, ok
from flare.http.server import ServerConfig
from flare.http.static_response import precompute_response
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SO_RCVTIMEO,
    SOCK_STREAM,
    SOL_SOCKET,
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

comptime _CAP = 2
comptime _SC_CLK_TCK = 2
comptime _KEEP_ALIVE = (
    "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection:"
    " keep-alive\r\n\r\n"
)


@fieldwise_init
struct _OkHandler(Copyable, Handler):
    var unused: Int

    def serve(self, req: Request) raises -> Response:
        return ok("OK")


# ── Loopback client helpers ────────────────────────────────────────────────


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("client socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa.unsafe_offset(i)).unsafe_write(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip.unsafe_offset(0)).unsafe_write(UInt8(127))
    (ip.unsafe_offset(1)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(2)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(3)).unsafe_write(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_uint(16)) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


def _set_recv_timeout(fd: c_int, seconds: Int) raises:
    """Bound ``recv`` so a stuck server fails the test instead of hanging it."""
    var tv = stack_allocation[16, UInt8]()
    for i in range(16):
        (tv.unsafe_offset(i)).unsafe_write(UInt8(0))
    (tv.unsafe_offset(0)).unsafe_write(UInt8(seconds))
    if _setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, TIMEVAL_SIZE) < c_int(0):
        raise Error("setsockopt(SO_RCVTIMEO) failed")


def _get(fd: c_int) raises:
    """Send one keep-alive request and read the response head."""
    var req = String(_KEEP_ALIVE)
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
    while attempts < 32:
        attempts += 1
        if got.find("\r\n\r\n") >= 0:
            if not got.startswith("HTTP/1.1 200"):
                raise Error("unexpected response: " + got)
            return
        var rc_recv = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(rc_recv) <= 0:
            raise Error("recv() returned " + String(Int(rc_recv)))
        for i in range(Int(rc_recv)):
            got += chr(Int(buf[unsafe_offset=i]))
    raise Error("response incomplete: " + got)


def _cpu_seconds(pid: Int) raises -> Float64:
    """User + system CPU time of process ``pid``, from ``/proc``."""
    var f = open("/proc/" + String(pid) + "/stat", "r")
    var text = f.read()
    f.close()
    # Fields after the parenthesised command name; utime and stime are the
    # 12th and 13th of them.
    var rest = String(text[byte = text.rfind(")") + 2 :])
    var parts = rest.split(" ")
    var ticks = Int(parts[11]) + Int(parts[12])
    var hz = Int(external_call["sysconf", Int](c_int(_SC_CLK_TCK)))
    return Float64(ticks) / Float64(hz)


# ── Server under test ──────────────────────────────────────────────────────


def _start_server(static: Bool) raises -> Tuple[Int, UInt16]:
    var cfg = ServerConfig(idle_timeout_ms=30_000, max_connections=_CAP)
    var srv = HttpServer.bind(SocketAddr.localhost(0), config=cfg^)
    var port = UInt16(srv.local_addr().port)
    assert_true(Int(port) > 0, "server must bind to a positive port")
    var pid = fork()
    if pid == 0:
        try:
            if static:
                # The io_uring static loop has no connection cap; pin the
                # epoll loop, which is the one under test.
                _ = setenv("FLARE_DISABLE_IO_URING", "1")
                var resp = precompute_response(
                    status=200,
                    content_type="text/plain; charset=utf-8",
                    body="OK",
                )
                srv.serve_static(resp^)
            else:
                srv.serve(_OkHandler(0))
        except:
            pass
        exit()
    usleep(300000)
    return (pid, port)


def _scenario(static: Bool) raises:
    var started = _start_server(static)
    var pid = started[0]
    var port = started[1]
    var held = List[c_int]()
    var waiting = c_int(-1)
    var failure = String("")
    var burned = Float64(0)
    try:
        for _ in range(_CAP):
            var fd = _connect_loopback(port)
            held.append(fd)
            _get(fd)
        # The cap is full; this client sits in the accept queue.
        waiting = _connect_loopback(port)
        usleep(300000)
        comptime if CompilationTarget.is_linux():
            var before = _cpu_seconds(pid)
            usleep(1000000)
            burned = _cpu_seconds(pid) - before
        # A slot frees: the waiting client must now be served.
        _ = _close(held[0])
        held[0] = c_int(-1)
        _set_recv_timeout(waiting, 5)
        _get(waiting)
    except e:
        failure = String(e)
    for i in range(len(held)):
        if held[i] >= c_int(0):
            _ = _close(held[i])
    if waiting >= c_int(0):
        _ = _close(waiting)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(failure, "")
    assert_true(
        burned < 0.25,
        "server burned " + String(burned) + " s of CPU in 1 s at the cap",
    )


# ── Tests ──────────────────────────────────────────────────────────────────


def test_handler_server_idles_at_the_cap_and_resumes() raises:
    _scenario(False)


def test_static_server_idles_at_the_cap_and_resumes() raises:
    _scenario(True)


def main() raises:
    print("=" * 60)
    print("test_max_connections_idle.mojo - no busy-loop at max_connections")
    print("=" * 60)
    TestSuite.discover_tests[__functions_in_module()]().run()
