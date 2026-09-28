"""Reactor connection lifecycle: timers, pipelining, half-close.

These drive a real forked reactor over loopback with raw sockets, so
the timings are generous: the default idle timeout is 500 ms and each
test stays well clear of it where it has to.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

from flare.http import HttpServer, Request, Response, ServerConfig, ok
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    SOL_SOCKET,
    SO_NOSIGPIPE,
    SO_RCVTIMEO,
    TIMEVAL_SIZE,
    _close,
    _connect,
    _fill_sockaddr_in,
    _recv,
    _setsockopt,
    _send,
    _socket,
    _strerror,
    get_errno,
)
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _b(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for c in s.as_bytes():
        out.append(c)
    return out^


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa.unsafe_offset(i)).unsafe_write(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip.unsafe_offset(0)).unsafe_write(UInt8(127))
    (ip.unsafe_offset(1)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(2)).unsafe_write(UInt8(0))
    (ip.unsafe_offset(3)).unsafe_write(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_int(16).cast[DType.uint32]()) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect failed: " + msg)
    # 2 s receive timeout: a server that wrongly keeps the connection
    # open makes the test fail on its assertion instead of hanging.
    var tv = stack_allocation[16, UInt8]()
    for i in range(16):
        (tv.unsafe_offset(i)).unsafe_write(UInt8(0))
    (tv.unsafe_offset(0)).unsafe_write(UInt8(2))
    _ = _setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, tv, TIMEVAL_SIZE)
    # A server that closes early must fail the assertion, not SIGPIPE
    # the test process (macOS has no MSG_NOSIGNAL; Linux passes it).
    if SO_NOSIGPIPE != c_int(0):
        var one = stack_allocation[4, UInt8]()
        (one.unsafe_offset(0)).unsafe_write(UInt8(1))
        for i in range(1, 4):
            (one.unsafe_offset(i)).unsafe_write(UInt8(0))
        _ = _setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, one, 4)
    return c


def _hello(req: Request) raises -> Response:
    if req.url == "/big":
        # Big enough to overflow the socket send buffer, so the write
        # goes partial and completes on later writable edges.
        var body = String(capacity_bytes=4 * 1024 * 1024)
        for _ in range(4 * 1024):
            body += "x" * 1024
        return ok(body)
    return ok("hi " + req.url)


def _spawn(var config: ServerConfig) raises -> Tuple[Int, UInt16]:
    var srv = HttpServer.bind(SocketAddr.localhost(0), config^)
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(250000)
    return (Int(pid), port)


def _stop(pid: Int):
    _ = kill(pid, SIGKILL)
    waitpid(pid)


def _send_str(fd: c_int, s: String):
    var b = _b(s)
    _ = _send(fd, b.unsafe_ptr(), c_size_t(len(b)), c_int(MSG_NOSIGNAL))


def _read_until_close(fd: c_int) -> String:
    # Bounded by the socket's 2 s receive timeout, not a read count:
    # some responses here are megabytes.
    var got = String("")
    var buf = stack_allocation[65536, UInt8]()
    while True:
        var n = _recv(fd, buf, c_size_t(65536), c_int(0))
        if Int(n) <= 0:
            break
        for i in range(Int(n)):
            got += chr(Int(buf[unsafe_offset=i]))
    return got


def _read_some(fd: c_int) -> String:
    var got = String("")
    var buf = stack_allocation[4096, UInt8]()
    var n = _recv(fd, buf, c_size_t(4096), c_int(0))
    for i in range(Int(n) if Int(n) > 0 else 0):
        got += chr(Int(buf[unsafe_offset=i]))
    return got


# ── A closed connection's timer must not fire on its fd's next owner ────────


def test_stale_idle_timer_does_not_kill_the_next_connection() raises:
    var srv = _spawn(ServerConfig())
    var pid = srv[0]
    var port = srv[1]
    var got = String("")
    try:
        # A: one keep-alive request, which arms a 500 ms idle timer on
        # the server, then close. The server frees the fd at EOF.
        var a = _connect_loopback(port)
        _send_str(a, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n")
        _ = _read_some(a)
        _ = _close(a)
        usleep(20000)
        # B reuses the fd number. It trickles its head every 150 ms, so
        # its own idle timer keeps being re-armed, until well past the
        # moment A's timer was due.
        var b = _connect_loopback(port)
        var parts = List[String]()
        parts.append("GET /b HTTP/1.1\r\n")
        parts.append("Host: x\r\n")
        parts.append("X-1: 1\r\n")
        parts.append("X-2: 2\r\n")
        parts.append("X-3: 3\r\n")
        parts.append("Connection: close\r\n\r\n")
        for i in range(len(parts)):
            _send_str(b, parts[i])
            usleep(150000)
        got = _read_until_close(b)
        _ = _close(b)
    except:
        pass
    _stop(pid)
    assert_true("hi /b" in got, "B was closed by A's stale timer: " + got)


# ── Connections that send nothing, or almost nothing ───────────────────────


def test_silent_connection_is_closed_by_the_idle_timer() raises:
    var srv = _spawn(ServerConfig())
    var closed = False
    try:
        var c = _connect_loopback(srv[1])
        # Send nothing. The 500 ms idle timer is armed at accept, so the
        # server closes well inside the client's 2 s receive timeout:
        # recv returns 0 (EOF) rather than -1 (timed out).
        var buf = stack_allocation[64, UInt8]()
        var n = _recv(c, buf, c_size_t(64), c_int(0))
        closed = Int(n) == 0
        _ = _close(c)
    except:
        pass
    _stop(srv[0])
    assert_true(closed, "a connection that never sent a byte stayed open")


def test_trickled_head_hits_the_request_deadline() raises:
    var srv = _spawn(
        ServerConfig(
            idle_timeout_ms=500,
            request_timeout_ms=1200,
            handler_timeout_ms=0,
            read_body_timeout_ms=0,
        )
    )
    var got = String("")
    try:
        var c = _connect_loopback(srv[1])
        _send_str(c, "GET /slow HTTP/1.1\r\n")
        # One header line every 300 ms: inside the idle timeout every
        # time, but the whole head never completes.
        for i in range(8):
            usleep(300000)
            _send_str(c, "X-" + String(i) + ": v\r\n")
        got = _read_until_close(c)
        _ = _close(c)
    except:
        pass
    _stop(srv[0])
    assert_true("HTTP/1.1 408" in got, "trickled head was not cut off: " + got)


# ── Pipelined requests already in the buffer are served ────────────────────


def _count(hay: String, needle: String) -> Int:
    var n = 0
    var i = hay.find(needle)
    while i >= 0:
        n += 1
        i = hay.find(needle, i + needle.byte_length())
    return n


def test_six_pipelined_requests_in_one_segment() raises:
    var srv = _spawn(ServerConfig())
    var got = String("")
    try:
        var c = _connect_loopback(srv[1])
        var raw = String("")
        for i in range(5):
            raw += "GET /p" + String(i) + " HTTP/1.1\r\nHost: x\r\n\r\n"
        raw += "GET /last HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        _send_str(c, raw)
        got = _read_until_close(c)
        _ = _close(c)
    except:
        pass
    _stop(srv[0])
    assert_equal(_count(got, "HTTP/1.1 200"), 6, "got: " + got)
    assert_true("hi /last" in got, "last pipelined request lost")


def test_request_pipelined_behind_a_partial_write() raises:
    var srv = _spawn(ServerConfig(idle_timeout_ms=2000))
    var got = String("")
    try:
        var c = _connect_loopback(srv[1])
        _send_str(
            c,
            (
                "GET /big HTTP/1.1\r\nHost: x\r\n\r\n"
                "GET /after HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            ),
        )
        # Do not read yet: the 4 MB response fills the socket buffers
        # and the server's write goes partial.
        usleep(200000)
        got = _read_until_close(c)
        _ = _close(c)
    except:
        pass
    _stop(srv[0])
    assert_equal(_count(got, "HTTP/1.1 200"), 2)
    assert_true("hi /after" in got, "request behind the big response lost")


def main() raises:
    print("=" * 60)
    print("test_server_lifecycle.mojo — reactor connection lifecycle")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
