"""HTTP/1.1 request-framing disagreements (request smuggling).

The reactor decides where a request ends before the parser runs, and
hands the parser ``read_buf[:body_total]``. Any byte the two read
differently is left in the buffer and served as the next request -- a
request a front proxy never saw. Each test here sends one raw byte
sequence to a real reactor and checks how many requests the handler
was asked to serve, and with what body.

The handler echoes ``<method> <target> <body-length>`` so a smuggled
request is visible in the reply stream.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

from flare.http import HttpServer, Request, Response, ok
from flare.http._scan import find_crlfcrlf, scan_content_length
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
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _b(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for c in s.as_bytes():
        out.append(c)
    return out^


def _echo(req: Request) raises -> Response:
    return ok(req.method + " " + req.url + " " + String(len(req.body)))


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
    return c


def _exchange(raw: String) raises -> String:
    """Send ``raw`` to a fresh reactor and return everything it wrote
    back until it closed the connection (idle timeout or close)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo)
        except:
            pass
        exit()
    usleep(250000)
    var got = String("")
    try:
        var fd = _connect_loopback(port)
        var bytes = _b(raw)
        _ = _send(
            fd, bytes.unsafe_ptr(), c_size_t(len(bytes)), c_int(MSG_NOSIGNAL)
        )
        var buf = stack_allocation[4096, UInt8]()
        var tries = 0
        while tries < 50:
            tries += 1
            var n = _recv(fd, buf, c_size_t(4096), c_int(0))
            if Int(n) <= 0:
                break
            for i in range(Int(n)):
                got += chr(Int(buf[unsafe_offset=i]))
        _ = _close(fd)
    except:
        pass
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return got


def _count(hay: String, needle: String) -> Int:
    var n = 0
    var i = hay.find(needle)
    while i >= 0:
        n += 1
        i = hay.find(needle, i + needle.byte_length())
    return n


# ── Content-Length must be a header, not a substring ────────────────────────


def test_scan_ignores_content_length_in_request_target() raises:
    var buf = _b(
        "POST /?content-length:0 HTTP/1.1\r\nContent-Length: 7\r\n\r\n"
    )
    assert_equal(scan_content_length(buf, find_crlfcrlf(buf, 0)), 7)


def test_scan_ignores_content_length_inside_other_names() raises:
    var buf = _b(
        "POST / HTTP/1.1\r\nX-Content-Length: 0\r\nContent-Length: 9\r\n\r\n"
    )
    assert_equal(scan_content_length(buf, find_crlfcrlf(buf, 0)), 9)


def test_scan_ignores_content_length_inside_values() raises:
    var buf = _b(
        "GET / HTTP/1.1\r\nReferer: http://x/?content-length: 5000\r\n\r\n"
    )
    assert_equal(scan_content_length(buf, find_crlfcrlf(buf, 0)), 0)


def test_content_length_in_target_does_not_smuggle() raises:
    """The request-target carries ``content-length:0``; the real header
    says 36. The 36 body bytes are a complete GET, and must stay a body.
    """
    var inner = "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    var raw = (
        "POST /?content-length:0 HTTP/1.1\r\nHost: x\r\nContent-Length: "
        + String(inner.byte_length())
        + "\r\n\r\n"
        + inner
    )
    var got = _exchange(raw)
    assert_false("GET /admin" in got, "smuggled request was served: " + got)
    assert_true(
        "POST /?content-length:0 " + String(inner.byte_length()) in got,
        "outer request lost its body: " + got,
    )


def test_x_content_length_does_not_smuggle() raises:
    var inner = "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    var raw = (
        "POST /p HTTP/1.1\r\nHost: x\r\nX-Content-Length: 0\r\n"
        + "Content-Length: "
        + String(inner.byte_length())
        + "\r\n\r\n"
        + inner
    )
    var got = _exchange(raw)
    assert_false("GET /admin" in got, "smuggled request was served: " + got)
    assert_equal(_count(got, "HTTP/1.1 200"), 1)


def main() raises:
    print("=" * 60)
    print("test_h1_smuggling.mojo — h1 framing disagreements")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
