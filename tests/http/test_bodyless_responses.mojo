"""Responses that must not carry content: HEAD, 1xx, 204, 304.

The serializer wrote ``Content-Length: len(body)`` and the body for
every response. A handler that answers HEAD with the GET body (the
common case: one handler for both) therefore put body bytes on the
wire that a keep-alive client, or a proxy sharing this connection
among users, reads as the start of the next response.

Each test pipelines a second request behind the one under test and
checks that the second response starts exactly where the first head
ends.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

from flare.http import HttpServer, Request, Response, ok
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


def _handler(req: Request) raises -> Response:
    if req.url == "/204":
        var r = ok("should not be sent")
        r.status = 204
        return r^
    if req.url == "/304":
        var r = ok("should not be sent either")
        r.status = 304
        return r^
    if req.url == "/declared":
        # A HEAD handler that knows the GET length without a body.
        var r = ok("")
        r.headers.set("Content-Length", "1234")
        return r^
    return ok("hello")


def _exchange(raw: String) raises -> String:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_handler)
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


def _first_head_then(raw_first: String) raises -> Tuple[String, String]:
    """Pipeline ``raw_first`` + a closing GET; return (first head,
    everything after it)."""
    var got = _exchange(
        raw_first + "GET /next HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    var end = got.find("\r\n\r\n")
    assert_true(end > 0, "no response head in: " + got)
    return (String(got[byte = : end + 4]), String(got[byte = end + 4 :]))


def test_head_sends_length_but_no_body() raises:
    var r = _first_head_then("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true("Content-Length: 5\r\n" in r[0], "head: " + r[0])
    assert_true(r[1].startswith("HTTP/1.1 200"), "body leaked: " + r[1])


def test_head_keeps_a_declared_length() raises:
    var r = _first_head_then("HEAD /declared HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true("Content-Length: 1234\r\n" in r[0], "head: " + r[0])
    assert_true(r[1].startswith("HTTP/1.1 200"), "after head: " + r[1])


def test_204_has_no_body_and_no_length() raises:
    var r = _first_head_then("GET /204 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true(r[0].startswith("HTTP/1.1 204"), r[0])
    assert_false("Content-Length" in r[0], "head: " + r[0])
    assert_true(r[1].startswith("HTTP/1.1 200"), "body leaked: " + r[1])


def test_304_has_no_body() raises:
    var r = _first_head_then("GET /304 HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true(r[0].startswith("HTTP/1.1 304"), r[0])
    assert_true(r[1].startswith("HTTP/1.1 200"), "body leaked: " + r[1])


def test_get_still_carries_its_body() raises:
    var r = _first_head_then("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert_true("Content-Length: 5\r\n" in r[0], r[0])
    assert_true(r[1].startswith("helloHTTP/1.1 200"), "after head: " + r[1])


def main() raises:
    print("=" * 60)
    print("test_bodyless_responses.mojo — HEAD / 1xx / 204 / 304")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
