"""Inbound ``Transfer-Encoding: chunked`` request bodies (v0.10 S2a).

Before this, the reactor sized every request from ``Content-Length``.
A chunked request has none, so ``_scan_content_length`` returned 0, the
request was declared complete the instant its headers landed, and the
handler saw an empty body while the chunk data sat unread in the
socket. Any client that streams an upload -- curl ``-T -``, a browser
``fetch`` with a stream body, most gRPC-over-h1 shims -- silently lost
its payload.

Covers the framing scanner directly (cheap, exhaustive on the corner
cases) and then one end-to-end round trip through a real reactor so the
wiring is proven, not just the helper.
"""

from std.testing import assert_equal, assert_true, TestSuite
from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

from flare.http.proto.chunked import (
    CHUNKED_INCOMPLETE,
    CHUNKED_MALFORMED,
    decode_chunked_body,
    header_says_chunked,
    scan_chunked_end,
)
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


# ── Framing scanner ─────────────────────────────────────────────────────────


def test_scan_finds_end_of_complete_body() raises:
    var buf = _b("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    var end = scan_chunked_end(Span[UInt8, _](buf), 0, 1024)
    assert_equal(end, len(buf))


def test_scan_reports_incomplete_until_terminator() raises:
    # Everything but the terminating chunk.
    var partial = _b("5\r\nhello\r\n")
    assert_equal(
        scan_chunked_end(Span[UInt8, _](partial), 0, 1024), CHUNKED_INCOMPLETE
    )
    # Terminator present but its trailing CRLF has not arrived.
    var almost = _b("5\r\nhello\r\n0\r\n")
    assert_equal(
        scan_chunked_end(Span[UInt8, _](almost), 0, 1024), CHUNKED_INCOMPLETE
    )


def test_scan_rejects_bad_hex_and_missing_size() raises:
    var bad = _b("zz\r\nhello\r\n0\r\n\r\n")
    assert_equal(
        scan_chunked_end(Span[UInt8, _](bad), 0, 1024), CHUNKED_MALFORMED
    )
    var empty_size = _b("\r\nhello\r\n0\r\n\r\n")
    assert_equal(
        scan_chunked_end(Span[UInt8, _](empty_size), 0, 1024),
        CHUNKED_MALFORMED,
    )


def test_scan_enforces_max_body_during_the_walk() raises:
    """The cap must trip before the buffer grows, not after."""
    var buf = _b("FFFF\r\n")
    assert_equal(
        scan_chunked_end(Span[UInt8, _](buf), 0, 16), CHUNKED_MALFORMED
    )


def test_scan_accepts_chunk_extensions_and_trailers() raises:
    var buf = _b("5;ext=1\r\nhello\r\n0\r\nX-Trace: abc\r\n\r\n")
    assert_equal(scan_chunked_end(Span[UInt8, _](buf), 0, 1024), len(buf))


def test_decode_concatenates_chunks() raises:
    var buf = _b("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    var out = List[UInt8]()
    _ = decode_chunked_body(Span[UInt8, _](buf), 0, out)
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](out)), "hello world")


def test_header_scan_detects_chunked() raises:
    var h = _b(
        "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    )
    assert_true(header_says_chunked(Span[UInt8, _](h), len(h)))
    var mixed = _b(
        "POST / HTTP/1.1\r\ntransfer-encoding: gzip, chunked\r\n\r\n"
    )
    assert_true(header_says_chunked(Span[UInt8, _](mixed), len(mixed)))
    var plain = _b("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n")
    assert_true(not header_says_chunked(Span[UInt8, _](plain), len(plain)))


# ── End to end through the reactor ──────────────────────────────────────────


def _echo_len(req: Request) raises -> Response:
    return ok(String(len(req.body)) + ":" + req.text())


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


def test_chunked_upload_reaches_the_handler() raises:
    """A chunked POST arrives whole, in two TCP writes.

    Split across writes on purpose: the first flush is not a complete
    body, so the reactor has to hold the connection open on the chunk
    framing rather than dispatch early.
    """
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_len)
        except:
            pass
        exit()
    usleep(250000)

    var got = String("")
    try:
        var fd = _connect_loopback(port)
        var head = _b(
            "POST /u HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding:"
            " chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n"
        )
        _ = _send(
            fd, head.unsafe_ptr(), c_size_t(len(head)), c_int(MSG_NOSIGNAL)
        )
        usleep(60000)
        var rest = _b("6\r\n world\r\n0\r\n\r\n")
        _ = _send(
            fd, rest.unsafe_ptr(), c_size_t(len(rest)), c_int(MSG_NOSIGNAL)
        )
        var buf = stack_allocation[4096, UInt8]()
        var tries = 0
        while tries < 30 and "11:" not in got:
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
    assert_true(
        "11:hello world" in got,
        "chunked body did not reach the handler intact; got: " + got,
    )


def main() raises:
    print("=" * 60)
    print("test_chunked_request.mojo — inbound chunked bodies")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
