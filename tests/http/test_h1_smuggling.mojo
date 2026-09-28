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
from flare.http._scan import (
    CONTENT_LENGTH_INVALID,
    find_crlfcrlf,
    parse_content_length,
    scan_content_length,
)
from flare.http.proto.chunked import (
    TE_ABSENT,
    TE_CHUNKED,
    TE_INVALID,
    TE_UNSUPPORTED,
    classify_transfer_coding,
    request_te_framing,
)
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


# ── Content-Length is 1-18 digits and nothing else ─────────────────────────


def test_parse_content_length_accepts_plain_decimals() raises:
    assert_equal(parse_content_length("0"), 0)
    assert_equal(parse_content_length("42"), 42)
    assert_equal(parse_content_length(" \t42 "), 42)
    assert_equal(parse_content_length("999999999999999999"), 999999999999999999)


def test_parse_content_length_rejects_everything_else() raises:
    for bad in [
        "",
        " ",
        "-1",
        "+5",
        "5abc",
        "5 6",
        "0x10",
        "1234567890123456789",
        "18446744073709551606",
    ]:
        assert_equal(
            parse_content_length(bad), CONTENT_LENGTH_INVALID, "accepted " + bad
        )


def test_scan_reports_an_overflowing_value_as_invalid() raises:
    var buf = _b(
        "POST / HTTP/1.1\r\nContent-Length: 18446744073709551606\r\n\r\n"
    )
    assert_equal(
        scan_content_length(buf, find_crlfcrlf(buf, 0)), CONTENT_LENGTH_INVALID
    )


def test_overflowing_content_length_is_refused() raises:
    var got = _exchange(
        "POST /u HTTP/1.1\r\nHost: x\r\n"
        "Content-Length: 18446744073709551606\r\n\r\n"
        "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    )
    assert_false("GET /admin" in got, "smuggled request was served: " + got)
    assert_true("HTTP/1.1 400" in got, "expected 400, got: " + got)


def test_content_length_with_trailing_garbage_is_refused() raises:
    var got = _exchange(
        "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 5abc\r\n\r\nhello"
    )
    assert_true("HTTP/1.1 400" in got, "expected 400, got: " + got)


# ── Transfer-Encoding is a list across every line ──────────────────────────


def test_classify_transfer_coding() raises:
    assert_equal(classify_transfer_coding("chunked"), TE_CHUNKED)
    assert_equal(classify_transfer_coding(" Chunked "), TE_CHUNKED)
    assert_equal(classify_transfer_coding("gzip, chunked"), TE_UNSUPPORTED)
    assert_equal(classify_transfer_coding("gzip,chunked"), TE_UNSUPPORTED)
    assert_equal(classify_transfer_coding("chunked, gzip"), TE_INVALID)
    assert_equal(classify_transfer_coding("chunked,chunked"), TE_INVALID)
    assert_equal(classify_transfer_coding("xchunkedx"), TE_INVALID)
    assert_equal(classify_transfer_coding("identity"), TE_INVALID)
    assert_equal(classify_transfer_coding(""), TE_INVALID)


def _te(raw: String) -> Int:
    var b = _b(raw)
    return request_te_framing(Span[UInt8, _](b), find_crlfcrlf(b, 0))


def test_te_framing_reads_every_line() raises:
    # The first line alone says gzip; the last alone says chunked.
    # Together they are gzip-then-chunked, which flare cannot decode.
    assert_equal(
        _te(
            "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
        ),
        TE_UNSUPPORTED,
    )
    # chunked then identity: chunked is not final, so no length.
    assert_equal(
        _te(
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
            "Transfer-Encoding: identity\r\n\r\n"
        ),
        TE_INVALID,
    )


def test_te_framing_rejects_te_with_content_length() raises:
    assert_equal(
        _te(
            "POST / HTTP/1.1\r\nContent-Length: 5\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
        ),
        TE_INVALID,
    )


def test_te_framing_ignores_lookalike_names() raises:
    assert_equal(
        _te(
            "POST /?transfer-encoding:chunked HTTP/1.1\r\n"
            "X-Transfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"
        ),
        TE_ABSENT,
    )


def test_te_gzip_then_chunked_is_refused_not_smuggled() raises:
    var got = _exchange(
        "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "1d\r\nGET /admin HTTP/1.1\r\nHost: x\r\n\r\n\r\n0\r\n\r\n"
    )
    assert_false("GET /admin" in got, "smuggled request was served: " + got)
    assert_true("HTTP/1.1 501" in got, "expected 501, got: " + got)


def test_te_chunked_then_identity_with_cl_is_refused() raises:
    var inner = "GET /admin HTTP/1.1\r\nHost: x\r\n\r\n"
    var got = _exchange(
        "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
        "Transfer-Encoding: identity\r\nContent-Length: 5\r\n\r\n"
        "0\r\n\r\n"
        + inner
    )
    assert_false("GET /admin" in got, "smuggled request was served: " + got)
    assert_true("HTTP/1.1 400" in got, "expected 400, got: " + got)


# ── Header lines the parser used to skip or misread ────────────────────────


def _parses(raw: String) -> Bool:
    from flare.http._server.parse import _parse_http_request_bytes

    var b = _b(raw)
    try:
        _ = _parse_http_request_bytes(Span[UInt8, _](b))
        return True
    except:
        return False


def test_bare_lf_cannot_end_the_header_block() raises:
    assert_false(
        _parses(
            "GET / HTTP/1.1\r\nHost: a\r\n\nGET /admin HTTP/1.1\r\nX: y\r\n\r\n"
        )
    )


def test_header_line_without_colon_is_rejected() raises:
    assert_false(
        _parses(
            "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding chunked\r\n"
            "Content-Length: 0\r\n\r\n"
        )
    )


def test_empty_header_name_is_rejected() raises:
    assert_false(_parses("GET / HTTP/1.1\r\nHost: a\r\n: x\r\n\r\n"))


def test_well_formed_request_still_parses() raises:
    assert_true(_parses("GET / HTTP/1.1\r\nHost: a\r\nX-A: b\r\n\r\n"))


# ── Repeated fields keep every value; Host may not repeat ──────────────────


def test_duplicate_host_is_rejected() raises:
    assert_false(_parses("GET / HTTP/1.1\r\nHost: good\r\nHost: evil\r\n\r\n"))


def test_repeated_fields_keep_every_value() raises:
    from flare.http._server.parse import _parse_http_request_bytes

    var b = _b(
        "GET / HTTP/1.1\r\nHost: a\r\nCookie: a=1\r\nCookie: b=2\r\n"
        "Accept: x\r\nAccept: y\r\n\r\n"
    )
    var req = _parse_http_request_bytes(Span[UInt8, _](b))
    assert_equal(len(req.headers.get_all("cookie")), 2)
    assert_equal(req.headers.get("accept"), "x")
    var jar = req.cookies()
    assert_equal(jar.get("a"), "1")
    assert_equal(jar.get("b"), "2")


def test_duplicate_host_is_answered_400() raises:
    var got = _exchange(
        "GET / HTTP/1.1\r\nHost: good\r\nHost: evil\r\n"
        "Connection: close\r\n\r\n"
    )
    assert_true("HTTP/1.1 400" in got, "expected 400, got: " + got)


def main() raises:
    print("=" * 60)
    print("test_h1_smuggling.mojo — h1 framing disagreements")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
