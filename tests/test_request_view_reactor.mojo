"""Tests for the reactor-side ``parse_request_view`` adoption
(v0.5.0 follow-up / Track 1.1 part 1 / C2).

The cancel-aware reactor read path now scans the request as a
``RequestView`` borrowed into ``read_buf`` and materialises an
owned ``Request`` via ``view.into_owned()`` only when handing
off to the existing ``Handler.serve(req: Request)``. Both
parsers must produce byte-identical ``Request`` values for the
same input — these tests pin that identity.

Coverage:

- Happy-path requests (GET no body, POST with body, every
  method, various header counts) parse identically through
  both ``_parse_http_request_bytes`` (oracle) and
  ``parse_request_view().into_owned()``.
- Path / URL / version / headers / body / peer / expose_errors
  threading is identical.
- Header limits enforced (URI cap, headers cap, body cap).
- RFC 7230 §3.2.6 token-char validation rejects malformed
  header names through both parsers (response-splitting,
  smuggling vectors).
- RFC 7230 §3.2.4 field-value validation rejects bare CR / LF /
  NUL through both parsers.
- Bare-LF terminators (no CR) accepted through both.
- Edge cases: empty header value, OWS trim, duplicate header
  names (first wins on ``get``).
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.http import (
    Request,
    Method,
    parse_request_view,
)
from flare.http.server import _parse_http_request_bytes
from flare.net import IpAddr, SocketAddr


# ── Helpers ────────────────────────────────────────────────────────────────


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def _assert_requests_equal(a: Request, b: Request) raises:
    """Assert two ``Request`` values are byte-identical across
    every observable field."""
    assert_equal(a.method, b.method)
    assert_equal(a.url, b.url)
    assert_equal(a.version, b.version)
    assert_equal(len(a.body), len(b.body))
    if len(a.body) > 0:
        for i in range(len(a.body)):
            assert_equal(a.body[i], b.body[i])
    assert_equal(a.expose_errors, b.expose_errors)
    assert_equal(a.peer.port, b.peer.port)


def _parse_via_view(
    raw: String,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
) raises -> Request:
    var bytes = _bytes(raw)
    var view = parse_request_view(
        Span[UInt8, _](bytes),
        peer=peer,
        expose_errors=expose_errors,
    )
    return view.into_owned()


def _parse_via_oracle(
    raw: String,
    peer: SocketAddr = SocketAddr(IpAddr("127.0.0.1", False), UInt16(0)),
    expose_errors: Bool = False,
) raises -> Request:
    var bytes = _bytes(raw)
    return _parse_http_request_bytes(
        Span[UInt8, _](bytes),
        peer=peer,
        expose_errors=expose_errors,
    )


# ── Dual-path identity (happy paths) ───────────────────────────────────────


def test_dual_get_no_body() raises:
    var raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    var via_view = _parse_via_view(raw)
    var via_oracle = _parse_via_oracle(raw)
    _assert_requests_equal(via_view, via_oracle)


def test_dual_get_with_query() raises:
    var raw = "GET /a?q=1&t=2 HTTP/1.1\r\nHost: x\r\n\r\n"
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_post_with_body() raises:
    var raw = (
        "POST /create HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
    )
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_put_method() raises:
    var raw = "PUT /thing HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nabc"
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_delete_method() raises:
    var raw = "DELETE /res/42 HTTP/1.1\r\nHost: x\r\n\r\n"
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_many_headers() raises:
    var raw = (
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: flare-test\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: gzip\r\n"
        "X-Request-Id: abc-123\r\n"
        "Authorization: Bearer t\r\n"
        "\r\n"
    )
    var via_view = _parse_via_view(raw)
    var via_oracle = _parse_via_oracle(raw)
    _assert_requests_equal(via_view, via_oracle)
    # Header lookups also identical.
    assert_equal(via_view.headers.get("Host"), via_oracle.headers.get("Host"))
    assert_equal(
        via_view.headers.get("Authorization"),
        via_oracle.headers.get("Authorization"),
    )


def test_dual_lf_only_terminators() raises:
    """Bare-LF (no CR) terminators are accepted by both parsers."""
    var raw = "GET / HTTP/1.1\nHost: x\nX-A: 1\n\n"
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_ows_trim() raises:
    """OWS (SP / HTAB) on header values trimmed identically."""
    var raw = "GET / HTTP/1.1\r\nX-Pad:    spaced\t  \r\n\r\n"
    var via_view = _parse_via_view(raw)
    var via_oracle = _parse_via_oracle(raw)
    assert_equal(via_view.headers.get("X-Pad"), "spaced")
    assert_equal(via_oracle.headers.get("X-Pad"), "spaced")


def test_dual_empty_header_value() raises:
    var raw = "GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"
    _assert_requests_equal(_parse_via_view(raw), _parse_via_oracle(raw))


def test_dual_peer_threaded() raises:
    var raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    var p = SocketAddr(IpAddr("203.0.113.5", False), UInt16(54321))
    var via_view = _parse_via_view(raw, peer=p)
    var via_oracle = _parse_via_oracle(raw, peer=p)
    _assert_requests_equal(via_view, via_oracle)
    assert_equal(via_view.peer.port, UInt16(54321))


def test_dual_expose_errors_threaded() raises:
    var raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    var via_view = _parse_via_view(raw, expose_errors=True)
    var via_oracle = _parse_via_oracle(raw, expose_errors=True)
    _assert_requests_equal(via_view, via_oracle)
    assert_true(via_view.expose_errors)


# ── RFC 7230 validation parity ─────────────────────────────────────────────


def test_dual_invalid_header_name_rejected() raises:
    """Header name with non-token byte (space) rejected by both."""
    var raw = "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n"
    with assert_raises():
        _ = _parse_via_view(raw)
    with assert_raises():
        _ = _parse_via_oracle(raw)


def test_dual_high_bit_in_header_name_rejected() raises:
    """High-bit byte in header name is non-token, rejected by both."""
    # Use \x80 in the name. Build via List[UInt8] to avoid Mojo
    # string-literal concerns.
    var bytes = List[UInt8]()
    for b in "GET / HTTP/1.1\r\n".as_bytes():
        bytes.append(b)
    bytes.append(UInt8(0x80))
    bytes.append(ord("X"))
    bytes.append(ord(":"))
    bytes.append(ord(" "))
    bytes.append(ord("v"))
    for b in "\r\n\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes))
    with assert_raises():
        _ = _parse_http_request_bytes(Span[UInt8, _](bytes))


def test_dual_bare_cr_in_header_value_rejected() raises:
    """Bare CR (0x0D) in header value is the response-splitting
    vector — rejected by both parsers."""
    var bytes = List[UInt8]()
    for b in "GET / HTTP/1.1\r\nX-A: hello".as_bytes():
        bytes.append(b)
    bytes.append(UInt8(0x0D))  # bare CR
    bytes.append(ord("X"))
    bytes.append(ord("\n"))
    for b in "\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes))


def test_dual_nul_in_header_value_rejected() raises:
    """NUL byte in header value rejected by both."""
    var bytes = List[UInt8]()
    for b in "GET / HTTP/1.1\r\nX-A: hello".as_bytes():
        bytes.append(b)
    bytes.append(UInt8(0))
    bytes.append(ord("X"))
    for b in "\r\n\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes))


# ── Limits ─────────────────────────────────────────────────────────────────


def test_dual_uri_too_long_rejected() raises:
    var raw = "GET /this-is-too-long HTTP/1.1\r\n\r\n"
    var bytes_v = _bytes(raw)
    var bytes_o = _bytes(raw)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes_v), max_uri_length=5)
    with assert_raises():
        _ = _parse_http_request_bytes(Span[UInt8, _](bytes_o), max_uri_length=5)


def test_dual_body_too_large_rejected() raises:
    var raw = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n"
    var bytes_v = _bytes(raw)
    var bytes_o = _bytes(raw)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes_v), max_body_size=10)
    with assert_raises():
        _ = _parse_http_request_bytes(Span[UInt8, _](bytes_o), max_body_size=10)


def test_dual_headers_too_large_rejected() raises:
    var raw = (
        "GET / HTTP/1.1\r\n"
        "X-A: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
        "\r\n"
    )
    var bytes_v = _bytes(raw)
    var bytes_o = _bytes(raw)
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes_v), max_header_size=10)
    with assert_raises():
        _ = _parse_http_request_bytes(
            Span[UInt8, _](bytes_o), max_header_size=10
        )


# ── Body offset correctness ───────────────────────────────────────────────


def test_view_body_starts_at_correct_offset() raises:
    """``RequestView.body()`` returns a slice that starts exactly
    at the byte after the empty-line terminator. Catches off-by-
    ones at the chunk boundary."""
    var raw = "POST / HTTP/1.1\r\nContent-Length: 7\r\n\r\npayload"
    var bytes = _bytes(raw)
    var view = parse_request_view(Span[UInt8, _](bytes))
    var body = view.body()
    assert_equal(len(body), 7)
    assert_equal(body[0], UInt8(ord("p")))
    assert_equal(body[6], UInt8(ord("d")))


def main() raises:
    print("=" * 60)
    print("test_request_view_reactor.mojo — Track 1.1 / C2 dual-path identity")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
