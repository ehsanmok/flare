"""Tests for ``RequestView[origin]``.

The ``parse_request_view`` parser produces a borrowed view of an
HTTP/1.1 request: the URL, headers, and body all point into the
caller-owned buffer rather than allocating ``String`` /
``HeaderMap`` / ``List[UInt8]`` copies. ``into_owned()``
materialises a ``Request`` for handlers that need owned
state.

The reactor's read path doesn't yet use this view directly — that
integration step (a ``ViewHandler`` trait + a parallel
``run_reactor_loop_view``) lands as a follow-up alongside the
streaming-body work in S2.7. Today's reactor still calls
``_parse_http_request_bytes`` and constructs an owned Request.

Covers:

- Happy-path parse of GET / POST requests; method, URL, version,
  headers, body all match.
- Body slice borrows directly into the buffer (verified by
  comparing pointer identity — no copy).
- ``into_owned()`` materialises a Request whose fields are
  decoupled from the source buffer (mutating the buffer after
  ``into_owned`` doesn't affect the owned Request).
- Headers accessor builds a HeaderMapView whose ``get`` matches
  the underlying request.
- Content-Length capping raises.
- URI capping raises.
- Header capping raises.
- Bare-LF terminators (no CR) accepted.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.http import RequestView, parse_request_view, Request, Method
from flare.net import IpAddr, SocketAddr


# ── Happy paths ─────────────────────────────────────────────────────────────


def test_parse_get_no_body() raises:
    var raw = "GET /a?q=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes))
    assert_equal(view.method, "GET")
    assert_equal(String(view.url()), "/a?q=1")
    assert_equal(view.version, "HTTP/1.1")
    assert_equal(String(view.headers().get("Host")), "x")
    assert_equal(len(view.body()), 0)


def test_parse_post_with_body() raises:
    var raw = (
        "POST /create HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
    )
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes))
    assert_equal(view.method, "POST")
    assert_equal(String(view.url()), "/create")
    assert_equal(len(view.body()), 5)
    var b = view.body()
    assert_equal(b[0], UInt8(ord("h")))
    assert_equal(b[1], UInt8(ord("e")))
    assert_equal(b[4], UInt8(ord("o")))


def test_url_borrows_into_buffer() raises:
    """``view.url()`` returns a slice that points into the original
    buffer — no copy, no allocation. We verify by checking the
    underlying byte pointer matches.
    """
    var raw = "GET /borrowed HTTP/1.1\r\n\r\n"
    var bytes_list = List[UInt8](capacity=len(raw))
    bytes_list.resize(len(raw), UInt8(0))
    for i in range(len(raw)):
        bytes_list[i] = raw.as_bytes()[i]
    var view = parse_request_view(Span[UInt8, _](bytes_list))
    var url = view.url()
    var url_ptr = url.unsafe_ptr()
    var buf_ptr = bytes_list.unsafe_ptr()
    # url_ptr must point inside the buffer (offset = "GET ".byte_length()).
    assert_true(Int(url_ptr) >= Int(buf_ptr))
    assert_true(Int(url_ptr) <= Int(buf_ptr) + len(bytes_list))


def test_body_borrows_into_buffer() raises:
    """``view.body()`` is a borrowed slice; pointer must lie inside
    the source buffer."""
    var raw = "POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nABC"
    var bytes_list = List[UInt8](capacity=len(raw))
    bytes_list.resize(len(raw), UInt8(0))
    for i in range(len(raw)):
        bytes_list[i] = raw.as_bytes()[i]
    var view = parse_request_view(Span[UInt8, _](bytes_list))
    var body = view.body()
    assert_equal(len(body), 3)
    assert_true(Int(body.unsafe_ptr()) >= Int(bytes_list.unsafe_ptr()))


# ── Headers ─────────────────────────────────────────────────────────────────


def test_multiple_headers() raises:
    var raw = (
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: test\r\n"
        "Accept: */*\r\n"
        "\r\n"
    )
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes))
    var hv = view.headers()
    assert_equal(hv.len(), 3)
    assert_equal(String(hv.get("host")), "example.com")
    assert_equal(String(hv.get("USER-AGENT")), "test")
    assert_equal(String(hv.get("Accept")), "*/*")


# ── into_owned() ────────────────────────────────────────────────────────────


def test_into_owned_round_trip() raises:
    var raw = "POST /x HTTP/1.1\r\nHost: y\r\nContent-Length: 4\r\n\r\ndata"
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes))
    var owned = view.into_owned()
    assert_equal(owned.method, "POST")
    assert_equal(owned.url, "/x")
    assert_equal(owned.headers.get("Host"), "y")
    assert_equal(len(owned.body), 4)


def test_into_owned_independent_lifetime() raises:
    """Mutating the source buffer after ``into_owned`` doesn't
    affect the owned Request's contents.
    """
    var raw = "GET /target HTTP/1.1\r\nHost: x\r\n\r\n"
    var bytes_list = List[UInt8](capacity=len(raw))
    bytes_list.resize(len(raw), UInt8(0))
    for i in range(len(raw)):
        bytes_list[i] = raw.as_bytes()[i]
    var view = parse_request_view(Span[UInt8, _](bytes_list))
    var owned = view.into_owned()
    # Smash the URL portion of the source buffer.
    bytes_list[5] = ord("Z")
    bytes_list[6] = ord("Z")
    bytes_list[7] = ord("Z")
    # Owned URL still reads "/target".
    assert_equal(owned.url, "/target")


def test_peer_threaded_through() raises:
    var raw = "GET / HTTP/1.1\r\n\r\n"
    var bytes = raw.as_bytes()
    var p = SocketAddr(IpAddr("203.0.113.5", False), UInt16(54321))
    var view = parse_request_view(Span[UInt8, _](bytes), peer=p)
    assert_equal(view.peer.port, UInt16(54321))
    var owned = view.into_owned()
    assert_equal(owned.peer.port, UInt16(54321))


def test_expose_errors_threaded_through() raises:
    var raw = "GET / HTTP/1.1\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes), expose_errors=True)
    assert_true(view.expose_errors)
    var owned = view.into_owned()
    assert_true(owned.expose_errors)


# ── Limit enforcement ──────────────────────────────────────────────────────


def test_uri_too_long_raises() raises:
    var raw = "GET /this-is-too-long HTTP/1.1\r\n\r\n"
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes), max_uri_length=5)


def test_body_too_large_raises() raises:
    var raw = "POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n"
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes), max_body_size=10)


def test_headers_too_large_raises() raises:
    var raw = (
        "GET / HTTP/1.1\r\n"
        "X-A: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
        "\r\n"
    )
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes), max_header_size=10)


# ── Edge cases ──────────────────────────────────────────────────────────────


def test_lf_only_terminators_accepted() raises:
    var raw = "GET / HTTP/1.1\nHost: x\n\n"
    var bytes = raw.as_bytes()
    var view = parse_request_view(Span[UInt8, _](bytes))
    assert_equal(view.method, "GET")
    assert_equal(String(view.headers().get("Host")), "x")


def test_empty_buffer_raises() raises:
    var bytes_list = List[UInt8]()
    with assert_raises():
        _ = parse_request_view(Span[UInt8, _](bytes_list))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
