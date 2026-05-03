"""Unit tests for ``_parse_http_request_bytes_minimal`` in
:mod:`flare.http.server`.

The minimal parser skips ``HeaderMap`` allocation entirely
for handlers that don't read headers (TFB plaintext, fixed
health-checks, etc.). The caller passes pre-scanned
``header_end`` + ``content_length`` (which the dispatch
already computed via ``_find_crlfcrlf`` +
``_scan_content_length``), so this parser only does the
request line split + body memcpy.

Test cases lock in the contract:

1. Bench-shape GET request -> method/url/version/empty headers.
2. POST with body -> body bytes copied correctly.
3. Body cap rejection.
4. Empty request line rejection.
5. Malformed request line rejection (no SP).
6. URI cap rejection.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http.server import _parse_http_request_bytes_minimal
from flare.http.headers import HeaderMap
from flare.net import IpAddr, SocketAddr


def _bytes_of(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        out.append(p[i])
    return out^


def test_parses_bench_shape_get_request() raises:
    """The exact wire format wrk2 sends for the TFB plaintext
    bench: GET /plaintext HTTP/1.1 + Host + Connection. Verifies
    the minimal parser extracts method/url/version correctly +
    leaves headers empty."""
    var data = _bytes_of(
        String(
            "GET /plaintext HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Connection: keep-alive\r\n\r\n"
        )
    )
    var span = Span[UInt8, _](data)
    var req = _parse_http_request_bytes_minimal(
        span,
        header_end=len(data),
        content_length=0,
    )
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/plaintext"))
    assert_equal(req.version, String("HTTP/1.1"))
    # The contract: empty headers -- the bench's BenchHandler
    # never reads them, and skipping the alloc is the win.
    # Verify by probing for known-present-in-wire headers
    # (Host, Connection); the minimal parser leaves them out.
    assert_equal(req.headers.get("Host"), String(""))
    assert_equal(req.headers.get("Connection"), String(""))


def test_parses_post_with_body() raises:
    """POST with Content-Length -> body bytes preserved exactly."""
    var raw = String(
        "POST /api/x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello"
    )
    var data = _bytes_of(raw)
    var span = Span[UInt8, _](data)
    # The dispatch passes header_end (= start of body) computed
    # via _find_crlfcrlf; for "...\r\n\r\nhello" the header_end
    # is len("...\r\n\r\n") = total - 5.
    var header_end = len(data) - 5
    var req = _parse_http_request_bytes_minimal(
        span,
        header_end=header_end,
        content_length=5,
    )
    assert_equal(req.method, String("POST"))
    assert_equal(req.url, String("/api/x"))
    assert_equal(len(req.body), 5)
    assert_equal(Int(req.body[0]), ord("h"))
    assert_equal(Int(req.body[1]), ord("e"))
    assert_equal(Int(req.body[2]), ord("l"))
    assert_equal(Int(req.body[3]), ord("l"))
    assert_equal(Int(req.body[4]), ord("o"))


def test_body_size_cap_raises() raises:
    """Content-Length > max_body_size -> Error."""
    var data = _bytes_of(String("PUT /big HTTP/1.1\r\n\r\n"))
    var span = Span[UInt8, _](data)
    var raised = False
    try:
        _ = _parse_http_request_bytes_minimal(
            span,
            header_end=len(data),
            content_length=1024,
            max_body_size=64,
        )
    except:
        raised = True
    assert_true(raised, "expected body-cap to raise")


def test_empty_request_line_raises() raises:
    var data = _bytes_of(String(""))
    var span = Span[UInt8, _](data)
    var raised = False
    try:
        _ = _parse_http_request_bytes_minimal(
            span,
            header_end=0,
            content_length=0,
        )
    except:
        raised = True
    assert_true(raised, "expected empty-request-line to raise")


def test_malformed_request_line_no_space_raises() raises:
    """Request line with no SP between method and URI."""
    var data = _bytes_of(String("GETnoSPACE\r\n\r\n"))
    var span = Span[UInt8, _](data)
    var raised = False
    try:
        _ = _parse_http_request_bytes_minimal(
            span,
            header_end=len(data),
            content_length=0,
        )
    except:
        raised = True
    assert_true(raised, "expected malformed-line to raise")


def test_uri_size_cap_raises() raises:
    var long_path = String("/")
    for _ in range(2000):
        long_path += "a"
    var raw = String("GET ") + long_path + String(" HTTP/1.1\r\n\r\n")
    var data = _bytes_of(raw)
    var span = Span[UInt8, _](data)
    var raised = False
    try:
        _ = _parse_http_request_bytes_minimal(
            span,
            header_end=len(data),
            content_length=0,
            max_uri_length=128,
        )
    except:
        raised = True
    assert_true(raised, "expected URI-cap to raise")


def test_default_version_when_no_second_space() raises:
    """Request line ``GET /``: no version, parser defaults to
    HTTP/1.1 (matches the full parser's behaviour)."""
    var data = _bytes_of(String("GET /\r\n\r\n"))
    var span = Span[UInt8, _](data)
    var req = _parse_http_request_bytes_minimal(
        span,
        header_end=len(data),
        content_length=0,
    )
    assert_equal(req.method, String("GET"))
    assert_equal(req.url, String("/"))
    assert_equal(req.version, String("HTTP/1.1"))


def main() raises:
    var suite = TestSuite()
    suite.test[test_parses_bench_shape_get_request]()
    suite.test[test_parses_post_with_body]()
    suite.test[test_body_size_cap_raises]()
    suite.test[test_empty_request_line_raises]()
    suite.test[test_malformed_request_line_no_space_raises]()
    suite.test[test_uri_size_cap_raises]()
    suite.test[test_default_version_when_no_second_space]()
    suite^.run()
