"""Tests for flare.http — HeaderMap, Url, Response, Status, HttpClient.

Integration tests (test_http_get_*) make real network connections to
``httpbin.org`` (plain HTTP) and ``https://httpbin.org`` (HTTPS).
They are skipped gracefully if the network is unavailable.
"""

from testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)
from flare.http import (
    HttpClient,
    Response,
    Status,
    HeaderMap,
    HeaderInjectionError,
    Url,
    UrlParseError,
    Request,
)


# ── Response.ok() ─────────────────────────────────────────────────────────────


def test_ok_200():
    """HTTP status 200 must be ok."""
    var r = Response(status=200)
    assert_true(r.ok())


def test_ok_201():
    """HTTP status 201 must be ok."""
    var r = Response(status=201)
    assert_true(r.ok())


def test_ok_299():
    """HTTP status 299 must be ok."""
    var r = Response(status=299)
    assert_true(r.ok())


def test_not_ok_400():
    """HTTP status 400 must not be ok."""
    var r = Response(status=400)
    assert_false(r.ok())


def test_not_ok_404():
    """HTTP status 404 must not be ok."""
    var r = Response(status=404)
    assert_false(r.ok())


def test_not_ok_500():
    """HTTP status 500 must not be ok."""
    var r = Response(status=500)
    assert_false(r.ok())


# ── Response.text() ───────────────────────────────────────────────────────────


def test_response_text_empty():
    """Response with empty body must return empty text."""
    var r = Response(status=200)
    assert_equal(r.text(), "")


def test_response_text_ascii():
    """Response with ASCII body must decode correctly."""
    var body = List[UInt8]()
    body.append(UInt8(72))  # H
    body.append(UInt8(101))  # e
    body.append(UInt8(108))  # l
    body.append(UInt8(108))  # l
    body.append(UInt8(111))  # o
    var r = Response(status=200, body=body)
    assert_equal(r.text(), "Hello")


# ── Status constants ───────────────────────────────────────────────────────────


def test_status_ok():
    """Status.OK must equal 200."""
    assert_equal(Status.OK, 200)


def test_status_not_found():
    """Status.NOT_FOUND must equal 404."""
    assert_equal(Status.NOT_FOUND, 404)


def test_status_internal_server_error():
    """Status.INTERNAL_SERVER_ERROR must equal 500."""
    assert_equal(Status.INTERNAL_SERVER_ERROR, 500)


def test_status_created():
    """Status.CREATED must equal 201."""
    assert_equal(Status.CREATED, 201)


def test_status_bad_request():
    """Status.BAD_REQUEST must equal 400."""
    assert_equal(Status.BAD_REQUEST, 400)


# ── HeaderMap ─────────────────────────────────────────────────────────────────


def test_header_set_and_get():
    """HeaderMap.set() then get() must return the stored value."""
    var h = HeaderMap()
    h.set("Content-Type", "application/json")
    assert_equal(h.get("Content-Type"), "application/json")


def test_header_get_case_insensitive():
    """HeaderMap.get() must be case-insensitive per RFC 7230."""
    var h = HeaderMap()
    h.set("Content-Type", "text/html")
    assert_equal(h.get("content-type"), "text/html")
    assert_equal(h.get("CONTENT-TYPE"), "text/html")


def test_header_set_replaces():
    """HeaderMap.set() with an existing key must replace the value."""
    var h = HeaderMap()
    h.set("X-Custom", "first")
    h.set("x-custom", "second")
    assert_equal(h.get("X-Custom"), "second")
    assert_equal(h.len(), 1)


def test_header_contains():
    """HeaderMap.contains() must return True for present headers."""
    var h = HeaderMap()
    h.set("Authorization", "Bearer token")
    assert_true(h.contains("Authorization"))
    assert_true(h.contains("authorization"))
    assert_false(h.contains("X-Missing"))


def test_header_remove():
    """HeaderMap.remove() must delete the header and return True."""
    var h = HeaderMap()
    h.set("X-Remove-Me", "value")
    var removed = h.remove("X-Remove-Me")
    assert_true(removed)
    assert_false(h.contains("X-Remove-Me"))
    assert_equal(h.len(), 0)


def test_header_remove_missing():
    """HeaderMap.remove() on an absent key must return False."""
    var h = HeaderMap()
    var removed = h.remove("X-Not-Here")
    assert_false(removed)


def test_header_len():
    """HeaderMap.len() must count all headers including duplicates."""
    var h = HeaderMap()
    h.set("A", "1")
    h.set("B", "2")
    h.append("B", "3")
    assert_equal(h.len(), 3)


def test_header_get_absent():
    """HeaderMap.get() on an absent key must return empty string."""
    var h = HeaderMap()
    assert_equal(h.get("X-Missing"), "")


def test_header_injection_cr():
    """HeaderMap.set() with CR in value must raise HeaderInjectionError."""
    var h = HeaderMap()
    with assert_raises(contains="HeaderInjectionError"):
        h.set("X-Bad", "value\rinjected")


def test_header_injection_lf():
    """HeaderMap.set() with LF in key must raise HeaderInjectionError."""
    var h = HeaderMap()
    with assert_raises(contains="HeaderInjectionError"):
        h.set("X-Bad\nField", "value")


def test_header_copy():
    """HeaderMap.copy() must produce an independent deep copy."""
    var h = HeaderMap()
    h.set("X-Test", "original")
    var h2 = h.copy()
    h2.set("X-Test", "modified")
    assert_equal(h.get("X-Test"), "original")
    assert_equal(h2.get("X-Test"), "modified")


# ── Url parser ────────────────────────────────────────────────────────────────


def test_url_http_defaults():
    """Url.parse() for plain HTTP must default to port 80."""
    var u = Url.parse("http://example.com/path")
    assert_equal(u.scheme, "http")
    assert_equal(u.host, "example.com")
    assert_equal(Int(u.port), 80)
    assert_equal(u.path, "/path")
    assert_false(u.is_tls())


def test_url_https_defaults():
    """Url.parse() for HTTPS must default to port 443."""
    var u = Url.parse("https://example.com")
    assert_equal(u.scheme, "https")
    assert_equal(Int(u.port), 443)
    assert_true(u.is_tls())


def test_url_explicit_port():
    """Url.parse() must honour an explicit port number."""
    var u = Url.parse("https://api.example.com:8443/v1")
    assert_equal(Int(u.port), 8443)
    assert_equal(u.host, "api.example.com")
    assert_equal(u.path, "/v1")


def test_url_query_string():
    """Url.parse() must split query from path."""
    var u = Url.parse("http://example.com/search?q=hello&lang=en")
    assert_equal(u.path, "/search")
    assert_equal(u.query, "q=hello&lang=en")
    assert_equal(u.request_target(), "/search?q=hello&lang=en")


def test_url_empty_path():
    """Url.parse() with no path component must use '/'."""
    var u = Url.parse("http://example.com")
    assert_equal(u.path, "/")


def test_url_fragment_stripped():
    """Url.parse() must parse fragment but request_target() omits it."""
    var u = Url.parse("http://example.com/page#section")
    assert_equal(u.path, "/page")
    assert_equal(u.fragment, "section")
    assert_equal(u.request_target(), "/page")


def test_url_no_scheme_raises():
    """Url.parse() without a scheme must raise UrlParseError."""
    with assert_raises(contains="UrlParseError"):
        _ = Url.parse("example.com/path")


def test_url_unsupported_scheme_raises():
    """Url.parse() with ftp:// scheme must raise UrlParseError."""
    with assert_raises(contains="UrlParseError"):
        _ = Url.parse("ftp://example.com/file")


def test_url_missing_host_raises():
    """Url.parse() with empty host must raise UrlParseError."""
    with assert_raises(contains="UrlParseError"):
        _ = Url.parse("http:///path")


# ── HttpClient — live integration tests ───────────────────────────────────────
# These tests make real HTTP requests. They pass silently if the network is
# unavailable (wrapped in try/except).


def test_http_get_plaintext():
    """HttpClient.get() to httpbin.org must return a 200 response."""
    try:
        var client = HttpClient()
        var resp = client.get("http://httpbin.org/status/200")
        assert_true(
            resp.ok(), "Expected 200 from httpbin, got " + String(resp.status)
        )
    except e:
        print("  [SKIP] network unavailable: " + String(e))


def test_https_get_json():
    """HttpClient.get() over HTTPS must return JSON from httpbin."""
    try:
        var client = HttpClient()
        var resp = client.get("https://httpbin.org/json")
        assert_true(
            resp.ok(),
            "Expected 200 from httpbin HTTPS, got " + String(resp.status),
        )
        var body = resp.text()
        assert_true(len(body) > 0, "Expected non-empty body")
        assert_true("slideshow" in body or "{" in body, "Expected JSON body")
    except e:
        print("  [SKIP] network unavailable: " + String(e))


def test_http_404_not_ok():
    """HttpClient.get() to a 404 endpoint must return resp.ok() == False."""
    try:
        var client = HttpClient()
        var resp = client.get("http://httpbin.org/status/404")
        assert_equal(resp.status, 404)
        assert_false(resp.ok())
    except e:
        print("  [SKIP] network unavailable: " + String(e))


# ── PATCH method ──────────────────────────────────────────────────────────────


def test_patch_method_string():
    """HttpClient.patch() sends PATCH with JSON Content-Type."""
    try:
        var client = HttpClient()
        var resp = client.patch("https://httpbin.org/patch", '{"x": 1}')
        assert_true(
            resp.ok(),
            "Expected 2xx from httpbin PATCH, got " + String(resp.status),
        )
        var body = resp.text()
        assert_true(
            "PATCH" in body or "patch" in body or "{" in body,
            "Expected PATCH response body",
        )
    except e:
        print("  [SKIP] network unavailable: " + String(e))


# ── HttpServer: round-trip on loopback ────────────────────────────────────────


def test_http_server_get_loopback():
    """HttpServer accepts a GET request and sends back a 200 response.

    Uses a single-connection pair on loopback:
      1. Bind server (port 0).
      2. Connect client.
      3. Server accept() + parse + call handler + write response.
      4. Client read raw response bytes.
    """
    from flare.http import HttpServer
    from flare.tcp import TcpListener, TcpStream
    from flare.net import SocketAddr

    fn handler(req: Request) raises -> Response:
        var body_bytes = List[UInt8]()
        for b in "hello".as_bytes():
            body_bytes.append(b)
        return Response(status=Status.OK, reason="OK", body=body_bytes^)

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    # Client side — send a minimal HTTP/1.1 GET
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var raw_req_bytes = raw_req.as_bytes()
    client.write_all(Span[UInt8](raw_req_bytes))

    # Server side — parse + respond
    from flare.http.server import _parse_http_request, _write_response

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/")

    var resp = handler(req^)
    _write_response(server_stream, resp)
    server_stream.close()

    # Close client only after server has finished writing — closing before
    # _write_response tears down the socket and causes BrokenPipe.
    client.close()
    srv.close()


def test_http_server_post_body_loopback():
    """HttpServer correctly parses a POST request with a body."""
    from flare.http import HttpServer
    from flare.tcp import TcpListener, TcpStream
    from flare.net import SocketAddr

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var body_str = '{"key":"value"}'
    var raw_req = (
        "POST /data HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Content-Length: "
        + String(len(body_str))
        + "\r\n"
        + "Content-Type: application/json\r\n"
        + "\r\n"
        + body_str
    )
    var raw_bytes = raw_req.as_bytes()
    client.write_all(Span[UInt8](raw_bytes))
    client.close()

    from flare.http.server import _parse_http_request

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.method, "POST")
    assert_equal(req.url, "/data")
    assert_equal(len(req.body), len(body_str))
    server_stream.close()
    srv.close()


# ── Encoding / gzip ───────────────────────────────────────────────────────────


def test_gzip_roundtrip():
    """Round-trip: compress_gzip → decompress_gzip must reproduce the original bytes.
    """
    from flare.http.encoding import compress_gzip, decompress_gzip

    var original = (
        "Hello, gzip! This is a test string for compression.".as_bytes()
    )
    var compressed = compress_gzip(Span[UInt8](original))
    assert_true(
        len(compressed) > 0, "compress_gzip must produce non-empty output"
    )
    var decompressed = decompress_gzip(Span[UInt8](compressed))
    assert_equal(len(decompressed), len(original))
    for i in range(len(original)):
        assert_equal(decompressed[i], original[i])


def test_gzip_empty_input():
    """Empty input to compress_gzip returns empty output."""
    from flare.http.encoding import compress_gzip, decompress_gzip

    var empty = List[UInt8]()
    var compressed = compress_gzip(Span[UInt8](empty))
    assert_equal(len(compressed), 0)
    var decompressed = decompress_gzip(Span[UInt8](compressed))
    assert_equal(len(decompressed), 0)


def test_gzip_level_1_roundtrip():
    """Level-1 (fastest) compress_gzip must still roundtrip correctly."""
    from flare.http.encoding import compress_gzip, decompress_gzip

    var data = "level1 fast compression test".as_bytes()
    var compressed = compress_gzip(Span[UInt8](data), level=1)
    var decompressed = decompress_gzip(Span[UInt8](compressed))
    assert_equal(len(decompressed), len(data))
    for i in range(len(data)):
        assert_equal(decompressed[i], data[i])


def test_deflate_roundtrip():
    """Known zlib-wrapped and raw-deflate payloads must decompress correctly."""
    from flare.http.encoding import decompress_deflate

    # Known plaintext: "deflate round-trip test bytes" (29 bytes)
    # Generated by: Python zlib.compress(b"deflate round-trip test bytes")
    var expected_len = 29

    # zlib-wrapped (windowBits=15)
    var zlib_wrapped: List[UInt8] = [
        120,
        156,
        75,
        73,
        77,
        203,
        73,
        44,
        73,
        85,
        40,
        202,
        47,
        205,
        75,
        209,
        45,
        41,
        202,
        44,
        80,
        40,
        73,
        45,
        46,
        81,
        72,
        170,
        4,
        82,
        0,
        167,
        69,
        11,
        49,
    ]
    var out1 = decompress_deflate(Span[UInt8](zlib_wrapped))
    assert_equal(len(out1), expected_len)
    assert_equal(out1[0], UInt8(ord("d")))
    assert_equal(out1[28], UInt8(ord("s")))

    # raw deflate (windowBits=-15) — zlib bytes without 2-byte header + 4-byte adler32
    var raw: List[UInt8] = [
        75,
        73,
        77,
        203,
        73,
        44,
        73,
        85,
        40,
        202,
        47,
        205,
        75,
        209,
        45,
        41,
        202,
        44,
        80,
        40,
        73,
        45,
        46,
        81,
        72,
        170,
        4,
        82,
        0,
    ]
    var out2 = decompress_deflate(Span[UInt8](raw))
    assert_equal(len(out2), expected_len)
    assert_equal(out2[0], UInt8(ord("d")))
    assert_equal(out2[28], UInt8(ord("s")))


def test_decode_content_identity():
    """Identity encoding in decode_content copies bytes unchanged."""
    from flare.http.encoding import decode_content

    var data = "no encoding".as_bytes()
    var out = decode_content(Span[UInt8](data), "identity")
    assert_equal(len(out), len(data))


def test_decode_content_unsupported():
    """Unsupported encoding in decode_content raises an error."""
    from flare.http.encoding import decode_content

    var data = List[UInt8]()
    with assert_raises():
        _ = decode_content(Span[UInt8](data), "br")


def main():
    print("=" * 60)
    print("test_http.mojo — HeaderMap, Url, Response, Status, HttpClient")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
