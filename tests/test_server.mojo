"""Tests for flare.http.server — buffered reads, keep-alive, error handling, response helpers.

Covers:
- Buffered request parsing (chunk reads vs byte-at-a-time)
- HTTP/1.1 keep-alive (multiple requests on one connection)
- HTTP/1.0 close-by-default
- Request body parsing (Content-Length)
- Request version parsing
- Large header / body / URI rejection
- Token-level header validation (RFC 7230)
- Malformed request handling (400 response)
- Response serialisation (single-buffer write)
- Response helpers (ok, ok_json, bad_request, not_found, internal_error, redirect)
- ServerConfig options (timeouts, limits)
- Internal helpers (_find_crlfcrlf, _scan_content_length, _is_token_char)
- Cookie parsing and serialisation
- Request.json() and Request.text()
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)
from flare.http import (
    HttpServer,
    Response,
    Status,
    HeaderMap,
    Request,
    Method,
    ServerConfig,
    ok,
    ok_json,
    bad_request,
    not_found,
    internal_error,
    redirect,
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
)
from flare.http.server import (
    _find_crlfcrlf,
    _scan_content_length,
    _parse_http_request_bytes,
    _parse_http_request,
    _write_response,
    _write_response_buffered,
    _status_reason,
    _is_token_char,
    _is_field_value_char,
)
from flare.tcp import TcpListener, TcpStream
from flare.net import SocketAddr, IpAddr


# ── _find_crlfcrlf tests ─────────────────────────────────────────────────────


def test_find_crlfcrlf_simple() raises:
    var data: List[UInt8] = [71, 69, 84, 32, 47, 13, 10, 13, 10]
    assert_equal(_find_crlfcrlf(data, 0), 9)


def test_find_crlfcrlf_with_headers() raises:
    var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\nbody"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var pos = _find_crlfcrlf(data, 0)
    assert_true(pos > 0)
    assert_equal(pos, 35)


def test_find_crlfcrlf_not_found() raises:
    var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    assert_equal(_find_crlfcrlf(data, 0), -1)


def test_find_crlfcrlf_empty() raises:
    var data = List[UInt8]()
    assert_equal(_find_crlfcrlf(data, 0), -1)


def test_find_crlfcrlf_too_short() raises:
    var data: List[UInt8] = [13, 10, 13]
    assert_equal(_find_crlfcrlf(data, 0), -1)


def test_find_crlfcrlf_at_start() raises:
    var data: List[UInt8] = [13, 10, 13, 10, 72, 101]
    assert_equal(_find_crlfcrlf(data, 0), 4)


def test_find_crlfcrlf_with_offset() raises:
    var raw = "first\r\n\r\nsecond\r\n\r\nthird"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var pos1 = _find_crlfcrlf(data, 0)
    assert_equal(pos1, 9)
    var pos2 = _find_crlfcrlf(data, pos1)
    assert_equal(pos2, 19)


# ── _scan_content_length tests ────────────────────────────────────────────────


def test_scan_content_length_present() raises:
    var raw = "GET / HTTP/1.1\r\nContent-Length: 42\r\nHost: x\r\n\r\n"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var header_end = _find_crlfcrlf(data, 0)
    assert_equal(_scan_content_length(data, header_end), 42)


def test_scan_content_length_absent() raises:
    var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var header_end = _find_crlfcrlf(data, 0)
    assert_equal(_scan_content_length(data, header_end), 0)


def test_scan_content_length_case_insensitive() raises:
    var raw = "GET / HTTP/1.1\r\ncontent-length: 100\r\n\r\n"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var header_end = _find_crlfcrlf(data, 0)
    assert_equal(_scan_content_length(data, header_end), 100)


def test_scan_content_length_mixed_case() raises:
    var raw = "GET / HTTP/1.1\r\nCONTENT-LENGTH: 256\r\n\r\n"
    var data = List[UInt8]()
    for b in raw.as_bytes():
        data.append(b)
    var header_end = _find_crlfcrlf(data, 0)
    assert_equal(_scan_content_length(data, header_end), 256)


# ── Token validation tests ────────────────────────────────────────────────────


def test_is_token_char_alpha() raises:
    assert_true(_is_token_char(UInt8(65)))  # A
    assert_true(_is_token_char(UInt8(90)))  # Z
    assert_true(_is_token_char(UInt8(97)))  # a
    assert_true(_is_token_char(UInt8(122)))  # z


def test_is_token_char_digit() raises:
    assert_true(_is_token_char(UInt8(48)))  # 0
    assert_true(_is_token_char(UInt8(57)))  # 9


def test_is_token_char_special() raises:
    assert_true(_is_token_char(UInt8(33)))  # !
    assert_true(_is_token_char(UInt8(45)))  # -
    assert_true(_is_token_char(UInt8(95)))  # _
    assert_true(_is_token_char(UInt8(126)))  # ~


def test_is_token_char_rejects_control() raises:
    assert_false(_is_token_char(UInt8(0)))  # NUL
    assert_false(_is_token_char(UInt8(10)))  # LF
    assert_false(_is_token_char(UInt8(13)))  # CR
    assert_false(_is_token_char(UInt8(32)))  # SP
    assert_false(_is_token_char(UInt8(127)))  # DEL


def test_is_token_char_rejects_separator() raises:
    assert_false(_is_token_char(UInt8(40)))  # (
    assert_false(_is_token_char(UInt8(41)))  # )
    assert_false(_is_token_char(UInt8(58)))  # :
    assert_false(_is_token_char(UInt8(64)))  # @


def test_is_field_value_char() raises:
    assert_true(_is_field_value_char(UInt8(32)))  # SP
    assert_true(_is_field_value_char(UInt8(9)))  # HTAB
    assert_true(_is_field_value_char(UInt8(65)))  # A
    assert_true(_is_field_value_char(UInt8(200)))  # obs-text
    assert_false(_is_field_value_char(UInt8(0)))  # NUL
    assert_false(_is_field_value_char(UInt8(10)))  # LF
    assert_false(_is_field_value_char(UInt8(13)))  # CR


# ── _parse_http_request_bytes tests ───────────────────────────────────────────


def test_parse_bytes_get() raises:
    var raw = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/index.html")
    assert_equal(req.headers.get("Host"), "example.com")
    assert_equal(len(req.body), 0)


def test_parse_bytes_post_with_body() raises:
    var body = '{"key":"value"}'
    var raw = (
        "POST /api HTTP/1.1\r\n"
        + "Host: api.example.com\r\n"
        + "Content-Type: application/json\r\n"
        + "Content-Length: "
        + String(body.byte_length())
        + "\r\n"
        + "\r\n"
        + body
    )
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "POST")
    assert_equal(req.url, "/api")
    assert_equal(len(req.body), body.byte_length())


def test_parse_bytes_version_11() raises:
    var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.version, "HTTP/1.1")


def test_parse_bytes_version_10() raises:
    var raw = "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.version, "HTTP/1.0")


def test_parse_bytes_uri_too_long() raises:
    var long_path = "/" + "a" * 100
    var raw = "GET " + long_path + " HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    with assert_raises(contains="URI exceeds limit"):
        _ = _parse_http_request_bytes(Span[UInt8, _](data), max_uri_length=50)


def test_parse_bytes_empty_raises() raises:
    var data = List[UInt8]()
    with assert_raises(contains="empty request line"):
        _ = _parse_http_request_bytes(Span[UInt8, _](data))


def test_parse_bytes_malformed_no_space() raises:
    var raw = "GETHTTP/1.1\r\n\r\n"
    var data = raw.as_bytes()
    with assert_raises(contains="malformed request line"):
        _ = _parse_http_request_bytes(Span[UInt8, _](data))


def test_parse_bytes_body_exceeds_limit() raises:
    var body = "x" * 100
    var raw = (
        "POST /data HTTP/1.1\r\n" + "Content-Length: 100\r\n" + "\r\n" + body
    )
    var data = raw.as_bytes()
    with assert_raises(contains="body exceeds limit"):
        _ = _parse_http_request_bytes(Span[UInt8, _](data), max_body_size=50)


def test_parse_bytes_invalid_header_name() raises:
    var raw = "GET / HTTP/1.1\r\nBad Header: value\r\n\r\n"
    var data = raw.as_bytes()
    with assert_raises(contains="invalid character in header name"):
        _ = _parse_http_request_bytes(Span[UInt8, _](data))


def test_parse_bytes_multiple_headers() raises:
    var raw = (
        "GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Accept: text/html\r\n"
        + "User-Agent: flare-test\r\n"
        + "Connection: keep-alive\r\n"
        + "\r\n"
    )
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.headers.get("Accept"), "text/html")
    assert_equal(req.headers.get("User-Agent"), "flare-test")
    assert_equal(req.headers.get("Connection"), "keep-alive")


def test_parse_bytes_path_with_query() raises:
    var raw = "GET /search?q=hello&page=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.url, "/search?q=hello&page=1")


def test_parse_bytes_head_method() raises:
    var raw = "HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "HEAD")


def test_parse_bytes_options_method() raises:
    var raw = "OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "OPTIONS")
    assert_equal(req.url, "*")


# ── Status reason phrases ─────────────────────────────────────────────────────


def test_status_reason_200() raises:
    assert_equal(_status_reason(200), "OK")


def test_status_reason_404() raises:
    assert_equal(_status_reason(404), "Not Found")


def test_status_reason_413() raises:
    assert_equal(_status_reason(413), "Content Too Large")


def test_status_reason_414() raises:
    assert_equal(_status_reason(414), "URI Too Long")


def test_status_reason_500() raises:
    assert_equal(_status_reason(500), "Internal Server Error")


def test_status_reason_unknown() raises:
    assert_equal(_status_reason(999), "Unknown")


# ── ServerConfig ──────────────────────────────────────────────────────────────


def test_server_config_defaults() raises:
    var cfg = ServerConfig()
    assert_equal(cfg.read_buffer_size, 8192)
    assert_equal(cfg.max_header_size, 8192)
    assert_equal(cfg.max_body_size, 10 * 1024 * 1024)
    assert_equal(cfg.max_uri_length, 8192)
    assert_true(cfg.keep_alive)
    assert_equal(cfg.max_keepalive_requests, 100)
    assert_equal(cfg.idle_timeout_ms, 500)
    assert_equal(cfg.write_timeout_ms, 5000)


def test_server_config_custom() raises:
    var cfg = ServerConfig(
        read_buffer_size=4096,
        max_header_size=4096,
        max_body_size=1024,
        max_uri_length=512,
        keep_alive=False,
        max_keepalive_requests=10,
        idle_timeout_ms=1000,
        write_timeout_ms=2000,
    )
    assert_equal(cfg.read_buffer_size, 4096)
    assert_equal(cfg.max_body_size, 1024)
    assert_equal(cfg.max_uri_length, 512)
    assert_false(cfg.keep_alive)
    assert_equal(cfg.idle_timeout_ms, 1000)
    assert_equal(cfg.write_timeout_ms, 2000)


# ── Response helpers ──────────────────────────────────────────────────────────


def test_ok_empty() raises:
    var resp = ok()
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 0)


def test_ok_with_body() raises:
    var resp = ok("hello world")
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 11)
    assert_equal(resp.headers.get("Content-Type"), "text/plain; charset=utf-8")


def test_ok_json_helper() raises:
    var resp = ok_json('{"key": "value"}')
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("Content-Type"), "application/json")
    assert_true(len(resp.body) > 0)


def test_bad_request_helper() raises:
    var resp = bad_request()
    assert_equal(resp.status, 400)


def test_bad_request_custom_msg() raises:
    var resp = bad_request("missing header")
    assert_equal(resp.status, 400)
    assert_true(len(resp.body) > 0)


def test_not_found_helper() raises:
    var resp = not_found()
    assert_equal(resp.status, 404)


def test_not_found_with_path() raises:
    var resp = not_found("/missing")
    assert_equal(resp.status, 404)


def test_internal_error_helper() raises:
    var resp = internal_error()
    assert_equal(resp.status, 500)


def test_redirect_default() raises:
    var resp = redirect("https://example.com")
    assert_equal(resp.status, 302)
    assert_equal(resp.headers.get("Location"), "https://example.com")


def test_redirect_301() raises:
    var resp = redirect("/new-location", 301)
    assert_equal(resp.status, 301)
    assert_equal(resp.headers.get("Location"), "/new-location")


# ── Request.json() and Request.text() ─────────────────────────────────────────


def test_request_text_empty() raises:
    var req = Request(method="GET", url="/")
    assert_equal(req.text(), "")


def test_request_text_with_body() raises:
    var body_str = "hello body"
    var body = List[UInt8]()
    for b in body_str.as_bytes():
        body.append(b)
    var req = Request(method="POST", url="/", body=body^)
    assert_equal(req.text(), "hello body")


def test_request_json() raises:
    var body_str = '{"key": "value"}'
    var body = List[UInt8]()
    for b in body_str.as_bytes():
        body.append(b)
    var req = Request(method="POST", url="/", body=body^)
    var val = req.json()
    assert_equal(val["key"].string_value(), "value")


def test_request_content_length() raises:
    var req = Request(method="GET", url="/")
    req.headers.set("Content-Length", "42")
    assert_equal(req.content_length(), 42)


def test_request_content_length_absent() raises:
    var req = Request(method="GET", url="/")
    assert_equal(req.content_length(), 0)


def test_request_connection_close() raises:
    var req = Request(method="GET", url="/")
    req.headers.set("Connection", "close")
    assert_true(req.connection_close())


def test_request_connection_not_close() raises:
    var req = Request(method="GET", url="/")
    req.headers.set("Connection", "keep-alive")
    assert_false(req.connection_close())


# ── Cookie tests ──────────────────────────────────────────────────────────────


def test_cookie_basic() raises:
    var c = Cookie("session", "abc123")
    assert_equal(c.name, "session")
    assert_equal(c.value, "abc123")
    assert_equal(c.to_request_pair(), "session=abc123")


def test_cookie_set_cookie_header() raises:
    var c = Cookie("id", "xyz", secure=True, http_only=True, path="/")
    var header = c.to_set_cookie_header()
    assert_true("id=xyz" in header)
    assert_true("Secure" in header)
    assert_true("HttpOnly" in header)
    assert_true("Path=/" in header)


def test_cookie_max_age() raises:
    var c = Cookie("tmp", "val", max_age=3600)
    var header = c.to_set_cookie_header()
    assert_true("Max-Age=3600" in header)


def test_cookie_same_site() raises:
    var c = Cookie("pref", "dark", same_site=SameSite.STRICT)
    var header = c.to_set_cookie_header()
    assert_true("SameSite=Strict" in header)


def test_cookie_jar_set_get() raises:
    var jar = CookieJar()
    jar.set(Cookie("session", "abc"))
    assert_equal(jar.get("session"), "abc")
    assert_equal(jar.len(), 1)


def test_cookie_jar_replace() raises:
    var jar = CookieJar()
    jar.set(Cookie("session", "old"))
    jar.set(Cookie("session", "new"))
    assert_equal(jar.get("session"), "new")
    assert_equal(jar.len(), 1)


def test_cookie_jar_remove() raises:
    var jar = CookieJar()
    jar.set(Cookie("a", "1"))
    jar.set(Cookie("b", "2"))
    assert_true(jar.remove("a"))
    assert_false(jar.contains("a"))
    assert_true(jar.contains("b"))
    assert_equal(jar.len(), 1)


def test_cookie_jar_to_request_header() raises:
    var jar = CookieJar()
    jar.set(Cookie("a", "1"))
    jar.set(Cookie("b", "2"))
    var header = jar.to_request_header()
    assert_true("a=1" in header)
    assert_true("b=2" in header)
    assert_true("; " in header)


def test_parse_cookie_header_simple() raises:
    var cookies = parse_cookie_header("session=abc; theme=dark")
    assert_equal(len(cookies), 2)
    assert_equal(cookies[0].name, "session")
    assert_equal(cookies[0].value, "abc")
    assert_equal(cookies[1].name, "theme")
    assert_equal(cookies[1].value, "dark")


def test_parse_cookie_header_single() raises:
    var cookies = parse_cookie_header("token=xyz123")
    assert_equal(len(cookies), 1)
    assert_equal(cookies[0].name, "token")
    assert_equal(cookies[0].value, "xyz123")


def test_parse_set_cookie_basic() raises:
    var c = parse_set_cookie_header("session=abc; Path=/; Secure; HttpOnly")
    assert_equal(c.name, "session")
    assert_equal(c.value, "abc")
    assert_equal(c.path, "/")
    assert_true(c.secure)
    assert_true(c.http_only)


def test_parse_set_cookie_max_age() raises:
    var c = parse_set_cookie_header("id=123; Max-Age=7200; Domain=.example.com")
    assert_equal(c.name, "id")
    assert_equal(c.value, "123")
    assert_equal(c.max_age, 7200)
    assert_equal(c.domain, ".example.com")


def test_parse_set_cookie_samesite() raises:
    var c = parse_set_cookie_header("pref=light; SameSite=Lax")
    assert_equal(c.same_site, "Lax")


# ── Loopback server round-trips ──────────────────────────────────────────────


def test_server_buffered_get() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/test")

    var body_bytes = List[UInt8]()
    for b in "ok".as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, reason="OK", body=body_bytes^)
    _write_response(server_stream, resp)
    server_stream.close()
    client.close()
    srv.close()


def test_server_buffered_post_with_body() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var body_str = "Hello, buffered server!"
    var raw_req = (
        "POST /submit HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Content-Length: "
        + String(body_str.byte_length())
        + "\r\n"
        + "\r\n"
        + body_str
    )
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.method, "POST")
    assert_equal(req.url, "/submit")
    assert_equal(len(req.body), body_str.byte_length())

    server_stream.close()
    client.close()
    srv.close()


def test_server_response_with_keepalive() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)

    var body_bytes = List[UInt8]()
    for b in "ok".as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, body=body_bytes^)
    _write_response_buffered(server_stream, resp, keep_alive=True)

    var resp_buf = List[UInt8](capacity=4096)
    resp_buf.resize(4096, 0)
    var n = client.read(resp_buf.unsafe_ptr(), 4096)
    assert_true(n > 0)

    var resp_str = String(capacity=n)
    for i in range(n):
        resp_str += chr(Int(resp_buf[i]))
    assert_true("keep-alive" in resp_str)

    server_stream.close()
    client.close()
    srv.close()


def test_server_response_with_close() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)

    var body_bytes = List[UInt8]()
    for b in "ok".as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, body=body_bytes^)
    _write_response_buffered(server_stream, resp, keep_alive=False)

    var resp_buf = List[UInt8](capacity=4096)
    resp_buf.resize(4096, 0)
    var n = client.read(resp_buf.unsafe_ptr(), 4096)

    var resp_str = String(capacity=n)
    for i in range(n):
        resp_str += chr(Int(resp_buf[i]))
    assert_true("close" in resp_str)

    server_stream.close()
    client.close()
    srv.close()


def test_server_large_headers() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\n"
    for i in range(20):
        raw_req += "X-Header-" + String(i) + ": value-" + String(i) + "\r\n"
    raw_req += "\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.headers.get("X-Header-0"), "value-0")
    assert_equal(req.headers.get("X-Header-19"), "value-19")

    server_stream.close()
    client.close()
    srv.close()


def test_server_methods() raises:
    var methods = List[String]()
    methods.append("GET")
    methods.append("POST")
    methods.append("PUT")
    methods.append("DELETE")
    methods.append("PATCH")
    methods.append("HEAD")

    for i in range(len(methods)):
        var m = methods[i]
        var raw = m + " /api HTTP/1.1\r\nHost: localhost\r\n\r\n"
        var data = raw.as_bytes()
        var req = _parse_http_request_bytes(Span[UInt8, _](data))
        assert_equal(req.method, m)


def test_server_response_content_length() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)

    var body_str = "exactly 13 b"
    var body_bytes = List[UInt8]()
    for b in body_str.as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, body=body_bytes^)
    _write_response_buffered(server_stream, resp, keep_alive=False)

    var resp_buf = List[UInt8](capacity=4096)
    resp_buf.resize(4096, 0)
    var n = client.read(resp_buf.unsafe_ptr(), 4096)

    var resp_str = String(capacity=n)
    for i in range(n):
        resp_str += chr(Int(resp_buf[i]))
    assert_true("Content-Length: 12" in resp_str)

    server_stream.close()
    client.close()
    srv.close()


def test_server_empty_body_response() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var client = TcpStream.connect(SocketAddr.localhost(port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)

    var resp = Response(status=Status.NO_CONTENT)
    _write_response_buffered(server_stream, resp, keep_alive=False)

    var resp_buf = List[UInt8](capacity=4096)
    resp_buf.resize(4096, 0)
    var n = client.read(resp_buf.unsafe_ptr(), 4096)

    var resp_str = String(capacity=n)
    for i in range(n):
        resp_str += chr(Int(resp_buf[i]))
    assert_true("Content-Length: 0" in resp_str)
    assert_true("204" in resp_str)

    server_stream.close()
    client.close()
    srv.close()


# ── _eq_icase tests ───────────────────────────────────────────────────────────


def test_eq_icase_same() raises:
    """_eq_icase matches identical strings."""
    from flare.http.headers import _eq_icase

    assert_true(_eq_icase("Content-Type", "Content-Type"))


def test_eq_icase_different_case() raises:
    """_eq_icase is case-insensitive."""
    from flare.http.headers import _eq_icase

    assert_true(_eq_icase("Content-Type", "content-type"))
    assert_true(_eq_icase("CONTENT-TYPE", "content-type"))
    assert_true(_eq_icase("Host", "HOST"))


def test_eq_icase_different_strings() raises:
    """_eq_icase rejects different strings."""
    from flare.http.headers import _eq_icase

    assert_false(_eq_icase("Content-Type", "Content-Length"))
    assert_false(_eq_icase("Host", "Hos"))
    assert_false(_eq_icase("", "x"))


def test_eq_icase_empty() raises:
    """_eq_icase matches two empty strings."""
    from flare.http.headers import _eq_icase

    assert_true(_eq_icase("", ""))


# ── encode_to tests ──────────────────────────────────────────────────────────


def test_encode_to_basic() raises:
    """Encode_to serialises headers as wire bytes."""
    var hm = HeaderMap()
    hm.set("Host", "example.com")
    hm.set("Accept", "text/html")
    var buf = List[UInt8](capacity=256)
    hm.encode_to(buf)
    var result = String(unsafe_from_utf8=Span[UInt8, _](buf))
    assert_true("Host: example.com\r\n" in result)
    assert_true("Accept: text/html\r\n" in result)


def test_encode_to_empty() raises:
    """Encode_to on empty HeaderMap produces no bytes."""
    var hm = HeaderMap()
    var buf = List[UInt8](capacity=64)
    hm.encode_to(buf)
    assert_equal(len(buf), 0)


# ── set_unchecked tests ──────────────────────────────────────────────────────


def test_set_unchecked_basic() raises:
    """Set_unchecked adds headers and get retrieves them case-insensitively."""
    var hm = HeaderMap()
    hm.set_unchecked("Content-Type", "content-type", "application/json")
    assert_equal(hm.get("content-type"), "application/json")
    assert_equal(hm.get("Content-Type"), "application/json")
    assert_equal(hm.len(), 1)


def test_set_unchecked_replaces() raises:
    """Set_unchecked replaces existing header."""
    var hm = HeaderMap()
    hm.set_unchecked("X-Foo", "x-foo", "old")
    hm.set_unchecked("X-Foo", "x-foo", "new")
    assert_equal(hm.get("X-Foo"), "new")
    assert_equal(hm.len(), 1)


# ── HeaderMap with _eq_icase integration ─────────────────────────────────────


def test_headermap_case_insensitive_after_rewrite() raises:
    """HeaderMap.set/get still works after _lower_keys removal."""
    var hm = HeaderMap()
    hm.set("Content-Type", "text/html")
    assert_equal(hm.get("content-type"), "text/html")
    assert_equal(hm.get("CONTENT-TYPE"), "text/html")
    assert_equal(hm.get("Content-Type"), "text/html")


def test_headermap_remove_case_insensitive() raises:
    """HeaderMap.remove works case-insensitively after rewrite."""
    var hm = HeaderMap()
    hm.set("X-Custom", "val")
    assert_true(hm.remove("x-custom"))
    assert_false(hm.contains("X-Custom"))


def test_headermap_contains_case_insensitive() raises:
    """HeaderMap.contains works case-insensitively."""
    var hm = HeaderMap()
    hm.set("Authorization", "Bearer tok")
    assert_true(hm.contains("authorization"))
    assert_true(hm.contains("AUTHORIZATION"))
    assert_false(hm.contains("X-Missing"))


def test_headermap_get_all_case_insensitive() raises:
    """HeaderMap.get_all returns all values case-insensitively."""
    var hm = HeaderMap()
    hm.append("Set-Cookie", "a=1")
    hm.append("set-cookie", "b=2")
    var vals = hm.get_all("SET-COOKIE")
    assert_equal(len(vals), 2)


# ── _read_line_buf edge cases ─────────────────────────────────────────────────


def test_parse_bytes_crlf_only() raises:
    """Request with CRLF line endings parses correctly."""
    var raw = "GET / HTTP/1.1\r\nHost: test\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "GET")
    assert_equal(req.headers.get("Host"), "test")


def test_parse_bytes_lf_only() raises:
    """Request with LF-only line endings parses correctly."""
    var raw = "GET / HTTP/1.1\nHost: test\n\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.method, "GET")


def test_parse_bytes_long_header_value() raises:
    """Long header value parses correctly."""
    var long_val = "x" * 500
    var raw = "GET / HTTP/1.1\r\nX-Long: " + long_val + "\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.headers.get("X-Long").byte_length(), 500)


def test_parse_bytes_empty_header_value() raises:
    """Header with empty value parses correctly."""
    var raw = "GET / HTTP/1.1\r\nX-Empty:\r\n\r\n"
    var data = raw.as_bytes()
    var req = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_equal(req.headers.get("X-Empty"), "")


# ── IPv6 sockaddr round-trip ─────────────────────────────────────────────────


def test_v6_server_loopback() raises:
    """HttpServer on [::1] accepts a request if IPv6 is available."""
    # Probe: can we bind IPv6 loopback? If not, skip to avoid hanging.
    try:
        var probe = TcpListener.bind(SocketAddr(IpAddr("::1", is_v6=True), 0))
        probe.close()
    except:
        print("  [SKIP] IPv6 loopback not available")
        return

    var addr = SocketAddr(IpAddr("::1", is_v6=True), 0)
    var srv = HttpServer.bind(addr)
    var port = srv.local_addr().port
    assert_true(srv.local_addr().ip.is_v6(), "Server should bind IPv6")

    var client = TcpStream.connect(SocketAddr(IpAddr("::1", is_v6=True), port))
    var server_stream = srv._listener.accept()

    var raw_req = "GET /v6 HTTP/1.1\r\nHost: [::1]\r\n\r\n"
    client.write_all(Span[UInt8, _](raw_req.as_bytes()))

    var req = _parse_http_request(server_stream, 8192, 1024 * 1024)
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/v6")

    var body_bytes = List[UInt8]()
    for b in "ok".as_bytes():
        body_bytes.append(b)
    var resp = Response(status=Status.OK, reason="OK", body=body_bytes^)
    _write_response(server_stream, resp)
    server_stream.close()
    client.close()
    srv.close()


# ── main ──────────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_server.mojo — server, helpers, cookies, parsing, IPv6")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
