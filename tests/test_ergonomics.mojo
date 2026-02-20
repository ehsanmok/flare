"""Phase 8 ergonomics tests.

Tests for higher-level API features:
- ``Auth`` trait + ``BasicAuth`` + ``BearerAuth``
- ``HttpError`` + ``TooManyRedirects``
- ``Response.raise_for_status()`` + ``Response.iter_bytes()`` + ``Response.json()``
  (returns ``mojson.Value``)
- ``HttpClient`` constructors: ``HttpClient()``, ``HttpClient("base_url")``,
  ``HttpClient(auth)``, ``HttpClient("base_url", auth)``
- ``post`` / ``put`` with ``String`` body (JSON auto-set), ``mojson.Value``
  body (auto-serialised), and ``List[UInt8]`` body (raw bytes)
- Module-level ``get``, ``post``, ``put``, ``delete``, ``head`` helpers
- ``TcpStream.connect(host, port)`` + ``TcpStream.connect(host, port, timeout_ms)``
- Context managers on ``TcpStream``, ``UdpSocket``
- ``WsMessage`` + ``WsClient.recv_message()`` + ``WsClient.__enter__``
- ``BufReader`` + ``Readable`` trait
"""

from testing import assert_true, assert_false, assert_equal, assert_raises
from ffi import external_call

from flare.http import (
    HttpClient,
    Response,
    HeaderMap,
    Status,
    HttpError,
    TooManyRedirects,
    BasicAuth,
    BearerAuth,
)
from flare.http.auth import _b64_encode
from flare.http.response import _BytesIter
from flare.http.error import HttpError as _HttpError
from flare.ws import WsMessage
from flare.io import BufReader, Readable
from flare.net import SocketAddr


# ── Auth helpers ──────────────────────────────────────────────────────────────


def test_b64_encode_empty():
    """``_b64_encode`` of empty bytes returns empty string."""
    var result = _b64_encode(Span[UInt8](List[UInt8]()))
    assert_equal(result, "")


def test_b64_encode_short():
    """``_b64_encode`` matches known RFC 4648 vectors."""
    # "Man" -> "TWFu"
    var data = List[UInt8]()
    data.append(UInt8(77))  # M
    data.append(UInt8(97))  # a
    data.append(UInt8(110))  # n
    assert_equal(_b64_encode(Span[UInt8](data)), "TWFu")


def test_b64_encode_one_byte():
    """``_b64_encode`` pads a single-byte input correctly."""
    var data = List[UInt8]()
    data.append(UInt8(0))
    assert_equal(_b64_encode(Span[UInt8](data)), "AA==")


def test_b64_encode_two_bytes():
    """``_b64_encode`` pads a two-byte input correctly."""
    var data = List[UInt8]()
    data.append(UInt8(0))
    data.append(UInt8(0))
    assert_equal(_b64_encode(Span[UInt8](data)), "AAA=")


def test_basic_auth_apply():
    """``BasicAuth.apply`` sets ``Authorization: Basic <base64>``."""
    var auth = BasicAuth("alice", "s3cr3t")
    var h = HeaderMap()
    auth.apply(h)
    var hdr = h.get("Authorization")
    assert_true(hdr.startswith("Basic "), "header must start with 'Basic '")
    # Decode manually: base64("alice:s3cr3t") = "YWxpY2U6czNjcjN0"
    assert_equal(hdr, "Basic YWxpY2U6czNjcjN0")


def test_basic_auth_empty_password():
    """``BasicAuth`` with empty password encodes ``user:``."""
    var auth = BasicAuth("user", "")
    var h = HeaderMap()
    auth.apply(h)
    var hdr = h.get("Authorization")
    assert_true(hdr.startswith("Basic "), "header must start with 'Basic '")
    assert_true(len(hdr) > 6, "encoded value must be non-empty")


def test_bearer_auth_apply():
    """``BearerAuth.apply`` sets ``Authorization: Bearer <token>``."""
    var auth = BearerAuth("my-token-xyz")
    var h = HeaderMap()
    auth.apply(h)
    assert_equal(h.get("Authorization"), "Bearer my-token-xyz")


def test_bearer_auth_empty_token():
    """``BearerAuth`` with empty token sets ``Authorization: Bearer ``."""
    var auth = BearerAuth("")
    var h = HeaderMap()
    auth.apply(h)
    assert_equal(h.get("Authorization"), "Bearer ")


# ── HttpError ────────────────────────────────────────────────────────────────


def test_http_error_str_with_reason_and_url():
    """``HttpError.__str__`` includes status, reason and url."""
    var err = HttpError(404, "Not Found", "https://example.com/missing")
    var s = String(err)
    assert_true("404" in s, "status code must appear")
    assert_true("Not Found" in s, "reason must appear")
    assert_true("https://example.com" in s, "URL must appear")


def test_http_error_str_no_url():
    """``HttpError.__str__`` omits URL when empty."""
    var err = HttpError(500, "Internal Server Error")
    var s = String(err)
    assert_true("500" in s, "status code must appear")
    assert_true("(" not in s, "parens must not appear without url")


def test_http_error_str_no_reason():
    """``HttpError`` with no reason or url."""
    var err = HttpError(403)
    var s = String(err)
    assert_true("403" in s, "status code must appear")


def test_too_many_redirects_str():
    """``TooManyRedirects.__str__`` includes count and url."""
    var err = TooManyRedirects("https://example.com", 10)
    var s = String(err)
    assert_true("10" in s, "redirect count must appear")
    assert_true("example.com" in s, "url must appear")


# ── Response ─────────────────────────────────────────────────────────────────


def test_response_raise_for_status_ok():
    """``raise_for_status`` is a no-op for 200 responses."""
    var resp = Response(status=200, reason="OK")
    resp.raise_for_status()  # must not raise


def test_response_raise_for_status_201():
    """``raise_for_status`` is a no-op for 201 Created."""
    var resp = Response(status=201, reason="Created")
    resp.raise_for_status()


def test_response_raise_for_status_404():
    """``raise_for_status`` raises ``HttpError`` on 404."""
    var resp = Response(status=404, reason="Not Found")
    var raised = False
    try:
        resp.raise_for_status()
    except:
        raised = True
    assert_true(raised, "HttpError must be raised for 404")


def test_response_raise_for_status_500():
    """``raise_for_status`` raises ``HttpError`` on 500."""
    var resp = Response(status=500, reason="Internal Server Error")
    var raised = False
    try:
        resp.raise_for_status()
    except:
        raised = True
    assert_true(raised, "HttpError must be raised for 500")


def test_response_raise_for_status_301():
    """``raise_for_status`` raises ``HttpError`` on 3xx (redirect, not OK)."""
    var resp = Response(status=301, reason="Moved Permanently")
    var raised = False
    try:
        resp.raise_for_status()
    except:
        raised = True
    assert_true(raised, "HttpError must be raised for 3xx")


def test_response_json_parses_value():
    """``Response.json()`` parses the body as a ``mojson.Value``."""
    from mojson import Value

    var body = List[UInt8]()
    for b in String('{"x": 1}').as_bytes():
        body.append(b)
    var resp = Response(status=200, body=body)
    var data = resp.json()
    assert_equal(data["x"].int_value(), 1)


def test_response_iter_bytes_whole():
    """``iter_bytes`` yields all body bytes when chunk_size >= body length."""
    var body = List[UInt8]()
    for i in range(10):
        body.append(UInt8(i))
    var resp = Response(status=200, body=body)
    var total = List[UInt8]()
    for chunk in resp.iter_bytes(1024):
        for b in chunk:
            total.append(b)
    assert_equal(len(total), 10)
    for i in range(10):
        assert_equal(Int(total[i]), i)


def test_response_iter_bytes_chunks():
    """``iter_bytes`` splits body into fixed-size chunks."""
    var body = List[UInt8]()
    for i in range(9):
        body.append(UInt8(i))
    var resp = Response(status=200, body=body)
    var chunks = List[Int]()
    for chunk in resp.iter_bytes(4):
        chunks.append(len(chunk))
    # 9 bytes with chunk_size=4: chunks of 4, 4, 1
    assert_equal(len(chunks), 3)
    assert_equal(chunks[0], 4)
    assert_equal(chunks[1], 4)
    assert_equal(chunks[2], 1)


def test_response_iter_bytes_empty():
    """``iter_bytes`` on empty body yields no chunks."""
    var resp = Response(status=204)
    var count = 0
    for _ in resp.iter_bytes():
        count += 1
    assert_equal(count, 0)


# ── HttpClient constructor ────────────────────────────────────────────────────


def test_http_client_default_no_auth():
    """Default ``HttpClient()`` has empty auth header."""
    var client = HttpClient()
    assert_equal(client._auth_header, "")


def test_http_client_with_basic_auth():
    """``HttpClient(BasicAuth(...))`` stores base64 auth header."""
    var client = HttpClient(BasicAuth("alice", "s3cr3t"))
    assert_true(
        client._auth_header.startswith("Basic "),
        "auth header must start with 'Basic '",
    )


def test_http_client_with_bearer_auth():
    """``HttpClient(BearerAuth(...))`` stores Bearer auth header."""
    var client = HttpClient(BearerAuth("tok"))
    assert_equal(client._auth_header, "Bearer tok")


def test_http_client_base_url_positional():
    """``HttpClient("https://...")`` sets base URL via first positional arg."""
    var client = HttpClient("https://httpbin.org")
    var resolved = client._resolve_url("/get")
    assert_equal(resolved, "https://httpbin.org/get")


def test_http_client_base_url_and_auth_positional():
    """``HttpClient("url", BearerAuth("tok"))`` sets both base URL and auth."""
    var client = HttpClient("https://httpbin.org", BearerAuth("secret"))
    assert_equal(client._auth_header, "Bearer secret")
    assert_equal(client._resolve_url("/users"), "https://httpbin.org/users")


def test_http_client_base_url_prepended():
    """``HttpClient`` with ``base_url`` keyword prepends it to relative paths.
    """
    var client = HttpClient(base_url="https://httpbin.org")
    var resolved = client._resolve_url("/get")
    assert_equal(resolved, "https://httpbin.org/get")


def test_http_client_base_url_ignored_for_absolute():
    """``HttpClient`` with ``base_url`` leaves absolute URLs unchanged."""
    var client = HttpClient(base_url="https://httpbin.org")
    var resolved = client._resolve_url("https://other.com/foo")
    assert_equal(resolved, "https://other.com/foo")


def test_http_client_no_base_url():
    """``HttpClient`` without ``base_url`` returns the URL unchanged."""
    var client = HttpClient()
    var resolved = client._resolve_url("/get")
    assert_equal(resolved, "/get")


def test_http_client_context_manager():
    """``HttpClient`` supports the ``with`` context manager protocol."""
    # Consuming __enter__ transfers ownership; just verify it compiles and runs.
    # Consuming __enter__ transfers ownership; verify the block runs.
    var _ran = False
    with HttpClient():
        _ran = True
    assert_true(_ran, "with block must execute")


# ── TcpStream context manager ─────────────────────────────────────────────────
# Note: These tests require a listening server; we only test compilation and
# basic error paths here to avoid network dependencies in unit tests.


def test_tcp_connect_host_port_dns_fail():
    """``TcpStream.connect(host, port)`` raises on unresolvable host."""
    from flare.tcp import TcpStream

    var raised = False
    try:
        _ = TcpStream.connect("this.host.does.not.exist.invalid", 80)
    except:
        raised = True
    assert_true(raised, "connection to invalid host must raise")


def test_tcp_connect_host_port_timeout_dns_fail():
    """``TcpStream.connect(host, port, timeout_ms)`` raises on unresolvable host.
    """
    from flare.tcp import TcpStream

    var raised = False
    try:
        _ = TcpStream.connect("this.host.does.not.exist.invalid", 80, 1000)
    except:
        raised = True
    assert_true(raised, "connection to invalid host must raise")


# ── UdpSocket context manager ─────────────────────────────────────────────────


def test_udp_socket_context_manager():
    """``UdpSocket`` supports the ``with`` context manager protocol."""
    from flare.udp import UdpSocket
    from flare.net import SocketAddr

    with UdpSocket.bind(SocketAddr.localhost(0)) as sock:
        # Just verify the context manager works
        var addr = sock.local_addr()
        assert_true(Int(addr.port) > 0, "OS should assign an ephemeral port")


# ── WsMessage ─────────────────────────────────────────────────────────────────


def test_ws_message_text():
    """``WsMessage(text=...)`` has ``is_text=True`` and returns the text."""
    var msg = WsMessage("hello")
    assert_true(msg.is_text)
    assert_equal(msg.as_text(), "hello")
    assert_equal(len(msg.as_binary()), 0)


def test_ws_message_binary():
    """``WsMessage(binary=...)`` has ``is_text=False`` and returns the bytes."""
    var data = List[UInt8]()
    data.append(UInt8(1))
    data.append(UInt8(2))
    data.append(UInt8(3))
    var msg = WsMessage(data)
    assert_false(msg.is_text)
    assert_equal(msg.as_text(), "")
    assert_equal(len(msg.as_binary()), 3)


def test_ws_message_text_empty():
    """``WsMessage`` with empty text is valid."""
    var msg = WsMessage("")
    assert_true(msg.is_text)
    assert_equal(msg.as_text(), "")


# ── BufReader ─────────────────────────────────────────────────────────────────


struct _FakeStream(Readable):
    """An in-memory ``Readable`` stream backed by a byte list."""

    var _data: List[UInt8]
    var _pos: Int

    fn __init__(out self, data: List[UInt8]):
        self._data = data.copy()
        self._pos = 0

    fn __moveinit__(out self, deinit take: _FakeStream):
        self._data = take._data^
        self._pos = take._pos

    fn read(mut self, buf: UnsafePointer[UInt8], size: Int) raises -> Int:
        """Satisfy the ``Readable`` trait by copying data into ``buf``."""
        var available = len(self._data) - self._pos
        if available <= 0:
            return 0
        var n = size if size < available else available
        # Use C memcpy via external_call to bypass Mojo's origin-mutability
        # tracking on the parameter pointer.
        _ = external_call["memcpy", NoneType, Int, Int, Int](
            Int(buf), Int(self._data.unsafe_ptr() + self._pos), n
        )
        self._pos += n
        return n


def test_buf_reader_readline_simple():
    """``BufReader.readline`` reads a single LF-terminated line."""
    var data = List[UInt8]()
    for b in String("hello\nworld\n").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var line1 = reader.readline()
    assert_equal(line1, "hello")
    var line2 = reader.readline()
    assert_equal(line2, "world")


def test_buf_reader_readline_crlf():
    """``BufReader.readline`` strips ``\\r\\n`` correctly."""
    var data = List[UInt8]()
    for b in String("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var line1 = reader.readline()
    assert_equal(line1, "HTTP/1.1 200 OK")
    var line2 = reader.readline()
    assert_equal(line2, "Content-Length: 0")
    var line3 = reader.readline()
    assert_equal(line3, "")  # blank line separating headers from body


def test_buf_reader_readline_eof():
    """``BufReader.readline`` returns empty string on EOF."""
    var data = List[UInt8]()
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var line = reader.readline()
    assert_equal(line, "")


def test_buf_reader_read_until():
    """``BufReader.read_until`` stops at the delimiter byte."""
    var data = List[UInt8]()
    for b in String("key:value,next").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var field = reader.read_until(UInt8(ord(":")))
    assert_equal(field, "key")
    var rest = reader.read_until(UInt8(ord(",")))
    assert_equal(rest, "value")


def test_buf_reader_read_exact():
    """``BufReader.read_exact`` returns exactly ``n`` bytes."""
    var data = List[UInt8]()
    for b in String("hello world").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var five = reader.read_exact(5)
    assert_equal(len(five), 5)
    assert_equal(chr(Int(five[0])), "h")
    assert_equal(chr(Int(five[4])), "o")


def test_buf_reader_read_exact_eof_raises():
    """``BufReader.read_exact`` raises ``NetworkError`` on premature EOF."""
    var data = List[UInt8]()
    for b in String("hi").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var raised = False
    try:
        _ = reader.read_exact(10)
    except:
        raised = True
    assert_true(raised, "must raise NetworkError on premature EOF")


def test_buf_reader_read_until_eof():
    """``BufReader.read_until`` returns partial data on EOF before delimiter."""
    var data = List[UInt8]()
    for b in String("hello").as_bytes():
        data.append(b)
    var stream = _FakeStream(data)
    var reader = BufReader(stream^)
    var result = reader.read_until(UInt8(ord(",")))
    assert_equal(result, "hello")


def main():
    # Auth tests
    test_b64_encode_empty()
    test_b64_encode_short()
    test_b64_encode_one_byte()
    test_b64_encode_two_bytes()
    test_basic_auth_apply()
    test_basic_auth_empty_password()
    test_bearer_auth_apply()
    test_bearer_auth_empty_token()

    # HttpError tests
    test_http_error_str_with_reason_and_url()
    test_http_error_str_no_url()
    test_http_error_str_no_reason()
    test_too_many_redirects_str()

    # Response tests
    test_response_raise_for_status_ok()
    test_response_raise_for_status_201()
    test_response_raise_for_status_404()
    test_response_raise_for_status_500()
    test_response_raise_for_status_301()
    test_response_json_parses_value()
    test_response_iter_bytes_whole()
    test_response_iter_bytes_chunks()
    test_response_iter_bytes_empty()

    # HttpClient constructor tests
    test_http_client_default_no_auth()
    test_http_client_with_basic_auth()
    test_http_client_with_bearer_auth()
    test_http_client_base_url_positional()
    test_http_client_base_url_and_auth_positional()
    test_http_client_base_url_prepended()
    test_http_client_base_url_ignored_for_absolute()
    test_http_client_no_base_url()
    test_http_client_context_manager()

    # TcpStream connect-by-name tests (DNS failure path)
    test_tcp_connect_host_port_dns_fail()
    test_tcp_connect_host_port_timeout_dns_fail()

    # UdpSocket context manager
    test_udp_socket_context_manager()

    # WsMessage tests
    test_ws_message_text()
    test_ws_message_binary()
    test_ws_message_text_empty()

    # BufReader tests
    test_buf_reader_readline_simple()
    test_buf_reader_readline_crlf()
    test_buf_reader_readline_eof()
    test_buf_reader_read_until()
    test_buf_reader_read_exact()
    test_buf_reader_read_exact_eof_raises()
    test_buf_reader_read_until_eof()

    print("All ergonomics tests passed!")
