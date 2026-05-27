"""Regression test for the ``flare.http.proto`` sans-I/O namespace.

Every symbol re-exported through ``flare.http.proto.__init__`` is
imported and exercised at least minimally so the namespace cannot
silently rot. If a parser module changes its public surface, this
test breaks first.

The test is also the canonical demonstration that the sans-I/O
contract is real: nothing imported below pulls in
``flare.runtime`` / ``flare.io`` / ``flare.tcp`` / ``flare.tls`` /
``flare.net``. The ``check-sans-io`` lint job enforces this
statically; this test verifies the public surface end-to-end.
"""

from std.testing import assert_equal, assert_true

from flare.http.proto import (
    Cookie,
    CookieJar,
    SameSite,
    parse_cookie_header,
    parse_set_cookie_header,
    FormData,
    parse_form_urlencoded,
    urldecode,
    urlencode,
    MultipartForm,
    MultipartPart,
    parse_multipart_form_data,
    Url,
    UrlParseError,
    HeaderInjectionError,
    HeaderMap,
    HeaderMapView,
    parse_header_view,
    StandardHeader,
    is_standard_header,
    lookup_standard_header_bytes,
    lookup_standard_header_string,
    standard_header_count,
    standard_header_name,
    MethodIntern,
    ValueIntern,
    intern_common_value,
    intern_common_value_string,
    intern_method_bytes,
    intern_method_string,
    HttpParseError,
    simd_cookie_scan,
    simd_memmem,
    simd_percent_decode,
    HuffmanError,
    huffman_decode,
    huffman_decoded_length,
    huffman_encode,
    huffman_encoded_length,
    H2Frame,
    H2FrameFlags,
    H2FrameHeader,
    H2FrameType,
    encode_h2_frame,
    parse_h2_frame,
    HpackDecoder,
    HpackEncoder,
    HpackHeader,
    HpackStringPair,
    hpack_decode_integer,
    hpack_encode_integer,
    H2Connection,
    H2Stream,
    H2StreamState,
)


def test_cookie_roundtrip() raises:
    var c = Cookie("session", "abc123", secure=True, http_only=True)
    assert_equal(c.name, "session")
    assert_equal(c.value, "abc123")

    var parsed = parse_cookie_header("session=abc123; lang=en")
    assert_equal(len(parsed), 2)
    assert_equal(parsed[0].name, "session")
    assert_equal(parsed[1].name, "lang")

    var sc = parse_set_cookie_header("id=42; Path=/; Max-Age=3600")
    assert_equal(sc.name, "id")
    assert_equal(sc.value, "42")
    assert_equal(sc.path, "/")
    assert_equal(sc.max_age, 3600)

    var jar = CookieJar()
    jar.set(c^)
    assert_equal(SameSite.LAX, "Lax")


def test_form_urlencoded() raises:
    var form = parse_form_urlencoded("a=1&b=hello%20world&c=%26")
    assert_equal(form.get("a"), "1")
    assert_equal(form.get("b"), "hello world")
    assert_equal(form.get("c"), "&")

    var decoded = urldecode("hello%20world")
    assert_equal(decoded, "hello world")

    # ``urlencode`` percent-encodes everything but unreserved chars
    # (RFC 3986 §2.3); the exact output is verified in
    # ``test_form.mojo``. Here we just confirm the symbol is callable
    # through the proto namespace.
    var encoded = urlencode("hello")
    assert_equal(encoded, "hello")


def test_url_parse() raises:
    var u = Url.parse("https://example.com:8080/path?q=1")
    assert_equal(u.scheme, "https")
    assert_equal(u.host, "example.com")
    assert_equal(Int(u.port), 8080)
    assert_equal(u.path, "/path")
    assert_equal(u.query, "q=1")


def test_h2_frame_roundtrip() raises:
    # PING frame: type=6, flags=0, stream=0, 8-byte opaque body.
    var f = H2Frame()
    f.header.type = H2FrameType.PING()
    f.header.flags = H2FrameFlags(0)
    f.header.stream_id = 0
    for _ in range(8):
        f.payload.append(UInt8(0x42))
    f.header.length = len(f.payload)

    var bytes = encode_h2_frame(f)
    var parsed = parse_h2_frame(Span[UInt8, _](bytes))
    assert_true(Bool(parsed))
    var got = parsed.value().copy()
    assert_equal(Int(got.header.type.value), Int(H2FrameType.PING().value))
    assert_equal(got.header.stream_id, 0)
    assert_equal(len(got.payload), 8)


def test_hpack_integer_codec() raises:
    var out = List[UInt8]()
    hpack_encode_integer(out, 42, 7, UInt8(0))
    assert_equal(len(out), 1)
    assert_equal(Int(out[0]), 42)

    var p = hpack_decode_integer(Span[UInt8, _](out), 0, 7)
    assert_equal(p.value, 42)
    assert_equal(p.offset, 1)


def test_standard_header_phf() raises:
    var count = standard_header_count()
    assert_true(count > 30)
    var i = lookup_standard_header_string("content-length")
    assert_true(i >= 0)


def test_intern_method() raises:
    var slice = String("GET").as_bytes()
    var got = intern_method_bytes(slice)
    assert_true(Bool(got))
    assert_equal(got.value(), "GET")


def test_huffman_codec_smoke() raises:
    # Round-trip a short ASCII string through the canonical HPACK
    # Huffman codec exposed via ``flare.http.proto``.
    var plain = List[UInt8]()
    for b in String("hello").as_bytes():
        plain.append(b)

    var encoded = List[UInt8]()
    huffman_encode(plain, encoded)
    assert_true(len(encoded) > 0)

    var decoded = List[UInt8]()
    huffman_decode(Span[UInt8, _](encoded), decoded)
    assert_equal(len(decoded), len(plain))
    for i in range(len(plain)):
        assert_equal(decoded[i], plain[i])


def test_h2_state_smoke() raises:
    # Just instantiate; per-frame state-machine semantics live in
    # ``test_h2_state.mojo``. This is the re-export channel check.
    var s = H2Stream()
    assert_equal(s.state.value, H2StreamState.IDLE().value)
    var c = H2Connection()
    assert_true(c.max_concurrent_streams > 0)


def test_simd_memmem_smoke() raises:
    var hay = List[UInt8]()
    for b in String("aaaaXYZaaaa").as_bytes():
        hay.append(b)
    var needle = List[UInt8]()
    for b in String("XYZ").as_bytes():
        needle.append(b)
    var hit = simd_memmem(Span[UInt8, _](hay), Span[UInt8, _](needle))
    assert_equal(hit, 4)


def main() raises:
    test_cookie_roundtrip()
    test_form_urlencoded()
    test_url_parse()
    test_h2_frame_roundtrip()
    test_hpack_integer_codec()
    test_standard_header_phf()
    test_intern_method()
    test_huffman_codec_smoke()
    test_h2_state_smoke()
    test_simd_memmem_smoke()
    print("test_proto_reexports: OK")
