"""Tests for ``HeaderMapView[origin]``.

Covers:

- ``parse_header_view`` correctly parses headers from a CRLF /
  LF-terminated byte buffer; the empty line stops parsing.
- ``len()``, ``contains(name)``, ``get(name)`` operate on offsets
  with no per-header allocation.
- Lookup is case-insensitive ASCII per RFC 7230.
- Leading / trailing OWS (SP / HTAB) on values is trimmed.
- ``into_owned()`` materialises an owned ``HeaderMap`` whose
  contents match the view's.
- Malformed inputs (missing colon, empty header name) raise.
- Returned ``StringSlice`` borrows from the underlying buffer
  (lifetime is enforced by Mojo's borrow checker; tested by
  reading after the parse function returns).

The integration into ``Request.headers`` (replacing or paralleling
``HeaderMap``) lands in S2.5 alongside ``RequestView[origin]``.
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)

from flare.http import HeaderMapView, parse_header_view


# ── Basic parsing ───────────────────────────────────────────────────────────


def test_parse_three_headers() raises:
    var raw = "Host: localhost\r\nX-A: 1\r\nX-B: hello world\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(view.len(), 3)


def test_get_returns_value() raises:
    var raw = "Host: example.com\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(String(view.get("Host")), "example.com")


def test_get_case_insensitive() raises:
    var raw = "Content-Type: text/plain\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(String(view.get("content-type")), "text/plain")
    assert_equal(String(view.get("CONTENT-TYPE")), "text/plain")
    assert_equal(String(view.get("Content-Type")), "text/plain")


def test_get_missing_returns_empty() raises:
    var raw = "X: 1\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    var got = view.get("Y")
    assert_equal(String(got), "")


def test_contains_case_insensitive() raises:
    var raw = "Host: x\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_true(view.contains("host"))
    assert_true(view.contains("HOST"))
    assert_false(view.contains("missing"))


def test_value_ows_trimmed() raises:
    """OWS (SP/HTAB) on the value is trimmed per RFC 7230."""
    var raw = "X: spaced\t \r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(String(view.get("X")), "spaced")


def test_empty_value_after_colon() raises:
    var raw = "X:\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_true(view.contains("X"))
    assert_equal(String(view.get("X")), "")


def test_lf_only_terminator_accepted() raises:
    """Bare LF (no CR) between header lines is accepted."""
    var raw = "X-A: 1\nX-B: 2\n\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(view.len(), 2)
    assert_equal(String(view.get("X-A")), "1")
    assert_equal(String(view.get("X-B")), "2")


def test_first_match_wins_on_duplicate() raises:
    """Duplicate header names: ``get`` returns the first occurrence."""
    var raw = "X: a\r\nX: b\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(view.len(), 2)
    assert_equal(String(view.get("X")), "a")


# ── Errors ──────────────────────────────────────────────────────────────────


def test_missing_colon_raises() raises:
    var raw = "BadHeader\r\n\r\n"
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


def test_empty_header_name_raises() raises:
    var raw = ": value\r\n\r\n"
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


def test_invalid_token_in_header_name_raises() raises:
    """RFC 7230 §3.2.6: header name must be a token. Space is
    not a token char — must be rejected. Catches the
    request-smuggling vector where a malformed name chains
    into the next header."""
    var raw = "Bad Header: value\r\n\r\n"
    var bytes = raw.as_bytes()
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


def test_high_bit_in_header_name_raises() raises:
    """High-bit byte in header name is non-token; reject."""
    var bytes = List[UInt8]()
    bytes.append(UInt8(0x80))
    bytes.append(UInt8(ord("X")))
    bytes.append(UInt8(ord(":")))
    bytes.append(UInt8(ord(" ")))
    bytes.append(UInt8(ord("v")))
    for b in "\r\n\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


def test_bare_cr_in_header_value_raises() raises:
    """Bare CR (0x0D) embedded mid-value is the response-
    splitting / header-injection vector — reject."""
    var bytes = List[UInt8]()
    for b in "X-A: hello".as_bytes():
        bytes.append(b)
    bytes.append(UInt8(0x0D))
    bytes.append(UInt8(ord("X")))
    bytes.append(UInt8(ord("\n")))
    for b in "\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


def test_nul_in_header_value_raises() raises:
    """NUL (0x00) in header value is implementation-defined-
    behaviour foot-gun — reject."""
    var bytes = List[UInt8]()
    for b in "X-A: hello".as_bytes():
        bytes.append(b)
    bytes.append(UInt8(0))
    bytes.append(UInt8(ord("X")))
    for b in "\r\n\r\n".as_bytes():
        bytes.append(b)
    with assert_raises():
        _ = parse_header_view(Span[UInt8, _](bytes))


# ── into_owned() ────────────────────────────────────────────────────────────


def test_into_owned_round_trip() raises:
    var raw = "Host: example.com\r\nContent-Type: text/plain\r\n\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    var owned = view.into_owned()
    assert_equal(owned.len(), 2)
    assert_equal(owned.get("Host"), "example.com")
    assert_equal(owned.get("Content-Type"), "text/plain")


def test_into_owned_independent_lifetime() raises:
    """The owned ``HeaderMap`` outlives the source bytes — it copied
    them out. A modification to the underlying buffer does not
    affect the owned map.
    """
    var raw = "Host: x\r\n\r\n".as_bytes()
    var bytes_list = List[UInt8](capacity=len(raw))
    bytes_list.resize(len(raw), UInt8(0))
    for i in range(len(raw)):
        bytes_list[i] = raw[i]
    var view = parse_header_view(Span[UInt8, _](bytes_list))
    var owned = view.into_owned()
    # Mutate the source buffer; the owned map should still see "x".
    bytes_list[6] = UInt8(ord("Y"))
    assert_equal(owned.get("Host"), "x")


# ── Empty input ─────────────────────────────────────────────────────────────


def test_empty_input_yields_empty_view() raises:
    var bytes_list = List[UInt8]()
    var view = parse_header_view(Span[UInt8, _](bytes_list))
    assert_equal(view.len(), 0)


def test_only_terminator_yields_empty_view() raises:
    var raw = "\r\n"
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(view.len(), 0)


# ── Many-header lookup ─────────────────────────────────────────────────────


def test_twelve_header_lookup() raises:
    """Simulate the typical web-app header burst (12 headers).
    Verifies the offset-based lookup works at the size that
    matters for production payloads."""
    var raw = (
        "Host: example.com\r\n"
        "User-Agent: flare/0.5\r\n"
        "Accept: */*\r\n"
        "Accept-Encoding: gzip, deflate\r\n"
        "Accept-Language: en-US\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 42\r\n"
        "Authorization: Bearer secret\r\n"
        "X-Request-Id: abc-123\r\n"
        "X-Forwarded-For: 10.0.0.1\r\n"
        "Cookie: sid=12345\r\n"
        "\r\n"
    )
    var bytes = raw.as_bytes()
    var view = parse_header_view(Span[UInt8, _](bytes))
    assert_equal(view.len(), 12)
    assert_equal(String(view.get("Host")), "example.com")
    assert_equal(String(view.get("Content-Length")), "42")
    assert_equal(String(view.get("Authorization")), "Bearer secret")
    assert_equal(String(view.get("X-Forwarded-For")), "10.0.0.1")
    # Verify case-insensitive with an unusual casing.
    assert_equal(String(view.get("content-tYPe")), "application/json")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
