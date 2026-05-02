"""Tests for ``flare.http.header_phf`` (Track B2)."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import (
    StandardHeader,
    standard_header_count,
    standard_header_name,
    lookup_standard_header_bytes,
    lookup_standard_header_string,
    is_standard_header,
)


def test_count_is_seventy() raises:
    """Sanity-pin the count — every appended header must extend
    the table, not renumber existing entries.
    """
    assert_equal(standard_header_count(), 70)


def test_lookup_common_lowercase() raises:
    """The common request-side names dispatch to the right index."""
    assert_equal(
        lookup_standard_header_string(String("host")), StandardHeader.HOST
    )
    assert_equal(
        lookup_standard_header_string(String("content-type")),
        StandardHeader.CONTENT_TYPE,
    )
    assert_equal(
        lookup_standard_header_string(String("content-length")),
        StandardHeader.CONTENT_LENGTH,
    )
    assert_equal(
        lookup_standard_header_string(String("user-agent")),
        StandardHeader.USER_AGENT,
    )
    assert_equal(
        lookup_standard_header_string(String("accept-encoding")),
        StandardHeader.ACCEPT_ENCODING,
    )
    assert_equal(
        lookup_standard_header_string(String("cookie")),
        StandardHeader.COOKIE,
    )
    assert_equal(
        lookup_standard_header_string(String("authorization")),
        StandardHeader.AUTHORIZATION,
    )


def test_lookup_is_case_insensitive() raises:
    """Per RFC 7230 §3.2 header names are case-insensitive at
    the wire level. The lookup must fold ASCII case.
    """
    assert_equal(
        lookup_standard_header_string(String("Host")), StandardHeader.HOST
    )
    assert_equal(
        lookup_standard_header_string(String("HOST")), StandardHeader.HOST
    )
    assert_equal(
        lookup_standard_header_string(String("hOsT")), StandardHeader.HOST
    )
    assert_equal(
        lookup_standard_header_string(String("Content-Type")),
        StandardHeader.CONTENT_TYPE,
    )
    assert_equal(
        lookup_standard_header_string(String("CONTENT-TYPE")),
        StandardHeader.CONTENT_TYPE,
    )
    assert_equal(
        lookup_standard_header_string(String("Set-Cookie")),
        StandardHeader.SET_COOKIE,
    )


def test_lookup_unknown_returns_negative_one() raises:
    """Unknown / non-standard header names return -1, not a
    silent zero (which would collide with HOST).
    """
    assert_equal(lookup_standard_header_string(String("X-Custom-Foo")), -1)
    assert_equal(lookup_standard_header_string(String("FooBar")), -1)
    assert_equal(lookup_standard_header_string(String("")), -1)


def test_lookup_handles_pathological_lengths() raises:
    """Lengths with no entries in the table return -1 fast."""
    assert_equal(lookup_standard_header_string(String("xx")), -1)  # length 2
    assert_equal(lookup_standard_header_string(String("x")), -1)  # length 1
    assert_equal(
        lookup_standard_header_string(
            String("a-very-very-long-name-that-isnt-real")
        ),
        -1,
    )


def test_round_trip_index_to_name_to_index() raises:
    """For every valid index, ``standard_header_name(i)`` returns
    the canonical lowercase form, and feeding it back through
    ``lookup_standard_header_bytes`` yields ``i``.

    This is the core PHF invariant.
    """
    for i in range(standard_header_count()):
        var name = standard_header_name(i)
        assert_true(name.byte_length() > 0)
        var got = lookup_standard_header_bytes(name.as_bytes())
        assert_equal(got, i)


def test_round_trip_uppercase_lookup() raises:
    """Every canonical name must also lookup correctly when its
    bytes are uppercased — exercises the case-fold path.
    """
    for i in range(standard_header_count()):
        var name = standard_header_name(i)
        var s = String(name)
        var upper = s.upper()
        var got = lookup_standard_header_string(upper)
        assert_equal(got, i)


def test_standard_header_name_out_of_range_returns_empty() raises:
    """An out-of-range index returns an empty StaticString rather
    than crashing.
    """
    var got = standard_header_name(-1)
    assert_equal(got.byte_length(), 0)
    var got2 = standard_header_name(99)
    assert_equal(got2.byte_length(), 0)
    var got3 = standard_header_name(standard_header_count())
    assert_equal(got3.byte_length(), 0)


def test_is_standard_header_boolean_shorthand() raises:
    var s = String("host")
    assert_true(is_standard_header(s.as_bytes()))
    var s2 = String("Set-Cookie")
    assert_true(is_standard_header(s2.as_bytes()))
    var s3 = String("X-Custom")
    assert_false(is_standard_header(s3.as_bytes()))
    var s4 = String("")
    assert_false(is_standard_header(s4.as_bytes()))


def test_constants_are_stable_distinct_indices() raises:
    """Sanity-pin a handful of known constants. If any of these
    change, downstream code that pinned the index breaks — the
    test exists to catch accidental renumbering.
    """
    assert_equal(StandardHeader.HOST, 0)
    assert_equal(StandardHeader.CONTENT_TYPE, 7)
    assert_equal(StandardHeader.AUTHORIZATION, 25)
    assert_equal(StandardHeader.SET_COOKIE, 46)
    assert_equal(StandardHeader.X_REQUEST_ID, 68)
    assert_equal(StandardHeader.STRICT_TRANSPORT_SECURITY, 69)


def test_websocket_headers_dispatch_correctly() raises:
    assert_equal(
        lookup_standard_header_string(String("Sec-WebSocket-Key")),
        StandardHeader.SEC_WEBSOCKET_KEY,
    )
    assert_equal(
        lookup_standard_header_string(String("Sec-WebSocket-Version")),
        StandardHeader.SEC_WEBSOCKET_VERSION,
    )
    assert_equal(
        lookup_standard_header_string(String("Sec-WebSocket-Accept")),
        StandardHeader.SEC_WEBSOCKET_ACCEPT,
    )


def test_cors_headers_dispatch_correctly() raises:
    assert_equal(
        lookup_standard_header_string(String("Access-Control-Allow-Origin")),
        StandardHeader.ACCESS_CONTROL_ALLOW_ORIGIN,
    )
    assert_equal(
        lookup_standard_header_string(
            String("Access-Control-Allow-Credentials")
        ),
        StandardHeader.ACCESS_CONTROL_ALLOW_CREDENTIALS,
    )
    assert_equal(
        lookup_standard_header_string(String("Access-Control-Request-Headers")),
        StandardHeader.ACCESS_CONTROL_REQUEST_HEADERS,
    )


def test_forwarding_headers_dispatch_correctly() raises:
    assert_equal(
        lookup_standard_header_string(String("X-Forwarded-For")),
        StandardHeader.X_FORWARDED_FOR,
    )
    assert_equal(
        lookup_standard_header_string(String("X-Real-IP")),
        StandardHeader.X_REAL_IP,
    )
    assert_equal(
        lookup_standard_header_string(String("Forwarded")),
        StandardHeader.FORWARDED,
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
