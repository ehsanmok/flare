"""What a streaming request is allowed to put on the wire.

``prepare_stream_headers`` is the single point where HTTP/1.1, HTTP/2
and HTTP/3 agree on the request head, so these are the rules all three
inherit. No sockets: the function is pure.

The reject cases matter more than the accept cases. A streaming client
that silently rewrites a bad header is how two parsers end up
disagreeing about where a message ends, which is the same class of bug
the HTTP/1 response reader was hardened against earlier in this release.
"""

from std.testing import assert_equal, assert_raises, assert_true, TestSuite

from flare.http._client.stream_request import prepare_stream_headers
from flare.http.headers import HeaderMap
from flare.http.url import Url


def _u() raises -> Url:
    return Url.parse("https://example.com/path")


def test_framing_fields_are_stripped() raises:
    """The writer owns framing; the caller does not get to set it.

    On h2 and h3 these are forbidden outright by RFC 9113 sec 8.2.2. On
    h1 they would fight the chunked writer. Same answer everywhere.
    """
    var h = HeaderMap()
    for name in [
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Upgrade",
        "TE",
        "Trailer",
        "Proxy-Connection",
        "Keep-Alive",
        "Host",
    ]:
        h.set(name, "x")
    h.set("X-Keep", "yes")
    var out = prepare_stream_headers("GET", _u(), h, "ua/1")
    assert_equal(out.get("x-keep"), "yes")
    for name in [
        "content-length",
        "transfer-encoding",
        "connection",
        "upgrade",
        "te",
        "trailer",
        "proxy-connection",
        "keep-alive",
        "host",
    ]:
        assert_equal(out.get(name), "", "expected " + name + " stripped")


def test_identity_encoding_is_the_default() raises:
    """A streamed body must not arrive compressed by default.

    Inflating it would mean buffering the whole response before the
    caller sees a byte, which is the opposite of streaming.
    """
    var out = prepare_stream_headers("GET", _u(), HeaderMap(), "ua/1")
    assert_equal(out.get("accept-encoding"), "identity")


def test_caller_can_opt_into_compression() raises:
    """Setting the header explicitly means the caller will decode it."""
    var h = HeaderMap()
    h.set("Accept-Encoding", "gzip")
    var out = prepare_stream_headers("GET", _u(), h, "ua/1")
    assert_equal(out.get("accept-encoding"), "gzip")


def test_user_agent_defaults_but_does_not_override() raises:
    var out = prepare_stream_headers("GET", _u(), HeaderMap(), "ua/1")
    assert_equal(out.get("user-agent"), "ua/1")

    var h = HeaderMap()
    h.set("User-Agent", "mine/2")
    var out2 = prepare_stream_headers("GET", _u(), h, "ua/1")
    assert_equal(out2.get("user-agent"), "mine/2")


def test_known_body_size_sets_content_length() raises:
    """A known-length streamed upload gets a Content-Length.

    The field is stripped when the caller sets it and added back here,
    so the value always matches what the writer will actually send.
    """
    var out = prepare_stream_headers(
        "POST", _u(), HeaderMap(), "ua/1", body_size=1234
    )
    assert_equal(out.get("content-length"), "1234")


def test_unknown_body_size_omits_content_length() raises:
    var out = prepare_stream_headers(
        "POST", _u(), HeaderMap(), "ua/1", body_size=-1
    )
    assert_equal(out.get("content-length"), "")


def test_rejects_header_values_that_could_inject() raises:
    """CR, LF and NUL are refused rather than escaped or dropped."""
    for bad in ["a\rb", "a\nb", "a\r\nX-Evil: 1", String("a\0b")]:
        var h = HeaderMap()
        h.set_unchecked("X-Bad", "x-bad", bad)
        with assert_raises():
            _ = prepare_stream_headers("GET", _u(), h, "ua/1")


def test_rejects_field_names_that_are_not_tokens() raises:
    for bad in ["X Bad", "X:Bad", "X(Bad)", "X@Bad", "X\tBad", ""]:
        var h = HeaderMap()
        h.set_unchecked(bad, bad.lower(), "v")
        with assert_raises():
            _ = prepare_stream_headers("GET", _u(), h, "ua/1")


def test_rejects_connect_and_expect() raises:
    """Both would need machinery the streaming writer does not have.

    CONNECT is a tunnel, not a request with a body. Expect would need
    100-continue handling, and pretending to support it by dropping the
    header would leave the caller waiting for a response that the origin
    is waiting to be asked for.
    """
    with assert_raises():
        _ = prepare_stream_headers("CONNECT", _u(), HeaderMap(), "ua/1")

    var h = HeaderMap()
    h.set("Expect", "100-continue")
    with assert_raises():
        _ = prepare_stream_headers("POST", _u(), h, "ua/1")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
