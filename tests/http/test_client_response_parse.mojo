"""The buffered client response parser: one set of head and framing
rules, shared with the streaming reader.

The buffered parser used to skip colonless lines, accept obs-fold and
whitespace before the colon, take either of two conflicting
Content-Lengths, return a ``103 Early Hints`` as the response, read a
HEAD response's Content-Length as a body to wait for, and truncate a
short Content-Length body silently. The streaming reader refused all
of it; now both use ``_parse_response_head`` / ``_response_framing``.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from std.ffi import external_call

from flare.http._client.parse import (
    _extract_body_and_trailers,
    _parse_http_response,
    _read_http_response_framed,
)
from flare.io.buf_reader import Readable
from flare.http.headers import HeaderMap


def _b(s: String) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def _refused(raw: String, method: String = "GET") -> Bool:
    try:
        _ = _parse_http_response(_b(raw), method)
        return False
    except:
        return True


def test_obs_fold_is_refused() raises:
    assert_true(
        _refused(
            "HTTP/1.1 200 OK\r\nX-A: b\r\n evil: v\r\nContent-Length: 0\r\n\r\n"
        )
    )


def test_bare_lf_head_cannot_hide_a_blank_line() raises:
    """H1-07: an LF-recognising peer ends this head at ``\\n\\n``.

    The client used to read to the first CRLFCRLF and skip the empty line,
    so ``Set-Cookie`` here was a header field to flare and body to a cache
    in front of it.
    """
    assert_true(
        _refused(
            "HTTP/1.1 200 OK\nX: a\n\nSet-Cookie: s=evil\r\nContent-Length:"
            " 4\r\n\r\nbody"
        )
    )
    assert_true(
        _refused(
            "HTTP/1.1 200 OK\r\nX: a\n\r\nSet-Cookie: s=evil\r\nContent-Length:"
            " 0\r\n\r\n"
        )
    )


def test_bare_lf_in_head_is_refused() raises:
    assert_true(_refused("HTTP/1.1 200 OK\nContent-Length: 2\r\n\r\nhi"))
    assert_true(_refused("HTTP/1.1 200 OK\r\nContent-Length: 2\n\r\n\r\nhi"))


def test_crlf_head_is_still_parsed() raises:
    var resp = _parse_http_response(
        _b("HTTP/1.1 200 OK\r\nX: a\r\nContent-Length: 2\r\n\r\nhi"), "GET"
    )
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("x"), "a")


def test_status_code_of_more_than_three_digits_is_refused() raises:
    """H1-08: ``HTTP/1.1 2041 OK`` is not a 204 with a stray digit.

    status-code is exactly 3DIGIT (RFC 9112 sec 4). A 204 has no body, so
    reading the code as 204 left the real body on the connection.
    """
    assert_true(_refused("HTTP/1.1 2041 OK\r\nContent-Length: 5\r\n\r\nhello"))
    assert_true(_refused("HTTP/1.1 1004 Hm\r\nContent-Length: 0\r\n\r\n"))
    assert_true(_refused("HTTP/1.1 20x OK\r\nContent-Length: 0\r\n\r\n"))


def test_status_line_with_and_without_reason_is_parsed() raises:
    var with_reason = _parse_http_response(
        _b("HTTP/1.1 204 No Content\r\n\r\n"), "GET"
    )
    assert_equal(with_reason.status, 204)
    var bare = _parse_http_response(
        _b("HTTP/1.1 200\r\nContent-Length: 2\r\n\r\nhi"), "GET"
    )
    assert_equal(bare.status, 200)
    var empty_reason = _parse_http_response(
        _b("HTTP/1.1 200 \r\nContent-Length: 2\r\n\r\nhi"), "GET"
    )
    assert_equal(empty_reason.status, 200)


struct _Wire(Movable, Readable):
    """A readable that serves ``text`` and then reports end of stream."""

    var bytes: List[UInt8]
    var pos: Int

    def __init__(out self, text: String):
        self.bytes = List[UInt8](text.as_bytes())
        self.pos = 0

    def read(mut self, buf: Pointer[UInt8, _], size: Int) raises -> Int:
        var n = min(size, len(self.bytes) - self.pos)
        if n > 0:
            _ = external_call["memcpy", NoneType, Int, Int, Int](
                Int(buf),
                Int(self.bytes.unsafe_ptr().unsafe_offset(self.pos)),
                n,
            )
        self.pos += n
        return n


def _reusable(wire: String) raises -> Bool:
    var s = _Wire(wire)
    var reuse = False
    _ = _read_http_response_framed(s, reuse, "GET")
    return reuse


def test_only_an_http11_response_keeps_the_connection() raises:
    """H1-09: RFC 9112 sec 9.3 -- HTTP/1.0 closes unless it says keep-alive.

    The reuse decision ignored the response version, so an HTTP/1.0 answer
    sent the connection back to the pool and the next request went to a
    socket the server was closing.
    """
    assert_true(
        _reusable("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
        "HTTP/1.1 stays reusable",
    )
    assert_false(
        _reusable("HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi"),
        "HTTP/1.0 must not be reused",
    )
    assert_false(
        _reusable(
            "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection:"
            " keep-alive\r\n\r\nhi"
        ),
        "HTTP/1.0 keep-alive is not pooled either",
    )
    assert_false(
        _reusable(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection:"
            " close\r\n\r\nhi"
        ),
        "Connection: close still closes",
    )


def test_whitespace_before_colon_is_refused() raises:
    assert_true(_refused("HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nhi"))


def test_colonless_line_is_refused() raises:
    assert_true(
        _refused("HTTP/1.1 200 OK\r\nTransfer-Encoding chunked\r\n\r\n")
    )


def test_duplicate_content_length_is_refused() raises:
    assert_true(
        _refused(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length:"
            " 5\r\n\r\nhello"
        )
    )


def test_te_other_than_chunked_is_refused() raises:
    assert_true(
        _refused(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,"
            " chunked\r\n\r\n0\r\n\r\n"
        )
    )


def test_truncated_body_is_refused() raises:
    assert_true(_refused("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi"))


def test_informational_heads_are_skipped() raises:
    var r = _parse_http_response(
        _b(
            "HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n"
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        )
    )
    assert_equal(r.status, 200)
    assert_equal(len(r.body), 2)


def test_head_response_has_no_body() raises:
    var r = _parse_http_response(
        _b("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"), "HEAD"
    )
    assert_equal(r.status, 200)
    assert_equal(len(r.body), 0)
    assert_equal(r.headers.get("content-length"), "1234")


def test_204_and_304_have_no_body() raises:
    assert_equal(
        len(_parse_http_response(_b("HTTP/1.1 204 No Content\r\n\r\n")).body), 0
    )
    assert_equal(
        len(
            _parse_http_response(
                _b("HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n")
            ).body
        ),
        0,
    )


def test_well_formed_responses_still_parse() raises:
    var r = _parse_http_response(
        _b(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            "5\r\nhello\r\n0\r\n\r\n"
        )
    )
    assert_equal(r.text(), "hello")


def test_truncated_chunked_body_is_refused() raises:
    """H1-06: a chunked body that ends before its last-chunk and the empty
    line after the trailers is an incomplete message (RFC 9112 sec 7.1),
    not a short but complete one. Every proper prefix of a valid response
    must raise, for the whole-buffer parser and the legacy extractor."""
    var head = String("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
    var body = String("5\r\nhello\r\n0\r\nX-T: v\r\n\r\n")
    var full = head + body
    var r = _parse_http_response(_b(full))
    assert_equal(r.text(), "hello")
    assert_equal(r.trailers.get("x-t"), "v")
    for cut in range(head.byte_length(), full.byte_length()):
        var prefix = String(String(unsafe_from_utf8=full.as_bytes()[:cut]))
        assert_true(
            _refused(prefix), "accepted a response cut at " + String(cut)
        )
    # The pure parser used to return "hel" here.
    assert_true(_refused(head + "5\r\nhel"))
    # Missing the final empty line, or the CRLF after a chunk.
    assert_true(_refused(head + "5\r\nhello\r\n0\r\n"))
    assert_true(_refused(head + "5\r\nhello0\r\n\r\n"))
    # Bytes after a complete body are not part of it.
    var extra = _parse_http_response(_b(full + "GET / HTTP/1.1\r\n"))
    assert_equal(extra.text(), "hello")


def test_extract_body_refuses_truncated_chunked() raises:
    var headers = HeaderMap()
    headers.append("Transfer-Encoding", "chunked")
    var trailers = HeaderMap()
    var cut = _b("5\r\nhel")
    var raised = False
    try:
        _ = _extract_body_and_trailers(cut, 0, headers, trailers)
    except:
        raised = True
    assert_true(raised)
    var ok = _extract_body_and_trailers(
        _b("5\r\nhello\r\n0\r\n\r\n"), 0, headers, trailers
    )
    assert_equal(String(unsafe_from_utf8=Span[UInt8, _](ok)), "hello")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
