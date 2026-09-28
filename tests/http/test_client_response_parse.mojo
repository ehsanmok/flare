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

from flare.http._client.parse import _parse_http_response


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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
