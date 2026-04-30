"""Tests for request / response cookie ergonomics (— track A).

Covers:

- ``Request.cookies()`` parses ``Cookie`` request header(s) and returns
  a populated ``CookieJar`` (empty when header absent).
- ``Request.cookie(name)`` / ``has_cookie(name)`` convenience helpers.
- Multiple ``Cookie`` headers (RFC 7230 paragraph 3.2.2) are merged.
- ``Response.set_cookie(c)`` emits one ``Set-Cookie`` header per call,
  preserves cookie attributes, and supports adding multiple cookies.
- ``Response.cookies()`` round-trips through
  ``parse_set_cookie_header``.
- ``Cookies`` extractor returns an equivalent ``CookieJar`` value.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http import (
    Cookie,
    CookieJar,
    Cookies,
    Method,
    Request,
    Response,
    SameSite,
)


def test_request_cookies_empty() raises:
    var req = Request(method=Method.GET, url="/")
    var jar = req.cookies()
    assert_equal(jar.len(), 0)
    assert_false(jar.contains("session"))


def test_request_cookies_single_header() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", "session=abc; theme=dark")
    var jar = req.cookies()
    assert_equal(jar.len(), 2)
    assert_equal(jar.get("session"), "abc")
    assert_equal(jar.get("theme"), "dark")


def test_request_cookies_multi_header() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.append("Cookie", "session=abc")
    req.headers.append("Cookie", "csrf=xyz")
    var jar = req.cookies()
    assert_equal(jar.len(), 2)
    assert_equal(jar.get("session"), "abc")
    assert_equal(jar.get("csrf"), "xyz")


def test_request_cookie_helper() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", "k=v; m=w")
    assert_equal(req.cookie("k"), "v")
    assert_equal(req.cookie("m"), "w")
    assert_equal(req.cookie("missing"), "")


def test_request_has_cookie() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", "k=v")
    assert_true(req.has_cookie("k"))
    assert_false(req.has_cookie("nope"))


def test_response_set_cookie_basic() raises:
    var resp = Response(status=200)
    resp.set_cookie(Cookie("session", "abc"))
    var values = resp.headers.get_all("set-cookie")
    assert_equal(len(values), 1)
    assert_equal(values[0], "session=abc")


def test_response_set_cookie_attributes() raises:
    var resp = Response(status=200)
    resp.set_cookie(
        Cookie(
            name="sid",
            value="xyz",
            domain="example.com",
            path="/",
            max_age=3600,
            secure=True,
            http_only=True,
            same_site=SameSite.STRICT,
        )
    )
    var got = resp.headers.get("set-cookie")
    assert_true("sid=xyz" in got)
    assert_true("Domain=example.com" in got)
    assert_true("Path=/" in got)
    assert_true("Max-Age=3600" in got)
    assert_true("Secure" in got)
    assert_true("HttpOnly" in got)
    assert_true("SameSite=Strict" in got)


def test_response_set_cookie_multiple() raises:
    var resp = Response(status=200)
    resp.set_cookie(Cookie("a", "1"))
    resp.set_cookie(Cookie("b", "2"))
    var values = resp.headers.get_all("set-cookie")
    assert_equal(len(values), 2)


def test_response_cookies_roundtrip() raises:
    var resp = Response(status=200)
    resp.set_cookie(Cookie(name="a", value="1", path="/"))
    resp.set_cookie(Cookie(name="b", value="2", secure=True))
    var jar = resp.cookies()
    assert_equal(jar.len(), 2)
    assert_equal(jar.get("a"), "1")
    assert_equal(jar.get("b"), "2")


def test_cookies_extractor() raises:
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Cookie", "user=alice; theme=dark")
    var ck = Cookies.extract(req)
    assert_equal(ck.value.len(), 2)
    assert_equal(ck.value.get("user"), "alice")
    assert_equal(ck.value.get("theme"), "dark")


def test_cookies_extractor_empty() raises:
    var req = Request(method=Method.GET, url="/")
    var ck = Cookies.extract(req)
    assert_equal(ck.value.len(), 0)


def main() raises:
    test_request_cookies_empty()
    test_request_cookies_single_header()
    test_request_cookies_multi_header()
    test_request_cookie_helper()
    test_request_has_cookie()
    test_response_set_cookie_basic()
    test_response_set_cookie_attributes()
    test_response_set_cookie_multiple()
    test_response_cookies_roundtrip()
    test_cookies_extractor()
    test_cookies_extractor_empty()
    print("test_request_cookies: 11 passed")
