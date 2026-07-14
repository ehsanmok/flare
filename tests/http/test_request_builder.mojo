"""Tests for the client-side RequestBuilder (per-request ergonomics).

Purely deterministic -- asserts the built Request's method, URL (with
percent-encoded query), headers, content-type, and body. No server.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import Method, RequestBuilder


def test_basic_get() raises:
    var b = RequestBuilder(Method.GET, "/users")
    var req = b^.build()
    assert_equal(req.method, Method.GET)
    assert_equal(req.url, "/users")
    assert_equal(len(req.body), 0)


def test_headers_appended() raises:
    var b = RequestBuilder(Method.GET, "/")
    b.header("X-A", "1")
    b.header("X-B", "2")
    var req = b^.build()
    assert_equal(req.headers.get("X-A"), "1")
    assert_equal(req.headers.get("X-B"), "2")


def test_query_encoded_and_appended() raises:
    var b = RequestBuilder(Method.GET, "/search")
    b.query("q", "a b&c")
    b.query("page", "2")
    var req = b^.build()
    # spaces -> '+', '&' -> %26; params joined with '&'.
    assert_equal(req.url, "/search?q=a+b%26c&page=2")


def test_query_merges_with_existing_query() raises:
    var b = RequestBuilder(Method.GET, "/x?a=1")
    b.query("b", "2")
    var req = b^.build()
    assert_equal(req.url, "/x?a=1&b=2")


def test_json_body_sets_content_type() raises:
    var b = RequestBuilder(Method.POST, "/items")
    b.json('{"name":"widget"}')
    var req = b^.build()
    assert_equal(req.headers.get("Content-Type"), "application/json")
    assert_equal(req.text(), '{"name":"widget"}')


def test_text_body_custom_content_type() raises:
    var b = RequestBuilder(Method.POST, "/echo")
    b.text("hello", content_type="text/csv")
    var req = b^.build()
    assert_equal(req.headers.get("Content-Type"), "text/csv")
    assert_equal(req.text(), "hello")


def test_raw_body() raises:
    var b = RequestBuilder(Method.PUT, "/blob")
    var data = List[UInt8]()
    data.append(1)
    data.append(2)
    data.append(3)
    b.body(data^, content_type="application/octet-stream")
    var req = b^.build()
    assert_equal(len(req.body), 3)
    assert_equal(req.headers.get("Content-Type"), "application/octet-stream")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
