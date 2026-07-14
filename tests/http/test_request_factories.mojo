"""Tests for the ``Request.test_get`` / ``Request.test_post`` static
factories that cookbook examples and unit tests use to build
synthetic requests without a live socket.
"""

from std.testing import assert_equal, assert_true

from flare.http import Method, Request


def test_test_get_basic() raises:
    """``test_get`` sets method to GET and the url, with empty body
    and HTTP/1.1 version."""
    var req = Request.test_get("/users/42")
    assert_equal(req.method, Method.GET)
    assert_equal(req.url, "/users/42")
    assert_equal(req.version, "HTTP/1.1")
    assert_equal(len(req.body), 0)


def test_test_get_with_query_string() raises:
    """The url argument is opaque -- query strings flow through verbatim."""
    var req = Request.test_get("/search?q=mojo&limit=10")
    assert_equal(req.url, "/search?q=mojo&limit=10")
    assert_equal(req.query_param("q"), "mojo")
    assert_equal(req.query_param("limit"), "10")


def test_test_post_default_content_type() raises:
    """``test_post`` with no content_type sets ``application/octet-stream``."""
    var req = Request.test_post("/echo", "hello")
    assert_equal(req.method, Method.POST)
    assert_equal(req.url, "/echo")
    assert_equal(req.version, "HTTP/1.1")
    assert_equal(req.text(), "hello")
    assert_equal(req.headers.get("Content-Type"), "application/octet-stream")


def test_test_post_explicit_content_type() raises:
    """``test_post`` with ``content_type`` sets that value."""
    var req = Request.test_post(
        "/users", '{"name":"alice"}', content_type="application/json"
    )
    assert_equal(req.headers.get("Content-Type"), "application/json")
    assert_equal(req.text(), '{"name":"alice"}')


def test_test_post_form_urlencoded() raises:
    """The form-data shape uses application/x-www-form-urlencoded."""
    var req = Request.test_post(
        "/login",
        "user=alice&password=secret",
        content_type="application/x-www-form-urlencoded",
    )
    assert_equal(
        req.headers.get("Content-Type"), "application/x-www-form-urlencoded"
    )
    assert_equal(req.text(), "user=alice&password=secret")


def test_test_post_empty_body() raises:
    """An empty body is allowed -- POST with no payload."""
    var req = Request.test_post("/ping", "")
    assert_equal(req.method, Method.POST)
    assert_equal(len(req.body), 0)


def test_factories_carry_default_peer() raises:
    """Both factories default to localhost peer (the same default as
    the regular Request constructor)."""
    var g = Request.test_get("/")
    assert_equal(String(g.peer.ip), "127.0.0.1")
    assert_equal(Int(g.peer.port), 0)
    var p = Request.test_post("/", "hi")
    assert_equal(String(p.peer.ip), "127.0.0.1")
    assert_equal(Int(p.peer.port), 0)


def test_optional_accessors_uniform_miss() raises:
    """param_opt / query_param_opt / cookie_opt give one uniform
    Optional miss semantics across the three sources."""
    var req = Request.test_get("/search?q=mojo&empty=")
    # query: present, present-empty, absent.
    var q = req.query_param_opt("q")
    assert_true(Bool(q))
    assert_equal(q.value(), "mojo")
    var e = req.query_param_opt("empty")
    assert_true(Bool(e))  # present-empty -> Some("")
    assert_equal(e.value(), "")
    assert_true(not req.query_param_opt("missing"))
    # path param: absent here (no router injected).
    assert_true(not req.param_opt("id"))
    req.params_mut()["id"] = "42"
    var pid = req.param_opt("id")
    assert_true(Bool(pid))
    assert_equal(pid.value(), "42")
    # cookie: absent.
    assert_true(not req.cookie_opt("session"))


def main() raises:
    test_test_get_basic()
    print("OK test_test_get_basic")

    test_test_get_with_query_string()
    print("OK test_test_get_with_query_string")

    test_test_post_default_content_type()
    print("OK test_test_post_default_content_type")

    test_test_post_explicit_content_type()
    print("OK test_test_post_explicit_content_type")

    test_test_post_form_urlencoded()
    print("OK test_test_post_form_urlencoded")

    test_test_post_empty_body()
    print("OK test_test_post_empty_body")

    test_factories_carry_default_peer()
    print("OK test_factories_carry_default_peer")

    test_optional_accessors_uniform_miss()
    print("OK test_optional_accessors_uniform_miss")
