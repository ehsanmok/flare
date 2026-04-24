"""Tests for ``flare.http.routes``: ``ComptimeRoute`` + ``ComptimeRouter``.

Covers the comptime-compiled dispatch path with feature-parity against
the runtime ``Router`` in [`test_router.mojo`](./test_router.mojo):

- Literal, parameter (``:name``), and wildcard-tail (``*``) segments.
- Method dispatch (``GET`` / ``POST`` / ``PUT`` / ``DELETE``).
- 404 on unknown paths.
- 405 with synthesised ``Allow:`` header on wrong method.
- Query-string stripping before match.
- ``set_handler`` bounds checking.
- Unbound slot → 500-class ``Error`` raise.
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)

from flare.http import (
    ComptimeRoute,
    ComptimeRouter,
    Request,
    Response,
    Status,
    Method,
    ok,
)


def _home(req: Request) raises -> Response:
    return ok("home")


def _list_users(req: Request) raises -> Response:
    return ok("list")


def _create_user(req: Request) raises -> Response:
    return ok("created")


def _get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))


def _get_files(req: Request) raises -> Response:
    return ok("files=" + req.param("*"))


def _delete_user(req: Request) raises -> Response:
    return ok("deleted=" + req.param("id"))


comptime _BASE_ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/"),
    ComptimeRoute(Method.GET, "/users"),
    ComptimeRoute(Method.POST, "/users"),
    ComptimeRoute(Method.GET, "/users/:id"),
    ComptimeRoute(Method.DELETE, "/users/:id"),
    ComptimeRoute(Method.GET, "/files/*"),
]


def _router() raises -> ComptimeRouter[_BASE_ROUTES]:
    """Build a fresh router bound to all six handlers in `_BASE_ROUTES`."""
    var r = ComptimeRouter[_BASE_ROUTES]()
    r.set_handler(0, _home)
    r.set_handler(1, _list_users)
    r.set_handler(2, _create_user)
    r.set_handler(3, _get_user)
    r.set_handler(4, _delete_user)
    r.set_handler(5, _get_files)
    return r^


# ── Literal matches ─────────────────────────────────────────────────────────


def test_literal_root() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "home")


def test_literal_users() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/users"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "list")


def test_literal_trailing_slash_matches() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/users/"))
    # Trailing slash produces the same set of non-empty segments.
    assert_equal(resp.status, Status.OK)


# ── Parameter match ─────────────────────────────────────────────────────────


def test_param_extraction() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/users/42"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "user=42")


def test_param_long_value() raises:
    var r = _router()
    var resp = r.serve(
        Request(method=Method.GET, url="/users/aa-bb-cc-dd-ee-ff")
    )
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "user=aa-bb-cc-dd-ee-ff")


# ── Wildcard match ──────────────────────────────────────────────────────────


def test_wildcard_single() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/files/one"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "files=one")


def test_wildcard_deep() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/files/a/b/c.txt"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "files=a/b/c.txt")


# ── Method dispatch + 405 ───────────────────────────────────────────────────


def test_post_users() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.POST, url="/users"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "created")


def test_delete_user() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.DELETE, url="/users/7"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "deleted=7")


def test_method_not_allowed_on_users() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.PUT, url="/users"))
    assert_equal(resp.status, Status.METHOD_NOT_ALLOWED)
    var allow = resp.headers.get("Allow")
    # Allow must list both GET and POST (order is route-declaration order).
    assert_true("GET" in allow)
    assert_true("POST" in allow)


def test_method_not_allowed_on_users_id() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.PATCH, url="/users/5"))
    assert_equal(resp.status, Status.METHOD_NOT_ALLOWED)
    var allow = resp.headers.get("Allow")
    assert_true("GET" in allow)
    assert_true("DELETE" in allow)


# ── 404 on unknown path ─────────────────────────────────────────────────────


def test_unknown_path_returns_404() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/unknown"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_partial_prefix_returns_404() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/user"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_deeper_path_returns_404() raises:
    var r = _router()
    # ``/users/:id`` has exactly two segments; three segments are
    # handled only by ``/files/*``, not by the users namespace.
    var resp = r.serve(Request(method=Method.GET, url="/users/1/posts"))
    assert_equal(resp.status, Status.NOT_FOUND)


# ── Query string is stripped before match ───────────────────────────────────


def test_query_stripped_before_match() raises:
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/users/9?expand=1"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "user=9")


# ── set_handler error paths ─────────────────────────────────────────────────


def test_set_handler_out_of_range_raises() raises:
    var r = ComptimeRouter[_BASE_ROUTES]()
    with assert_raises():
        r.set_handler(99, _home)


def test_set_handler_negative_raises() raises:
    var r = ComptimeRouter[_BASE_ROUTES]()
    with assert_raises():
        r.set_handler(-1, _home)


# ── Unbound slot raises on dispatch ─────────────────────────────────────────


def test_unbound_slot_raises() raises:
    var r = ComptimeRouter[_BASE_ROUTES]()
    # Only bind index 0; hitting /users/42 requires slot 3.
    r.set_handler(0, _home)
    with assert_raises():
        _ = r.serve(Request(method=Method.GET, url="/users/42"))


# ── Parity with runtime Router on the match primitive ──────────────────────


def test_comptime_matches_runtime_route_shape() raises:
    """Sanity-check: the comptime table recognises routes in registration
    order, so handler 0 is always ``/``.
    """
    var r = _router()
    var resp = r.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "home")


# ── Entry ──────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_routes_comptime.mojo — ComptimeRouter")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
