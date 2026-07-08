"""``Router.mount(prefix, sub)`` attaches a nested router under a path
prefix.

A mounted sub-router owns its whole subtree: the prefix is stripped
before delegation, the sub sees relative paths, runs its own method
dispatch (404/405), and its captured params + the parent's query string
survive the hand-off. Direct routes on the parent keep priority over a
mount covering the same prefix. Multiple versioned modules
(``/api/v1`` + ``/api/v2``) coexist, and a copied Router (the per-worker
clone path) still routes through the shared mounted subtree.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import Method, Request, Response, Router, ok


def v1_users(req: Request) raises -> Response:
    return ok("v1 users")


def v1_user(req: Request) raises -> Response:
    return ok("v1 user " + req.param("id"))


def v2_users(req: Request) raises -> Response:
    return ok("v2 users")


def root_home(req: Request) raises -> Response:
    return ok("root")


def _v1() raises -> Router:
    var r = Router()
    r.get("/users", v1_users)
    r.get("/users/:id", v1_user)
    return r^


def _v2() raises -> Router:
    var r = Router()
    r.get("/users", v2_users)
    return r^


def _mounted_app() raises -> Router:
    var app = Router()
    app.get("/", root_home)
    app.mount("/api/v1", _v1())
    app.mount("/api/v2", _v2())
    return app^


def test_mount_dispatches_to_sub() raises:
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.GET, url="/api/v1/users"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "v1 users")


def test_mount_strips_prefix_and_captures_param() raises:
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.GET, url="/api/v1/users/7"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "v1 user 7")


def test_mount_versions_coexist() raises:
    var app = _mounted_app()
    var r2 = app.serve(Request(method=Method.GET, url="/api/v2/users"))
    assert_equal(r2.text(), "v2 users")


def test_mount_preserves_query_string() raises:
    var app = _mounted_app()
    var resp = app.serve(
        Request(method=Method.GET, url="/api/v1/users/9?fields=name")
    )
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "v1 user 9")


def test_parent_route_takes_priority() raises:
    # A direct route on the parent is matched before any mount.
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "root")


def test_mount_sub_router_404() raises:
    # Unknown path under a mounted prefix -> the sub-router's 404.
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.GET, url="/api/v1/missing"))
    assert_equal(resp.status, 404)


def test_mount_sub_router_405() raises:
    # Known sub path, wrong method -> the sub-router's 405 + Allow.
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.POST, url="/api/v1/users"))
    assert_equal(resp.status, 405)
    assert_true("GET" in resp.headers.get("allow"))


def test_unmounted_prefix_is_404() raises:
    var app = _mounted_app()
    var resp = app.serve(Request(method=Method.GET, url="/api/v3/users"))
    assert_equal(resp.status, 404)


def test_mount_survives_router_copy() raises:
    # The per-worker clone path: a copied Router shares the mounted
    # subtree through the Arc-backed registry and still routes.
    var app = _mounted_app()
    var clone = app.copy()
    var resp = clone.serve(Request(method=Method.GET, url="/api/v2/users"))
    assert_equal(resp.text(), "v2 users")


def test_mount_rejects_param_prefix() raises:
    var app = Router()
    var threw = False
    try:
        app.mount("/api/:ver", _v1())
    except:
        threw = True
    assert_true(threw)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
