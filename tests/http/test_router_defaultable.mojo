"""Router satisfies ``Defaultable`` so stock middleware composes over it.

Before v0.9 ``Router`` was ``Handler & Copyable & Movable`` but **not**
``Defaultable``, so the stock middleware family -- whose inner bound is
``Handler & Copyable & Defaultable`` (see ``flare.http.middleware``) --
could not wrap a ``Router`` directly. Callers had to hand-roll a
Defaultable forwarding struct. These tests pin the now-direct
composition: ``Logger[Router]`` and ``RequestId[Router]`` build and route.
"""

from std.testing import assert_equal, TestSuite

from flare.http import (
    Logger,
    Method,
    Request,
    RequestId,
    Response,
    Router,
    ok,
)


def h_home(req: Request) raises -> Response:
    return ok("home")


def h_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))


def _router_with_routes() raises -> Router:
    var r = Router()
    r.get("/", h_home)
    r.get("/users/:id", h_user)
    return r^


def test_router_is_defaultable_default_construct() raises:
    # The Defaultable contract: a no-arg constructor. If Router did not
    # conform this line would not type-check against Defaultable users.
    var r = Router()
    var resp = r.serve(Request(method=Method.GET, url="/"))
    # Empty router -> 404.
    assert_equal(resp.status, 404)


def test_logger_wraps_router() raises:
    var lg = Logger(_router_with_routes(), prefix="[t]")
    var resp = lg.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "home")


def test_logger_wraps_router_param_route() raises:
    var lg = Logger(_router_with_routes(), prefix="[t]")
    var resp = lg.serve(Request(method=Method.GET, url="/users/42"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "user 42")


def test_request_id_wraps_router() raises:
    var rid = RequestId(_router_with_routes())
    var req = Request(method=Method.GET, url="/")
    req.headers.set("X-Request-Id", "abc-123")
    var resp = rid.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.headers.get("x-request-id"), "abc-123")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
