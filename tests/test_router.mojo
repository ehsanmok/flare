"""Tests for ``flare.http.Router``.

Covers:

- Literal path matching (exact, leading/trailing slashes).
- Parameter segments (``:name``) and their appearance in ``req.params``.
- Wildcard tail (``*``) capturing multi-segment remainders.
- Method dispatch (GET / POST / PUT / PATCH / DELETE / HEAD).
- 404 for unknown paths.
- 405 Method Not Allowed with an ``Allow:`` header listing supported
  methods.
- ``mount(prefix, sub)`` for nesting.
- Query-string stripping (``"/users?x=1"`` still routes to ``/users``).
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)

from flare.http import (
    Router,
    Request,
    Response,
    Status,
    Method,
    ok,
)
from flare.http.handler import Handler


# ── Handler functions used across tests ─────────────────────────────────────


def h_home(req: Request) raises -> Response:
    return ok("home")


def h_list_users(req: Request) raises -> Response:
    return ok("list")


def h_create_user(req: Request) raises -> Response:
    return ok("created")


def h_get_user(req: Request) raises -> Response:
    return ok("user:" + req.param("id"))


def h_get_post(req: Request) raises -> Response:
    return ok("user=" + req.param("uid") + " post=" + req.param("pid"))


def h_files(req: Request) raises -> Response:
    return ok("files:" + req.param("*"))


def h_delete_user(req: Request) raises -> Response:
    return ok("deleted")


def h_admin(req: Request) raises -> Response:
    return ok("admin:" + req.url)


# ── Literal paths ───────────────────────────────────────────────────────────


def test_literal_root() raises:
    """Literal ``/`` matches exactly the root."""
    var r = Router()
    r.get("/", h_home)
    var resp = r.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "home")


def test_literal_multi_segment() raises:
    """Literal ``/users`` matches exactly."""
    var r = Router()
    r.get("/users", h_list_users)
    var resp = r.serve(Request(method=Method.GET, url="/users"))
    assert_equal(resp.text(), "list")


def test_literal_not_matched_returns_404() raises:
    """A different literal path returns 404."""
    var r = Router()
    r.get("/users", h_list_users)
    var resp = r.serve(Request(method=Method.GET, url="/other"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_trailing_slash_ignored_on_request() raises:
    """Trailing slash on request URL still matches the literal route."""
    var r = Router()
    r.get("/users", h_list_users)
    var resp = r.serve(Request(method=Method.GET, url="/users/"))
    assert_equal(resp.text(), "list")


def test_trailing_slash_ignored_on_route() raises:
    """Trailing slash on route pattern still matches a plain URL."""
    var r = Router()
    r.get("/users/", h_list_users)
    var resp = r.serve(Request(method=Method.GET, url="/users"))
    assert_equal(resp.text(), "list")


# ── Parameter segments ──────────────────────────────────────────────────────


def test_param_single() raises:
    """``:id`` captures a segment into req.params."""
    var r = Router()
    r.get("/users/:id", h_get_user)
    var resp = r.serve(Request(method=Method.GET, url="/users/42"))
    assert_equal(resp.text(), "user:42")


def test_param_multiple() raises:
    """Multiple params in one pattern get captured separately."""
    var r = Router()
    r.get("/users/:uid/posts/:pid", h_get_post)
    var resp = r.serve(Request(method=Method.GET, url="/users/3/posts/7"))
    assert_equal(resp.text(), "user=3 post=7")


def test_param_does_not_match_too_short() raises:
    """A pattern with a parameter does not match shorter paths."""
    var r = Router()
    r.get("/users/:id", h_get_user)
    var resp = r.serve(Request(method=Method.GET, url="/users"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_param_does_not_match_too_long() raises:
    """A pattern with a parameter does not match longer paths."""
    var r = Router()
    r.get("/users/:id", h_get_user)
    var resp = r.serve(Request(method=Method.GET, url="/users/42/extra"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_param_named_value() raises:
    """Captured param is the exact text of the segment."""
    var r = Router()
    r.get("/users/:id", h_get_user)
    var resp = r.serve(Request(method=Method.GET, url="/users/abc-DEF-123"))
    assert_equal(resp.text(), "user:abc-DEF-123")


# ── Wildcard tail ───────────────────────────────────────────────────────────


def test_wildcard_one_segment() raises:
    """``*`` captures a single remaining segment."""
    var r = Router()
    r.get("/files/*", h_files)
    var resp = r.serve(Request(method=Method.GET, url="/files/hello.txt"))
    assert_equal(resp.text(), "files:hello.txt")


def test_wildcard_many_segments() raises:
    """``*`` captures multiple remaining segments joined by ``/``."""
    var r = Router()
    r.get("/files/*", h_files)
    var resp = r.serve(
        Request(method=Method.GET, url="/files/deep/nested/file.txt")
    )
    assert_equal(resp.text(), "files:deep/nested/file.txt")


def test_wildcard_zero_segments_does_not_match() raises:
    """Wildcard requires at least one remaining segment."""
    var r = Router()
    r.get("/files/*", h_files)
    var resp = r.serve(Request(method=Method.GET, url="/files"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_wildcard_not_last_rejected() raises:
    """A wildcard not in the final position is rejected at registration."""
    var r = Router()
    with assert_raises():
        r.get("/files/*/extra", h_files)


# ── Method dispatch ─────────────────────────────────────────────────────────


def test_method_get_and_post_on_same_path() raises:
    """GET and POST on the same path dispatch to different handlers."""
    var r = Router()
    r.get("/users", h_list_users)
    r.post("/users", h_create_user)
    var get_resp = r.serve(Request(method=Method.GET, url="/users"))
    var post_resp = r.serve(Request(method=Method.POST, url="/users"))
    assert_equal(get_resp.text(), "list")
    assert_equal(post_resp.text(), "created")


def test_method_wrong_on_known_path_returns_405() raises:
    """Wrong method on a known path returns 405."""
    var r = Router()
    r.get("/users", h_list_users)
    var resp = r.serve(Request(method=Method.POST, url="/users"))
    assert_equal(resp.status, Status.METHOD_NOT_ALLOWED)


def test_method_not_allowed_includes_allow_header() raises:
    """405 responses list supported methods in an ``Allow:`` header."""
    var r = Router()
    r.get("/users", h_list_users)
    r.delete("/users", h_delete_user)
    var resp = r.serve(Request(method=Method.POST, url="/users"))
    assert_equal(resp.status, Status.METHOD_NOT_ALLOWED)
    var allow = resp.headers.get("Allow")
    assert_true(allow.find("GET") >= 0)
    assert_true(allow.find("DELETE") >= 0)


def test_method_all_six() raises:
    """All six major HTTP methods each get their own route."""
    var r = Router()
    r.get("/x", h_home)
    r.post("/x", h_home)
    r.put("/x", h_home)
    r.patch("/x", h_home)
    r.delete("/x", h_home)
    r.head("/x", h_home)
    assert_equal(r.serve(Request(method=Method.GET, url="/x")).status, 200)
    assert_equal(r.serve(Request(method=Method.POST, url="/x")).status, 200)
    assert_equal(r.serve(Request(method=Method.PUT, url="/x")).status, 200)
    assert_equal(r.serve(Request(method=Method.PATCH, url="/x")).status, 200)
    assert_equal(r.serve(Request(method=Method.DELETE, url="/x")).status, 200)
    assert_equal(r.serve(Request(method=Method.HEAD, url="/x")).status, 200)


# ── 404 for unknown paths ───────────────────────────────────────────────────


def test_404_empty_router() raises:
    """A router with no routes returns 404 for any request."""
    var r = Router()
    var resp = r.serve(Request(method=Method.GET, url="/anywhere"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_404_unknown_path() raises:
    """A path that matches no registered route returns 404."""
    var r = Router()
    r.get("/users", h_list_users)
    var resp = r.serve(Request(method=Method.GET, url="/admin"))
    assert_equal(resp.status, Status.NOT_FOUND)


# ── Query string handling ───────────────────────────────────────────────────


def test_query_string_stripped() raises:
    """Routing ignores the ``?query=...`` portion of the URL."""
    var r = Router()
    r.get("/search", h_home)
    var resp = r.serve(
        Request(method=Method.GET, url="/search?q=mojo&limit=10")
    )
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "home")


def test_query_string_with_param() raises:
    """Query-string stripping does not interfere with path params."""
    var r = Router()
    r.get("/users/:id", h_get_user)
    var resp = r.serve(Request(method=Method.GET, url="/users/5?format=json"))
    assert_equal(resp.text(), "user:5")


@fieldwise_init
struct _RouterWrapper[Inner: Handler](Handler):
    """Tiny test wrapper proving ``Router`` satisfies ``Handler``."""

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        return self.inner.serve(req)


# ── Router is a Handler ─────────────────────────────────────────────────────


def test_router_is_handler() raises:
    """Router can be wrapped by a struct that takes a Handler."""
    var r = Router()
    r.get("/", h_home)
    var wrapped = _RouterWrapper(r^)
    var resp = wrapped.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "home")


# ── — Router accepts Handler structs (Track 1.4) ─────────────

# Tiny stateful Handler used by the struct-handler tests below.
# The Router's `get[H]` / `post[H]` / etc. heap-allocate `H`,
# capture monomorphised serve / destroy thunks, and free in
# Router.__del__. Each test exercises a different facet of the
# new dispatch path.


@fieldwise_init
struct _StatefulGreeter(Copyable, Handler, Movable):
    """Handler with state that shows the boxed value survives
    registration + dispatch."""

    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting + ":" + req.url)


def test_router_get_accepts_handler_struct() raises:
    """``Router.get[H]`` accepts an ``H: Handler`` struct."""
    var r = Router()
    r.get[_StatefulGreeter]("/hi", _StatefulGreeter("hello"))
    var resp = r.serve(Request(method=Method.GET, url="/hi"))
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "hello:/hi")


def test_router_post_accepts_handler_struct() raises:
    var r = Router()
    r.post[_StatefulGreeter]("/echo", _StatefulGreeter("posted"))
    var resp = r.serve(Request(method=Method.POST, url="/echo"))
    assert_equal(resp.text(), "posted:/echo")


def test_router_put_patch_delete_head_accept_handler_structs() raises:
    """All six method overloads accept ``H: Handler`` structs."""
    var r = Router()
    r.put[_StatefulGreeter]("/x", _StatefulGreeter("PUT"))
    r.patch[_StatefulGreeter]("/x", _StatefulGreeter("PATCH"))
    r.delete[_StatefulGreeter]("/x", _StatefulGreeter("DEL"))
    r.head[_StatefulGreeter]("/x", _StatefulGreeter("HEAD"))
    assert_equal(r.serve(Request(method=Method.PUT, url="/x")).text(), "PUT:/x")
    assert_equal(
        r.serve(Request(method=Method.PATCH, url="/x")).text(),
        "PATCH:/x",
    )
    assert_equal(
        r.serve(Request(method=Method.DELETE, url="/x")).text(),
        "DEL:/x",
    )
    assert_equal(
        r.serve(Request(method=Method.HEAD, url="/x")).text(),
        "HEAD:/x",
    )


def test_router_mixes_def_and_struct_handlers() raises:
    """Same Router holds a ``def(Request) -> Response`` and an
    ``H: Handler`` struct on parallel paths; dispatch picks the
    right kind per route."""
    var r = Router()
    r.get("/fn", h_home)
    r.get[_StatefulGreeter]("/struct", _StatefulGreeter("S"))
    var fn_resp = r.serve(Request(method=Method.GET, url="/fn"))
    var struct_resp = r.serve(Request(method=Method.GET, url="/struct"))
    assert_equal(fn_resp.text(), "home")
    assert_equal(struct_resp.text(), "S:/struct")


def test_router_404_with_struct_handler_present() raises:
    """An unknown path still returns 404 even when struct handlers
    are registered."""
    var r = Router()
    r.get[_StatefulGreeter]("/known", _StatefulGreeter("K"))
    var resp = r.serve(Request(method=Method.GET, url="/missing"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_router_405_with_struct_handler_present() raises:
    """405 Method Not Allowed still includes the Allow header when
    a struct handler is the registered method."""
    var r = Router()
    r.get[_StatefulGreeter]("/users", _StatefulGreeter("G"))
    var resp = r.serve(Request(method=Method.POST, url="/users"))
    assert_equal(resp.status, Status.METHOD_NOT_ALLOWED)
    var allow = resp.headers.get("Allow")
    assert_true(allow.find("GET") >= 0)


struct _IdEcho(Copyable, Defaultable, Handler, Movable):
    """Stateless Handler used by
    ``test_router_struct_handler_path_param_capture``. Echoes the
    captured ``:id`` path param.
    """

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return ok("id=" + req.param("id"))


def test_router_struct_handler_path_param_capture() raises:
    """``:id``-style path params still populate ``req.params``
    when the route's handler is a struct."""
    var r = Router()
    r.get[_IdEcho]("/users/:id", _IdEcho())
    var resp = r.serve(Request(method=Method.GET, url="/users/42"))
    assert_equal(resp.text(), "id=42")


def test_router_drops_struct_handlers_cleanly() raises:
    """Stress: register 100 struct handlers on a Router, then drop
    it. Each ``H`` must be freed via the matching destroy thunk;
    no leaks (validated by the test process not crashing on
    repeated runs).
    """
    for _ in range(5):
        var r = Router()
        for i in range(100):
            r.get[_StatefulGreeter](
                "/p" + String(i), _StatefulGreeter("g" + String(i))
            )
        # ``r`` drops here; Router.__del__ runs every destroy_thunk.


# ── Entry point ─────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_router.mojo — Router path matching + method dispatch")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
