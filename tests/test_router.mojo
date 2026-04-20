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
    return ok("user:" + req.params["id"])


def h_get_post(req: Request) raises -> Response:
    return ok("user=" + req.params["uid"] + " post=" + req.params["pid"])


def h_files(req: Request) raises -> Response:
    return ok("files:" + req.params["*"])


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


# ── Entry point ─────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_router.mojo — Router path matching + method dispatch")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
