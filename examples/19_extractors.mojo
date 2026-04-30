"""Example 19 — Typed extractors + reflective auto-injection.

Demonstrates two ways to use flare's typed extractors:

1. **Value-constructor** — call ``PathInt[name].extract(req).value``
   inside a plain handler. Direct, no struct boilerplate.
2. **Auto-injection via ``Extracted[H]``** — declare the extractors
   as the fields of a ``Handler`` struct; the adapter reflects on
   the struct, pulls each field from the request, and calls the
   inner ``serve``.

Since :

- ``Router.get(path, handler)`` accepts any ``H: Handler & Copyable
  & Movable`` (Track 1.4), so the production shape is
  ``r.get("/users/:id", Extracted[GetUser]())``.
- The concrete ``PathInt`` / ``PathStr`` / ``PathFloat`` /
  ``PathBool`` / ``QueryInt`` / ``HeaderStr`` / ... extractors
  expose ``.value`` as the primitive directly (Track 1.3) — no
  ``.value.value`` chain. The parametric ``Path[T: ParamParser,
  name]`` etc. stay public for users who want to plug in a custom
  ``ParamParser``.

Run:
    pixi run example-extractors
"""

from flare.http import (
    Request,
    Response,
    Method,
    Status,
    ok,
    PathInt,
    OptionalQueryInt,
    QueryStr,
    HeaderStr,
    Handler,
    Router,
    Extracted,
)


# ── Shape 1: value-constructor extractors inside a function handler ─────────


def list_user_posts(req: Request) raises -> Response:
    """Single-dot ``.value`` access via the concrete extractors."""
    var id = PathInt["id"].extract(req).value  # → Int
    var page_opt = OptionalQueryInt["page"].extract(req).value
    var page = 1
    if page_opt:
        page = page_opt.value()
    return ok("user " + String(id) + " posts (page " + String(page) + ")")


# ── Shape 2: Handler struct + Extracted[H] auto-injection ──────────────────


@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    """All the handler's inputs are declared as fields. The adapter
    walks the field list via reflection and populates each one from the
    request before calling ``serve``. With the concrete extractors,
    each field's ``.value`` is the primitive directly.
    """

    var id: PathInt["id"]
    var trace: QueryStr["trace"]
    var auth: HeaderStr["Authorization"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.trace = QueryStr["trace"]()
        self.auth = HeaderStr["Authorization"]()

    def serve(self, req: Request) raises -> Response:
        return ok(
            "user="
            + String(self.id.value)
            + " trace="
            + self.trace.value
            + " auth_len="
            + String(self.auth.value.byte_length())
        )


def main() raises:
    print("=" * 60)
    print("flare example 19 — Typed extractors")
    print("=" * 60)

    # Shape 1 — drive list_user_posts with synthesised requests.
    var r1 = Request(method=Method.GET, url="/users/7/posts?page=2")
    r1.params_mut()["id"] = "7"
    print("GET /users/7/posts?page=2 →", end=" ")
    var resp1 = list_user_posts(r1)
    print(resp1.status, resp1.text())

    var r2 = Request(method=Method.GET, url="/users/9/posts")
    r2.params_mut()["id"] = "9"
    print("GET /users/9/posts →", end=" ")
    var resp2 = list_user_posts(r2)
    print(resp2.status, resp2.text())

    # Shape 2 — Extracted[GetUser] registered on a Router (the
    # production shape since ). Router.get[H] accepts
    # any Handler struct; here it's the reflective-extractor
    # adapter wrapping our GetUser handler. The Router routes the
    # path, captures :id, and dispatches into Extracted's serve
    # which fills in each field before invoking GetUser.serve.
    var router = Router()
    router.get[Extracted[GetUser]]("/users/:id", Extracted[GetUser]())

    var r3 = Request(method=Method.GET, url="/users/42?trace=req-abc")
    r3.headers.set("Authorization", "Bearer secret")
    var resp3 = router.serve(r3)
    print("router GET /users/42 ok →", resp3.status, resp3.text())

    # Error path: GET /users/abc → ParamInt rejects "abc" → 400.
    # ``expose_errors`` defaults False on synthesised requests so
    # the body is the fixed "Bad Request" string.
    var bad = Request(method=Method.GET, url="/users/abc?trace=x")
    bad.headers.set("Authorization", "Bearer x")
    var bad_resp = router.serve(bad)
    print("router GET /users/abc err →", bad_resp.status, bad_resp.text())

    print()
    print("OK.")
