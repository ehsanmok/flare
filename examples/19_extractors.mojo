"""Example 19 — Typed extractors + reflective auto-injection.

Demonstrates two ways to use flare's typed extractors:

1. **Value-constructor** — call ``Path[T, name].extract(req)`` inside a
   plain handler. Direct, no struct boilerplate.
2. **Auto-injection via ``Extracted[H]``** — declare the extractors as
   the fields of a ``Handler`` struct; the adapter reflects on the
   struct, pulls each field from the request, and calls the inner
   ``serve``.

Since v0.5.0 Step 2, ``Router.get(path, handler)`` accepts ``H:
Handler & Copyable & Movable`` directly (Track 1.4), so the
production shape is ``r.get("/users/:id", Extracted[GetUser]())``.
This example demonstrates both the value-constructor shape (driven
through synthesised requests so it can run without spinning up a
server) and the Router-registered shape (also driven through
``Router.serve`` to keep the example self-contained).

A note on ``.value.value``: each extractor (``Path``, ``Query``, ...)
wraps a ``ParamParser`` (``ParamInt``, ``ParamString``, ...) which in
turn wraps a primitive (``Int``, ``String``, ...). The wrapper exists
because Mojo can't yet retrofit the ``ParamParser`` trait onto built-in
``Int``. The collapse to single-dot ``.value`` access via concrete
``PathInt[name]``/``PathStr[name]``/etc. lands in S2.2 of v0.5.0
Step 2; until then every example pulls the primitive into a local
variable once and uses that local everywhere.

Run:
    pixi run example-extractors
"""

from flare.http import (
    Request,
    Response,
    Method,
    Status,
    ok,
    ParamInt,
    ParamString,
    Path,
    Query,
    OptionalQuery,
    Header,
    Handler,
    Router,
    Extracted,
)


# ── Shape 1: value-constructor extractors inside a function handler ─────────


def list_user_posts(req: Request) raises -> Response:
    """Pull each parameter once, then reuse the unwrapped primitive."""
    var id = Path[ParamInt, "id"].extract(req).value.value  # → Int
    var page_param = OptionalQuery[ParamInt, "page"].extract(req)
    var page = 1
    if page_param.value:
        page = page_param.value.value().value  # Optional → ParamInt → Int
    return ok("user " + String(id) + " posts (page " + String(page) + ")")


# ── Shape 2: Handler struct + Extracted[H] auto-injection ──────────────────


@fieldwise_init
struct GetUser(Copyable, Defaultable, Handler, Movable):
    """All the handler's inputs are declared as fields. The adapter
    walks the field list via reflection and populates each one from the
    request before calling ``serve``.
    """

    var id: Path[ParamInt, "id"]
    var trace: Query[ParamString, "trace"]
    var auth: Header[ParamString, "Authorization"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()
        self.trace = Query[ParamString, "trace"]()
        self.auth = Header[ParamString, "Authorization"]()

    def serve(self, req: Request) raises -> Response:
        # One unwrap per field at the top; the rest reads as primitives.
        var id = self.id.value.value
        var trace = self.trace.value.value
        var auth = self.auth.value.value
        return ok(
            "user="
            + String(id)
            + " trace="
            + trace
            + " auth_len="
            + String(auth.byte_length())
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
    print("GET /users/9/posts        →", end=" ")
    var resp2 = list_user_posts(r2)
    print(resp2.status, resp2.text())

    # Shape 2 — Extracted[GetUser] registered on a Router (the
    # production shape since v0.5.0 Step 2). Router.get[H] accepts
    # any Handler struct; here it's the reflective-extractor
    # adapter wrapping our GetUser handler. The Router routes the
    # path, captures :id, and dispatches into Extracted's serve
    # which fills in each field before invoking GetUser.serve.
    var router = Router()
    router.get[Extracted[GetUser]]("/users/:id", Extracted[GetUser]())

    var r3 = Request(method=Method.GET, url="/users/42?trace=req-abc")
    r3.headers.set("Authorization", "Bearer secret")
    var resp3 = router.serve(r3)
    print("router GET /users/42 ok   →", resp3.status, resp3.text())

    # Error path: GET /users/abc → ParamInt rejects "abc" → 400.
    # ``expose_errors`` defaults False on synthesised requests so
    # the body is the fixed "Bad Request" string.
    var bad = Request(method=Method.GET, url="/users/abc?trace=x")
    bad.headers.set("Authorization", "Bearer x")
    var bad_resp = router.serve(bad)
    print("router GET /users/abc err →", bad_resp.status, bad_resp.text())

    print()
    print("OK.")
