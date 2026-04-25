"""Example 19 — Typed extractors + reflective auto-injection.

Demonstrates two ways to use flare's v0.4.1 extractors:

1. **Value-constructor** — call ``Path[T, name].extract(req)`` inside a
   plain handler. Direct, no struct boilerplate.
2. **Auto-injection via ``Extracted[H]``** — declare the extractors as
   the fields of a ``Handler`` struct; the adapter reflects on the
   struct, pulls each field from the request, and calls the inner
   ``serve``.

Both are driven by synthesised ``Request`` values via the public
``Request.params_mut()`` setter (the same accessor ``Router`` itself
uses) so the example exercises every codepath the production
request-handling path takes — minus the Router → Handler-struct bridge,
which is a v0.5 item: ``Router.get(...)`` today only accepts plain
``def`` handlers, so ``Extracted[H]`` is invoked directly here.

A note on ``.value.value``: each extractor (``Path``, ``Query``, ...)
wraps a ``ParamParser`` (``ParamInt``, ``ParamString``, ...) which in
turn wraps a primitive (``Int``, ``String``, ...). The wrapper exists
because Mojo can't yet retrofit the ``ParamParser`` trait onto built-in
``Int``. Until trait associated types stabilise enough to collapse
the layers, every example below pulls the primitive into a local
variable once and uses that local everywhere. Read each
``.value.value`` chain as "extractor → parser-wrapper → primitive".

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

    # Shape 2 — Extracted[GetUser] driven directly. Production code
    # would route through Router; today's Router only accepts def
    # handlers, so Extracted[H].serve is invoked here for the
    # demonstration. The Router → Handler-struct bridge is a v0.5
    # item.
    var h = Extracted[GetUser]()

    var r3 = Request(method=Method.GET, url="/users/42?trace=req-abc")
    r3.params_mut()["id"] = "42"
    r3.headers.set("Authorization", "Bearer secret")
    var resp3 = h.serve(r3)
    print("Extracted[GetUser] ok     →", resp3.status, resp3.text())

    # Error path: missing :id → 400 from the adapter.
    var bad = Request(method=Method.GET, url="/users/?trace=x")
    bad.headers.set("Authorization", "Bearer x")
    var bad_resp = h.serve(bad)
    print("Extracted[GetUser] err    →", bad_resp.status, bad_resp.text())

    print()
    print("OK.")
