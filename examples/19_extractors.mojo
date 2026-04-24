"""Example 19 — Typed extractors + reflective auto-injection.

Demonstrates two ways to use flare's v0.4.1 extractors:

1. **Value-constructor** — call ``Path[T, name].extract(req)`` inside a
   plain handler. Direct, no struct boilerplate.
2. **Auto-injection via ``Extracted[H]``** — declare the extractors as
   the fields of a ``HandlerStruct``; the adapter reflects on the
   struct, pulls each field from the request, and calls ``handle``.

Both are driven by synthesised ``Request`` values so the example stays
runnable under ``pixi run tests`` without binding a socket.

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
    QueryOpt,
    Header,
    HandlerStruct,
    Extracted,
)


# ── Shape 1: value-constructor extractors inside a function handler ─────────


def list_user_posts(req: Request) raises -> Response:
    """Extract path and query params explicitly from the request."""
    var user_id = Path[ParamInt, "id"].extract(req).value.value
    var q = QueryOpt[ParamInt, "page"].extract(req)
    var page = Int(1)
    if q.value:
        page = q.value.value().value
    return ok("user " + String(user_id) + " posts (page " + String(page) + ")")


# ── Shape 2: HandlerStruct + Extracted[H] auto-injection ────────────────────


@fieldwise_init
struct GetUser(Copyable, HandlerStruct, Movable):
    """All the handler's inputs are declared as fields. The adapter
    walks the field list via reflection and populates each one from the
    request before calling ``handle``.
    """

    var id: Path[ParamInt, "id"]
    var trace: Query[ParamString, "trace"]
    var auth: Header[ParamString, "Authorization"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()
        self.trace = Query[ParamString, "trace"]()
        self.auth = Header[ParamString, "Authorization"]()

    def handle(self, req: Request) raises -> Response:
        return ok(
            "user="
            + String(self.id.value.value)
            + " trace="
            + self.trace.value.value
            + " auth_len="
            + String(self.auth.value.value.byte_length())
        )


def main() raises:
    print("=" * 60)
    print("flare example 19 — Typed extractors")
    print("=" * 60)

    # Shape 1
    var r1 = Request(method=Method.GET, url="/users/7/posts?page=2")
    r1._params_mut()["id"] = "7"
    var resp1 = list_user_posts(r1)
    print("GET /users/7/posts?page=2 →", resp1.status, resp1.text())

    var r2 = Request(method=Method.GET, url="/users/9/posts")
    r2._params_mut()["id"] = "9"
    var resp2 = list_user_posts(r2)
    print("GET /users/9/posts        →", resp2.status, resp2.text())

    # Shape 2 — Extracted[H]
    var r3 = Request(method=Method.GET, url="/users/42?trace=req-abc")
    r3._params_mut()["id"] = "42"
    r3.headers.set("Authorization", "Bearer secret")
    var h = Extracted[GetUser]()
    var resp3 = h.serve(r3)
    print("Extracted[GetUser] ok     →", resp3.status, resp3.text())

    # Error path: missing :id → 400 from the adapter.
    var bad_req = Request(method=Method.GET, url="/users/?trace=x")
    bad_req.headers.set("Authorization", "Bearer x")
    var bad_resp = h.serve(bad_req)
    print("Extracted[GetUser] err    →", bad_resp.status, bad_resp.text())

    print()
    print("OK.")
