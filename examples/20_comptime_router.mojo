"""Example 20 — Comptime route dispatch via ``ComptimeRouter``.

``ComptimeRouter`` has the same request-handling contract as
``Router`` but the route table — method, pattern, *and* handler — is
a single ``comptime`` list, so segment parsing happens at compile
time and the dispatch loop unrolls per route. No separate handler
binding step; every ``ComptimeRoute`` triple names its handler
directly.

Drives the router via synthesised requests so it stays runnable under
``pixi run tests`` without binding a socket.

Run:
    pixi run example-comptime-router
"""

from flare.http import (
    ComptimeRoute,
    ComptimeRouter,
    Request,
    Response,
    Method,
    Status,
    ok,
)


def home(req: Request) raises -> Response:
    return ok("home")


def get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))


def create_user(req: Request) raises -> Response:
    return ok("created")


def files(req: Request) raises -> Response:
    return ok("files=" + req.param("*"))


comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/", home),
    ComptimeRoute(Method.GET, "/users/:id", get_user),
    ComptimeRoute(Method.POST, "/users", create_user),
    ComptimeRoute(Method.GET, "/files/*", files),
]


def main() raises:
    print("=" * 60)
    print("flare example 20 — ComptimeRouter")
    print("=" * 60)

    var r = ComptimeRouter[ROUTES]()

    var r1 = r.serve(Request(method=Method.GET, url="/"))
    print("GET /          →", r1.status, r1.text())

    var r2 = r.serve(Request(method=Method.GET, url="/users/42"))
    print("GET /users/42  →", r2.status, r2.text())

    var r3 = r.serve(Request(method=Method.POST, url="/users"))
    print("POST /users    →", r3.status, r3.text())

    var r4 = r.serve(Request(method=Method.GET, url="/files/a/b.txt"))
    print("GET /files/... →", r4.status, r4.text())

    # 405 on wrong method
    var r5 = r.serve(Request(method=Method.PUT, url="/users"))
    print(
        "PUT /users     →",
        r5.status,
        "Allow:",
        r5.headers.get("Allow"),
    )

    # 404 on unknown
    var r6 = r.serve(Request(method=Method.GET, url="/nope"))
    print("GET /nope      →", r6.status)

    print()
    print("OK.")
