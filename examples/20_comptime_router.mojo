"""Example 20 — Comptime route dispatch via ``ComptimeRouter``.

``ComptimeRouter`` has the same request-handling contract as
``Router`` but the route table is a ``comptime`` value, so segment
parsing happens at compile time and the dispatch loop unrolls per
route. Handlers are still bound at runtime because Mojo can't yet
pack heterogeneous ``def`` types into a comptime list; ``set_handler``
wires each slot after construction.

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
    ComptimeRoute(Method.GET, "/"),
    ComptimeRoute(Method.GET, "/users/:id"),
    ComptimeRoute(Method.POST, "/users"),
    ComptimeRoute(Method.GET, "/files/*"),
]


def main() raises:
    print("=" * 60)
    print("flare example 20 — ComptimeRouter")
    print("=" * 60)

    var r = ComptimeRouter[ROUTES]()
    r.set_handler(0, home)
    r.set_handler(1, get_user)
    r.set_handler(2, create_user)
    r.set_handler(3, files)

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
