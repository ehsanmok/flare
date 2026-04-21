"""Example 15 - Router: path parameters, method dispatch, 404 / 405.

Builds a ``Router`` with a home route, a parameterised user route,
and a POST endpoint. The example does not actually bind a server
socket (that would block the test runner forever); it drives the
Router directly via synthesised ``Request`` values. This keeps the
example runnable inside ``pixi run tests`` while still
demonstrating every major Router feature.

Run:
    pixi run example-router
"""

from flare.http import (
    Router,
    Request,
    Response,
    Method,
    Status,
    ok,
    not_found,
)


def home(req: Request) raises -> Response:
    return ok("flare - home")


def get_user(req: Request) raises -> Response:
    return ok("user id = " + req.param("id"))


def create_user(req: Request) raises -> Response:
    return ok("created")


def main() raises:
    print("=" * 60)
    print("flare example 15 - Router")
    print("=" * 60)

    var r = Router()
    r.get("/", home)
    r.get("/users/:id", get_user)
    r.post("/users", create_user)

    # Literal hit
    var home_resp = r.serve(Request(method=Method.GET, url="/"))
    print("GET /            →", home_resp.status, home_resp.text())

    # Parameter extraction
    var u_resp = r.serve(Request(method=Method.GET, url="/users/42"))
    print("GET /users/42    →", u_resp.status, u_resp.text())

    # POST routed to its own handler
    var post_resp = r.serve(Request(method=Method.POST, url="/users"))
    print("POST /users      →", post_resp.status, post_resp.text())

    # Wrong method on a known path → 405 with Allow header
    var wrong = r.serve(Request(method=Method.PUT, url="/users"))
    print(
        "PUT /users       →",
        wrong.status,
        "Allow:",
        wrong.headers.get("Allow"),
    )

    # Unknown path → 404
    var nope = r.serve(Request(method=Method.GET, url="/whoami"))
    print("GET /whoami      →", nope.status)

    print()
    print("OK.")
