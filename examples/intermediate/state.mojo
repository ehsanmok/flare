"""Example 16 - shared application state via a captured handler.

Shows how a handler reads request-independent state without globals
or a framework-provided injection layer. The pattern is a wrapping
``Handler`` struct that captures state by value; ``flare.http``
treats middleware-style wrappers as first-class because they
implement the same ``Handler`` trait the leaf handlers do.

Run:
    pixi run example-state
"""

from flare.http import (
    Router,
    Handler,
    Request,
    Response,
    ok,
)


# Application state - a tiny counter, Copyable so the wrapping
# handler can hand a snapshot to each layer.
@fieldwise_init
struct Counters(Copyable, Movable):
    var hits: Int
    var misses: Int


def home(req: Request) raises -> Response:
    return ok("home")


def details(req: Request) raises -> Response:
    return ok("details")


@fieldwise_init
struct _ObserveHits[Inner: Handler](Handler):
    """Middleware that tags the response with the captured snapshot."""

    var inner: Self.Inner
    var counters: Counters

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req).lower()
        resp.headers.set("X-Hits", String(self.counters.hits))
        resp.headers.set("X-Misses", String(self.counters.misses))
        return resp^


def main() raises:
    print("=" * 60)
    print("flare example 16 - shared state via a captured handler")
    print("=" * 60)

    var router = Router()
    router.get("/", home)
    router.get("/details", details)

    # The wrapper holds the state and is itself a Handler; serve it
    # directly. Mutable shared state would store atomics or use an
    # interior-mutability type instead of a plain ``Counters``.
    var serve_tree = _ObserveHits(
        inner=router^, counters=Counters(hits=7, misses=2)
    )

    var resp = serve_tree.serve(Request.test_get("/"))
    print("GET / →", resp.status, resp.text())
    print(" X-Hits: ", resp.headers.get("X-Hits"))
    print(" X-Misses: ", resp.headers.get("X-Misses"))

    var resp2 = serve_tree.serve(Request.test_get("/details"))
    print("GET /details →", resp2.status, resp2.text())
    print(" X-Hits: ", resp2.headers.get("X-Hits"))

    print()
    print("OK.")
