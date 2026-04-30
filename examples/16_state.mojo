"""Example 16 - App[S] with typed ``State[T]``.

Shows how to wrap a Router in an ``App`` that carries application-
scoped state, and how a middleware handler reads that state through
a ``State[T]`` view. Exact same pattern ``test_app_state.mojo``
uses in the unit tests, deliberately: the Example is the living
version of the unit test.

Run:
    pixi run example-state
"""

from flare.http import (
    App,
    State,
    Router,
    Handler,
    Request,
    Response,
    Method,
    ok,
)


# Application state - a tiny counter, Copyable so the App can hand a
# snapshot to each handler / middleware layer.
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
    """Middleware that tags the response with the current state snapshot."""

    var inner: Self.Inner
    var snapshot: State[Counters]

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.snapshot.get().hits))
        resp.headers.set("X-Misses", String(self.snapshot.get().misses))
        return resp^


def main() raises:
    print("=" * 60)
    print("flare example 16 - App[Counters] + State[T]")
    print("=" * 60)

    var router = Router()
    router.get("/", home)
    router.get("/details", details)

    var app = App(state=Counters(hits=7, misses=2), handler=router^)
    var view = app.state_view()

    # Wrap App in the observing middleware. The wrapper captures a
    # state snapshot and injects it into every response.
    var serve_tree = _ObserveHits(app^, view^)

    var resp = serve_tree.serve(Request(method=Method.GET, url="/"))
    print("GET / →", resp.status, resp.text())
    print(" X-Hits: ", resp.headers.get("X-Hits"))
    print(" X-Misses: ", resp.headers.get("X-Misses"))

    var resp2 = serve_tree.serve(Request(method=Method.GET, url="/details"))
    print("GET /details →", resp2.status, resp2.text())
    print(" X-Hits: ", resp2.headers.get("X-Hits"))

    print()
    print("OK.")
