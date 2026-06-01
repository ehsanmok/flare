"""Example: infallible handlers -- bare function vs HandlerInfallible.

flare accepts three shapes for a "this handler cannot fail" endpoint.
In rough order of ergonomics (cheapest first):

1. **Bare function, no ``raises``.**

       def health(req: Request) -> Response:
           return ok('{"status":"ok"}')

       r.get("/health", health)

   Mojo's function-type subtyping implicitly upcasts a non-raising
   ``def(Request) -> Response`` to the raising ``def(Request) raises
   thin -> Response`` parameter type that ``Router.get`` declares,
   so the call site needs nothing extra. **Use this for stateless
   infallible endpoints** -- health checks, ``/version``,
   fixed-string responses. No struct, no trait constraint trio,
   no adapter.

2. **A struct that conforms to** :trait:`flare.http.HandlerInfallible`.

   For *stateful* infallible handlers (the body still cannot fail
   but needs to carry struct fields), implement
   :trait:`HandlerInfallible` -- the no-``raises`` sibling of the
   regular :trait:`Handler` trait. Wrap with :class:`WithRaises` to
   slot into ``Router`` and middleware that expect the
   regular :trait:`Handler`. The ``WithRaises`` adapter is
   zero-overhead at runtime (``@always_inline`` forwards directly
   to the inner ``serve``).

3. **A regular** :trait:`Handler` **struct or function with**
   ``raises``. The default for everything else; the server's
   catch-converts-to-500 contract handles arbitrary failures
   uniformly.

Run:
    mojo -I . examples/intermediate/infallible_handler.mojo
"""

from flare.http import (
    Handler,
    Request,
    Response,
    Router,
    ok,
)
from flare.http.handler import HandlerInfallible, WithRaises


# ── Shape 1: bare function, no ``raises`` -------------------------------------


def health(req: Request) -> Response:
    """Stateless health probe.

    Provably infallible: no parsing, no allocation that can fail in
    the reactor's hot path. Mounts on a Router with a single line
    and no adapter::

        r.get("/health", health)
    """
    return ok('{"status":"ok"}')


def echo_method(req: Request) -> Response:
    """Stateless: returns a fixed string for the request method.
    Still provably infallible -- no header parsing, no body read.
    Shows that infallible bare-function handlers can still inspect
    the request, just not in ways that can raise."""
    return ok("method=" + req.method)


# ── Shape 2: HandlerInfallible struct (for *stateful* infallible bodies) ──────


@fieldwise_init
struct GreetingProbe(Copyable, HandlerInfallible, Movable):
    """A health probe that carries a configurable greeting in
    struct state. The body still literally cannot fail (no parsing,
    no I/O, no allocation that can raise) but the handler needs to
    carry a field, so the bare-function shape doesn't fit.

    :class:`WithRaises[GreetingProbe]` adapts this to the regular
    :trait:`Handler` constraint for ``Router.get(...)``.
    """

    var greeting: String

    @always_inline
    def serve(self, req: Request) -> Response:
        return ok(self.greeting)


# ── Shape 3 (counterpoint): regular Handler with ``raises`` -------------------


def fallible_user_lookup(req: Request) raises -> Response:
    """A regular :trait:`Handler`-shaped handler: parsing the
    request URL into an int *can* fail (non-numeric path param),
    so this handler keeps the ``raises`` shape and lets the
    server's catch-converts-to-500 contract take over."""
    var id_str = req.param("id")
    if id_str.byte_length() == 0:
        return Response(status=400, reason="Missing :id")
    var as_int = atol(id_str)
    return ok("user=" + String(as_int))


def main() raises:
    """Demo only -- no live server. Shows each shape side-by-side.

    A real app would wire all three on the same Router::

        var r = Router()
        r.get("/health", health)                                           # shape 1
        r.get("/method", echo_method)                                      # shape 1
        r.get[WithRaises[GreetingProbe]]("/greet",
            WithRaises[GreetingProbe](GreetingProbe(greeting="hi")))       # shape 2
        r.get("/user/:id", fallible_user_lookup)                           # shape 3
        srv.serve(r^)
    """
    var req = Request.test_get("/health")

    var hr = health(req)
    print("health (bare fn):  status=", hr.status, "body=", hr.text())

    var er = echo_method(req)
    print("method (bare fn):  status=", er.status, "body=", er.text())

    var probe = GreetingProbe(
        greeting="hello from a stateful infallible handler"
    )
    var pr = probe.serve(req)
    print("greet (struct):    status=", pr.status, "body=", pr.text())

    var adapted = WithRaises[GreetingProbe](
        GreetingProbe(greeting="via WithRaises adapter")
    )
    var ar = adapted.serve(req)
    print("greet (adapted):   status=", ar.status, "body=", ar.text())

    # Register the bare-function shapes on a Router to prove the
    # implicit no-raises -> raises upcast at the registration site.
    var r = Router()
    r.get("/health", health)
    r.get("/method", echo_method)
    var hresp = r.serve(req)
    print("router /health:    status=", hresp.status, "body=", hresp.text())
