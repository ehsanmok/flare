"""HandlerInfallible trait + WithRaises adapter (v0.7 Track 2b).

Exercises the no-``raises`` handler shape and its adapter to the
regular :trait:`Handler` constraint:

* ``HandlerInfallible.serve(self, req: Request) -> Response`` --
  declares the body cannot fail. Mojo's ``def`` allows both the
  ``raises`` and no-``raises`` shapes; the trait variant lets the
  framework express the no-``raises`` contract on a per-handler
  basis instead of the global "every handler raises" assumption
  the cookbook implies.
* ``WithRaises[Inner: HandlerInfallible](Handler)`` -- wraps an
  infallible handler so it fits anywhere a regular :trait:`Handler`
  is expected (Router, App, middleware nesting). Zero runtime
  cost: ``serve`` is ``@always_inline``.
"""

from std.testing import assert_equal

from flare.http import (
    Handler,
    Request,
    Response,
    ok,
)
from flare.http.handler import HandlerInfallible, WithRaises


@fieldwise_init
struct StaticOk(Copyable, HandlerInfallible, Movable):
    """The simplest possible infallible handler: always returns 200 OK
    with a fixed body, no I/O, no parsing, no allocation paths that
    can fail."""

    var body: String

    @always_inline
    def serve(self, req: Request) -> Response:
        return ok(self.body)


@fieldwise_init
struct HealthHandler(Copyable, HandlerInfallible, Movable):
    """A health-check handler that always returns 200 with a fixed
    JSON body. Provably infallible -- no body allocation that can
    OOM in the reactor's hot path, no header munging that can
    raise on token validation."""

    @always_inline
    def serve(self, req: Request) -> Response:
        return ok('{"status":"ok"}')


def test_handler_infallible_direct_call() raises:
    """A struct implementing :trait:`HandlerInfallible` can be called
    directly without a ``try`` / ``except`` block at the call site."""
    var h = StaticOk("hello v0.7")
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    var resp = h.serve(req)  # No ``raises`` keyword required at the call.
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hello v0.7")


def test_with_raises_adapts_infallible_to_handler() raises:
    """:class:`WithRaises[Inner]` makes an infallible handler fit
    the :trait:`Handler` constraint without changing behaviour."""
    var adapted = WithRaises[HealthHandler](HealthHandler())
    var req = Request(method="GET", url="/health", version="HTTP/1.1")
    var resp = adapted.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), '{"status":"ok"}')


def _accept_handler[H: Handler](handler: H) raises -> Int:
    """Helper that is generic over :trait:`Handler` (NOT
    HandlerInfallible). Used to verify the adapter satisfies the
    regular Handler bound."""
    var req = Request(method="GET", url="/", version="HTTP/1.1")
    var resp = handler.serve(req)
    return resp.status


def test_with_raises_satisfies_handler_bound() raises:
    """A :class:`WithRaises[Inner]` value satisfies a function bound
    that requires :trait:`Handler` -- the adapter is the only
    direction that's safe (raises is a superset of no-raises)."""
    var adapted = WithRaises[StaticOk](StaticOk("hi"))
    var status = _accept_handler(adapted)
    assert_equal(status, 200)


def test_handler_infallible_distinct_from_handler() raises:
    """The two traits are deliberately distinct: a regular
    :trait:`Handler` cannot be passed to a function that demands a
    :trait:`HandlerInfallible` (there's no reverse adapter --
    ``raises -> no-raises`` is an unsound widening). This test
    documents the contract by showing that the
    ``HealthHandler`` -> ``WithRaises`` -> ``Handler`` path is the
    only sanctioned direction."""
    var adapted = WithRaises[HealthHandler](HealthHandler())
    var req = Request(method="GET", url="/health", version="HTTP/1.1")
    var resp = adapted.serve(req)  # via Handler.serve (raises -> Response)
    assert_equal(resp.status, 200)


def main() raises:
    test_handler_infallible_direct_call()
    test_with_raises_adapts_infallible_to_handler()
    test_with_raises_satisfies_handler_bound()
    test_handler_infallible_distinct_from_handler()
    print("test_handler_infallible: 4 passed")
