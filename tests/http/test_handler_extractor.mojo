"""Tests for the ``HandlerExtractor`` convenience trait composition.

Verifies that a struct declared as ``HandlerExtractor`` is
trait-equivalent to declaring ``(Copyable, Defaultable, Handler,
Movable)`` directly: the same struct flows through ``Extracted[H]``
and registers on a ``Router`` without any extra adapter.
"""

from std.testing import assert_equal

from flare.http import (
    Extracted,
    Handler,
    PathInt,
    QueryStr,
    Request,
    Response,
    Router,
    ok,
)
from flare.http.handler import HandlerExtractor


@fieldwise_init
struct EchoUser(HandlerExtractor):
    var id: PathInt["id"]
    var trace: QueryStr["trace"]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.trace = QueryStr["trace"]()

    def serve(self, req: Request) raises -> Response:
        return ok(
            "user="
            + String(self.id.value)
            + " trace="
            + String(self.trace.value)
        )


def _accept_handler[H: Handler](handler: H) raises -> Int:
    """Helper generic over ``Handler``. The fact that an
    ``EchoUser`` flows through this proves ``HandlerExtractor``
    transitively conforms to ``Handler``."""
    return 1


def _accept_extracted[
    H: Copyable & Defaultable & Handler & Movable
](extracted: Extracted[H]) -> Int:
    """Helper generic over the bound that ``Extracted`` declares.
    The fact that ``Extracted[EchoUser]`` flows through this
    proves ``HandlerExtractor`` collapses to the four traits
    ``Extracted`` requires."""
    return 2


def test_handler_extractor_satisfies_handler_bound() raises:
    """A ``HandlerExtractor`` struct can be passed to a function
    generic over ``Handler``."""
    var h = EchoUser()
    assert_equal(_accept_handler(h), 1)


def test_handler_extractor_flows_through_extracted() raises:
    """``Extracted[H]`` accepts a ``HandlerExtractor`` struct as
    its type argument because ``HandlerExtractor`` transitively
    satisfies ``Copyable & Defaultable & Handler & Movable``."""
    var ex = Extracted[EchoUser]()
    assert_equal(_accept_extracted(ex), 2)


def test_handler_extractor_registers_on_router_without_turbofish() raises:
    """``Router.get`` with ``Extracted[H]()`` runtime arg infers the
    parametric ``H`` type without an explicit turbofish."""
    var r = Router()
    r.get("/users/:id", Extracted[EchoUser]())

    var req = Request.test_get("/users/42?trace=abc")
    var resp = r.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "user=42 trace=abc")


def test_handler_extractor_serves_directly() raises:
    """The struct itself is also a ``Handler``; ``serve(req)``
    works directly (without ``Extracted[H]``) on a manually
    populated instance."""
    var probe = EchoUser(id=PathInt["id"](7), trace=QueryStr["trace"]("abc"))
    var req = Request.test_get("/anything")
    var resp = probe.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "user=7 trace=abc")


def main() raises:
    test_handler_extractor_satisfies_handler_bound()
    print("OK test_handler_extractor_satisfies_handler_bound")

    test_handler_extractor_flows_through_extracted()
    print("OK test_handler_extractor_flows_through_extracted")

    test_handler_extractor_registers_on_router_without_turbofish()
    print("OK test_handler_extractor_registers_on_router_without_turbofish")

    test_handler_extractor_serves_directly()
    print("OK test_handler_extractor_serves_directly")
