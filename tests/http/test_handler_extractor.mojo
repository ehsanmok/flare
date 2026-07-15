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
    State,
    ok,
)
from flare.http.handler import HandlerExtractor


@fieldwise_init
struct GreetUser(HandlerExtractor):
    var id: PathInt["id"]
    var greeting: State[String]

    def __init__(out self):
        self.id = PathInt["id"]()
        self.greeting = State[String]()

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting.value + " " + String(self.id.value))


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


def test_state_flows_through_prototype() raises:
    """A ``State[T]`` field set on the registered prototype survives
    the per-request copy while the extractor field is populated from
    the request."""
    var proto = GreetUser()
    proto.greeting = State[String]("hello")
    var r = Router()
    r.get("/users/:id", Extracted[GreetUser](proto^))
    var req = Request.test_get("/users/7")
    var resp = r.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hello 7")


def test_state_defaults_when_no_prototype() raises:
    """``Extracted[H]()`` default-constructs the prototype, so a
    ``State[T]`` field is its default value."""
    var r = Router()
    r.get("/users/:id", Extracted[GreetUser]())
    var req = Request.test_get("/users/9")
    var resp = r.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), " 9")


def main() raises:
    test_handler_extractor_satisfies_handler_bound()
    print("OK test_handler_extractor_satisfies_handler_bound")

    test_handler_extractor_flows_through_extracted()
    print("OK test_handler_extractor_flows_through_extracted")

    test_handler_extractor_registers_on_router_without_turbofish()
    print("OK test_handler_extractor_registers_on_router_without_turbofish")

    test_handler_extractor_serves_directly()
    print("OK test_handler_extractor_serves_directly")

    test_state_flows_through_prototype()
    print("OK test_state_flows_through_prototype")

    test_state_defaults_when_no_prototype()
    print("OK test_state_defaults_when_no_prototype")
