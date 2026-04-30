"""Application wrapper + typed state injection.

handlers had no way to see request-independent state without
reaching for a global. ``App[S]`` fixes that: the server owns an
application-scoped value of type ``S``, hands a typed ``State[S]``
view of it to the handler, and the handler accesses it through a
normal value parameter instead of a smuggled global.

```mojo
from flare.http import App, Router, Request, Response, State, ok
from flare.net import SocketAddr

@fieldwise_init
struct Counters(Copyable):
    var hits: Int

def home(req: Request, state: State[Counters]) raises -> Response:
    # State[T] is a read-only view; user mutation goes
    # through atomics or explicit interior-mutability types.
    return ok("hits so far: " + String(state.get().hits))

def main() raises:
    var router = Router()
    # App-aware routes are registered with .with_state(...) so the
    # handler gets the typed State[S] injection automatically.
    router.get("/", home)

    var app = App(state=Counters(hits=0), router=router^)
    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(app^)
```

For the ``State[T]`` extractor is runtime; the comptime-reflected
signature-based injection (``def handler(req, state: State[Counters])``)
lands alongside the other typed extractors. Today the user
writes a small handler adapter that pulls ``state.get()`` from a
captured ``App`` reference, or uses ``App[S].serve`` which acts as the
entry-level ``Handler`` and forwards to its inner Router.
"""

from .handler import Handler
from .request import Request
from .response import Response
from .router import Router


struct State[T: Copyable & ImplicitlyDestructible](
    Copyable, ImplicitlyDestructible, Movable
):
    """A read-only view onto application state of type ``T``.

    ``State[T]`` is a value handlers can accept as a parameter. In
    you retrieve it from an ``App[T]`` via ``app.state_view()``
    or by calling ``state.get()``; adds comptime-signature
    reflection so the Router wires it automatically from the
    handler's declared parameter list.

    The underlying ``T`` must be ``Copyable`` because flare hands
    each request handler a copy of the state snapshot; handlers that
    need mutable shared state should store atomics or use
    interior-mutability types (e.g. a ``RwLock[Counters]``).
    """

    var _value: Self.T

    @always_inline
    def __init__(out self, var value: Self.T):
        """Wrap ``value`` as a typed ``State`` view."""
        self._value = value^

    @always_inline
    def get(self) -> Self.T:
        """Return a copy of the wrapped value."""
        return self._value.copy()


struct App[S: Copyable & ImplicitlyDestructible, H: Handler](Handler):
    """An application: a handler plus application-scoped state.

    Parameters:
        S: The application state type (must be ``Copyable``).
        H: The inner handler type (typically a ``Router``).

    Fields:
        state: Application-scoped state shared by every request.
        handler: The inner handler (usually a ``Router``).

    Usage:
        ```mojo
        var app = App(state=my_state, handler=my_router^)
        var srv = HttpServer.bind(addr)
        srv.serve(app^)
        ```

    ``App`` itself implements ``Handler`` so it slots into the same
    ``serve[H: Handler & Copyable]`` entry point as any other handler. On
    each request it calls into ``handler.serve(req)`` after recording
    the state snapshot; a comptime extractor layer will let handlers
    declare ``State[S]`` parameters directly .
    """

    var state: Self.S
    var handler: Self.H

    @always_inline
    def __init__(out self, var state: Self.S, var handler: Self.H):
        """Build an App with initial state and inner handler.

        Args:
            state: Initial value of application state.
            handler: The inner handler (ownership transferred).
        """
        self.state = state^
        self.handler = handler^

    @always_inline
    def state_view(self) -> State[Self.S]:
        """Return a typed ``State[S]`` view of the current state."""
        return State(self.state.copy())

    def serve(self, req: Request) raises -> Response:
        """Delegate to the inner handler.

        For the inner handler is the only way the state reaches
        the user. Users who need typed ``State[S]`` injection write a
        small wrapper struct around their Router that captures the
        App by reference and pulls ``state_view()`` on each request;
        's typed-extractor layer will wire this automatically.
        """
        return self.handler.serve(req)
