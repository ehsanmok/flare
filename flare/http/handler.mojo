"""The ``Handler`` trait: flare's request-to-response contract.

A ``Handler`` is anything that can turn a ``Request`` into a ``Response``.
Structs with state implement it directly, functions adapt via ``FnHandler``,
and higher-level types (``Router``, ``App[S]``, middleware wrappers) all
nest by wrapping another ``Handler``.

## Writing a handler as a struct

```mojo
from flare.http import Handler, Request, Response, ok

struct Greeter(Handler):
    var greeting: String

    fn serve(self, req: Request) raises -> Response:
        return ok(self.greeting + " " + req.url)
```

## Writing a handler as a plain function

```mojo
from flare.http import FnHandler, Request, Response, ok

def hello(req: Request) raises -> Response:
    return ok("hello")

var handler = FnHandler(hello)
```

``FnHandler`` is the backwards-compatibility shim for v0.3.x's
``def(Request) raises -> Response`` signature. ``HttpServer.serve`` keeps
accepting that function signature directly; internally it wraps the
function in ``FnHandler`` and dispatches through the same ``Handler``
codepath.

## Composing handlers

Handlers compose by wrapping. Middleware is a ``Handler`` that holds an
inner ``Handler`` and does something before / around / after the inner
call:

```mojo
struct Logged[Inner: Handler](Handler):
    var inner: Inner
    var prefix: String

    fn serve(self, req: Request) raises -> Response:
        print(self.prefix, req.method, req.url)
        return self.inner.serve(req)
```
"""

from .cancel import Cancel
from .request import Request
from .response import Response


# ── Trait ────────────────────────────────────────────────────────────────────


trait Handler(ImplicitlyDestructible, Movable):
    """The request-to-response contract every flare endpoint satisfies.

    Implementors turn a ``Request`` into a ``Response``. Handler structs
    may own state, compose inner handlers, or both.

    Contract:

    - ``serve`` takes ``req`` by read-only borrow (the default
      convention). If a handler needs to move the request body, it
      clones or consumes the relevant fields.
    - ``serve`` returns a ``Response`` value. To stream, return a
      response whose body reads incrementally (see ``Body`` trait,
      landing in v0.4.3+).
    - ``serve`` may raise. The server catches the exception and
      converts it to a 500 Internal Server Error; handlers that want
      to signal a 4xx should return the response directly (use
      ``not_found``, ``bad_request``, etc.).

    Concrete implementations live at all layers: ``FnHandler`` wraps a
    plain function, ``Router`` dispatches by method + path, ``App[S]``
    injects state, and any user struct can implement the trait for its
    own routing / middleware / adapter needs.
    """

    def serve(self, req: Request) raises -> Response:
        """Produce a ``Response`` for ``req``.

        Args:
            req: The incoming request.

        Returns:
            The response to send back to the client.

        Raises:
            Error: Any error; the server maps this to a 500 response.
        """
        ...


# ── FnHandler: backwards-compatibility shim ───────────────────────────────────


struct FnHandler(Copyable, Handler):
    """Adapts a plain ``def(Request) raises -> Response`` into a ``Handler``.

    Stores the function as a runtime field (same cost as v0.3.x's
    existing ``HttpServer.serve(handler)`` path). Use this when you want
    ``Router.get(path, my_fn)`` to accept a bare function without a
    user-side wrapper struct.

    For the fastest possible dispatch, implement ``Handler`` directly on
    a struct (no indirection) or use ``HttpServer.serve[handler]()`` in
    comptime-specialised mode (landing in Step 6).

    Example:
        ```mojo
        def hello(req: Request) raises -> Response:
            return ok("hello")

        var h = FnHandler(hello)
        var resp = h.serve(some_req)
        ```
    """

    var f: def(Request) raises thin -> Response
    """The wrapped function."""

    @always_inline
    def __init__(out self, f: def(Request) raises thin -> Response):
        """Wrap ``f`` as a ``Handler``.

        Args:
            f: A function with signature ``def(Request) raises -> Response``.
        """
        self.f = f

    @always_inline
    def serve(self, req: Request) raises -> Response:
        """Call the wrapped function with ``req``. Inlined so the extra
        trait dispatch layer is eliminated and the call site reduces to
        a direct ``self.f(req)`` - matches v0.3.x's hot path.
        """
        return self.f(req)


# ── FnHandlerCT: comptime-parametric, zero-size ─────────────────────────────


struct FnHandlerCT[F: def(Request) raises thin -> Response](Copyable, Handler):
    """Comptime-parametric adapter: the wrapped function is a type
    parameter, not a runtime field.

    Zero-size at runtime (no ``var f``); the compiler monomorphises
    ``serve`` per ``F`` so the call site reduces to a direct,
    statically-known ``F(req)``. This is what gives the Handler path
    the same machine code as a bare function call in the v0.3.x
    ``HttpServer.serve(def...)`` shape.

    Usage:
        ```mojo
        def hello(req: Request) raises -> Response:
            return ok("hello")

        alias HelloHandler = FnHandlerCT[hello]

        def main() raises:
            var h = HelloHandler()
            var srv = HttpServer.bind(SocketAddr.localhost(8080))
            srv.serve(h^)
        ```

    Prefer ``FnHandlerCT[fn]`` over ``FnHandler(fn)`` in hot paths
    where the handler identity is known at compile time (benches,
    single-handler servers, comptime-composed Routers). Use the
    runtime ``FnHandler`` only when the handler is chosen at runtime
    (e.g. when a Router needs to store ``def`` handlers in a list
    indexed at request time).
    """

    @always_inline
    def __init__(out self):
        """Default-construct the zero-size handler."""
        pass

    @always_inline
    def serve(self, req: Request) raises -> Response:
        """Direct call to the comptime-bound function ``F``."""
        return Self.F(req)


# ── CancelHandler trait + WithCancel adapter (v0.5.0 Step 1) ────────────────


trait CancelHandler(ImplicitlyDestructible, Movable):
    """A request-to-response contract that takes a ``Cancel`` token.

    The reactor calls ``serve(req, cancel)`` once per parsed request.
    The handler reads ``cancel.cancelled()`` between expensive steps
    and returns early when the cell flips.

    Mojo as of v0.26.3.0.dev2026042205 cannot express "trait B refines
    trait A by adding an extra parameter to the same method," so
    ``CancelHandler`` is a sibling trait to ``Handler`` rather than a
    subtype. Adapter ``WithCancel[H: Handler]`` forwards a plain
    ``Handler`` to a ``CancelHandler`` shape (ignoring ``cancel``);
    pass it to ``HttpServer.serve_cancellable`` to plug existing
    ``Handler`` code into the cancel-aware reactor path.

    Cancellation is cooperative: if the handler never reads
    ``cancel``, it runs to completion as before. The reactor flips
    the cell on:

    - ``CancelReason.PEER_CLOSED`` — peer FIN before response queued.
    - ``CancelReason.TIMEOUT`` — a deadline expired (commit 5).
    - ``CancelReason.SHUTDOWN`` — drain mode (commit 6).

    Example:
        ```mojo
        from flare.http import CancelHandler, Cancel, Request, Response, ok

        @fieldwise_init
        struct SlowHandler(CancelHandler, Copyable, Movable):
            fn serve(self, req: Request, cancel: Cancel) raises -> Response:
                for i in range(100):
                    if cancel.cancelled():
                        return ok("partial: " + String(i))
                    # ... one expensive step ...
                return ok("done")
        ```
    """

    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        """Produce a ``Response`` for ``req``, observing ``cancel``.

        Args:
            req:    The incoming request.
            cancel: Per-request cancel token. Polled by the handler
                between expensive steps; the reactor flips the cell
                on peer FIN, deadline, or drain.

        Returns:
            The response to send back to the client.

        Raises:
            Error: Any error; the reactor maps this to a 500 response.
        """
        ...


@fieldwise_init
struct WithCancel[H: Handler & Copyable & Movable](
    CancelHandler, Copyable, Movable
):
    """Adapter that lets a plain ``Handler`` plug into the
    cancel-aware reactor path.

    ``WithCancel[H]`` ignores the ``cancel`` argument and forwards
    every request to ``H.serve(req)``. Use when you have a stateful
    handler that does not need to observe cancellation but the
    surrounding code is using ``HttpServer.serve_cancellable``
    (because a sibling handler does, or because the user wants the
    consistent type signature).

    This is the design-doc "blanket impl from the existing 1-arg
    ``Handler.serve``" expressed as an explicit Mojo adapter, since
    Mojo currently lacks the trait-method-overloading needed to do
    it implicitly. See the ``CancelHandler`` docstring.

    Wrapping is zero-overhead at runtime: the inner ``H.serve(req)``
    call is the only generated work, and Mojo monomorphises away the
    adapter's struct field for stateless ``H``.

    Example:
        ```mojo
        from flare.http import (
            HttpServer, Router, WithCancel, Request, Response, ok,
        )
        from flare.net import SocketAddr

        def hello(req: Request) raises -> Response:
            return ok("hello")

        def main() raises:
            var r = Router()
            r.get("/", hello)
            var srv = HttpServer.bind(SocketAddr.localhost(8080))
            # Pass through the cancel-aware path even though the
            # handler doesn't observe cancellation.
            srv.serve_cancellable(WithCancel[Router](r^))
        ```
    """

    var inner: Self.H
    """Wrapped plain handler; ``serve(req)`` is called from the
    cancel-aware ``serve(req, cancel)``."""

    @always_inline
    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        """Ignore ``cancel`` and forward to ``self.inner.serve(req)``.

        Args:
            req:    The incoming request.
            cancel: Per-request cancel token. **Ignored** by the
                adapter; the wrapped ``Handler`` does not observe
                cancellation.

        Returns:
            Whatever ``self.inner.serve(req)`` returns.
        """
        return self.inner.serve(req)
