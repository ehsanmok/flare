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
        a direct ``self.f(req)`` — matches v0.3.x's hot path.
        """
        return self.f(req)
