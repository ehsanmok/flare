"""The ``Handler`` trait: flare's request-to-response contract.

A ``Handler`` is anything that can turn a ``Request`` into a ``Response``.
Structs with state implement it directly, functions adapt via ``FnHandler``,
and higher-level types (``Router``, middleware wrappers) all
nest by wrapping another ``Handler``.

## Writing a handler as a struct

```mojo
from flare.http import Handler, Request, Response, ok

struct Greeter(Handler):
    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting + " " + req.url)
```

## Writing a handler as a plain function

```mojo
from flare.http import FnHandler, Request, Response, ok

def hello(req: Request) raises -> Response:
    return ok("hello")

var handler = FnHandler(hello)
```

``FnHandler`` is the backwards-compatibility shim for 's
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

    def serve(self, req: Request) raises -> Response:
        print(self.prefix, req.method, req.url)
        return self.inner.serve(req)
```
"""

from .cancel import Cancel
from .request import Request
from .request_view import RequestView
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
      landing +).
    - ``serve`` may raise. The server catches the exception and
      converts it to a 500 Internal Server Error; handlers that want
      to signal a 4xx should return the response directly (use
      ``not_found``, ``bad_request``, etc.).

    Concrete implementations live at all layers: ``FnHandler`` wraps a
    plain function, ``Router`` dispatches by method + path, and any
    user struct can implement the trait for its own routing /
    middleware / adapter needs.

    The bare-function ``def(Request) -> Response`` (no ``raises``)
    shape is also accepted at every ``Router.get`` / ``Router.post``
    / ... call site: Mojo's function-type subtyping implicitly
    upcasts a non-raising function pointer to the raising
    ``def(Request) raises thin -> Response`` parameter type. For
    stateless infallible endpoints (health checks, ``/version``,
    fixed-string responses) prefer the bare-function shape — it
    avoids the trait-and-adapter ceremony of the struct path::

        def health(req: Request) -> Response:
            return ok('{"status":"ok"}')

        r.get("/health", health)

    For *stateful* infallible handlers (the body still cannot fail
    but needs to carry struct fields), see the sibling
    :trait:`HandlerInfallible` trait + :class:`WithRaises` adapter.
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


# ── HandlerExtractor: convenience trait composition ──────────────────────────


trait HandlerExtractor(Copyable, Defaultable, Handler, Movable):
    """Convenience trait composition for typed-extractor handler structs.

    .. note::

       **Internal adapter.** Not part of the curated public surface;
       import explicitly via ``from flare.http.handler import
       HandlerExtractor``. Plain ``(Copyable, Defaultable, Handler,
       Movable)`` is the documented public shape.

    Equivalent to declaring ``(Copyable, Defaultable, Handler,
    Movable)`` directly -- no new methods, no new behaviour.
    Collapses the four-trait conformance line that every
    ``Extracted[H]``-mounted handler ends up writing into one
    name.

    The four conformances are required by :class:`Extracted[H]`:

    * ``Defaultable`` -- ``Extracted`` default-constructs ``H``
      once per request before walking its fields with the
      reflection step.
    * ``Handler`` -- ``H.serve(req)`` is the actual user code
      that runs after extractor population.
    * ``Copyable & Movable`` -- the same bound the parametric
      ``Router.get[H: Handler & Copyable & Movable]`` overload
      requires for boxed-handler registration.

    Use as the trait-conformance line on any handler struct
    intended for ``Extracted[H]`` auto-injection::

        @fieldwise_init
        struct GetUser(HandlerExtractor):
            var id: PathInt[\"id\"]
            var trace: QueryStr[\"trace\"]
            var auth: HeaderStr[\"Authorization\"]

            def __init__(out self):
                self.id = PathInt[\"id\"]()
                self.trace = QueryStr[\"trace\"]()
                self.auth = HeaderStr[\"Authorization\"]()

            def serve(self, req: Request) raises -> Response:
                ...

        var r = Router()
        r.get(\"/users/:id\", Extracted[GetUser]())

    Re-exported from :mod:`flare.http.handler` only (the demoted
    internal-adapter import path).

    The manual no-arg ``__init__`` body is still required
    today because Mojo's ``@fieldwise_init`` doesn't auto-derive a
    no-arg constructor from per-field ``Defaultable`` impls. Ceiling:
    every handler struct must hand-write the field-by-field default
    constructor. Upgrade path: a Mojo language-support item -- once
    ``@fieldwise_init`` (or a ``@default``-style derive) synthesizes
    the no-arg ctor from per-field ``Defaultable``, each handler's
    body collapses to ``pass``. Tracked here rather than worked
    around, since there is no in-language workaround that removes the
    boilerplate.
    """

    pass


trait HandlerInfallible(ImplicitlyDestructible, Movable):
    """A :trait:`Handler` whose ``serve`` is provably infallible.

    .. note::

       **Internal adapter.** Not part of the curated public surface;
       import explicitly via ``from flare.http.handler import
       HandlerInfallible``. The everyday public path is plain
       ``Handler`` with ``raises`` annotated only on bodies that
       actually fail; this trait variant exists as a niche
       optimisation for static-fast-path handlers and the
       :class:`WithRaises` adapter.

    The standard :trait:`Handler` requires ``serve(self, req: Request)
    raises -> Response``. For most handlers this is the right shape:
    real code paths can fail for many reasons (DB query, deserialise,
    external HTTP, etc.), and the server's catch-converts-to-500
    contract handles them uniformly.

    But some handler bodies *literally cannot* fail:

    * A static-response fast path that returns a pre-computed
      :class:`StaticResponse` (no parsing, no I/O, no allocation).
    * A health-check route that always returns 200.
    * A sentinel "the handler ran" route in tests.

    For those, :trait:`HandlerInfallible` lets the implementer write
    ``def serve(self, req: Request) -> Response`` (no ``raises``).
    The :class:`WithRaises` adapter wraps an infallible handler so it
    fits anywhere a regular :trait:`Handler` is expected (Router, App,
    middleware nesting). Mojo's ``def`` supports both raises and
    no-raises declarations -- this trait variant just lets the
    framework express the no-raises shape on a handler-by-handler
    basis.
    """

    def serve(self, req: Request) -> Response:
        """Produce a ``Response`` for ``req``. Cannot fail.

        Args:
            req: The incoming request.

        Returns:
            The response to send back to the client. Implementations
            that might fail must use :trait:`Handler` instead.
        """
        ...


# ── FnHandler: backwards-compatibility shim ───────────────────────────────────


struct FnHandler(Copyable, Handler):
    """Adapts a plain ``def(Request) raises -> Response`` into a ``Handler``.

    Stores the function as a runtime field (same cost as 's
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
        a direct ``self.f(req)`` - matches 's hot path.
        """
        return self.f(req)


# ── FnHandlerCT: comptime-parametric, zero-size ─────────────────────────────


struct FnHandlerCT[F: def(Request) raises thin -> Response](Copyable, Handler):
    """Comptime-parametric adapter: the wrapped function is a type
    parameter, not a runtime field.

    Zero-size at runtime (no ``var f``); the compiler monomorphises
    ``serve`` per ``F`` so the call site reduces to a direct,
    statically-known ``F(req)``. This is what gives the Handler path
    the same machine code as a bare function call in the prior ``HttpServer.serve(def...)`` shape.

    Usage:
        ```mojo
        def hello(req: Request) raises -> Response:
            return ok("hello")

        comptime HelloHandler = FnHandlerCT[hello]

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


# ── CancelHandler trait + WithCancel adapter ────────────────


trait CancelHandler(ImplicitlyDestructible, Movable):
    """A request-to-response contract that takes a ``Cancel`` token.

    The reactor calls ``serve(req, cancel)`` once per parsed request.
    The handler reads ``cancel.cancelled()`` between expensive steps
    and returns early when the cell flips.

    Mojo as of .dev2026042205 cannot express "trait B refines
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
            def serve(self, req: Request, cancel: Cancel) raises -> Response:
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
            req: The incoming request.
            cancel: Per-request cancel token. Polled by the handler
                between expensive steps; the reactor flips the cell
                on peer FIN, deadline, or drain.

        Returns:
            The response to send back to the client.

        Raises:
            Error: Any error; the reactor maps this to a 500 response.
        """
        ...


# ── ViewHandler trait + WithViewCancel adapter ────


trait ViewHandler(ImplicitlyDestructible, Movable):
    """Borrowed-input request-to-response contract.

    Like ``CancelHandler`` but takes a ``RequestView[origin]`` whose
    ``body`` is a ``Span[UInt8, origin]`` borrowed from the
    connection's read buffer. Handlers that don't need owned
    request state get true zero-copy reads — the body slice points
    directly into ``read_buf`` rather than into a heap-allocated
    ``List[UInt8]``.

    The reactor's view-aware read path
    (``run_reactor_loop_view`` + ``HttpServer.serve_view``)
    constructs a ``RequestView`` per request via
    ``parse_request_view`` and dispatches it through this trait.
    The owned ``Request`` materialisation that
    ``Handler.serve(req: Request)`` requires happens only when a
    handler explicitly calls ``view.into_owned()`` — e.g. to keep
    request state past the current event-loop iteration, or to
    forward to a wrapped ``Handler`` (see ``WithViewCancel``
    below).

    Cancellation: same ``Cancel`` token shape as
    ``CancelHandler``. The reactor flips the cell on peer FIN,
    deadline, or drain; the handler polls ``cancel.cancelled()``
    between expensive steps.

    Example:
        ```mojo
        from flare.http import (
            ViewHandler, RequestView, Cancel, Response, ok,
        )

        @fieldwise_init
        struct UploadEcho(ViewHandler, Copyable, Movable):
            def serve_view[
                origin: Origin
            ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
                # ``req.body()`` returns Span[UInt8, origin] —
                # borrowed from the connection buffer, no copy.
                var body = req.body()
                if len(body) >= 16:
                    var head = body[0:16]
                    var s = String(unsafe_from_utf8=head)
                    return ok("got 16 bytes: " + s)
                return ok("short body, len=" + String(len(body)))
        ```
    """

    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        """Produce a ``Response`` for ``req``, observing ``cancel``.

        Args:
            req: The incoming request as a borrowed view. Body
                / URL / headers are offsets into the connection's
                read buffer; no allocation per request on the
                read path.
            cancel: Per-request cancel token. Polled by the
                handler between expensive steps.

        Returns:
            The response to send back to the client.

        Raises:
            Error: Any error; the reactor maps this to a 500
                response.
        """
        ...


@fieldwise_init
struct WithViewCancel[H: Handler & Copyable & Movable](
    Copyable, Movable, ViewHandler
):
    """Adapter that lets a plain ``Handler`` plug into the
    view-aware reactor path.

    .. note::

       **Internal adapter.** Not part of the curated public surface;
       import explicitly via ``from flare.http.handler import
       WithViewCancel``. The documented public path for the view
       reactor is implementing :trait:`ViewHandler` directly.

    ``WithViewCancel[H]`` materialises an owned ``Request`` from
    the borrowed view via ``into_owned()`` and forwards every
    request to ``H.serve(req)``. Defeats the zero-copy benefit of
    the view path — use ``ViewHandler`` directly when the handler
    can read body / headers / URL through the borrowed slice.
    Use this adapter only when you need to plug an existing
    ``Handler`` struct into a server entry point that takes
    ``serve_view`` (e.g. a Router that's a ``Handler`` but must
    coexist with ``ViewHandler``-shaped sibling handlers in the
    same server).

    Wrapping is zero-overhead apart from the ``into_owned`` body
    copy: ``H.serve`` is the only generated work after the copy.

    Example:
        ```mojo
        from flare.http import HttpServer, Router, Request, Response, ok
        from flare.http.handler import WithViewCancel
        from flare.net import SocketAddr

        def hello(req: Request) raises -> Response:
            return ok("hello")

        def main() raises:
            var r = Router()
            r.get("/", hello)
            var srv = HttpServer.bind(SocketAddr.localhost(8080))
            srv.serve_view(WithViewCancel[Router](r^))
        ```
    """

    var inner: Self.H
    """Wrapped plain handler; ``serve(req)`` is called after
    ``view.into_owned()``."""

    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        """Materialise an owned ``Request`` and forward.

        Args:
            req: Borrowed-view request.
            cancel: Per-request cancel token. **Ignored** by the
                adapter; the wrapped ``Handler`` does not observe
                cancellation.

        Returns:
            Whatever ``self.inner.serve(owned)`` returns.
        """
        var owned = req.into_owned()
        return self.inner.serve(owned^)


# ── (existing) WithCancel adapter ──────────────────────────────────────────


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
            req: The incoming request.
            cancel: Per-request cancel token. **Ignored** by the
                adapter; the wrapped ``Handler`` does not observe
                cancellation.

        Returns:
            Whatever ``self.inner.serve(req)`` returns.
        """
        return self.inner.serve(req)


# ── WithRaises: HandlerInfallible -> Handler adapter ─────────────────────────


@fieldwise_init
struct WithRaises[Inner: HandlerInfallible & Copyable & Movable](
    Copyable, Handler, Movable
):
    """Adapt a :trait:`HandlerInfallible` so it fits the regular
    :trait:`Handler` constraint.

    .. note::

       **Internal adapter.** Not part of the curated public surface;
       import explicitly via ``from flare.http.handler import
       WithRaises``. Pairs with :trait:`HandlerInfallible`, which
       lives behind the same import path.

    Use cases:

    * ``Router.get(path, h)`` accepts a :trait:`Handler`. Wrapping
      an infallible handler in :class:`WithRaises` lets it slot in
      without rewriting the router signature.
    * Middleware chains (:class:`Logger`, :class:`Cors`, etc.)
      compose against :trait:`Handler`. The adapter fits the
      infallible handler at the bottom of the chain.

    The adapter has zero runtime cost: ``serve`` is ``@always_inline``,
    forwards directly to the inner ``serve(req)``, and the only added
    work is satisfying the ``raises`` contract (which the compiler
    elides since the inner call is provably infallible).

    The reverse adapter does NOT exist: a :trait:`Handler` can fail,
    so it isn't safe to expose as :trait:`HandlerInfallible`.
    """

    var inner: Self.Inner
    """The wrapped infallible handler."""

    @always_inline
    def serve(self, req: Request) raises -> Response:
        """Forward to ``self.inner.serve(req)``. The ``raises``
        annotation is satisfied vacuously: the inner ``serve`` is
        infallible by construction."""
        return self.inner.serve(req)
