"""``flare.grpc.interceptor`` -- chainable unary server interceptors.

An interceptor wraps a :trait:`GrpcUnary` handler so cross-cutting
concerns (auth, logging, metrics, metadata injection) compose without
touching the business handler. Mojo has no first-class closures for a
``handler(ctx, req, next)`` shape, so interception is modeled as a
``before`` / ``after`` pair around the wrapped call:

* :meth:`GrpcInterceptor.before` runs first. Returning a
  :class:`GrpcUnaryReply` short-circuits the call (e.g. an auth
  interceptor rejecting with ``UNAUTHENTICATED``); returning the empty
  :class:`Optional` proceeds to the inner handler.
* :meth:`GrpcInterceptor.after` post-processes the inner handler's
  reply (e.g. attaching trailing metadata or remapping a status).

:class:`Intercepted` adapts ``(interceptor, handler)`` into a new
:trait:`GrpcUnary`, so chains nest:

    Intercepted(authI, Intercepted(logI, EchoHandler()))

The outermost interceptor's ``before`` runs first and its ``after``
runs last (standard onion ordering).
"""

from std.collections import Optional
from std.memory import Span

from .server import GrpcCallContext, GrpcUnary, GrpcUnaryReply


trait GrpcInterceptor(Copyable, Movable):
    """A unary server interceptor: a ``before`` gate + an ``after``
    post-processor around a wrapped :trait:`GrpcUnary` handler."""

    def before(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> Optional[GrpcUnaryReply]:
        """Run before the inner handler. Return a reply to
        short-circuit the call, or the empty ``Optional`` to proceed.
        """
        ...

    def after(
        mut self,
        ctx: GrpcCallContext,
        var reply: GrpcUnaryReply,
    ) raises -> GrpcUnaryReply:
        """Run after the inner handler with its reply. Return the
        (possibly modified) reply.
        """
        ...


struct Intercepted[
    I: Copyable & GrpcInterceptor & ImplicitlyDestructible,
    H: Copyable & GrpcUnary & ImplicitlyDestructible,
](Copyable, GrpcUnary, Movable):
    """Wrap ``handler`` with ``interceptor`` to form a new
    :trait:`GrpcUnary`. Nest to chain multiple interceptors.

    Example:
        ```mojo
        var svc = GrpcService(
            Intercepted(AuthInterceptor(token), EchoHandler())
        )
        ```
    """

    var interceptor: Self.I
    var handler: Self.H

    def __init__(out self, var interceptor: Self.I, var handler: Self.H):
        self.interceptor = interceptor^
        self.handler = handler^

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        var short = self.interceptor.before(ctx, request_bytes)
        if Bool(short):
            return short.value().copy()
        var reply = self.handler.serve_unary(ctx, request_bytes)
        return self.interceptor.after(ctx, reply^)
