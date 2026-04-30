"""HTTP request router with method dispatch + path parameters.

A ``Router`` is a ``Handler`` that dispatches each request to a
per-(method, path) inner handler. It supports:

- **Literal segments**: ``"/users"`` matches exactly ``/users``.
- **Parameter segments**: ``":id"`` matches one segment of any non-empty
  value; the captured value lands in ``req.params[name]``.
- **Wildcard tail**: a final segment ``"*"`` matches the rest of the
  path (captured as ``req.param("*")``, including path separators).
- **Method dispatch**: ``get`` / ``post`` / ``put`` / ``patch`` /
  ``delete`` / ``head`` register one handler per (method, path) pair.

Unknown paths return **404 Not Found**; known paths called with the
wrong method return **405 Method Not Allowed** with a synthesised
``Allow:`` header listing the supported methods.

Sub-router mounting (``mount(prefix, sub)``) is scheduled for once the ownership model for nested routers is settled; the current
Router is a flat map from ``(method, path)`` to handler.

Example:

```mojo
from flare.http import Router, Request, Response, ok, not_found

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user " + req.param("id"))

def main() raises:
    var r = Router()
    r.get("/", home)
    r.get("/users/:id", get_user)

    # `r` is a Handler; pass it to HttpServer.serve.
```

This first release uses a simple runtime match (linear scan per depth
plus a per-entry segment compare). A compile-time trie lives on the
roadmap; the public Router API will not change when the trie
lands, only the internal representation.
"""

from std.collections import Dict
from std.memory import UnsafePointer, alloc

from ..runtime import Pool
from .handler import Handler, FnHandler
from .headers import HeaderMap
from .request import Request, Method
from .response import Response, Status
from .server import not_found


# ── Internal path compilation ────────────────────────────────────────────────


struct _Segment(Copyable, Movable):
    """A single compiled path segment.

    ``kind`` is 0 for literal, 1 for parameter (``":name"``), 2 for
    wildcard tail (``"*"``). ``text`` is the literal text for
    ``kind=0`` or the parameter name for ``kind=1``.
    """

    var kind: Int
    var text: String

    def __init__(out self, kind: Int, text: String):
        self.kind = kind
        self.text = text


comptime _SLASH: UInt8 = 47
comptime _QMARK: UInt8 = 63
comptime _COLON: UInt8 = 58
comptime _STAR: UInt8 = 42


@always_inline
def _split_path(path: String) -> List[String]:
    """Split a path on ``/``. Drops empty segments produced by a
    leading or trailing ``/`` so ``"/users/"`` and ``"users"`` both
    yield ``["users"]``.
    """
    var out = List[String]()
    var n = path.byte_length()
    if n == 0:
        return out^
    var p = path.unsafe_ptr()
    var start = 0
    if p[0] == _SLASH:
        start = 1
    var i = start
    while i < n:
        if p[i] == _SLASH:
            if i > start:
                out.append(String(unsafe_from_utf8=path.as_bytes()[start:i]))
            start = i + 1
        i += 1
    if start < n:
        out.append(String(unsafe_from_utf8=path.as_bytes()[start:n]))
    return out^


def _compile_segments(path: String) raises -> List[_Segment]:
    """Turn a route pattern like ``"/users/:id/posts"`` into a list of
    ``_Segment`` values the matcher can consume one at a time.
    """
    var raw = _split_path(path)
    var segs = List[_Segment]()
    for i in range(len(raw)):
        var s = raw[i]
        var sn = s.byte_length()
        if sn == 0:
            continue
        var sp = s.unsafe_ptr()
        if sn == 1 and sp[0] == _STAR:
            if i != len(raw) - 1:
                raise Error("wildcard '*' must be the last segment in a route")
            segs.append(_Segment(2, "*"))
        elif sn >= 2 and sp[0] == _COLON:
            segs.append(
                _Segment(1, String(unsafe_from_utf8=s.as_bytes()[1:sn]))
            )
        else:
            segs.append(_Segment(0, s))
    return segs^


# ── Route entries ────────────────────────────────────────────────────────────


comptime _ROUTE_KIND_FN: Int = 0
"""Route handler is a plain ``def(Request) raises -> Response``
wrapped in ``FnHandler``. ``handler_idx`` indexes into
``Router._handlers``."""

comptime _ROUTE_KIND_STRUCT: Int = 1
"""Route handler is an arbitrary ``H: Handler`` struct
(). ``handler_idx`` indexes into
``Router._struct_handlers``; the struct lives behind a
heap-allocated opaque pointer with monomorphised serve / destroy
thunks (see ``_StructHandler``)."""


struct _Route(Copyable, Movable):
    """Compiled pattern + method + handler index into the router's
    handler storage.
    """

    var method: String
    var segs: List[_Segment]
    var handler_kind: Int
    """One of ``_ROUTE_KIND_FN`` / ``_ROUTE_KIND_STRUCT``."""
    var handler_idx: Int

    def __init__(
        out self,
        method: String,
        var segs: List[_Segment],
        handler_kind: Int,
        handler_idx: Int,
    ):
        self.method = method
        self.segs = segs^
        self.handler_kind = handler_kind
        self.handler_idx = handler_idx


# ── Struct-handler boxing ───────────────────────

# Mojo can't yet store heterogeneous ``H: Handler`` structs in a
# single ``List``, so we type-erase via a heap-allocated opaque
# pointer paired with two monomorphised function pointers: a serve
# thunk that bitcasts the pointer back to the concrete ``H`` and
# calls ``H.serve``, and a destroy thunk that does the same for
# ``H``'s destructor + ``free``. Both thunks are monomorphised at
# the registration site (``Router.get[H](...)``) so the call
# inside ``Router.serve`` is a direct call through a function
# pointer with no runtime trait dispatch.
#
# This is the same opaque-pointer + typed-thunk idiom the multicore
# ``Scheduler`` uses for ``_WorkerCtx[H]``. The Router's lifecycle
# differs only in that the destroy thunk runs on the Router's
# destructor (when the server stops) rather than after a pthread
# join.


def _struct_serve_thunk[
    H: Handler & Copyable & Movable
](addr: Int, req: Request) raises -> Response:
    """Thunk that materialises the boxed ``H`` from its address
    and forwards to ``H.serve``.

    Monomorphised per ``H`` at the call site so Mojo emits a direct
    call to the inlined ``H.serve`` body — no per-request trait
    dispatch.

    Routes through ``Pool[H].get_ptr`` rather than reconstructing
    the ``UnsafePointer`` arithmetic in-line — keeps the unsafe
    pointer plumbing confined to ``flare/runtime/`` per the
    criticism §2.9 invariant.
    """
    var ptr = Pool[H].get_ptr(addr)
    return ptr[].serve(req)


def _struct_destroy_thunk[H: Handler & Copyable & Movable](addr: Int) -> None:
    """Thunk that destroys + frees the heap-allocated ``H`` at
    ``addr``. Called once per route from ``Router.__del__`` via
    the parallel ``_struct_destroy_thunks`` list.
    """
    Pool[H].free(addr)


# ``_StructHandler`` is represented as three parallel lists on
# ``Router`` rather than a single ``List[_StructHandler]`` because
# Mojo's ``List`` requires ``T: Copyable`` and a Copyable wrapper
# around an owning heap pointer would double-free on copy. The
# parallel-lists trick stores only ``Int`` and function-pointer
# values (all Copyable) and Router's destructor walks the
# ``destroy_thunks`` list once to free every owned allocation.


# ── Router ───────────────────────────────────────────────────────────────────


struct Router(Handler):
    """HTTP router with method dispatch, path parameters, and nesting.

    Accepts both plain ``def(Request) raises -> Response`` functions
    (wrapped internally in ``FnHandler``) **and** arbitrary
    ``H: Handler & Copyable & Movable`` structs (boxed via
    ``_StructHandler`` with monomorphised serve / destroy thunks)
    since (Track 1.4). Use the latter to register
    ``Extracted[H]()``, app-state-bearing handlers, middleware
    wrappers, and any other stateful Handler.

    Routes are stored as ``(method, compiled-segments,
    handler-kind, handler-index)`` quadruples; ``handler-kind``
    selects ``_handlers`` (FnHandler list) or ``_struct_handlers``
    (boxed Handler structs) for the actual call site.

    Example:
        ```mojo
        var r = Router()
        r.get("/", home) # def(Request)
        r.get("/users/:id", Extracted[GetUser]()) # Handler struct
        ```
    """

    var _routes: List[_Route]
    var _handlers: List[FnHandler]
    var _struct_addrs: List[Int]
    """Heap addresses of boxed ``H: Handler`` structs, one per
    struct-handler route. Owned by the Router; freed in ``__del__``
    via the matching ``_struct_destroy_thunks`` entry."""
    var _struct_serve_thunks: List[def(Int, Request) raises thin -> Response]
    """Monomorphised serve thunks; ``_struct_serve_thunks[i]`` is
    the thunk for ``_struct_addrs[i]``."""
    var _struct_destroy_thunks: List[def(Int) thin -> None]
    """Monomorphised destroy thunks; ``_struct_destroy_thunks[i]``
    is the thunk for ``_struct_addrs[i]``. Called from ``__del__``."""

    def __init__(out self):
        """Create an empty router (no routes)."""
        self._routes = List[_Route]()
        self._handlers = List[FnHandler]()
        self._struct_addrs = List[Int]()
        self._struct_serve_thunks = List[
            def(Int, Request) raises thin -> Response
        ]()
        self._struct_destroy_thunks = List[def(Int) thin -> None]()

    def __del__(deinit self):
        """Free every boxed ``H: Handler`` the Router owns.

        Each ``_struct_addrs[i]`` was heap-allocated by
        ``_add_struct[H]`` and is freed here via the matching
        ``_struct_destroy_thunks[i]`` (which runs ``H``'s destructor
        and then ``free``). Indices that already saw a destroy
        (e.g. via a Router move) carry a zero ``addr`` so the
        thunk short-circuits.
        """
        for i in range(len(self._struct_addrs)):
            var addr = self._struct_addrs[i]
            if addr != 0:
                self._struct_destroy_thunks[i](addr)

    # ── Registration per method (def-function overloads) ────────────────────

    def get(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``GET path``.

        Args:
            path: Route pattern (e.g. ``"/users/:id"``).
            handler: The function to call on a match.
        """
        self._add_fn(Method.GET, path, handler)

    def post(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``POST path``."""
        self._add_fn(Method.POST, path, handler)

    def put(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``PUT path``."""
        self._add_fn(Method.PUT, path, handler)

    def patch(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``PATCH path``."""
        self._add_fn(Method.PATCH, path, handler)

    def delete(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``DELETE path``."""
        self._add_fn(Method.DELETE, path, handler)

    def head(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``HEAD path``."""
        self._add_fn(Method.HEAD, path, handler)

    def _add_fn(
        mut self,
        method: String,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        var segs = _compile_segments(path)
        self._handlers.append(FnHandler(handler))
        self._routes.append(
            _Route(method, segs^, _ROUTE_KIND_FN, len(self._handlers) - 1)
        )

    # ── Registration per method (Handler-struct overloads, ) ──

    def get[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``GET path``.

        ``H`` is type-erased into ``_StructHandler`` via heap
        allocation + monomorphised serve / destroy thunks; the
        per-request dispatch is a direct call through the cached
        thunk pointer with no trait-table lookup.

        Use this overload to register ``Extracted[H]()``, app-state
        handlers, middleware-wrapped handlers, and any user-defined
        Handler struct. The ``def(Request) raises -> Response``
        overload above continues to work unchanged.

        Args:
            path: Route pattern (e.g. ``"/users/:id"``).
            handler: A ``Handler & Copyable & Movable`` instance;
                     ownership transfers into the Router (the
                     Router owns the heap allocation and frees it
                     in its destructor).
        """
        self._add_struct[H](Method.GET, path, handler^)

    def post[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``POST path``.
        See ``get[H]`` for the type-erasure shape."""
        self._add_struct[H](Method.POST, path, handler^)

    def put[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``PUT path``.
        See ``get[H]`` for the type-erasure shape."""
        self._add_struct[H](Method.PUT, path, handler^)

    def patch[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``PATCH path``.
        See ``get[H]`` for the type-erasure shape."""
        self._add_struct[H](Method.PATCH, path, handler^)

    def delete[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``DELETE path``.
        See ``get[H]`` for the type-erasure shape."""
        self._add_struct[H](Method.DELETE, path, handler^)

    def head[
        H: Handler & Copyable & Movable
    ](mut self, path: String, var handler: H) raises:
        """Register ``handler`` (a Handler struct) for ``HEAD path``.
        See ``get[H]`` for the type-erasure shape."""
        self._add_struct[H](Method.HEAD, path, handler^)

    def _add_struct[
        H: Handler & Copyable & Movable
    ](mut self, method: String, path: String, var handler: H) raises:
        """Heap-allocate ``handler`` via ``Pool[H]`` (which gates
        on ``size_of[H]() > 0`` internally for ZST handlers like
        ``Extracted[GetUser]``), capture monomorphised serve /
        destroy thunks, append to the route + struct-handler
        tables.

        Per the follow-up cleanup, this routes through
        ``Pool[H]`` rather than reaching into ``alloc[H]``
        directly — keeps the unsafe-pointer plumbing confined to
        ``flare/runtime/`` and drops the ``_Boxed[H]``
        1-byte phantom pad now that ``size_of`` is public.
        """
        var segs = _compile_segments(path)
        var addr = Pool[H].alloc_move(handler^)

        self._struct_addrs.append(addr)
        self._struct_serve_thunks.append(_struct_serve_thunk[H])
        self._struct_destroy_thunks.append(_struct_destroy_thunk[H])
        self._routes.append(
            _Route(
                method,
                segs^,
                _ROUTE_KIND_STRUCT,
                len(self._struct_addrs) - 1,
            )
        )

    # ── Handler impl ─────────────────────────────────────────────────────────

    def serve(self, req: Request) raises -> Response:
        """Dispatch ``req`` to the matching handler.

        Returns the handler's response, or a 404 / 405 if no
        route matches.
        """
        var url_path = _path_only(req.url)
        var segs_in = _split_path(url_path)

        var allowed = List[String]()
        for i in range(len(self._routes)):
            var m_result = _match(segs_in, self._routes[i].segs)
            if not m_result.matched:
                continue
            if self._routes[i].method != req.method:
                if not _contains(allowed, self._routes[i].method):
                    allowed.append(self._routes[i].method)
                continue
            # Match — inject params, invoke handler.
            var child = Request(
                method=req.method,
                url=req.url,
                body=req.body.copy(),
                version=req.version,
            )
            child.headers = req.headers.copy()
            # Copy any params already on the parent (e.g. nested routers
            # via ``mount``) into the child. ``req`` is a read-only
            # borrow here, so we peek at the raw ``_params`` pointer
            # rather than calling the ``mut self`` accessor. Only
            # allocates ``child._params`` when there is something to
            # copy, so the plaintext-bench path (no Router, no params)
            # stays allocation-free.
            if req.has_params():
                for kv in req._params.value()[].items():
                    child.params_mut()[kv.key] = kv.value
            # Copy the captures from this match. ``_MatchResult.params``
            # is always populated (even if empty), so guard on length to
            # avoid a pointless lazy-allocate for literal-only routes.
            if len(m_result.params) > 0:
                for kv in m_result.params.items():
                    child.params_mut()[kv.key] = kv.value
            # Dispatch based on handler kind. ``_ROUTE_KIND_FN`` goes
            # through the FnHandler list (zero-overhead direct call);
            # ``_ROUTE_KIND_STRUCT`` calls the monomorphised serve thunk
            # captured at registration time, which bitcasts the boxed
            # Handler struct back to its concrete type and forwards
            # to ``H.serve``.
            if self._routes[i].handler_kind == _ROUTE_KIND_FN:
                return self._handlers[self._routes[i].handler_idx].serve(child^)
            else:
                var sh_idx = self._routes[i].handler_idx
                var addr = self._struct_addrs[sh_idx]
                var thunk = self._struct_serve_thunks[sh_idx]
                return thunk(addr, child^)

        if len(allowed) > 0:
            return _method_not_allowed(allowed)
        return not_found(req.url)


# ── Internals ────────────────────────────────────────────────────────────────


struct _MatchResult(Movable):
    var matched: Bool
    var params: Dict[String, String]

    def __init__(out self):
        self.matched = False
        self.params = Dict[String, String]()


def _match(
    url_segs: List[String], pattern: List[_Segment]
) raises -> _MatchResult:
    """Return whether ``url_segs`` matches the pattern; on match,
    fills in captured params.
    """
    var result = _MatchResult()
    var i = 0
    var j = 0
    while j < len(pattern):
        var kind = pattern[j].kind
        if kind == 2:
            # Wildcard tail — must consume at least one segment.
            if i >= len(url_segs):
                return result^
            var tail = String("")
            while i < len(url_segs):
                if tail.byte_length() > 0:
                    tail += "/"
                tail += url_segs[i]
                i += 1
            result.params["*"] = tail
            result.matched = True
            return result^
        if i >= len(url_segs):
            return result^
        if kind == 0:
            if url_segs[i] != pattern[j].text:
                return result^
        else:
            result.params[pattern[j].text] = url_segs[i]
        i += 1
        j += 1
    if i == len(url_segs):
        result.matched = True
    return result^


def _method_not_allowed(allowed: List[String]) raises -> Response:
    """Synthesise a 405 Method Not Allowed response with an ``Allow``
    header listing the supported methods.
    """
    var allow_value = String("")
    for i in range(len(allowed)):
        if i > 0:
            allow_value += ", "
        allow_value += allowed[i]
    var body_bytes = List[UInt8]()
    var msg = "Method Not Allowed"
    for b in msg.as_bytes():
        body_bytes.append(b)
    var resp = Response(
        status=Status.METHOD_NOT_ALLOWED,
        reason="Method Not Allowed",
        body=body_bytes^,
    )
    resp.headers.set("Content-Type", "text/plain; charset=utf-8")
    resp.headers.set("Allow", allow_value)
    return resp^


@always_inline
def _path_only(url: String) -> String:
    """Return the path portion of ``url`` (strip query string)."""
    var n = url.byte_length()
    var p = url.unsafe_ptr()
    for i in range(n):
        if p[i] == _QMARK:
            return String(unsafe_from_utf8=url.as_bytes()[0:i])
    return url


@always_inline
def _contains(xs: List[String], x: String) -> Bool:
    for i in range(len(xs)):
        if xs[i] == x:
            return True
    return False
