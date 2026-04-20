"""HTTP request router with method dispatch + path parameters.

A ``Router`` is a ``Handler`` that dispatches each request to a
per-(method, path) inner handler. It supports:

- **Literal segments**: ``"/users"`` matches exactly ``/users``.
- **Parameter segments**: ``":id"`` matches one segment of any non-empty
  value; the captured value lands in ``req.params[name]``.
- **Wildcard tail**: a final segment ``"*"`` matches the rest of the
  path (captured as ``req.params["*"]``, including path separators).
- **Method dispatch**: ``get`` / ``post`` / ``put`` / ``patch`` /
  ``delete`` / ``head`` register one handler per (method, path) pair.

Unknown paths return **404 Not Found**; known paths called with the
wrong method return **405 Method Not Allowed** with a synthesised
``Allow:`` header listing the supported methods.

Sub-router mounting (``mount(prefix, sub)``) is scheduled for v0.4.1
once the ownership model for nested routers is settled; the current
Router is a flat map from ``(method, path)`` to handler.

Example:

```mojo
from flare.http import Router, Request, Response, ok, not_found

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user " + req.params["id"])

def main() raises:
    var r = Router()
    r.get("/",           home)
    r.get("/users/:id",  get_user)

    # `r` is a Handler; pass it to HttpServer.serve.
```

This first release uses a simple runtime match (linear scan per depth
plus a per-entry segment compare). A compile-time trie lives on the
v0.4.1 roadmap; the public Router API will not change when the trie
lands, only the internal representation.
"""

from std.collections import Dict
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


struct _Route(Copyable, Movable):
    """Compiled pattern + method + handler index into the router's
    handler storage.
    """

    var method: String
    var segs: List[_Segment]
    var handler_idx: Int

    def __init__(
        out self,
        method: String,
        var segs: List[_Segment],
        handler_idx: Int,
    ):
        self.method = method
        self.segs = segs^
        self.handler_idx = handler_idx


# ── Router ───────────────────────────────────────────────────────────────────


struct Router(Handler):
    """HTTP router with method dispatch, path parameters, and nesting.

    Routes are stored as ``(method, compiled-segments, handler-index)``
    triples. Handlers live in a parallel ``List[FnHandler]`` so the
    index is stable across moves.

    For v0.4.0 the router accepts plain ``def(Request) raises -> Response``
    functions (wrapped internally in ``FnHandler``). Future versions will
    accept arbitrary ``Handler`` structs and comptime-compiled
    signatures; the ``get`` / ``post`` / ``put`` ... entry points stay
    the same.
    """

    var _routes: List[_Route]
    var _handlers: List[FnHandler]

    def __init__(out self):
        """Create an empty router (no routes)."""
        self._routes = List[_Route]()
        self._handlers = List[FnHandler]()

    # ── Registration per method ──────────────────────────────────────────────

    def get(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``GET path``.

        Args:
            path:    Route pattern (e.g. ``"/users/:id"``).
            handler: The function to call on a match.
        """
        self._add(Method.GET, path, handler)

    def post(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``POST path``."""
        self._add(Method.POST, path, handler)

    def put(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``PUT path``."""
        self._add(Method.PUT, path, handler)

    def patch(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``PATCH path``."""
        self._add(Method.PATCH, path, handler)

    def delete(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``DELETE path``."""
        self._add(Method.DELETE, path, handler)

    def head(
        mut self,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Register ``handler`` for ``HEAD path``."""
        self._add(Method.HEAD, path, handler)

    def _add(
        mut self,
        method: String,
        path: String,
        handler: def(Request) raises thin -> Response,
    ) raises:
        var segs = _compile_segments(path)
        self._handlers.append(FnHandler(handler))
        self._routes.append(_Route(method, segs^, len(self._handlers) - 1))

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
            for kv in req.params.items():
                child.params[kv.key] = kv.value
            for kv in m_result.params.items():
                child.params[kv.key] = kv.value
            return self._handlers[self._routes[i].handler_idx].serve(child^)

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
