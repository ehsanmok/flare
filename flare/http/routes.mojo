"""Comptime-compiled route table and ``ComptimeRouter``.

``Router`` in [`flare.http.router`](./router.mojo) is a runtime-driven
dispatcher: patterns are parsed into segment lists at registration
time and scanned linearly on every request. That's a fine default
when routes are registered dynamically or come from user input, but
it leaves two concrete wins on the table when the route table is
known at compile time:

1. **Zero start-up work.** Segment parsing for every route happens at
   compile time via ``comptime for`` over the comptime ``routes``
   list. Nothing allocates at module import time.
2. **Monomorphised dispatch.** The serve loop unrolls per-route via
   ``comptime for`` so each iteration's literal / param / wildcard
   decision is a compile-time constant and the compiler can inline
   the per-route work. No ``List[_Route]`` iteration at runtime.

Usage mirrors the runtime ``Router``:

```mojo
from flare.http import (
    ComptimeRoute, ComptimeRouter, Request, Response, Method, ok,
)

def home(req: Request) raises -> Response:
    return ok("home")

def get_user(req: Request) raises -> Response:
    return ok("user=" + req.param("id"))

comptime ROUTES: List[ComptimeRoute] = [
    ComptimeRoute(Method.GET, "/",          home),
    ComptimeRoute(Method.GET, "/users/:id", get_user),
]

def main() raises:
    var r = ComptimeRouter[ROUTES]()
    # r is a Handler; pass to HttpServer.serve.
```

All three fields of ``ComptimeRoute`` (method, pattern, handler) are
comptime values, so the dispatch loop monomorphises fully per route.
Because every handler shares a common ``def(Request) raises ->
Response`` signature, the list is homogeneous and can live as a
comptime constant — no separate ``set_handler`` step, no runtime
handler-index book-keeping.

Same status-code contract as ``Router``: unknown path → 404, known
path wrong method → 405 with a synthesised ``Allow:`` header. Path
parameters captured by a match land in ``req.params_mut()`` just
like the runtime router.
"""

from std.collections import Dict

from .handler import Handler
from .headers import HeaderMap
from .request import Request, Method
from .response import Response, Status


# ── Public comptime route metadata ──────────────────────────────────────────


@fieldwise_init
struct ComptimeRoute(Copyable, Movable):
    """A comptime-known ``(method, pattern, handler)`` triple.

    All three fields share a common function-pointer signature
    (``def(Request) raises -> Response``), so a homogeneous
    ``List[ComptimeRoute]`` can live as a comptime value and be
    unrolled by ``ComptimeRouter.serve`` at compile time.
    """

    var method: StaticString
    var pattern: StaticString
    var handler: def(Request) raises thin -> Response


# ── Segment classification (pure comptime) ──────────────────────────────────


comptime _SLASH: UInt8 = 47
comptime _QMARK: UInt8 = 63
comptime _COLON: UInt8 = 58
comptime _STAR: UInt8 = 42


@always_inline
def _split_static(path: StaticString) -> List[String]:
    """Split a ``StaticString`` path on ``/``, dropping empty segments.

    Runs at compile time when ``path`` is a comptime value; the return
    type is a ``List[String]`` (not ``List[StaticString]``) so the
    dispatch code can compare against request bytes using the same
    owned-``String`` ergonomics as the runtime router.
    """
    var s = String(path)
    var out = List[String]()
    var n = s.byte_length()
    if n == 0:
        return out^
    var p = s.unsafe_ptr()
    var start = 0
    if p[0] == _SLASH:
        start = 1
    var i = start
    while i < n:
        if p[i] == _SLASH:
            if i > start:
                out.append(String(unsafe_from_utf8=s.as_bytes()[start:i]))
            start = i + 1
        i += 1
    if start < n:
        out.append(String(unsafe_from_utf8=s.as_bytes()[start:n]))
    return out^


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
def _split_path(path: String) -> List[String]:
    """Split a runtime request path on ``/``, dropping empty segments."""
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


# ── Per-segment match primitives ────────────────────────────────────────────


@always_inline
def _seg_is_param(seg: String) -> Bool:
    """Return True if ``seg`` is a ``:name`` capture."""
    return seg.byte_length() >= 2 and seg.unsafe_ptr()[0] == _COLON


@always_inline
def _seg_is_wildcard(seg: String) -> Bool:
    """Return True if ``seg`` is a bare ``*`` wildcard tail."""
    return seg.byte_length() == 1 and seg.unsafe_ptr()[0] == _STAR


@always_inline
def _param_name(seg: String) -> String:
    """Strip the leading ``:`` from a param segment."""
    return String(unsafe_from_utf8=seg.as_bytes()[1 : seg.byte_length()])


# ── ComptimeRouter ──────────────────────────────────────────────────────────


struct ComptimeRouter[routes: List[ComptimeRoute]](Copyable, Handler, Movable):
    """A ``Handler`` whose route table is comptime-parametric.

    Parameters:
        routes: Comptime-known list of ``(method, pattern, handler)``
            triples. Segment parsing happens at compile time; the
            dispatch loop unrolls via ``comptime for`` so each
            iteration sees the route's pattern and handler as
            comptime values and the compiler can inline both.

    ``ComptimeRouter`` carries no runtime handler table — the
    handlers are part of the comptime ``routes`` parameter — so the
    struct is zero-size (``__init__`` is a no-op). Pass it to
    ``HttpServer.serve`` the same way as the runtime ``Router``.
    """

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        """Dispatch ``req`` by walking the comptime routes table.

        Same contract as ``Router.serve``: first matching route wins;
        404 on no match; 405 with ``Allow:`` header on method mismatch.
        """
        var url_path = _path_only(req.url)
        var seg_in = _split_path(url_path)

        var allowed = List[String]()

        # Walk the comptime route table. ``comptime for`` unrolls the
        # loop: each iteration's pattern segments, method, and handler
        # are comptime values the compiler can inline directly.
        comptime n_routes = len(Self.routes)
        comptime for i in range(n_routes):
            comptime r = Self.routes[i]
            comptime pat_segs = _split_static(r.pattern)
            var rt_pat = materialize[pat_segs]()
            var params = Dict[String, String]()
            if _match_one(seg_in, rt_pat, params):
                if r.method == req.method:
                    var child = Request(
                        method=req.method,
                        url=req.url,
                        body=req.body.copy(),
                        version=req.version,
                    )
                    child.headers = req.headers.copy()
                    if req.has_params():
                        for kv in req._params.value()[].items():
                            child.params_mut()[kv.key] = kv.value
                    if len(params) > 0:
                        for kv in params.items():
                            child.params_mut()[kv.key] = kv.value
                    return r.handler(child^)
                else:
                    var m = String(r.method)
                    if not _contains(allowed, m):
                        allowed.append(m)

        if len(allowed) > 0:
            return _method_not_allowed(allowed)
        return _not_found(req.url)


# ── Match primitive ─────────────────────────────────────────────────────────


def _match_one(
    url_segs: List[String],
    pat_segs: List[String],
    mut params: Dict[String, String],
) raises -> Bool:
    """Attempt to match one request against one comptime-compiled pattern.

    Same semantics as the runtime Router's ``_match``: literal equality,
    ``:name`` captures one segment, trailing ``*`` captures the rest.
    """
    var i = 0
    var j = 0
    while j < len(pat_segs):
        var seg = pat_segs[j]
        if _seg_is_wildcard(seg):
            if i >= len(url_segs):
                return False
            var tail = String("")
            while i < len(url_segs):
                if tail.byte_length() > 0:
                    tail += "/"
                tail += url_segs[i]
                i += 1
            params["*"] = tail
            return True
        if i >= len(url_segs):
            return False
        if _seg_is_param(seg):
            params[_param_name(seg)] = url_segs[i]
        else:
            if url_segs[i] != seg:
                return False
        i += 1
        j += 1
    return i == len(url_segs)


# ── Response helpers ────────────────────────────────────────────────────────


def _not_found(url: String) raises -> Response:
    var msg = "Not Found"
    if url.byte_length() > 0:
        msg = "Not Found: " + url
    var body = List[UInt8](capacity=msg.byte_length())
    for b in msg.as_bytes():
        body.append(b)
    var resp = Response(status=Status.NOT_FOUND, reason="Not Found", body=body^)
    resp.headers.set("Content-Type", "text/plain")
    return resp^


def _method_not_allowed(allowed: List[String]) raises -> Response:
    var allow_value = String("")
    for i in range(len(allowed)):
        if i > 0:
            allow_value += ", "
        allow_value += allowed[i]
    var body = List[UInt8]()
    var msg = "Method Not Allowed"
    for b in msg.as_bytes():
        body.append(b)
    var resp = Response(
        status=Status.METHOD_NOT_ALLOWED,
        reason="Method Not Allowed",
        body=body^,
    )
    resp.headers.set("Content-Type", "text/plain; charset=utf-8")
    resp.headers.set("Allow", allow_value)
    return resp^


@always_inline
def _contains(xs: List[String], x: String) -> Bool:
    for i in range(len(xs)):
        if xs[i] == x:
            return True
    return False
