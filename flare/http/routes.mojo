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
    ComptimeRoute(Method.GET, "/"),
    ComptimeRoute(Method.GET, "/users/:id"),
]

def main() raises:
    var r = ComptimeRouter[ROUTES]()
    r.set_handler(0, home)
    r.set_handler(1, get_user)
    # r is a Handler; pass to HttpServer.serve.
```

Handlers still live on a runtime ``List[FnHandler]`` because Mojo cannot
yet pack heterogeneous ``def`` types into a single comptime list; the
``ComptimeRoute`` values carry just the method + pattern metadata so
the segment dispatch can still monomorphise even though the actual
handler dispatch is a ``FnHandler`` indirect call.

Same status-code contract as ``Router``: unknown path → 404, known
path wrong method → 405 with a synthesised ``Allow:`` header. Path
parameters captured by a match land in ``req._params_mut()`` just
like the runtime router.
"""

from std.collections import Dict

from .handler import Handler, FnHandler
from .headers import HeaderMap
from .request import Request, Method
from .response import Response, Status


# ── Public comptime route metadata ──────────────────────────────────────────


@fieldwise_init
struct ComptimeRoute(Copyable, Movable):
    """A comptime-known ``(method, pattern)`` pair.

    Only the strings that are genuinely known at compile time are
    stored; the handler is bound separately at runtime via
    ``ComptimeRouter.set_handler(idx, fn)`` so different ``fn`` types
    can coexist in one table.
    """

    var method: StaticString
    var pattern: StaticString


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
        routes: Comptime-known list of ``(method, pattern)`` pairs.
            Segment parsing happens at compile time; dispatch
            monomorphises per-route via ``comptime for``.

    The handler list is a runtime ``List[FnHandler]`` aligned by index
    with ``routes``; users bind each handler with
    ``set_handler(idx, fn)`` before passing the router to
    ``HttpServer.serve``. Leaving a slot unset is allowed and surfaces
    as a 500 at request time (unset slots are caught by ``serve``).
    """

    var _handlers: List[FnHandler]
    var _bound: List[Bool]

    def __init__(out self):
        """Create a router with no handlers bound yet.

        The handler list is pre-sized to ``len(routes)`` so
        ``set_handler`` is O(1).
        """
        self._handlers = List[FnHandler]()
        self._bound = List[Bool]()
        comptime n = len(Self.routes)
        for _ in range(n):
            self._handlers.append(FnHandler(_unset_handler))
            self._bound.append(False)

    def set_handler(
        mut self,
        idx: Int,
        handler: def(Request) raises thin -> Response,
    ) raises:
        """Bind ``handler`` to the route at ``idx`` (0-indexed into
        ``routes``). Raises ``Error`` if ``idx`` is out of range.
        """
        if idx < 0 or idx >= len(self._handlers):
            raise Error(
                "ComptimeRouter.set_handler: index "
                + String(idx)
                + " out of range (have "
                + String(len(self._handlers))
                + " routes)"
            )
        self._handlers[idx] = FnHandler(handler)
        self._bound[idx] = True

    def serve(self, req: Request) raises -> Response:
        """Dispatch ``req`` by walking the comptime routes table.

        Same contract as ``Router.serve``: first matching route wins;
        404 on no match; 405 with ``Allow:`` header on method mismatch.
        """
        var url_path = _path_only(req.url)
        var seg_in = _split_path(url_path)

        var allowed = List[String]()
        var matched_idx = -1
        var matched_params: Dict[String, String] = Dict[String, String]()

        # Walk the comptime route table. ``comptime for`` unrolls the
        # loop: each iteration's pattern segments are comptime values.
        comptime n_routes = len(Self.routes)
        comptime for i in range(n_routes):
            if matched_idx < 0:
                comptime r = Self.routes[i]
                comptime pat_segs = _split_static(r.pattern)
                var rt_pat = materialize[pat_segs]()
                var params = Dict[String, String]()
                var matched = _match_one(seg_in, rt_pat, params)
                if matched:
                    if r.method == req.method:
                        matched_idx = i
                        matched_params = params^
                    else:
                        var m = String(r.method)
                        if not _contains(allowed, m):
                            allowed.append(m)

        if matched_idx >= 0:
            if not self._bound[matched_idx]:
                raise Error(
                    "ComptimeRouter: route index "
                    + String(matched_idx)
                    + " has no bound handler"
                )
            var child = Request(
                method=req.method,
                url=req.url,
                body=req.body.copy(),
                version=req.version,
            )
            child.headers = req.headers.copy()
            if req.has_params():
                for kv in req._params[].items():
                    child._params_mut()[kv.key] = kv.value
            if len(matched_params) > 0:
                for kv in matched_params.items():
                    child._params_mut()[kv.key] = kv.value
            return self._handlers[matched_idx].serve(child^)

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


@always_inline
def _unset_handler(req: Request) raises -> Response:
    """Placeholder for an unbound ``ComptimeRouter`` slot. ``serve``
    guards against reaching this path, but the list has to be
    pre-filled with *some* ``FnHandler`` because ``FnHandler`` wraps a
    runtime ``def`` pointer.
    """
    raise Error("ComptimeRouter: handler not bound")
