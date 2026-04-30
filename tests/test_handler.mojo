"""Tests for ``flare.http.Handler`` and ``FnHandler``.

The tests exercise four angles:

1. A plain struct implementing ``Handler`` with state that the handler
   reads.
2. ``FnHandler`` wrapping a ``def(Request) raises -> Response`` so the
   signature keeps working unchanged.
3. Handlers that compose by wrapping (``Logged`` wraps an inner handler).
4. Handlers that raise an error (the trait allows this; the server's
   job is to catch + convert to 500).
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    assert_raises,
    TestSuite,
)

from flare.http import Handler, FnHandler, Request, Response, Status, Method, ok
from flare.http.server import bad_request


# ── Handler trait: struct implementations ───────────────────────────────────


@fieldwise_init
struct _Greeter(Handler, Movable):
    """A greeter handler with stateful greeting string."""

    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting + " from " + req.url)


def test_struct_handler_basic() raises:
    """A struct implementing Handler responds using its own state."""
    var h = _Greeter("hello")
    var req = Request(method=Method.GET, url="/home")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)


def test_struct_handler_reads_state() raises:
    """Handler state is visible in the response body."""
    var h = _Greeter("ciao")
    var req = Request(method=Method.GET, url="/x")
    var resp = h.serve(req)
    assert_true(resp.text().find("ciao") >= 0)


def test_struct_handler_reads_request_url() raises:
    """Handler can read req.url."""
    var h = _Greeter("yo")
    var req = Request(method=Method.GET, url="/deep/path")
    var resp = h.serve(req)
    assert_true(resp.text().find("/deep/path") >= 0)


def test_struct_handler_many_calls_share_state() raises:
    """Multiple calls on the same handler share state (no reset)."""
    var h = _Greeter("hi")
    var r1 = Request(method=Method.GET, url="/a")
    var r2 = Request(method=Method.GET, url="/b")
    assert_equal(h.serve(r1).status, Status.OK)
    assert_equal(h.serve(r2).status, Status.OK)
    assert_equal(h.greeting, "hi")


# ── FnHandler: adapter for def(Request) raises -> Response ──────────────────


def _hello_fn(req: Request) raises -> Response:
    return ok("hello")


def _echo_path_fn(req: Request) raises -> Response:
    return ok(req.url)


def _post_only_fn(req: Request) raises -> Response:
    if req.method != Method.POST:
        return bad_request("method not allowed")
    return ok("posted")


def test_fnhandler_wraps_def() raises:
    """FnHandler wraps a plain function and returns the same response."""
    var h = FnHandler(_hello_fn)
    var req = Request(method=Method.GET, url="/")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "hello")


def test_fnhandler_forwards_url() raises:
    """FnHandler forwards req.url to the wrapped function."""
    var h = FnHandler(_echo_path_fn)
    var req = Request(method=Method.GET, url="/users/42")
    var resp = h.serve(req)
    assert_equal(resp.text(), "/users/42")


def test_fnhandler_preserves_method_logic() raises:
    """FnHandler preserves method-dependent branches in the wrapped fn."""
    var h = FnHandler(_post_only_fn)
    var get_req = Request(method=Method.GET, url="/x")
    var post_req = Request(method=Method.POST, url="/x")
    assert_equal(h.serve(get_req).status, 400)
    assert_equal(h.serve(post_req).status, Status.OK)


# ── Handlers that raise ─────────────────────────────────────────────────────


@fieldwise_init
struct _FailingHandler(Handler, Movable):
    var dummy: Int

    def serve(self, req: Request) raises -> Response:
        raise Error("intentional failure")


def test_handler_can_raise() raises:
    """A handler's serve may raise; caller sees the exception."""
    var h = _FailingHandler(0)
    var req = Request(method=Method.GET, url="/")
    with assert_raises():
        _ = h.serve(req)


def _raising_fn(req: Request) raises -> Response:
    raise Error("boom")


def test_fnhandler_propagates_raise() raises:
    """FnHandler propagates exceptions from the wrapped function."""
    var h = FnHandler(_raising_fn)
    var req = Request(method=Method.GET, url="/")
    with assert_raises():
        _ = h.serve(req)


# ── Handlers composing: inner handler wrapped by outer ──────────────────────


@fieldwise_init
struct _Tagged[Inner: Handler](Handler):
    """Middleware handler that runs ``inner`` and tags the response."""

    var inner: Self.Inner
    var tag: String

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Tag", self.tag)
        return resp^


def test_handler_composition_wraps_inner() raises:
    """Wrapping handler delegates to the inner handler."""
    var inner = _Greeter("wrapped")
    var outer = _Tagged(inner^, "outer")
    var req = Request(method=Method.GET, url="/a")
    var resp = outer.serve(req)
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.headers.get("X-Tag"), "outer")


def test_handler_composition_preserves_inner_body() raises:
    """Wrapper preserves the body the inner handler produced."""
    var inner = _Greeter("hello")
    var outer = _Tagged(inner^, "pre")
    var req = Request(method=Method.GET, url="/abc")
    var resp = outer.serve(req)
    assert_true(resp.text().find("hello") >= 0)


def test_handler_composition_nested_three_deep() raises:
    """Handler composition nests arbitrarily deep; outermost tag wins."""
    var innermost = _Greeter("deep")
    var middle = _Tagged(innermost^, "mid")
    var outer = _Tagged(middle^, "outer")
    var req = Request(method=Method.GET, url="/nested")
    var resp = outer.serve(req)
    assert_equal(resp.status, Status.OK)
    # Outer overwrites the middle's X-Tag header.
    assert_equal(resp.headers.get("X-Tag"), "outer")


# ── FnHandler composing under a wrapping handler ───────────────────────────


def test_wrapping_fnhandler() raises:
    """A wrapping handler can hold an FnHandler as its inner."""
    var inner = FnHandler(_hello_fn)
    var outer = _Tagged(inner^, "fn-wrapped")
    var req = Request(method=Method.GET, url="/")
    var resp = outer.serve(req)
    assert_equal(resp.text(), "hello")
    assert_equal(resp.headers.get("X-Tag"), "fn-wrapped")


# ── Trivial handlers (sanity) ──────────────────────────────────────────────


@fieldwise_init
struct _AlwaysOk(Handler, Movable):
    var dummy: Int

    def serve(self, req: Request) raises -> Response:
        return ok("")


def test_always_ok_handler() raises:
    """Minimal Handler impl returning a bare 200."""
    var h = _AlwaysOk(0)
    var req = Request(method=Method.GET, url="/")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)


# ── Entry point ─────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_handler.mojo — Handler trait + FnHandler")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
