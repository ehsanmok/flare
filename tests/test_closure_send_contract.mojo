"""Closure-shape + send-discipline contract tests.

Pins the surface area of what callable shapes flare's public API
accepts on Mojo ``1.0.0b1.dev2026042717`` so a future Mojo nightly
that lifts the capturing-closure runtime-materialisation block can
be detected by the same test file (the additional shapes will start
compiling).

The contract documented in :doc:`docs/concurrency.md` and pinned
here:

1. ``def(...) raises thin -> ...`` — top-level / nested functions
   with no captures. Materialise as runtime values; bind into
   ``def(...) raises thin -> ...`` and ``FnHandler`` slots.
2. ``H: Handler & Copyable & Movable`` structs — first-class
   handler shape; compose by struct wrapping
   (``Logger[Inner]`` / ``WithCancel[H]`` / ...).
3. ``FnHandlerCT[F]`` with ``F: def(Request) raises thin -> Response``
   as a comptime parameter — zero-size, monomorphised; the existing
   v0.6 zero-overhead pattern.
4. ``block_in_pool[T](work, cancel)`` accepts only
   ``work: def() raises thin -> T`` — by construction, the closure
   has no captures. State shared with the pthread worker travels
   through heap-allocated structs whose addresses are read on the
   worker side. See ``flare/runtime/blocking.mojo``.

The capturing-closure / unified-closure runtime path is documented
as Mojo-blocked in ``.cursor/rules/development.mdc`` § Mojo-blocked
items remaining; the re-probe target is "drop the manually-tracked
shape table here once the compiler accepts the additional shapes".
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_true,
)

from flare.http import (
    FnHandler,
    Handler,
    Method,
    Request,
    Response,
    Status,
    ok,
)
from flare.http.handler import FnHandlerCT, WithCancel
from flare.http.cancel import Cancel
from flare.runtime.blocking import block_in_pool


# ── Shape 1: thin closure — top-level def ───────────────────────────────────


def _shape_thin_top_level(req: Request) raises -> Response:
    return ok("thin top-level")


def test_shape_thin_top_level_via_fnhandler() raises:
    """A top-level ``def(Request) raises -> Response`` binds into the
    runtime ``FnHandler`` slot and dispatches via the trait."""
    var h = FnHandler(_shape_thin_top_level)
    var req = Request(method=Method.GET, url="/x")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)
    assert_true(resp.text().find("thin top-level") >= 0)


def test_shape_thin_top_level_via_fnhandler_ct() raises:
    """A top-level ``def(Request) raises -> Response`` binds into the
    comptime-parametric ``FnHandlerCT[F]`` slot. Zero-size at
    runtime; the call site reduces to a direct ``F(req)`` call."""
    comptime H = FnHandlerCT[_shape_thin_top_level]
    var h = H()
    var req = Request(method=Method.GET, url="/x")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)


# ── Shape 2: Handler trait struct ───────────────────────────────────────────


@fieldwise_init
struct _ShapeHandlerStruct(Copyable, Handler, Movable):
    """A ``Handler`` struct that closes over per-handler state via
    fields. The canonical shape for handlers that need to capture
    state — replaces what would have been an inline closure with
    captures in axum / actix.
    """

    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting + " " + req.url)


def test_shape_handler_struct_state_capture() raises:
    """A ``Handler`` struct closes over state via fields. This is
    the documented workaround for "capture by value into a closure"
    on the pinned Mojo nightly."""
    var h = _ShapeHandlerStruct("hi")
    var req = Request(method=Method.GET, url="/p")
    var resp = h.serve(req)
    assert_equal(resp.status, Status.OK)
    assert_true(resp.text().find("hi /p") >= 0)


def test_shape_handler_struct_composes_with_with_cancel() raises:
    """A ``Handler`` struct nests inside ``WithCancel[H]`` for the
    cancel-aware reactor path."""
    var h = WithCancel[_ShapeHandlerStruct](_ShapeHandlerStruct("ciao"))
    var req = Request(method=Method.GET, url="/q")
    var resp = h.serve(req, Cancel.never())
    assert_equal(resp.status, Status.OK)
    assert_true(resp.text().find("ciao /q") >= 0)


# ── Shape 4: block_in_pool — only thin closures cross pthreads ──────────────


def _shape_block_work() raises -> Int:
    return 7 + 35


def _shape_block_boom() raises -> Int:
    raise Error("explode")


def test_shape_block_in_pool_accepts_thin_closure() raises:
    """``block_in_pool`` accepts only ``def() raises thin -> T``.

    The thin annotation is enforced at the type level: a captured
    variable in a nested def would promote the def to ``capturing``,
    which would fail to bind here. This guarantees nothing
    Mojo-managed crosses the pthread boundary as a hidden capture —
    the discipline that makes the per-call detached pthread shape
    sound on a Mojo nightly without a compiler-checked Send trait.
    """
    var got = block_in_pool[Int](_shape_block_work, Cancel.never())
    assert_equal(got, 42)


def test_shape_block_in_pool_propagates_raise() raises:
    """A thin-closure ``work`` that raises has its message surface
    through the join boundary."""
    var raised = False
    try:
        var _unused = block_in_pool[Int](_shape_block_boom, Cancel.never())
    except e:
        raised = True
        assert_true(String(e).find("explode") >= 0)
    assert_true(raised)


# ── Negative-shape contract: documented Mojo-blocked path ───────────────────
#
# These are the shapes that DO NOT compile on the pinned Mojo nightly
# and are documented in ``.cursor/rules/development.mdc`` §
# Mojo-blocked items remaining. We do not try to compile them in this
# file; the test module itself is the documentation that we attempted
# them via probe and they failed.
#
# 1. Capturing closure as runtime value:
#       var multiplier = 7
#       def scale(x: Int) raises -> Int:
#           return x * multiplier
#       FnHandler-style runtime slot binding fails with:
#         "TODO: capturing closures cannot be materialized as runtime values"
#
# 2. Body-block capture syntax (speculative future shape):
#       def scale(x: Int) -> Int { var multiplier }: ...
#       Fails to parse: "expected ':' in function definition".
#
# 3. unified declaration site:
#       def f(x: Int) raises unified -> Int: ...
#       Fails: "use of unknown declaration 'unified'".
#
# 4. Comptime-parametric capturing as Handler trait member:
#       struct CapturingCT[F: def(Int) raises capturing -> Int](Handler):
#           def serve(self, x: Int) raises -> Int:
#               return Self.F(x)
#       The call to ``Self.F(x)`` silently promotes ``serve`` to
#       ``capturing``, which can't satisfy the trait's plain ``serve``
#       signature.
#
# When the next Mojo nightly bump lands, re-probe each of the four
# shapes above and add the now-passing ones as positive tests here.


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
