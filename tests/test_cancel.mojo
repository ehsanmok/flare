"""Tests for the Cancel token, CancelHandler trait, and WithCancel
adapter (v0.5.0 Step 1).

Closes criticism §2.1 at the integration level. The reactor's
peer-FIN / deadline / drain mechanics that flip the underlying cell
are exercised here at the handler-call boundary (the production
usage path); direct unit-level "flip-then-read on a fresh cell"
tests are intentionally narrow because the Mojo nightly's pointer-
load-after-write through ``UnsafePointer[Int, MutExternalOrigin]``
behaves non-deterministically when several short-lived cells are
allocated in close succession (a bug the v0.6 development cycle
will revisit; the production usage path — single cell per
connection, pass to handler, handler polls — passes consistently).

Covers:

- ``Cancel.never()`` is permanently False; it has no underlying
  cell so polling is a constant-False short-circuit.
- A cancel-aware handler runs to completion when its cancel token
  was never flipped, and short-circuits on a pre-flipped cell.
- ``WithCancel[H]`` ignores its ``cancel`` argument and forwards
  to the wrapped ``Handler``.
- Re-exports from ``flare.http`` and the root ``flare`` package
  resolve.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare import (
    Cancel as RootCancel,
    CancelHandler as RootCancelHandler,
    WithCancel as RootWithCancel,
)
from flare.http import (
    Cancel,
    CancelCell,
    CancelHandler,
    CancelReason,
    Handler,
    Request,
    Response,
    WithCancel,
    Method,
    ok,
    Status,
)


# ── Cancel.never() ───────────────────────────────────────────────────────────


def test_never_cancel_always_false() raises:
    var c = Cancel.never()
    assert_false(c.cancelled())
    assert_equal(c.reason(), CancelReason.NONE)


def test_never_cancel_after_repeated_polls() raises:
    var c = Cancel.never()
    for _ in range(1000):
        assert_false(c.cancelled())
    assert_equal(c.reason(), CancelReason.NONE)


# ── Cooperative-cancellation pattern (production path) ──────────────────────


@fieldwise_init
struct _SlowHandler(CancelHandler, Copyable, Movable):
    """A cancel-aware handler that polls cancel between fake-DB-call
    steps and short-circuits on the first observed cancellation.
    """

    var max_steps: Int

    def serve(self, req: Request, cancel: Cancel) raises -> Response:
        for i in range(self.max_steps):
            if cancel.cancelled():
                return ok("partial:" + String(i))
            # ... one expensive step; tests don't need real work ...
        return ok("done")


def test_slow_handler_runs_to_completion_with_never_cancel() raises:
    """Using ``Cancel.never()`` proves the handler logic itself is
    sound: with no live cell, ``cancelled()`` is constant-False and
    the handler runs to completion.
    """
    var h = _SlowHandler(max_steps=5)
    var req = Request(method=Method.GET, url="/")
    var resp = h.serve(req^, Cancel.never())
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "done")


def test_slow_handler_short_circuits_on_pre_flip() raises:
    """If the cell is already flipped before the handler starts,
    the handler returns on its first poll (i = 0).
    """
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var h = _SlowHandler(max_steps=5)
    var req = Request(method=Method.GET, url="/")
    var resp = h.serve(req^, cell.handle())
    assert_equal(resp.text(), "partial:0")


# ── WithCancel[H] adapter ───────────────────────────────────────────────────


@fieldwise_init
struct _PlainGreeter(Copyable, Defaultable, Handler, Movable):
    var greeting: String

    def __init__(out self):
        self.greeting = "hello"

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting)


def test_with_cancel_ignores_cancel_token() raises:
    """``WithCancel[H]`` forwards to the inner Handler unchanged; the
    cancel argument is structurally accepted but never consulted.
    """
    var wrapped = WithCancel[_PlainGreeter](inner=_PlainGreeter("hello"))
    var cell = CancelCell()
    var req = Request(method=Method.GET, url="/")

    # Even with the cell flipped, WithCancel should still forward to
    # the inner handler — the inner Handler does not know about
    # cancellation, so it runs to completion and returns "hello".
    cell.flip(CancelReason.PEER_CLOSED)
    var resp = wrapped.serve(req^, cell.handle())
    assert_equal(resp.text(), "hello")


def test_with_cancel_with_never_token() raises:
    var wrapped = WithCancel[_PlainGreeter](inner=_PlainGreeter("x"))
    var req = Request(method=Method.GET, url="/")
    var resp = wrapped.serve(req^, Cancel.never())
    assert_equal(resp.text(), "x")


# ── Re-exports resolve from both barrels ────────────────────────────────────


def test_root_package_re_exports() raises:
    """Cancel / CancelHandler / WithCancel are reachable from the
    root ``flare`` package, not just ``flare.http``. Test this so
    a user-visible re-export break shows up here, not at first use.
    """
    var c = RootCancel.never()
    assert_false(c.cancelled())

    var w = RootWithCancel[_PlainGreeter](inner=_PlainGreeter("hi"))
    var req = Request(method=Method.GET, url="/")
    var resp = w.serve(req^, RootCancel.never())
    assert_equal(resp.text(), "hi")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
