"""Tests for ``flare.http.App[S, H]`` and ``flare.http.State[T]``.

Covers:

- Constructing an ``App`` with a simple state struct and a Router.
- The ``App`` struct implements ``Handler`` — it dispatches to its
  inner Router.
- ``State[T].get()`` returns a copy of the value it was wrapping.
- ``App.state_view()`` returns a ``State`` that reflects the current
  ``App.state``.
- A handler that captures an ``App`` reference can read state while
  serving a request (the runtime-extractor path; the comptime-
  signature version lands in v0.4.1).
"""

from std.testing import (
    assert_true,
    assert_equal,
    TestSuite,
)

from flare.http import (
    App,
    State,
    Router,
    Handler,
    Request,
    Response,
    Method,
    Status,
    ok,
)


# ── Simple state types ──────────────────────────────────────────────────────


@fieldwise_init
struct _Counter(Copyable, Movable):
    var hits: Int


@fieldwise_init
struct _DbLike(Copyable, Movable):
    """Tiny read-only database stand-in: a single record."""

    var user_id: Int
    var user_name: String


# ── State[T] ────────────────────────────────────────────────────────────────


def test_state_wrap_and_get() raises:
    """State.get() returns a copy of the wrapped value."""
    var s = State(_Counter(hits=5))
    var v = s.get()
    assert_equal(v.hits, 5)


def test_state_get_is_copy() raises:
    """State.get() returns a copy, not a reference (mutation of the
    returned value does not affect the wrapped value).
    """
    var s = State(_Counter(hits=5))
    var snap = s.get()
    snap.hits = 99
    assert_equal(s.get().hits, 5)


def test_state_complex_struct() raises:
    """State wraps a struct with multiple fields."""
    var s = State(_DbLike(user_id=7, user_name="alice"))
    var v = s.get()
    assert_equal(v.user_id, 7)
    assert_equal(v.user_name, "alice")


# ── App[S, H] ──────────────────────────────────────────────────────────────


def h_home(req: Request) raises -> Response:
    return ok("home")


def h_users(req: Request) raises -> Response:
    return ok("users")


def test_app_constructs_and_dispatches() raises:
    """App[Counter, Router] dispatches the request to its inner Router."""
    var r = Router()
    r.get("/", h_home)
    var app = App(state=_Counter(hits=0), handler=r^)
    var resp = app.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "home")


def test_app_router_404() raises:
    """App dispatches 404 through the inner Router."""
    var r = Router()
    r.get("/known", h_home)
    var app = App(state=_Counter(hits=0), handler=r^)
    var resp = app.serve(Request(method=Method.GET, url="/unknown"))
    assert_equal(resp.status, Status.NOT_FOUND)


def test_app_state_readable_on_struct() raises:
    """App.state is readable after construction."""
    var r = Router()
    r.get("/", h_home)
    var app = App(state=_Counter(hits=42), handler=r^)
    assert_equal(app.state.hits, 42)


def test_app_state_view() raises:
    """App.state_view() returns a State matching App.state."""
    var r = Router()
    r.get("/", h_home)
    var app = App(state=_Counter(hits=11), handler=r^)
    var view = app.state_view()
    assert_equal(view.get().hits, 11)


def test_app_with_dblike_state() raises:
    """App works with a complex state struct."""
    var r = Router()
    r.get("/me", h_home)
    var app = App(state=_DbLike(user_id=7, user_name="alice"), handler=r^)
    var view = app.state_view()
    assert_equal(view.get().user_id, 7)
    assert_equal(view.get().user_name, "alice")


@fieldwise_init
struct _Tagged[Inner: Handler](Handler):
    """Top-level tag-wrapping handler used by tests."""

    var inner: Self.Inner

    def serve(self, req: Request) raises -> Response:
        return self.inner.serve(req)


def test_app_is_handler() raises:
    """App[S, H] satisfies the Handler trait itself."""
    var r = Router()
    r.get("/", h_home)
    var app = App(state=_Counter(hits=0), handler=r^)
    var tagged = _Tagged(app^)
    var resp = tagged.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "home")


# ── Handler reading state via a captured App ───────────────────────────────


@fieldwise_init
struct _StateReadingHandler[Inner: Handler](Handler):
    """Pseudo-middleware that injects an app-state snapshot into the
    response header. Proves a handler can read ``State[_Counter]``
    through a captured reference without globals.
    """

    var inner: Self.Inner
    var snapshot: State[_Counter]

    def serve(self, req: Request) raises -> Response:
        var resp = self.inner.serve(req)
        resp.headers.set("X-Hits", String(self.snapshot.get().hits))
        return resp^


def test_handler_reads_state_via_capture() raises:
    """A wrapping handler captures an App's state view and uses it
    to decorate the response."""
    var r = Router()
    r.get("/", h_home)
    var app = App(state=_Counter(hits=37), handler=r^)
    var view = app.state_view()
    # Move App into the wrapper so no partial-consumption split occurs.
    var wrapper = _StateReadingHandler(app^, view^)
    var resp = wrapper.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "home")
    assert_equal(resp.headers.get("X-Hits"), "37")


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_app_state.mojo — App[S, H] + State[T]")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
