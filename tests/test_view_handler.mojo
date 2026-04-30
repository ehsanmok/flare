"""Tests for the ``ViewHandler`` trait + ``WithViewCancel`` adapter
(follow-up / Track 1.1 part 2 / C3).

The reactor's view-aware read path (lands in this same commit
under ``HttpServer.serve_view``) constructs a ``RequestView`` per
request and dispatches it through ``ViewHandler.serve_view``.
Handlers that don't need owned request state get true zero-copy
reads — the body slice borrows directly into the connection's
read buffer.

These tests pin the trait shape, the adapter behaviour, and the
borrowed-vs-owned semantics. The end-to-end loopback test that
validates the reactor's view-aware dispatch lives in
``test_server.mojo`` (extended in this same commit).
"""

from std.testing import (
    assert_equal,
    assert_true,
    assert_false,
    TestSuite,
)

from flare.http import (
    Request,
    Response,
    Method,
    Status,
    ok,
    Handler,
    ViewHandler,
    WithViewCancel,
    Cancel,
    CancelCell,
    CancelReason,
    RequestView,
    parse_request_view,
)


# ── Test handlers ──────────────────────────────────────────────────────────


@fieldwise_init
struct _BodyEcho(Copyable, Movable, ViewHandler):
    """Reads the body via the borrowed slice and echoes its
    length. Demonstrates the zero-copy contract — the body
    pointer should equal the buffer pointer + body_start."""

    var tag: String

    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        var body = req.body()
        return ok(self.tag + ":len=" + String(len(body)))


@fieldwise_init
struct _UrlEcho(Copyable, Movable, ViewHandler):
    """Reads the URL via the borrowed slice and echoes it."""

    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        return ok("url=" + String(req.url()))


@fieldwise_init
struct _CancelAware(Copyable, Movable, ViewHandler):
    """Observes Cancel and short-circuits if pre-flipped."""

    def serve_view[
        origin: Origin
    ](self, req: RequestView[origin], cancel: Cancel) raises -> Response:
        if cancel.cancelled():
            return ok("cancelled-early")
        return ok("done:" + req.method)


@fieldwise_init
struct _PlainHandler(Copyable, Handler, Movable):
    """A -shape Handler used to test the WithViewCancel
    adapter."""

    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting + ":" + req.url)


def _drive[
    VH: ViewHandler & Copyable & Movable
](
    var handler: VH,
    raw: String,
    cancel: Cancel = Cancel.never(),
) raises -> Response:
    """Helper: parse ``raw`` into a RequestView and dispatch
    through ``handler.serve_view`` — what the reactor's view path
    will do per request."""
    var bytes = List[UInt8]()
    for b in raw.as_bytes():
        bytes.append(b)
    var view = parse_request_view(Span[UInt8, _](bytes))
    return handler.serve_view(view, cancel)


# ── ViewHandler trait conformance ──────────────────────────────────────────


def test_view_handler_body_echo() raises:
    var raw = "POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"
    var resp = _drive[_BodyEcho](_BodyEcho("body"), raw)
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "body:len=5")


def test_view_handler_url_echo() raises:
    var raw = "GET /path?q=1 HTTP/1.1\r\nHost: x\r\n\r\n"
    var resp = _drive[_UrlEcho](_UrlEcho(), raw)
    assert_equal(resp.text(), "url=/path?q=1")


def test_view_handler_zero_body() raises:
    var raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    var resp = _drive[_BodyEcho](_BodyEcho("z"), raw)
    assert_equal(resp.text(), "z:len=0")


def test_view_handler_observes_cancel() raises:
    """Inlines the _drive helper so the cell + handle stay live
    in the same scope as the serve_view call. Mirrors the
    pattern in tests/test_cancel.mojo that survives Mojo's
    pointer-aliasing rules for ``CancelCell``."""
    var raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    var bytes = List[UInt8]()
    for b in raw.as_bytes():
        bytes.append(b)
    var view = parse_request_view(Span[UInt8, _](bytes))
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var handler = _CancelAware()
    var resp = handler.serve_view(view, cell.handle())
    assert_equal(resp.text(), "cancelled-early")


def test_view_handler_does_not_short_circuit_on_never() raises:
    var raw = "PUT / HTTP/1.1\r\nHost: x\r\n\r\n"
    var resp = _drive[_CancelAware](_CancelAware(), raw)
    assert_equal(resp.text(), "done:PUT")


# ── WithViewCancel adapter ─────────────────────────────────────────────────


def test_with_view_cancel_forwards_to_inner() raises:
    var raw = "GET /hi HTTP/1.1\r\nHost: x\r\n\r\n"
    var adapter = WithViewCancel[_PlainHandler](_PlainHandler("hello"))
    var resp = _drive[WithViewCancel[_PlainHandler]](adapter^, raw)
    assert_equal(resp.status, Status.OK)
    assert_equal(resp.text(), "hello:/hi")


def test_with_view_cancel_ignores_cancel_token() raises:
    """``WithViewCancel`` doesn't observe Cancel — the wrapped
    Handler runs to completion regardless of the token state."""
    var raw = "GET /still-runs HTTP/1.1\r\nHost: x\r\n\r\n"
    var cell = CancelCell()
    cell.flip(CancelReason.SHUTDOWN)
    var adapter = WithViewCancel[_PlainHandler](_PlainHandler("g"))
    var resp = _drive[WithViewCancel[_PlainHandler]](
        adapter^, raw, cell.handle()
    )
    assert_equal(resp.text(), "g:/still-runs")


# ── Borrowed-body pointer identity ─────────────────────────────────────────


def test_view_body_pointer_identity() raises:
    """``view.body()`` returns a slice whose underlying pointer
    is inside the original buffer — no copy, no allocation. This
    is the core promise of the view path; if it ever returns a
    pointer outside the buffer, the zero-copy contract is broken
    and the test fails loudly.
    """
    var raw = "POST / HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world"
    var bytes = List[UInt8]()
    for b in raw.as_bytes():
        bytes.append(b)
    var view = parse_request_view(Span[UInt8, _](bytes))
    var body = view.body()
    var body_addr = Int(body.unsafe_ptr())
    var buf_start = Int(bytes.unsafe_ptr())
    var buf_end = buf_start + len(bytes)
    assert_true(body_addr >= buf_start)
    assert_true(body_addr < buf_end)


# ── Stress: 1000 round-trips through serve_view ───────────────────────────


def test_thousand_roundtrips_no_leak() raises:
    """1000 sequential dispatches through serve_view + into_owned
    via WithViewCancel — catches Mojo move/copy regressions in
    the trait dispatch path."""
    var raw = "GET /x HTTP/1.1\r\nHost: x\r\n\r\n"
    for _ in range(1000):
        var adapter = WithViewCancel[_PlainHandler](_PlainHandler("g"))
        var resp = _drive[WithViewCancel[_PlainHandler]](adapter^, raw)
        assert_equal(resp.text(), "g:/x")


def main() raises:
    print("=" * 60)
    print("test_view_handler.mojo — ViewHandler / WithViewCancel")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
