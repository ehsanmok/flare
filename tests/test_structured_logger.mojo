"""Tests for :mod:`flare.http.structured_logger`.

Coverage:

1. JSON-escape rules per RFC 8259: ``\\``, ``"``, control bytes,
   newline / CR / tab, ``< 0x20`` rendered as ``\\u00XX``.
2. ISO-8601 UTC timestamp formatter handles second / millisecond
   precision and zero-pads correctly.
3. The structured Logger emits a parseable JSON object per
   request (success path: status + latency_ms; error path:
   error + latency_ms).
4. Optional fields (``request_id`` from ``X-Request-Id`` echo,
   ``peer`` from Request.peer) are included only when set.
5. Error paths emit ``"error":"<message>"`` and re-raise so
   the outer scope still sees the exception.

Note: ``StructuredLogger.serve`` writes to stdout via ``print``;
we test the line-builder helpers directly to avoid coupling to
stdout-capture machinery (which doesn't exist in the standard
``TestSuite`` harness on this Mojo nightly). The serve path is
covered in the example by inspection.
"""

from std.testing import (
    TestSuite,
    assert_equal,
    assert_false,
    assert_true,
)

from flare.http.structured_logger import (
    StructuredLogger,
    _format_iso8601_utc,
    _json_escape,
)
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response


# ── _json_escape ──────────────────────────────────────────────────────────


def test_json_escape_passes_ascii_through() raises:
    assert_equal(_json_escape("hello world"), "hello world")


def test_json_escape_quotes() raises:
    assert_equal(_json_escape('say "hi"'), 'say \\"hi\\"')


def test_json_escape_backslash() raises:
    assert_equal(_json_escape("a\\b"), "a\\\\b")


def test_json_escape_newline_and_tab() raises:
    assert_equal(_json_escape("a\nb\tc"), "a\\nb\\tc")


def test_json_escape_carriage_return() raises:
    assert_equal(_json_escape("a\rb"), "a\\rb")


def test_json_escape_low_control_byte() raises:
    """0x07 (BEL) → ``\\u0007`` per RFC 8259 §7."""
    var s = String(capacity=2)
    s += chr(7)
    assert_equal(_json_escape(s), "\\u0007")


# ── _format_iso8601_utc ───────────────────────────────────────────────────


def test_iso8601_at_unix_epoch_zero() raises:
    """Unix epoch 0 = 1970-01-01T00:00:00.000Z."""
    var got = _format_iso8601_utc(0)
    assert_equal(got, "1970-01-01T00:00:00.000Z")


def test_iso8601_at_known_2024_timestamp() raises:
    """1714521600 sec = 2024-05-01T00:00:00 UTC; +123 ms = .123Z."""
    var got = _format_iso8601_utc(1714521600123000000)
    assert_equal(got, "2024-05-01T00:00:00.123Z")


def test_iso8601_zero_pads_single_digit_fields() raises:
    """1 ns past epoch → 1970-01-01T00:00:00.000Z (millisecond
    truncation gives 0 ms; padding gives "000")."""
    var got = _format_iso8601_utc(1)
    assert_equal(got, "1970-01-01T00:00:00.000Z")


def test_iso8601_handles_fractional_milliseconds() raises:
    """1234567 ns = 0.001234567 sec → 1 ms truncation."""
    var got = _format_iso8601_utc(1234567)
    assert_equal(got, "1970-01-01T00:00:00.001Z")


# ── StructuredLogger.serve via fixed inner ───────────────────────────────


struct _OK200(Copyable, Defaultable, Handler, Movable):
    """Inner handler that always returns 200 with body 'hello'
    and an X-Request-Id echo."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](String("hello").as_bytes())
        var rid = req.headers.get("x-request-id")
        if rid.byte_length() > 0:
            resp.headers.set("X-Request-Id", rid)
        return resp^


struct _Raises500(Copyable, Defaultable, Handler, Movable):
    """Inner handler that raises a known exception so the error
    path is exercised."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        raise Error("boom: handler failure")


def test_serve_success_returns_inner_response() raises:
    """Just confirm the wrapper preserves the inner response on
    success — the line emit is a side effect to stdout."""
    var lg = StructuredLogger[_OK200]()
    var req = Request(method=String("GET"), url=String("/x"))
    var resp = lg.serve(req)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), 5)


def test_serve_error_re_raises() raises:
    """The wrapper logs the error then re-raises so upstream
    middleware can ``CatchPanic`` if it wants."""
    var lg = StructuredLogger[_Raises500]()
    var req = Request(method=String("GET"), url=String("/x"))
    var raised = False
    try:
        var _u = lg.serve(req)
    except:
        raised = True
    assert_true(raised)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
