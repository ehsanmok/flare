"""Tests for sanitised 4xx error responses.

a 400 response built from an extractor's
``raise Error("expected integer, got '" + s + "'")`` must NOT echo
the user-controlled bytes into the response body by default.

Covers:

- ``ServerConfig.expose_error_messages`` defaults to ``False`` and is
  wired through the constructor.
- ``Request.expose_errors`` defaults to ``False`` and is wired through
  the ``Request.__init__`` keyword.
- ``_parse_http_request_bytes`` threads ``expose_errors`` onto the
  parsed request.
- ``_bad_request_from_error(e, expose=False)`` returns the fixed
  reason ``"Bad Request"`` as the body and ignores the message.
- ``_bad_request_from_error(e, expose=True)`` echoes the verbatim
  ``Error`` message (local-dev mode).
- A round-trip through ``Extracted[H]`` with a deliberately hostile
  path parameter (``<script>alert(1)</script>``) produces a 400
  whose body is exactly ``"Bad Request"`` — i.e. the user payload
  never reaches the wire when ``Request.expose_errors=False``.
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import (
    Request,
    Response,
    Status,
    Method,
    HttpServer,
    ServerConfig,
    Handler,
    ok,
    Path,
    ParamInt,
    Extracted,
)
from flare.http.extract import _bad_request_from_error
from flare.http.server import _parse_http_request_bytes
from flare.net import SocketAddr


# ── ServerConfig field default ───────────────────────────────────────────────


def test_server_config_default_disables_message_exposure() raises:
    var c = ServerConfig()
    assert_false(c.expose_error_messages)


def test_server_config_explicit_true() raises:
    var c = ServerConfig(expose_error_messages=True)
    assert_true(c.expose_error_messages)


# ── Request field plumbing ───────────────────────────────────────────────────


def test_request_expose_errors_default_false() raises:
    var req = Request(method=Method.GET, url="/")
    assert_false(req.expose_errors)


def test_request_expose_errors_explicit_true() raises:
    var req = Request(method=Method.GET, url="/", expose_errors=True)
    assert_true(req.expose_errors)


def test_parser_threads_expose_errors() raises:
    var raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    var data = raw.as_bytes()
    var req_off = _parse_http_request_bytes(Span[UInt8, _](data))
    assert_false(req_off.expose_errors)
    var req_on = _parse_http_request_bytes(
        Span[UInt8, _](data), expose_errors=True
    )
    assert_true(req_on.expose_errors)


# ── _bad_request_from_error sanitisation ─────────────────────────────────────


def test_bad_request_body_sanitised_by_default() raises:
    var resp = _bad_request_from_error(
        Error("expected integer, got '<script>alert(1)</script>'")
    )
    assert_equal(resp.status, Status.BAD_REQUEST)
    assert_equal(resp.text(), "Bad Request")


def test_bad_request_body_exposed_when_flag_set() raises:
    var msg = "expected integer, got '42abc'"
    var resp = _bad_request_from_error(Error(msg), expose=True)
    assert_equal(resp.status, Status.BAD_REQUEST)
    assert_equal(resp.text(), msg)


def test_bad_request_reason_always_fixed() raises:
    """Even with exposure enabled, the reason phrase stays generic."""
    var resp = _bad_request_from_error(Error("anything"), expose=True)
    assert_equal(resp.reason, "Bad Request")


# ── End-to-end through Extracted[H] ─────────────────────────────────────────


@fieldwise_init
struct _IdHandler(Copyable, Defaultable, Handler, Movable):
    var id: Path[ParamInt, "id"]

    def __init__(out self):
        self.id = Path[ParamInt, "id"]()

    def serve(self, req: Request) raises -> Response:
        return ok("user " + String(self.id.value.value))


def test_extracted_400_body_is_sanitised_against_hostile_input() raises:
    """Drive an extractor that builds an error message from raw URL
    bytes (``ParamInt.parse("<script>...")``) and assert the response
    body never contains the payload by default.
    """
    var req = Request(method=Method.GET, url="/users/<hostile>")
    req.params_mut()["id"] = "<script>alert(1)</script>"
    var resp = Extracted[_IdHandler]().serve(req)
    assert_equal(resp.status, Status.BAD_REQUEST)
    assert_equal(resp.text(), "Bad Request")
    var body_str = resp.text()
    assert_false("<script>" in body_str)


def test_extracted_400_body_echoes_when_exposure_enabled() raises:
    """With ``Request.expose_errors=True`` the message can flow through.
    Used by local-dev servers configured with
    ``ServerConfig(expose_error_messages=True)``.
    """
    var req = Request(method=Method.GET, url="/users/abc", expose_errors=True)
    req.params_mut()["id"] = "abc"
    var resp = Extracted[_IdHandler]().serve(req)
    assert_equal(resp.status, Status.BAD_REQUEST)
    var body_str = resp.text()
    # The ParamInt error message mentions the input "abc"; assert
    # the substring shows up. (Exact wording is not pinned — only
    # that user input can flow through when explicitly opted in.)
    assert_true("abc" in body_str)


# ── HttpServer config plumbing ───────────────────────────────────────────────


def test_http_server_carries_default_policy() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    assert_false(srv.config.expose_error_messages)
    srv.close()


def test_http_server_with_explicit_policy() raises:
    var srv = HttpServer.bind(
        SocketAddr.localhost(0), ServerConfig(expose_error_messages=True)
    )
    assert_true(srv.config.expose_error_messages)
    srv.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
