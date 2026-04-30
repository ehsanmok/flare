"""Tests for ``flare.http.static_response``.

Covers the in-memory ``StaticResponse`` wire-form builder. End-to-end
reactor integration is covered by the TFB plaintext benchmark
(``benchmark/baselines/flare_static/``) once that harness lands; these
unit tests focus on byte-level correctness of the pre-encoded buffers
so the reactor fast path can trust them blindly.

Covers:

- ``precompute_response`` emits a well-formed HTTP/1.1 response with
  status line, Content-Type, Content-Length, Connection header, and
  body in the expected order.
- Keep-alive and close variants differ only in their Connection
  header value.
- ``Content-Length`` matches ``body.byte_length()`` for ASCII and
  UTF-8 bodies.
- Known status codes produce canonical reason phrases; unknown
  codes emit an empty reason (the caller can still feed them to the
  reactor, which accepts any status number).
- Zero-length bodies are allowed.
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    TestSuite,
)

from flare.http import HttpServer, StaticResponse, precompute_response
from flare.http.server import ServerConfig
from flare.net import SocketAddr


@always_inline
def _bytes_to_string(buf: List[UInt8]) -> String:
    """Decode a wire-form buffer back into a ``String`` for regex-ish checks."""
    var out = String(capacity=len(buf) + 1)
    for b in buf:
        out += chr(Int(b))
    return out^


# ── Basic shape ─────────────────────────────────────────────────────────────


def test_precompute_200_hello_world() raises:
    var r = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    assert_equal(r.body_length, 13)

    var ka = _bytes_to_string(r.keepalive_bytes)
    assert_true(ka.startswith("HTTP/1.1 200 OK\r\n"))
    assert_true("Content-Type: text/plain; charset=utf-8\r\n" in ka)
    assert_true("Content-Length: 13\r\n" in ka)
    assert_true("Connection: keep-alive\r\n" in ka)
    assert_true(ka.endswith("\r\n\r\nHello, World!"))


def test_close_variant_swaps_connection_header() raises:
    var r = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    var cl = _bytes_to_string(r.close_bytes)
    assert_true("Connection: close\r\n" in cl)
    assert_false("Connection: keep-alive\r\n" in cl)


def test_keepalive_and_close_differ_only_by_connection() raises:
    var r = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    # Both buffers have the same body suffix.
    var ka = _bytes_to_string(r.keepalive_bytes)
    var cl = _bytes_to_string(r.close_bytes)
    assert_true(ka.endswith("Hello, World!"))
    assert_true(cl.endswith("Hello, World!"))
    # Only difference is the Connection header value (keep-alive is 5
    # bytes longer than close).
    assert_equal(len(r.keepalive_bytes) - len(r.close_bytes), 5)


# ── Status phrase mapping ───────────────────────────────────────────────────


def test_known_status_has_reason_phrase() raises:
    for code, phrase in [
        (200, "OK"),
        (201, "Created"),
        (204, "No Content"),
        (301, "Moved Permanently"),
        (302, "Found"),
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
        (404, "Not Found"),
        (500, "Internal Server Error"),
        (503, "Service Unavailable"),
    ]:
        var r = precompute_response(
            status=code, content_type="text/plain", body=""
        )
        var ka = _bytes_to_string(r.keepalive_bytes)
        assert_true(
            ka.startswith("HTTP/1.1 " + String(code) + " " + phrase + "\r\n")
        )


def test_unknown_status_has_empty_reason() raises:
    """Unknown codes still serialize; the reason phrase is empty."""
    var r = precompute_response(
        status=418, content_type="text/plain", body="teapot"
    )
    var ka = _bytes_to_string(r.keepalive_bytes)
    # "HTTP/1.1 418 \r\n" — note the empty reason between the status
    # number and CRLF.
    assert_true(ka.startswith("HTTP/1.1 418 \r\n"))


# ── Body handling ───────────────────────────────────────────────────────────


def test_empty_body_content_length_zero() raises:
    var r = precompute_response(status=204, content_type="text/plain", body="")
    assert_equal(r.body_length, 0)
    var ka = _bytes_to_string(r.keepalive_bytes)
    assert_true("Content-Length: 0\r\n" in ka)
    assert_true(ka.endswith("\r\n\r\n"))


def test_multibyte_utf8_body_content_length_is_bytes() raises:
    """Content-Length must be the byte count, not the codepoint count."""
    var body = "héllo"  # 6 bytes, 5 codepoints
    var r = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body=body,
    )
    assert_equal(r.body_length, body.byte_length())
    var ka = _bytes_to_string(r.keepalive_bytes)
    assert_true("Content-Length: " + String(body.byte_length()) + "\r\n" in ka)


# ── Header order (deterministic so the reactor memcpy is stable) ───────────


def test_header_order_is_content_type_length_connection() raises:
    var r = precompute_response(
        status=200,
        content_type="application/json",
        body="{}",
    )
    var ka = _bytes_to_string(r.keepalive_bytes)
    var ct_pos = ka.find("Content-Type:")
    var cl_pos = ka.find("Content-Length:")
    var cn_pos = ka.find("Connection:")
    assert_true(ct_pos >= 0)
    assert_true(cl_pos > ct_pos)
    assert_true(cn_pos > cl_pos)


# ── Copy semantics ──────────────────────────────────────────────────────────


def test_static_response_copy_is_independent() raises:
    var r = precompute_response(
        status=200,
        content_type="text/plain",
        body="original",
    )
    var c = r.copy()
    assert_equal(len(c.keepalive_bytes), len(r.keepalive_bytes))
    assert_equal(len(c.close_bytes), len(r.close_bytes))
    # Mutate the original; the copy stays intact.
    r.keepalive_bytes.clear()
    assert_true(len(c.keepalive_bytes) > 0)


# ── HttpServer.serve_static lifecycle ───────────────────────────────────────


def test_server_binds_with_static_response() raises:
    """``HttpServer`` accepts a port bind while holding the static
    response in scope — a no-regression check for the new import chain
    (``HttpServer`` → ``_server_reactor_impl`` → ``StaticResponse``).
    """
    var _resp = precompute_response(
        status=200,
        content_type="text/plain; charset=utf-8",
        body="Hello, World!",
    )
    var cfg = ServerConfig(idle_timeout_ms=200, shutdown_timeout_ms=300)
    var srv = HttpServer.bind(SocketAddr.localhost(0), cfg^)
    assert_true(srv.local_addr().port != 0)
    srv.close()


def test_serve_static_close_without_serve_is_noop() raises:
    """``close()`` on a server that never ran ``serve_static`` is a no-op."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    srv.close()


# ── Entry ──────────────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_static_response.mojo — Pre-encoded static responses")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
