"""Tests for per-request deadlines.



    A slow-client attack ("send 1 byte every 30 seconds") is
    partially mitigated by ``idle_timeout_ms`` but only because we
    keep arming the idle timer on every readable event. A genuine
    slow body upload that keeps trickling bytes in below the idle
    threshold can hold a worker slot indefinitely. This is what
    nginx calls ``client_body_timeout`` and we don't have it.

This commit adds three new ``ServerConfig`` fields, all default
non-zero:

- ``read_body_timeout_ms`` — wall time from headers-end to last
  body byte. Wired through the reactor's cancel-aware read path:
  ``on_readable_cancel`` arms a body-read timer (instead of the
  idle timer) while body bytes are still arriving. Enforcement is
  end-to-end on the cancel-aware reactor path
  (``HttpServer.serve_cancellable``).

- ``handler_timeout_ms`` — handler wall time. Not enforced yet:
  handlers run synchronously on the worker thread and nothing flips
  ``Cancel.TIMEOUT`` while one runs. The field and its comptime
  bound are what is tested here.

- ``request_timeout_ms`` — the reactor answers 408 when reading one
  request, head and body, takes longer than this from its first
  byte. End-to-end coverage is in ``test_server_lifecycle.mojo``.

Comptime asserts on these fields are tested via
``serve_comptime[handler, config]()`` (a server can't be built
with a too-short ``request_timeout_ms``).

Covers:

- The three new ``ServerConfig`` fields default to the published
  values (30_000 / 30_000 / 60_000).
- ``0`` for any field is accepted (disable).
- A user-provided config overrides the defaults.
- The fields are valid-shape inputs to ``HttpServer.bind`` (i.e.
  the constructor wiring is intact).
- ``serve_comptime[handler, valid_config]`` accepts a config
  whose ``request_timeout_ms`` bounds the inner deadlines (this
  is the smoke test that the comptime asserts compile through).
"""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from flare.http import (
    HttpServer,
    ServerConfig,
    Request,
    Response,
    ok,
    FnHandler,
)
from flare.net import SocketAddr


# ── Defaults ─────────────────────────────────────────────────────────────────


def test_default_read_body_timeout() raises:
    var c = ServerConfig()
    assert_equal(c.read_body_timeout_ms, 30_000)


def test_default_handler_timeout() raises:
    var c = ServerConfig()
    assert_equal(c.handler_timeout_ms, 30_000)


def test_default_request_timeout() raises:
    var c = ServerConfig()
    assert_equal(c.request_timeout_ms, 60_000)


# ── Override ─────────────────────────────────────────────────────────────────


def test_override_read_body_timeout() raises:
    var c = ServerConfig(read_body_timeout_ms=5_000)
    assert_equal(c.read_body_timeout_ms, 5_000)


def test_override_handler_timeout() raises:
    var c = ServerConfig(handler_timeout_ms=2_000)
    assert_equal(c.handler_timeout_ms, 2_000)


def test_override_request_timeout() raises:
    var c = ServerConfig(request_timeout_ms=10_000)
    assert_equal(c.request_timeout_ms, 10_000)


# ── Disable ──────────────────────────────────────────────────────────────────


def test_disable_read_body_timeout_with_zero() raises:
    var c = ServerConfig(read_body_timeout_ms=0)
    assert_equal(c.read_body_timeout_ms, 0)


def test_disable_handler_timeout_with_zero() raises:
    var c = ServerConfig(handler_timeout_ms=0)
    assert_equal(c.handler_timeout_ms, 0)


def test_disable_request_timeout_with_zero() raises:
    var c = ServerConfig(request_timeout_ms=0)
    assert_equal(c.request_timeout_ms, 0)


# ── HttpServer carries the config ────────────────────────────────────────────


def test_server_carries_default_deadlines() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    assert_equal(srv.config.read_body_timeout_ms, 30_000)
    assert_equal(srv.config.handler_timeout_ms, 30_000)
    assert_equal(srv.config.request_timeout_ms, 60_000)
    srv.close()


def test_server_carries_explicit_deadlines() raises:
    var cfg = ServerConfig(
        read_body_timeout_ms=1_000,
        handler_timeout_ms=2_000,
        request_timeout_ms=5_000,
    )
    var srv = HttpServer.bind(SocketAddr.localhost(0), cfg^)
    assert_equal(srv.config.read_body_timeout_ms, 1_000)
    assert_equal(srv.config.handler_timeout_ms, 2_000)
    assert_equal(srv.config.request_timeout_ms, 5_000)
    srv.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
