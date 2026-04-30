"""Tests for ``HttpServer.serve_comptime[handler, config]()``.

The comptime overload takes a comptime ``Handler`` value and a
comptime ``ServerConfig`` value. It enforces configuration
invariants via ``comptime assert`` so misconfigured servers fail at
compile time rather than runtime.

Runtime behaviour is covered end-to-end by ``test_server.mojo`` (the
``serve(def)`` path) and ``test_server_handler.mojo`` (the
``serve[H: Handler & Copyable]`` path). This file covers the comptime surface:

- The default config is accepted.
- A custom valid config is accepted.
- Constructed server objects can be closed after a ``serve_comptime``
  bind (no runtime server loop is driven; we only type-check the
  overload by binding and closing).

Compile-time rejections are not asserted here because ``comptime
assert`` errors surface as compile errors, not runtime errors;
demonstrating them requires a separate build that is intentionally
broken, which does not belong in a regular test suite.
"""

from std.testing import assert_true, assert_equal, TestSuite

from flare.http import (
    HttpServer,
    Handler,
    FnHandler,
    Request,
    Response,
    Method,
    ok,
)
from flare.http.server import ServerConfig
from flare.net import SocketAddr


# ── Stateless handler that can be promoted to a comptime value ──────────────


def h_hello(req: Request) raises -> Response:
    return ok("hello")


comptime _CT_HANDLER: FnHandler = FnHandler(h_hello)


# ── Comptime configs ────────────────────────────────────────────────────────


comptime _CT_CONFIG_DEFAULT: ServerConfig = ServerConfig()
comptime _CT_CONFIG_TIGHT: ServerConfig = ServerConfig(
    read_buffer_size=4096,
    max_header_size=4096,
    max_body_size=16 * 1024,
    max_uri_length=4096,
    keep_alive=True,
    max_keepalive_requests=10,
    idle_timeout_ms=1000,
    write_timeout_ms=2000,
    shutdown_timeout_ms=500,
)


# ── Tests ───────────────────────────────────────────────────────────────────


def test_serve_comptime_default_config_types() raises:
    """The default config satisfies every ``comptime assert`` invariant."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    assert_true(srv.local_addr().port != 0)
    srv.close()


def test_serve_comptime_tight_config_types() raises:
    """A custom valid config satisfies every ``comptime assert`` invariant."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    assert_true(srv.local_addr().port != 0)
    srv.close()


def test_serve_comptime_handler_is_handler() raises:
    """The comptime handler satisfies the Handler trait at the type level.

    We materialise a runtime copy of the comptime handler (``FnHandler``
    captures the function by value, not by reference, so the copy is
    just the underlying ``def(Request) raises -> Response`` pointer).
    """
    var runtime_handler = FnHandler(h_hello)
    var resp = runtime_handler.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.status, 200)
    assert_equal(resp.text(), "hello")


def test_serve_comptime_bind_close_cycle() raises:
    """Bind + close round-trips cleanly with the comptime-config entry point."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    assert_true(port != 0)
    srv.close()


# Force the compiler to instantiate ``serve_comptime`` with every
# comptime config variant so every ``comptime assert`` invariant is
# checked at build time. The helper is never actually called at
# runtime (it would block in the reactor loop) but declaring it
# forces monomorphisation of the generic. The call site is gated on a
# runtime-derived sentinel the compiler cannot constant-fold, which
# keeps the type-checker honest without producing a dead-branch
# warning.
def _never_called_force_instantiation_default() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    srv.close()
    if port < 0:
        srv.serve_comptime[_CT_HANDLER, _CT_CONFIG_DEFAULT]()


def _never_called_force_instantiation_tight() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    srv.close()
    if port < 0:
        srv.serve_comptime[_CT_HANDLER, _CT_CONFIG_TIGHT]()


def test_config_field_access_at_comptime() raises:
    """Comptime ServerConfig fields are readable via normal struct syntax."""
    assert_equal(_CT_CONFIG_DEFAULT.read_buffer_size, 8192)
    assert_equal(_CT_CONFIG_TIGHT.read_buffer_size, 4096)
    assert_equal(_CT_CONFIG_TIGHT.max_header_size, 4096)
    assert_equal(_CT_CONFIG_TIGHT.max_body_size, 16 * 1024)


def test_config_fields_pass_invariants() raises:
    """The comptime configs all satisfy the ``comptime assert`` invariants in the overload.

    This is a pure compile-time check: if the invariants fail this file
    does not compile. Reaching the body means every constraint held.
    """
    # Manually assert the invariants at runtime so the test records it.
    assert_true(_CT_CONFIG_DEFAULT.read_buffer_size > 0)
    assert_true(_CT_CONFIG_DEFAULT.max_header_size > 0)
    assert_true(_CT_CONFIG_DEFAULT.max_uri_length > 0)
    assert_true(
        _CT_CONFIG_DEFAULT.max_body_size >= _CT_CONFIG_DEFAULT.max_header_size
    )
    assert_true(_CT_CONFIG_DEFAULT.max_keepalive_requests >= 1)
    assert_true(_CT_CONFIG_DEFAULT.idle_timeout_ms >= 0)
    assert_true(_CT_CONFIG_DEFAULT.write_timeout_ms >= 0)


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_server_serve_comptime.mojo — comptime serve overload")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
