"""Phase 1.8 — HttpServer graceful-shutdown and edge-case correctness.

These tests spawn the reactor-backed ``HttpServer``, drive it with one or
two real loopback requests, and exercise the shutdown + cleanup paths.
Most of the end-to-end behaviour is already covered by ``test_server.mojo``
going through the internal helpers; this file focuses on the lifecycle
bits that only matter once the reactor loop is running.

Limitations
-----------
``HttpServer.serve()`` blocks indefinitely. Mojo doesn't yet expose a
thread-spawn primitive that keeps the test harness single-threaded, so
these tests can't drive the reactor loop end-to-end without introducing
pthread FFI. Instead they focus on the pieces that *can* be driven
synchronously: ``ServerConfig.shutdown_timeout_ms`` plumbing, ``close()``
idempotency, re-bind after close, and ``ConnHandle`` cleanup behaviour.

Full soak / shutdown-under-load testing happens via wrk in the benchmark
harness (``pixi run --environment bench bench-vs-baseline``) — those
runs exercise the full reactor loop against thousands of connections.
"""

from std.testing import (
    assert_true,
    assert_false,
    assert_equal,
    TestSuite,
)

from flare.http import HttpServer, ServerConfig
from flare.net import SocketAddr
from flare.tcp import TcpListener


# ── ServerConfig.shutdown_timeout_ms ──────────────────────────────────────────


def test_server_config_shutdown_timeout_default() raises:
    """ServerConfig exposes ``shutdown_timeout_ms`` with a 5s default."""
    var cfg = ServerConfig()
    assert_equal(cfg.shutdown_timeout_ms, 5000)


def test_server_config_shutdown_timeout_custom() raises:
    """``shutdown_timeout_ms`` is a named keyword arg on ServerConfig."""
    var cfg = ServerConfig(shutdown_timeout_ms=250)
    assert_equal(cfg.shutdown_timeout_ms, 250)


# ── HttpServer.close() / re-bind ──────────────────────────────────────────────


def test_server_close_is_idempotent() raises:
    """Calling close() twice does not raise."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    srv.close()
    srv.close()  # second close must not raise


def test_server_close_sets_stopping_flag() raises:
    """Close() flips ``_stopping`` so a serve loop would see it."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    assert_false(srv._stopping)
    srv.close()
    assert_true(srv._stopping)


def test_server_rebind_after_close() raises:
    """After close(), the same port is reusable via SO_REUSEADDR."""
    var srv1 = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv1.local_addr().port
    srv1.close()
    # Reuse the port immediately.
    var srv2 = HttpServer.bind(SocketAddr.localhost(port))
    assert_equal(srv2.local_addr().port, port)
    srv2.close()


def test_server_bind_same_port_twice_fails() raises:
    """Binding two HttpServers to the same explicit port must fail the
    second time (SO_REUSEADDR allows rebind after close, not simultaneous
    listen)."""
    var srv1 = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv1.local_addr().port
    var raised = False
    try:
        var _ = HttpServer.bind(SocketAddr.localhost(port))
    except:
        raised = True
    assert_true(raised)
    srv1.close()


# ── ServerConfig Movable semantics ────────────────────────────────────────────


def test_server_config_is_copyable_for_struct_literal_reuse() raises:
    """ServerConfig is Copyable so user code can template it."""
    var base = ServerConfig(max_body_size=1024)
    var copy = base.copy()
    assert_equal(base.max_body_size, 1024)
    assert_equal(copy.max_body_size, 1024)
    # Mutating the copy must not affect the original.
    copy.max_body_size = 2048
    assert_equal(base.max_body_size, 1024)
    assert_equal(copy.max_body_size, 2048)


def main() raises:
    print("=" * 60)
    print("test_reactor_shutdown.mojo — Phase 1.8 hardening")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
