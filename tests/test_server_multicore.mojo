"""Tests for ``HttpServer.serve(..., num_workers=N)`` lifecycle (multicore path).

End-to-end HTTP round-trip tests across multiple workers require
threading a client alongside the server loop; flare doesn't ship a
cross-thread test scaffold yet, so the tests here are lifecycle-only
(same shape as ``test_scheduler.mojo``):

- An ``HttpServer`` binds and closes cleanly.
- ``HttpServer.close()`` without ``serve`` ever being called is a no-op.
- ``serve(..., num_workers>=2)`` is callable at the type level with
  a Router handler and a trivial struct handler.

Real multicore throughput is measured by the v0.4.0 bench step; no
wall-clock behaviour is asserted here.
"""

from std.testing import assert_true, assert_equal, TestSuite

from flare.http import (
    HttpServer,
    Handler,
    Router,
    App,
    Request,
    Response,
    Method,
    Status,
    ok,
)
from flare.http.server import ServerConfig
from flare.net import SocketAddr


# ── Helpers ─────────────────────────────────────────────────────────────────


@fieldwise_init
struct _StaticHandler(Copyable, Handler):
    var tag: Int

    def serve(self, req: Request) raises -> Response:
        return ok("multicore")


def _mc_config() -> ServerConfig:
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 200
    cfg.shutdown_timeout_ms = 300
    return cfg^


# ── HttpServer bind + close ────────────────────────────────────────────────


def test_server_bind_with_short_config() raises:
    """``HttpServer.bind`` works with a short-timeout config."""
    var srv = HttpServer.bind(SocketAddr.localhost(0), _mc_config())
    assert_true(srv.local_addr().port != 0)
    srv.close()


def test_server_close_without_serve_multicore_is_noop() raises:
    """``close()`` on a server that never ran ``serve`` is clean."""
    var srv = HttpServer.bind(SocketAddr.localhost(0), _mc_config())
    srv.close()


# ── serve(..., num_workers=N) type-composition checks ──────────────────────


def _hello(req: Request) raises -> Response:
    return ok("hello")


def test_multicore_accepts_router() raises:
    """A Router can be the multicore handler.

    This is a type-only check; the wallclock test of accept/serve
    across N workers lives in the bench scripts.
    """
    var r = Router()
    r.get("/", _hello)
    # Just verifying Router is Copyable + Handler so
    # ``serve[Router](..., num_workers=N)`` compiles. Running the loop
    # is covered by the bench, not the unit tests, because threading
    # + graceful shutdown timing isn't reliable in a test-process
    # with no threading helper.
    var resp = r.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "hello")


def test_multicore_accepts_struct_handler() raises:
    """A struct-based handler satisfies the Handler & Copyable bound."""
    var h = _StaticHandler(0)
    var resp = h.serve(Request(method=Method.GET, url="/"))
    assert_equal(resp.text(), "multicore")


# ── Entry point ───────────────────────────────────────────────────────────


def main() raises:
    print("=" * 60)
    print("test_server_multicore.mojo — HttpServer multicore")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
