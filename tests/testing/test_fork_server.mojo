"""Tests for ``flare.testing.fork_server`` / ``kill_forked_server``."""

from std.testing import assert_equal, assert_true

from flare.http import Handler, HttpClient, HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


def _route(req: Request) raises -> Response:
    if req.url == "/":
        return ok("hello")
    if req.url == "/echo":
        return ok(req.method)
    return Response(status=404, reason="Not Found")


def test_fork_server_bare_function_overload() raises:
    """Verify the bare-fn overload spawns a server the parent can talk to."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = fork_server(srv^, _route)
    assert_true(pid > 0)
    var base = String("http://127.0.0.1:") + String(port)
    with HttpClient(base_url=base) as c:
        var r = c.get("/")
        assert_equal(r.status, 200)
        assert_equal(r.text(), "hello")
        var r2 = c.get("/echo")
        assert_equal(r2.status, 200)
        assert_equal(r2.text(), "GET")
    kill_forked_server(pid)


@fieldwise_init
struct _StaticHandler(Copyable, Handler):
    """Tiny Copyable Handler struct for the parametric-overload test."""

    var greeting: String

    def serve(self, req: Request) raises -> Response:
        return ok(self.greeting)


def test_fork_server_handler_struct_overload() raises:
    """Verify the parametric overload accepts a Handler struct."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = fork_server(srv^, _StaticHandler(greeting="hi from struct"))
    assert_true(pid > 0)
    var base = String("http://127.0.0.1:") + String(port)
    with HttpClient(base_url=base) as c:
        var resp = c.get("/")
        assert_equal(resp.status, 200)
        assert_equal(resp.text(), "hi from struct")
    kill_forked_server(pid)


def test_fork_server_router_handler_only() raises:
    """Verify a Router (Handler-only, not Copyable) flows through
    fork_server's relaxed parametric overload."""
    from flare.http import Router

    var r = Router()
    r.get("/", _route)
    r.get("/echo", _route)

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = fork_server(srv^, r^)
    assert_true(pid > 0)
    var base = String("http://127.0.0.1:") + String(port)
    with HttpClient(base_url=base) as c:
        var resp = c.get("/")
        assert_equal(resp.status, 200)
        assert_equal(resp.text(), "hello")
        var resp2 = c.get("/echo")
        assert_equal(resp2.status, 200)
        assert_equal(resp2.text(), "GET")
    kill_forked_server(pid)


def main() raises:
    test_fork_server_bare_function_overload()
    print("OK test_fork_server_bare_function_overload")

    test_fork_server_handler_struct_overload()
    print("OK test_fork_server_handler_struct_overload")

    test_fork_server_router_handler_only()
    print("OK test_fork_server_router_handler_only")
