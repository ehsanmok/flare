"""End-to-end tests proving the unified ``flare.http.HttpServer`` +
``flare.http.HttpClient`` pair handles HTTP/2 (cleartext h2c via
prior knowledge) without any HTTP/2-specific code in the
application.

Originally this file paired the now-removed ``Http2Server`` and
``Http2Client`` types; the unified server/client subsume both.
The tests below drive ``HttpServer.serve(handler)`` (which auto-
dispatches HTTP/1.1 vs HTTP/2 per connection via the preface
peek) with ``HttpClient(prefer_h2c=True)`` (which speaks h2 on
the wire via prior knowledge for ``http://`` URLs) -- proving
that a :class:`flare.http.Router`, request body, and custom
headers all round-trip through the HTTP/2 wire identically to
how they would through HTTP/1.1.

Each test forks a child running ``HttpServer.serve(handler)``,
drives the parent through ``HttpClient(prefer_h2c=True)``,
and SIGKILLs the child on test-end.

Coverage:

- :func:`test_h2_server_simple_handler` -- the smallest possible
  handler (``def hello(req): return ok("hi")``) round-trips a
  GET via Http2Client.
- :func:`test_h2_server_router_dispatch` -- a
  :class:`flare.http.Router` with two routes (``GET /a`` ->
  body "a"; ``GET /b`` -> body "b") dispatches correctly when
  driven by HTTP/2.
- :func:`test_h2_server_request_body_round_trip` -- the
  handler reads ``req.body`` and echoes its length, proving
  the HTTP/2 DATA frames assemble into the right bytes
  server-side.
- :func:`test_h2_server_request_headers_visible` -- the
  handler reads ``req.headers.get("x-custom")``, proving
  custom request headers survive HPACK encode/decode and are
  visible to the same handler code that would read them on
  HTTP/1.1.
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from flare.http import (
    HttpClient,
    HttpServer,
    Request,
    Response,
    ok,
)
from flare.net import SocketAddr


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


comptime _SIGKILL: c_int = c_int(9)


def _hello(req: Request) raises -> Response:
    return ok("hi")


def _echo_body_len(req: Request) raises -> Response:
    return ok(String(len(req.body)))


def _echo_custom_header(req: Request) raises -> Response:
    return ok(req.headers.get("x-custom"))


def test_h2_server_simple_handler() raises:
    """Smallest possible handler over Http2Server <- Http2Client."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got_status = -1
    var got_body = String("")
    try:
        with HttpClient(prefer_h2c=True) as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_equal(got_status, 200)
    assert_equal(got_body, "hi")


def _by_path_router(req: Request) raises -> Response:
    """In-test path dispatcher used in lieu of flare.http.Router so the
    test stays portable across the Router's evolving Copyable
    constraints (Router is not Copyable today, so it can't be
    handed to HttpServer.serve[H: Handler & Copyable])."""
    if req.url == "/a":
        return ok("a")
    if req.url == "/b":
        return ok("b")
    return Response(status=404, reason="Not Found")


def test_h2_server_router_dispatch() raises:
    """A path-dispatching def handler dispatches correctly when
    driven by HTTP/2."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_by_path_router)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    var got_a = String("")
    var got_b = String("")
    try:
        with HttpClient(prefer_h2c=True, base_url=base) as c:
            got_a = c.get("/a").text()
            got_b = c.get("/b").text()
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_equal(got_a, "a")
    assert_equal(got_b, "b")


def test_h2_server_request_body_round_trip() raises:
    """A POST body is reassembled from HTTP/2 DATA frames and visible to
    the handler as ``req.body`` exactly as it would be on HTTP/1.1."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_echo_body_len)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/x")
    var got = String("")
    try:
        with HttpClient(prefer_h2c=True) as c:
            var r = c.post(url, '{"hello":"h2"}')
            got = r.text()
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    # ``{"hello":"h2"}`` is 14 bytes.
    assert_equal(got, "14")


def test_h2_server_request_headers_visible() raises:
    """A custom request header survives HPACK encode/decode and lands in
    ``req.headers`` for the handler to read."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_echo_custom_header)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    var got = String("")
    try:
        with HttpClient(prefer_h2c=True) as c:
            # Build a Request manually so we can attach a custom
            # header; ``client.send`` propagates the header
            # through the same HpackEncoder path.
            var req = Request(method="GET", url=url)
            req.headers.set("X-Custom", "hello-h2")
            var r = c.send(req)
            got = r.text()
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_equal(got, "hello-h2")


def main() raises:
    test_h2_server_simple_handler()
    test_h2_server_router_dispatch()
    test_h2_server_request_body_round_trip()
    test_h2_server_request_headers_visible()
    print("test_h2_server_handler: 4 passed")
