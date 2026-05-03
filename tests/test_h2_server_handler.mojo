"""End-to-end tests for ``flare.http2.Http2Server`` paired with
``flare.http2.Http2Client``.

The point of these tests is to prove that **all of the existing
HTTP/1.1 application-level features work over HTTP/2** without
any HTTP/2-specific code in the application -- if the handler is
a :class:`flare.http.Router` (or wrapped in middleware, or built
on :class:`flare.http.App[S]`), it just works on both wires.

Each test forks a child running :class:`Http2Server` over h2c
(cleartext HTTP/2 via prior knowledge) and a parent running
:class:`Http2Client`, exchanging real requests on a loopback
socket. SIGKILL the child on test-end.

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

from flare.http import Router, Request, Response, ok
from flare.http2 import Http2Client, Http2Server
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
    var srv = Http2Server.bind(SocketAddr.localhost(0))
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
        with Http2Client() as c:
            var r = c.get(url)
            got_status = r.status
            got_body = r.text()
    except:
        pass

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_equal(got_status, 200)
    assert_equal(got_body, "hi")


def test_h2_server_router_dispatch() raises:
    """``flare.http.Router`` dispatches correctly when driven by HTTP/2."""
    var srv = Http2Server.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = _fork()
    if pid == 0:
        try:
            var r = Router()

            def _route_a(req: Request) raises -> Response:
                return ok("a")

            def _route_b(req: Request) raises -> Response:
                return ok("b")

            r.get("/a", _route_a)
            r.get("/b", _route_b)
            srv.serve(r^)
        except:
            pass
        _exit_child()
    _usleep(c_int(200000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    var got_a = String("")
    var got_b = String("")
    try:
        with Http2Client(base_url=base) as c:
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
    var srv = Http2Server.bind(SocketAddr.localhost(0))
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
        with Http2Client() as c:
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
    var srv = Http2Server.bind(SocketAddr.localhost(0))
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
        with Http2Client() as c:
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
