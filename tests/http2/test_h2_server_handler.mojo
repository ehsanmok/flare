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

from std.collections import Optional
from std.ffi import c_int
from std.testing import assert_equal, assert_true


from flare.utils import (
    SIGKILL,
    exit,
    fork,
    kill,
    usleep,
    waitpid,
)

from flare.http import (
    HttpClient,
    HttpServer,
    Request,
    Response,
    ok,
)
from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.response import stream_response
from flare.net import SocketAddr


def _hello(req: Request) raises -> Response:
    return ok("hi")


struct _CountSource(ChunkSource, Movable):
    """Yields ``count`` chunks ("chunk0".."chunkN-1"), then None."""

    var count: Int
    var i: Int

    def __init__(out self, count: Int):
        self.count = count
        self.i = 0

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.i >= self.count:
            return Optional[List[UInt8]]()
        var s = String("chunk") + String(self.i)
        self.i += 1
        var out = List[UInt8]()
        for b in s.as_bytes():
            out.append(b)
        return Optional[List[UInt8]](out^)


def _stream_greeter(req: Request) raises -> Response:
    var resp = stream_response[_CountSource](_CountSource(3))
    resp.headers.set("Content-Type", "text/plain")
    return resp^


def _echo_body_len(req: Request) raises -> Response:
    return ok(String(len(req.body)))


def _echo_custom_header(req: Request) raises -> Response:
    return ok(req.headers.get("x-custom"))


def test_h2_server_simple_handler() raises:
    """Smallest possible handler over Http2Server <- Http2Client."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(200000)

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

    _ = kill(pid, SIGKILL)
    waitpid(pid)
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

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_by_path_router)
        except:
            pass
        exit()
    usleep(200000)

    var base = String("http://127.0.0.1:") + String(Int(port))
    var got_a = String("")
    var got_b = String("")
    try:
        with HttpClient(prefer_h2c=True, base_url=base) as c:
            got_a = c.get("/a").text()
            got_b = c.get("/b").text()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(got_a, "a")
    assert_equal(got_b, "b")


def test_h2_server_request_body_round_trip() raises:
    """A POST body is reassembled from HTTP/2 DATA frames and visible to
    the handler as ``req.body`` exactly as it would be on HTTP/1.1."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_body_len)
        except:
            pass
        exit()
    usleep(200000)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/x")
    var got = String("")
    try:
        with HttpClient(prefer_h2c=True) as c:
            var r = c.post(url, '{"hello":"h2"}')
            got = r.text()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    # ``{"hello":"h2"}`` is 14 bytes.
    assert_equal(got, "14")


def test_h2_server_request_headers_visible() raises:
    """A custom request header survives HPACK encode/decode and lands in
    ``req.headers`` for the handler to read."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_custom_header)
        except:
            pass
        exit()
    usleep(200000)

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

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(got, "hello-h2")


def test_h2_server_streaming_response() raises:
    """A handler returning ``stream_response`` streams incremental DATA
    frames on h2; the client reassembles them into the full body (K1)."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_stream_greeter)
        except:
            pass
        exit()
    usleep(200000)

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

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    assert_equal(got_status, 200)
    assert_equal(got_body, "chunk0chunk1chunk2")


def main() raises:
    test_h2_server_simple_handler()
    test_h2_server_router_dispatch()
    test_h2_server_request_body_round_trip()
    test_h2_server_request_headers_visible()
    test_h2_server_streaming_response()
    print("test_h2_server_handler: 5 passed")
