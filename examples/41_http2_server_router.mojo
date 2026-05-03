"""HTTP/2 server example: drive a flare.http.Router over h2c.

The point of this example is to make the *compatibility story*
self-evident: the same :class:`flare.http.Router` (with path
params, multiple methods, typed handlers) that you'd hand to
:meth:`flare.http.HttpServer.serve` works unchanged when you
hand it to :meth:`flare.http2.Http2Server.serve`. The
application code doesn't know -- and doesn't need to know --
which wire protocol is talking to it.

Topology (mirrors examples/40_http2_client.mojo):
* Child process: bind an Http2Server on an ephemeral port,
  serve a Router with three routes, exit on connection close.
* Parent process: connect via Http2Client, hit each route,
  print the response.

Run:
    pixi run -e dev mojo -I . examples/41_http2_server_router.mojo
"""

from std.ffi import c_int, external_call

from flare.http import Request, Response, Router, ok
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
    """Return a small JSON greeting."""
    return ok('{"hello":"h2"}')


def _user_lookup(req: Request) raises -> Response:
    """Echo the user id from the URL so the path-param plumbing is visible.

    The same handler shape works on HTTP/1.1; flare.http2.Http2Server
    hands the parsed flare.http.Request straight to the Router.
    """
    return ok(String('{"user":"') + req.url + String('"}'))


def _bytes_in(req: Request) raises -> Response:
    """Report the number of bytes the server received in the body.

    Confirms that HTTP/2 DATA frames reassemble into req.body
    exactly the way HTTP/1.1's Content-Length-delimited body
    reads do.
    """
    return ok(String("got ") + String(len(req.body)) + String(" bytes"))


def main() raises:
    var srv = Http2Server.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("[h2 server] listening on 127.0.0.1:" + String(Int(port)))

    var pid = _fork()
    if pid == 0:
        try:
            var r = Router()
            r.get("/", _hello)
            r.get("/users/me", _user_lookup)
            r.post("/bytes", _bytes_in)
            srv.serve(r^)
        except:
            pass
        _exit_child()
    _usleep(c_int(150000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    print("[h2 client] connecting to " + base)
    with Http2Client(base_url=base) as c:
        var r1 = c.get("/")
        print("[h2] GET /          -> " + String(r1.status) + " " + r1.text())
        var r2 = c.get("/users/me")
        print("[h2] GET /users/me  -> " + String(r2.status) + " " + r2.text())
        var r3 = c.post("/bytes", '{"name":"flare","payload":[1,2,3]}')
        print("[h2] POST /bytes    -> " + String(r3.status) + " " + r3.text())

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    print("[done]")
