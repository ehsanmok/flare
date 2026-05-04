"""HTTP/2 server example: drive a path-dispatching handler over h2c
via the unified ``HttpServer`` + ``HttpClient``.

The compatibility story made self-evident: the same
:class:`flare.http.HttpServer` accept loop dispatches both
HTTP/1.1 and HTTP/2 on the same port (preface peek picks the
wire per connection); the same handler shape
``def(Request) raises -> Response`` runs unchanged on either.
:class:`flare.http.HttpClient` with ``prefer_h2c=True`` forces
HTTP/2 cleartext via prior knowledge, mirroring how
``HttpClient.get("https://...")`` would auto-negotiate via
ALPN once the handler is fronted by TLS.

Topology:
* Child process: bind ``HttpServer`` on an ephemeral port,
  serve a path-dispatching handler with three routes, exit
  on connection close.
* Parent process: connect via ``HttpClient(prefer_h2c=True)``,
  hit each route, print the response.

Run:
    pixi run -e dev mojo -I . examples/41_http2_server_router.mojo
"""

from std.ffi import c_int, external_call

from flare.http import HttpClient, HttpServer, Request, Response, ok
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


def _route(req: Request) raises -> Response:
    """In-place path dispatcher. The same handler shape works on
    HTTP/1.1 and HTTP/2 because flare.http.HttpServer hands the
    parsed flare.http.Request straight through both wires."""
    if req.url == "/":
        return ok('{"hello":"h2"}')
    if req.url == "/users/me":
        return ok(String('{"user":"') + req.url + String('"}'))
    if req.url == "/bytes":
        return ok(String("got ") + String(len(req.body)) + String(" bytes"))
    return Response(status=404, reason="Not Found")


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("[h2 server] listening on 127.0.0.1:" + String(Int(port)))

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_route)
        except:
            pass
        _exit_child()
    _usleep(c_int(150000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    print("[h2 client] connecting to " + base)
    with HttpClient(prefer_h2c=True, base_url=base) as c:
        var r1 = c.get("/")
        print("[h2] GET /          -> " + String(r1.status) + " " + r1.text())
        var r2 = c.get("/users/me")
        print("[h2] GET /users/me  -> " + String(r2.status) + " " + r2.text())
        var r3 = c.post("/bytes", '{"name":"flare","payload":[1,2,3]}')
        print("[h2] POST /bytes    -> " + String(r3.status) + " " + r3.text())

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    print("[done]")
