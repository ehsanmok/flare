"""HTTP/2 client example: cleartext h2c against a flare HTTP/2 server.

Spawns a child process that runs an HTTP/2 server (driving
``flare.http2.server.H2Connection`` over a real TCP socket on
loopback, no ALPN since this is cleartext h2c) and a parent
that uses :class:`flare.http2.Http2Client` to make a few
requests against it.

This mirrors the flare.http examples (``05_http_get.mojo``
etc.) but talks the binary HTTP/2 protocol instead of HTTP/1.1.
The :class:`Http2Client` API is intentionally identical to
:class:`flare.http.HttpClient` so application code can switch
protocols by changing only the type name and the URL scheme.

For the TLS (h2 over ALPN) variant, swap ``http://`` for
``https://`` -- the client picks up TLS automatically and
advertises ``h2`` on the ClientHello via
:attr:`flare.tls.TlsConfig.alpn`. This example sticks with
loopback h2c so it's hermetic (no public origin needed, no
self-signed cert dance).

Run with::

    pixi run -e dev mojo -I . examples/40_http2_client.mojo
"""

from std.ffi import c_int, external_call
from std.memory import stack_allocation

from flare.http2 import H2Connection, Http2Client
from flare.http import Response
from flare.tcp import TcpListener, TcpStream
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


def _serve_one_h2_connection(
    mut listener: TcpListener,
) raises:
    """Accept one h2c connection and serve it until the peer closes.

    Drives :class:`flare.http2.server.H2Connection` over the raw
    TCP socket. Every completed request gets a fixed
    ``200 OK { "hello": "h2" }`` response. Loops until ``read``
    returns 0 (peer closed).
    """
    var stream = listener.accept()
    var h2 = H2Connection()
    var buf = stack_allocation[16384, UInt8]()
    while True:
        var n = stream.read(buf, 16384)
        if n == 0:
            return
        var slice = List[UInt8](capacity=n)
        for i in range(n):
            slice.append(buf[i])
        h2.feed(Span[UInt8, _](slice))
        var ids = h2.take_completed_streams()
        for i in range(len(ids)):
            var sid = ids[i]
            _ = h2.take_request(sid)
            var resp = Response(status=200)
            resp.headers.set("Content-Type", "application/json")
            resp.body = List[UInt8](String('{"hello":"h2"}').as_bytes())
            h2.emit_response(sid, resp^)
        var out = h2.drain()
        if len(out) > 0:
            stream.write_all(Span[UInt8, _](out))


def main() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = UInt16(listener.local_addr().port)
    print("[h2c] listening on 127.0.0.1:" + String(Int(port)))

    var pid = _fork()
    if pid == 0:
        try:
            _serve_one_h2_connection(listener)
        except:
            pass
        _exit_child()
    # Give the child a moment to reach accept().
    _usleep(c_int(150000))

    var base = String("http://127.0.0.1:") + String(Int(port))
    print("[h2c] client connecting to " + base)
    with Http2Client(base_url=base) as c:
        var r1 = c.get("/api/users")
        print("[h2c] GET /api/users  ->  " + String(r1.status))
        print("       body: " + r1.text())

        var r2 = c.post("/api/items", '{"name":"flare"}')
        print("[h2c] POST /api/items ->  " + String(r2.status))
        print("       body: " + r2.text())

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    print("[h2c] done")
