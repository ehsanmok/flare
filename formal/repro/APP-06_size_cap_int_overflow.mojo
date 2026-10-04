# PLATFORM: any
"""APP-06: max_header_size + max_body_size wraps, so a config that
ServerConfig.check accepts rejects every request with 413.

Lean: Flare.Bugs.APP_06.overflow_cap_rejects_one_byte (counterexample)
and Flare.Bugs.APP_06.capFixed_spec (fix meets spec).
flare/http/_reactor/conn_handle.mojo:448-453 @59bda50 (also 492-497 and
536-541): ``len(self.read_buf) > config.max_header_size +
config.max_body_size``; flare/http/_server/config.mojo:251-329
(``ServerConfig.check``) has no bound that keeps the sum in range.

Spec: a request whose head is at most max_header_size bytes and whose
body is at most max_body_size bytes is not rejected as too large.

Expected: with max_body_size = Int.MAX (an "unlimited" body cap that
check accepts) a 27-byte GET is served (200).
Actual: 8192 + Int.MAX wraps to a negative Int, every non-empty read
buffer exceeds it, and the request is answered 413.

Minimal fix: compare without the sum,
``len(self.read_buf) - config.max_header_size > config.max_body_size``
(len and max_header_size are non-negative), at all three sites.
"""

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle
from flare.utils import usleep

comptime CFG = ServerConfig(max_body_size=Int.MAX, idle_timeout_ms=0)


def _ok(req: Request) raises -> Response:
    return Response(status=200, reason="OK")


def main() raises:
    ServerConfig.check[CFG]()  # accepted at compile time
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(
        SocketAddr.localhost(listener.local_addr().port)
    )
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = materialize[CFG]()
    var req = String("GET / HTTP/1.1\r\nHost: a\r\n\r\n")
    _ = client.write(req.as_bytes())
    var h = FnHandler(_ok)
    # Poll until the request has arrived and a response is queued.
    for _ in range(50):
        usleep(20000)
        _ = ch.on_readable(h, cfg)
        if len(ch.write_buf) > 0:
            break
    var wire = String(unsafe_from_utf8=ch.write_buf)
    # Keep the peer open: Mojo drops `client` after its last use, and its
    # FIN would turn this into a half-close (peer_eof) case.
    var client_fd = client._socket.fd
    if wire.startswith("HTTP/1.1 413"):
        print(
            "BUG REPRODUCED: a",
            req.byte_length(),
            "byte GET was answered 413 with max_body_size=Int.MAX",
        )
        raise Error("APP-06")
    if not wire.startswith("HTTP/1.1 200"):
        raise Error("unexpected response: " + wire)
    print("OK: the GET is served with max_body_size=Int.MAX")
    _ = client_fd
    client.close()
