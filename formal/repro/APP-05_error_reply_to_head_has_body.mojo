# PLATFORM: any
"""APP-05: when the handler raises on a HEAD request, the error response
carries a body.

Lean: Flare.Bugs.APP_05.handler_error_head_emits_body (counterexample)
and Flare.Bugs.APP_05.errorFixed_head_no_body (fix meets spec).
flare/http/_reactor/conn_handle.mojo:910-915 @59bda50 (handler error
branch of ``on_readable``) -> ``_queue_error`` (conn_handle.mojo:1576-1580)
-> ``_serialize_response`` (conn_handle.mojo:1589-1594), which calls
``serialize_response_into`` without ``head_request``.

Spec (RFC 9110 sec 9.3.2): the server MUST NOT send content in a
response to HEAD; this holds for error statuses too.

Expected: the 500 queued for a HEAD whose handler raised ends at the
header terminator.
Actual: the 500 carries the text body "500 Internal Server Error" (the
error paths ignore ``self.head_request``). The connection closes
afterwards, so the extra bytes cannot be mistaken for a later response
on this connection, but the HEAD response still has content.

Minimal fix: in ``_serialize_response`` pass ``self.head_request`` as
``head_request`` to ``serialize_response_into``.
"""

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle
from flare.utils import usleep


def _boom(req: Request) raises -> Response:
    raise Error("boom")


def main() raises:
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var client = TcpStream.connect(
        SocketAddr.localhost(listener.local_addr().port)
    )
    var server = listener.accept()
    server._socket.set_nonblocking(True)
    var ch = ConnHandle(server^)
    var cfg = ServerConfig()
    cfg.idle_timeout_ms = 0
    var req = String("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n")
    _ = client.write(req.as_bytes())
    var h = FnHandler(_boom)
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
    var hdr_end = wire.find("\r\n\r\n")
    if hdr_end < 0:
        raise Error("setup: no header terminator in: " + wire)
    var trailing = len(ch.write_buf) - (hdr_end + 4)
    if trailing > 0:
        print(
            "BUG REPRODUCED: error response to HEAD carries",
            trailing,
            "body bytes:",
            repr(String(wire[byte = hdr_end + 4 :])),
        )
        raise Error("APP-05")
    print("OK: the error response to HEAD has no body")
    _ = client_fd
    client.close()
