# PLATFORM: any
"""APP-01: the 426 answer to a bad WebSocket version says "Connection: close"
but the connection stays open and keeps serving requests.

Lean: Flare.Bugs.APP_01.ws426_close_header_but_kept_open (counterexample)
and Flare.Bugs.APP_01.fixed_close_header_implies_close (fix meets spec).
flare/http/_reactor/conn_handle.mojo:846-856 @59bda50 (the
``_is_ws_version_mismatch`` branch of ``on_readable``), together with
``_finalise_response`` (conn_handle.mojo:718-756), which only uses
``close_after`` for the header and never sets ``should_close``.

Spec (RFC 9112 sec 9.6): a server that sends the ``close`` connection
option MUST initiate closure after that response and MUST NOT process
further requests on the connection.

Expected: after the 426 flushes, ``on_writable`` returns ``done=True``.
Actual: the 426 carries ``Connection: close`` but ``should_close`` is
still False, so ``on_writable`` returns to STATE_READING with
``want_read=True``, and a following request on the same connection is
dispatched to the HTTP handler. The 426 path also skips
``_apply_keepalive_policy``, so it does not count toward
``max_keepalive_requests``.

Minimal fix: set ``self.should_close = True`` before
``return self._finalise_response(r426^, True)``.
"""

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http import WsUpgrade
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ServerConfig
from flare.http.handler import FnHandler
from flare.http._server_reactor_impl import ConnHandle, STATE_READING
from flare.ws import WsConnection
from flare.utils import usleep


def _ws(mut c: WsConnection) raises -> None:
    pass


def _http(req: Request) raises -> Response:
    return Response(status=200, reason="OK")


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
    cfg.write_timeout_ms = 0
    cfg.ws = WsUpgrade(_ws)
    var req = String(
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection:"
        " Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 8\r\n\r\n"
    )
    _ = client.write(req.as_bytes())
    var h = FnHandler(_http)
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
    var says_close = "Connection: close" in wire
    var step = ch.on_writable(cfg)
    var reading_after = ch.state == STATE_READING
    if not wire.startswith("HTTP/1.1 426"):
        raise Error("setup: expected a 426, got: " + wire)
    if not says_close:
        raise Error("setup: the 426 does not say Connection: close: " + wire)
    if says_close and not step.done:
        # The connection is still live: a second request is served.
        var req2 = String("GET /after HTTP/1.1\r\nHost: a\r\n\r\n")
        _ = client.write(req2.as_bytes())
        for _ in range(50):
            usleep(20000)
            _ = ch.on_readable(h, cfg)
            if len(ch.write_buf) > 0:
                break
        var wire2 = String(unsafe_from_utf8=ch.write_buf)
        var shown = min(15, wire2.byte_length())
        print(
            "second request on the same connection answered:",
            repr(String(wire2[byte=0:shown])),
        )
        print(
            "BUG REPRODUCED: 426 sent 'Connection: close' but on_writable"
            " returned done=False, want_read=",
            step.want_read,
            "state_reading=",
            reading_after,
        )
        raise Error("APP-01")
    print("OK: the 426 response closes the connection (done=True)")
    _ = client_fd
    client.close()
