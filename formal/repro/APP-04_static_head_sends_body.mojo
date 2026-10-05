# PLATFORM: any
# RESOLVED: APP-04 fixed on fix/formal-findings
"""APP-04: the static fast path sends the body in reply to HEAD.

Lean: Flare.Bugs.APP_04.static_head_emits_body (counterexample) and
Flare.Bugs.APP_04.staticFixed_head_no_body (fix meets spec).
flare/http/_reactor/conn_handle.mojo:1174-1211 @59bda50
(``on_readable_static``) with
flare/http/_reactor/write_path.mojo:107-148 (``serialize_static_into``).

Spec (RFC 9110 sec 9.3.2: the server MUST NOT send content in a
response to HEAD; RFC 9112 sec 6.3: a response to HEAD ends at the
header terminator).

Expected: the bytes queued for ``HEAD / HTTP/1.1`` end at the blank
line after the headers.
Before the fix: ``on_readable_static`` never looks at the method and copies
the whole pre-encoded GET response, body included, with
``Connection: keep-alive``. A keep-alive client reads the body bytes as
the start of the next response (response desynchronisation).

Minimal fix: when the request line starts with ``HEAD ``, queue only
the head of the pre-encoded bytes (up to and including the first
CRLFCRLF).
"""

from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener
from flare.http import precompute_response
from flare.http.server import ServerConfig
from flare.http._server_reactor_impl import ConnHandle
from flare.utils import usleep


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
    var resp = precompute_response(
        status=200, content_type="text/plain", body="Hello, World!"
    )
    var req = String("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n")
    _ = client.write(req.as_bytes())
    # Poll until the request has arrived and a response is queued.
    for _ in range(50):
        usleep(20000)
        _ = ch.on_readable_static(resp, cfg)
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
            "BUG REPRODUCED: HEAD on the static path queued",
            trailing,
            "body bytes after the headers; keep-alive=",
            "Connection: keep-alive" in wire,
        )
        raise Error("APP-04")
    print("OK: HEAD on the static path queues the head only")
    _ = client_fd
    client.close()
