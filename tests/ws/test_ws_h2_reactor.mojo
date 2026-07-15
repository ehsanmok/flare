"""WebSocket-over-HTTP/2 sidecar dispatch on the unified reactor (RFC 8441).

Forks a real ``HttpServer.serve(handler, ws_handler)`` (h2c prior-knowledge,
no TLS) and hand-drives an ``Http2ClientConnection`` over a socket: opens an
Extended CONNECT tunnel, sends a masked client TEXT frame, and asserts the
edge-driven ``WsH2Handler.on_message`` echo rides back unmasked. Proves the
reactor accept/pump/teardown wiring, not just the sans-I/O bridge.
"""

from std.testing import assert_equal, assert_true

from flare.http import HttpServer
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http2.client import Http2ClientConfig, Http2ClientConnection
from flare.http2.server import Http2Connection
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from flare.ws.frame import WsFrame, WsOpcode
from flare.ws.server_h2 import WsH2Handler, WsOverH2ServerStream


struct _OkHandler(Copyable, Handler, Movable):
    """Trivial HTTP handler; the WS tunnel never reaches it."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return Response(200)


struct _EchoWsH2(Copyable, Movable, WsH2Handler):
    """Echoes each client TEXT frame back prefixed with ``echo:``."""

    def __init__(out self):
        pass

    def on_open(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
    ) raises -> None:
        pass

    def on_message(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
        frame: WsFrame,
    ) raises -> None:
        if frame.opcode == WsOpcode.TEXT:
            carrier.send_frame(
                conn, WsFrame.text("echo:" + frame.text_payload())
            )

    def on_close(
        mut self,
        mut carrier: WsOverH2ServerStream,
        mut conn: Http2Connection,
    ) raises -> None:
        pass


def _write_all(mut s: TcpStream, data: List[UInt8]) raises:
    var off = 0
    while off < len(data):
        var n = s.write(Span[UInt8, _](data)[off:])
        if n <= 0:
            raise Error("socket write made no progress")
        off += n


def _flush(mut client: Http2ClientConnection, mut s: TcpStream) raises:
    var out = client.drain()
    if len(out) > 0:
        _write_all(s, out)


def _pull(mut client: Http2ClientConnection, mut s: TcpStream) raises -> Bool:
    """Read one chunk (recv-timeout bounded) into the client; False on timeout.
    """
    var buf = List[UInt8](capacity=8192)
    buf.resize(8192, 0)
    try:
        var n = s.read(buf.unsafe_ptr(), 8192)
        if n <= 0:
            return False
        client.feed(Span[UInt8, _](buf)[:n])
        return True
    except:
        return False  # recv timeout -- nothing more this round


def main() raises:
    print("test_ws_h2_reactor")
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_OkHandler(), _EchoWsH2())
        except:
            pass
        exit()
    usleep(300_000)

    var client_stream = TcpStream.connect(SocketAddr.localhost(port))
    client_stream._socket.set_recv_timeout(400)

    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)

    # Preface + SETTINGS exchange until the server advertises Extended CONNECT.
    for _i in range(16):
        _flush(client, client_stream)
        _ = _pull(client, client_stream)
        if client.peer_supports_extended_connect():
            break
    assert_true(
        client.peer_supports_extended_connect(),
        "server must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL",
    )

    # Open the tunnel and send a masked TEXT frame.
    var sid = client.next_stream_id()
    bootstrap_ws_over_h2(
        client, sid, String("example.com"), String("/chat"), String("AAAA")
    )
    var client_ws = WsOverH2Stream(sid)
    client_ws.send_frame(client, WsFrame.text("ping"))

    # Pump until the echo reply decodes client-side.
    var got = Optional[WsFrame]()
    for _i in range(32):
        _flush(client, client_stream)
        _ = _pull(client, client_stream)
        got = client_ws.try_pull_frame(client)
        if got:
            break

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(Bool(got), "client must decode the server echo reply")
    assert_equal(got.value().opcode, WsOpcode.TEXT)
    assert_equal(got.value().text_payload(), "echo:ping")
    print("test_ws_h2_reactor: 1 passed")
