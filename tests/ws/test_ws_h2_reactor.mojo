"""WebSocket-over-HTTP/2 sidecar dispatch on the unified reactor (RFC 8441).

Forks a real server with ``attach_ws_h2(ws_handler)`` then ``serve(handler)``
(h2c prior-knowledge, no TLS) and hand-drives an ``Http2ClientConnection`` over a socket: opens an
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


struct _OkHandler(Copyable, Handler):
    """Trivial HTTP handler; the WS tunnel never reaches it."""

    def __init__(out self):
        pass

    def serve(self, req: Request) raises -> Response:
        return Response(200)


struct _EchoWsH2(Copyable, WsH2Handler):
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


def _echo_once(port: UInt16) raises -> String:
    """Open a tunnel on a fresh connection, send ``ping``, return the
    echo's text (empty if none came)."""
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
    if not client.peer_supports_extended_connect():
        return ""
    var sid = client.next_stream_id()
    bootstrap_ws_over_h2(
        client, sid, String("example.com"), String("/chat"), String("AAAA")
    )
    var client_ws = WsOverH2Stream(sid)
    client_ws.send_frame(client, WsFrame.text("ping"))
    for _i in range(32):
        _flush(client, client_stream)
        _ = _pull(client, client_stream)
        var got = client_ws.try_pull_frame(client)
        if got:
            return got.value().text_payload()
    return ""


def _serve(workers: Int, addrs: Int = 1) raises -> Tuple[Int, List[UInt16]]:
    var bind_to = List[SocketAddr]()
    for _ in range(addrs):
        bind_to.append(SocketAddr.localhost(0))
    var srv = HttpServer.bind(bind_to^)
    var ports = List[UInt16]()
    for a in srv.local_addrs():
        ports.append(UInt16(a.port))
    var pid = fork()
    if pid == 0:
        try:
            srv.attach_ws_h2(_EchoWsH2())
            if workers == 0:
                srv.serve(_OkHandler())
            else:
                srv.serve(_OkHandler(), num_workers=workers, pin_cores=False)
        except:
            pass
        exit()
    usleep(300_000)
    return (pid, ports^)


def _echoes(workers: Int, addrs: Int = 1, rounds: Int = 1) raises -> Int:
    var s = _serve(workers, addrs)
    var echoed = 0
    for _ in range(rounds):
        for p in s[1]:
            if _echo_once(p) == "echo:ping":
                echoed += 1
    _ = kill(s[0], SIGKILL)
    waitpid(s[0])
    return echoed


def test_ws_h2_reactor() raises:
    print("test_ws_h2_reactor")
    assert_equal(_echoes(0), 1)


def test_ws_h2_with_one_worker_given() raises:
    """``serve(h, num_workers=1)`` used to drop the sidecar."""
    assert_equal(_echoes(1), 1)


def test_ws_h2_on_every_address() raises:
    """A multi-address single-worker server used to refuse the sidecar."""
    assert_equal(_echoes(0, addrs=2), 2)


def test_ws_h2_on_several_workers() raises:
    """Every worker serves tunnels with its own copy of the sidecar; the
    multi-worker path used to drop it."""
    assert_equal(_echoes(4, rounds=8), 8)


def main() raises:
    test_ws_h2_reactor()
    test_ws_h2_with_one_worker_given()
    test_ws_h2_on_every_address()
    test_ws_h2_on_several_workers()
    print("test_ws_h2_reactor: 4 passed")
