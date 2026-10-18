"""WebSocket over HTTP/3 (RFC 9220), server and client, over real QUIC.

* :meth:`flare.http.HttpServer.attach_ws_h3` routes extended CONNECT
  streams with ``:protocol: websocket`` to an edge-driven
  :class:`flare.ws.server_h3.WsH3Handler`; ``serve_http3`` serves plain
  requests to the ``Handler`` as usual.
* :meth:`flare.ws.WsOverH3Stream.open` opens a tunnel on an
  :class:`flare.http3.Http3ClientConnection` once the server's SETTINGS
  allow extended CONNECT, then sends and receives WebSocket frames.

Run:
    pixi run example-ws-over-h3
"""

from flare.http import Handler, HttpServer
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.http3 import Http3ClientConnection
from flare.net import IpAddr, SocketAddr
from flare.quic import QuicServerConfig
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener
from flare.tls import RustlsQuicConnector
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import WsFrame, WsOpcode, WsOverH3Stream
from flare.ws.server_h3 import WsH3Handler, WsOverH3ServerStream


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


@fieldwise_init
struct Plain(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("plain h3")


@fieldwise_init
struct Echo(WsH3Handler):
    """Echoes every text frame back."""

    def on_open(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises:
        pass

    def on_message(
        mut self,
        mut carrier: WsOverH3ServerStream,
        mut listener: QuicListener,
        frame: WsFrame,
    ) raises:
        if frame.opcode == WsOpcode.TEXT:
            carrier.send_frame(
                listener, WsFrame.text("echo: " + frame.text_payload())
            )

    def on_close(
        mut self, mut carrier: WsOverH3ServerStream, mut listener: QuicListener
    ) raises:
        pass


def _read_file(path: String) raises -> String:
    with open(path, "r") as f:
        return f.read()


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def main() raises:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = _read_file(_FIXDIR + "cert.pem")
    cfg.rustls_config.private_key_pem = _read_file(_FIXDIR + "key.pem")
    cfg.rustls_config.alpn_protocols = _alpn()
    var srv = HttpServer.bind_with_http3(
        SocketAddr(IpAddr.localhost(), UInt16(0)), cfg^
    )
    srv.attach_ws_h3(Echo())
    var addr = srv.local_http3_addr()
    print("[server] h3 + WebSocket on", String(addr))

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_http3(Plain())
        except:
            pass
        exit()
    usleep(300_000)

    var echoed = String("")
    try:
        var quic = QuicClientConnection.connect(
            addr,
            RustlsQuicConnector(_read_file(_FIXDIR + "ca.pem"), _alpn()),
            String("localhost"),
        )
        var h3 = Http3ClientConnection(quic^)
        var ws = WsOverH3Stream.open(h3, "localhost", "/chat")
        ws.send_frame(h3, WsFrame.text("hello over h3"))
        for _ in range(100):
            var f = ws.try_pull_frame(h3, 20)
            if f:
                echoed = f.value().text_payload()
                break
        ws.close(h3)
        h3.close()
    except e:
        print("[client] failed:", String(e))

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("[client] got:", echoed)
