"""Streamed HTTP/3 request bodies (``Http3Config.stream_request_bodies``).

A request reached its handler only once the whole body had been
buffered. With the option on it arrives on its HEADERS and the body
follows through ``Request.body_stream()``; credit is granted as the
handler reads, so an upload far past the initial window streams through.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.http import HttpServer, ok
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http3 import Http3ClientConnection
from flare.net import IpAddr, SocketAddr
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.testing import kill_forked_server
from flare.tls import RustlsQuicConnector
from flare.utils import exit, fork


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"
comptime _CHUNK: Int = 64 * 1024


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


@fieldwise_init
struct _Echo(Copyable, Handler):
    """Streams the upload straight back."""

    def serve(self, req: Request) raises -> Response:
        var r = ok("")
        r.body_stream = req.body_stream()
        return r^


def test_an_upload_streams_through_its_handler() raises:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.http3.stream_request_bodies = True
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var srv = HttpServer.bind_with_http3(
        SocketAddr(IpAddr.localhost(), UInt16(0)), cfg^
    )
    var addr = srv.local_http3_addr()
    var pid = fork()
    if pid == 0:
        try:
            srv.serve_http3[_Echo](_Echo())
        except:
            pass
        exit()
    var quic = QuicClientConnection.connect(
        addr,
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), _alpn()),
        String("localhost"),
    )
    var h3 = Http3ClientConnection(quic^)
    var sid = h3.send_request_open(
        "POST", "https", "localhost", "/up", List[QpackHeader]()
    )
    var chunk = List[UInt8](length=_CHUNK, fill=UInt8(7))
    h3.send_request_body(sid, chunk, False)
    var deadline = _monotonic_ms() + 3_000
    while not h3.head_ready(sid) and _monotonic_ms() < deadline:
        _ = h3.poll_responses(10)
    var early = h3.head_ready(sid)
    var echoed = 0
    for _ in range(64):  # 4 MiB more: four times the initial window
        h3.send_request_body(sid, chunk, False)
        echoed += len(h3.poll_body(sid, 1).data)
    h3.send_request_body(sid, List[UInt8](), True)
    deadline = _monotonic_ms() + 10_000
    while _monotonic_ms() < deadline:
        var c = h3.poll_body(sid, 10)
        echoed += len(c.data)
        if c.done:
            break
    h3.close()
    kill_forked_server(pid)
    assert_true(early, "the handler answered before the upload ended")
    assert_equal(echoed, 65 * _CHUNK)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
