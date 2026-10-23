"""HTTP/3 over a lossy, reordering path.

A relay between client and server drops every 13th datagram and holds
every 5th back behind the next one. The handshake, a 512 KiB download
and a 256 KiB upload must still complete: lost
handshake CRYPTO, lost 1-RTT STREAM data and lost flow-control grants
are all recovered by loss detection and the PTO.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.http.server import ok
from flare.http3 import Http3ClientConnection
from flare.net import IpAddr, SocketAddr
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector
from flare.udp import UdpSocket


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


struct _Relay(Movable):
    """Client <-> front | back <-> server, dropping and reordering."""

    var front: UdpSocket
    var back: UdpSocket
    var server: SocketAddr
    var client: SocketAddr
    var seen: Int
    var held: List[UInt8]
    var held_to_server: Bool
    var dropped: Int

    def __init__(out self, server: SocketAddr) raises:
        self.front = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
        self.back = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
        self.server = server
        self.client = server
        self.seen = 0
        self.held = List[UInt8]()
        self.held_to_server = False
        self.dropped = 0

    def _forward(mut self, data: List[UInt8], to_server: Bool) raises:
        self.seen += 1
        if self.seen % 13 == 0:
            self.dropped += 1
            return
        if self.seen % 5 == 0 and len(self.held) == 0:
            self.held = data.copy()
            self.held_to_server = to_server
            return
        self._send(data, to_server)
        if len(self.held) > 0:
            var h = self.held^
            self.held = List[UInt8]()
            self._send(h, self.held_to_server)

    def _send(self, data: List[UInt8], to_server: Bool) raises:
        if to_server:
            _ = self.back.send_to(Span[UInt8, _](data), self.server)
        else:
            _ = self.front.send_to(Span[UInt8, _](data), self.client)

    def pump(mut self) raises:
        var buf = List[UInt8](length=2048, fill=0)
        for _ in range(256):
            var got: Int
            try:
                var r = self.front.try_recv_from(Span[UInt8, _](buf))
                got = r[0]
                self.client = r[1]
            except:
                break
            if got <= 0:
                break
            self._forward(List[UInt8](Span[UInt8, _](buf)[:got]), True)
        for _ in range(256):
            var got: Int
            try:
                got = self.back.try_recv_from(Span[UInt8, _](buf))[0]
            except:
                break
            if got <= 0:
                break
            self._forward(List[UInt8](Span[UInt8, _](buf)[:got]), False)


def _serve_once(mut server: QuicListener, body_len: Int) raises:
    _ = server.tick(timeout_ms=1)
    for slot in range(server.connection_count()):
        var ready = server.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var req = server.take_http3_request(slot, ready[i])
            var resp = ok(String(len(req.body)))
            if len(req.body) == 0:
                resp.body = List[UInt8](length=body_len, fill=UInt8(0x5A))
            server.emit_http3_response(slot, ready[i], resp^)
    _ = server.drain_all_egress()
    _ = server.advance_timers(_monotonic_ms())


def test_handshake_download_and_upload_survive_loss() raises:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var server = QuicListener.bind(cfg^)
    var relay = _Relay(server.local_addr())
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(
        relay.front.local_addr(), connector, String("localhost")
    )
    var deadline = _monotonic_ms() + 10_000
    while not quic.is_established() and _monotonic_ms() < deadline:
        relay.pump()
        _serve_once(server, 0)
        relay.pump()
        _ = quic.poll(timeout_ms=2)
    assert_true(quic.is_established(), "handshake over the lossy path")
    var h3 = Http3ClientConnection(quic^)

    comptime DOWN = 512 * 1024
    var sid = h3.request(
        "GET", "https", "localhost", "/", List[QpackHeader](), List[UInt8]()
    )
    var got = -1
    deadline = _monotonic_ms() + 30_000
    while got < 0 and _monotonic_ms() < deadline:
        relay.pump()
        _serve_once(server, DOWN)
        relay.pump()
        _ = h3.poll_responses(1)
        var r = h3.take_if_complete(sid)
        if r:
            got = len(r.value().body)
    assert_equal(got, DOWN)

    comptime UP = 256 * 1024
    var up = h3.send_request_open(
        "POST", "https", "localhost", "/", List[QpackHeader]()
    )
    var body = List[UInt8](length=UP, fill=UInt8(0x33))
    var pos = 0
    deadline = _monotonic_ms() + 30_000
    while pos < UP and _monotonic_ms() < deadline:
        var take = min(4096, UP - pos)
        var cap = h3.quic.send_capacity(up)
        if cap >= take + 16:
            h3.send_request_body(
                up, List[UInt8](Span[UInt8, _](body)[pos : pos + take]), False
            )
            pos += take
        relay.pump()
        _serve_once(server, 0)
        relay.pump()
        _ = h3.poll_responses(1)
    h3.send_request_body(up, List[UInt8](), True)
    var echoed = String("")
    while echoed.byte_length() == 0 and _monotonic_ms() < deadline:
        relay.pump()
        _serve_once(server, 0)
        relay.pump()
        _ = h3.poll_responses(1)
        var r = h3.take_if_complete(up)
        if r:
            echoed = String(unsafe_from_utf8=Span[UInt8, _](r.value().body))
    assert_equal(echoed, String(UP))
    assert_true(relay.dropped > 10, "the path really dropped datagrams")
    server.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
