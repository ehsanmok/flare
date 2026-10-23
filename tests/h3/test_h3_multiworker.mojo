"""Multi-worker HTTP/3 (``QuicServerConfig.num_workers``).

Server CIDs name their worker through a keyed hash; a short-header
packet for another worker's CID is forwarded to that worker instead of
being answered with a stateless reset; and an ``HttpServer`` with four
``SO_REUSEPORT`` workers answers clients spread across them.
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
from flare.quic.packet import ConnectionId, LongHeader, PACKET_TYPE_INITIAL
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.quic._worker_route import (
    cid_owner,
    free_inbox_table,
    inbox_at,
    new_inbox_table,
)
from flare.testing import kill_forked_server
from flare.tls import RustlsQuicConnector
from flare.utils import exit, fork


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _worker_cfg(
    id: Int, key: List[UInt8], table: Int, port: UInt16
) -> QuicServerConfig:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = port
    cfg.num_workers = 2
    cfg.worker_id = id
    cfg.cid_route_key = key.copy()
    cfg.inbox_table = table
    return cfg^


def test_issued_cids_name_their_worker() raises:
    var key = List[UInt8](length=32, fill=UInt8(7))
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.num_workers = 4
    cfg.worker_id = 2
    cfg.cid_route_key = key.copy()
    var listener = QuicListener.bind(cfg)
    for _ in range(16):
        var cid = listener._new_local_cid()
        assert_equal(cid_owner(key, cid.bytes, 4), 2)
    listener.close()


def test_a_packet_for_another_workers_cid_is_forwarded() raises:
    var key = List[UInt8](length=32, fill=UInt8(9))
    var table = new_inbox_table(2)
    var w0 = QuicListener.bind(_worker_cfg(0, key, table, UInt16(0)))
    var w1 = QuicListener.bind(_worker_cfg(1, key, table, w0.local_addr().port))
    var lh = LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=UInt32(1),
        dcid=ConnectionId(bytes=List[UInt8](length=8, fill=UInt8(1))),
        scid=ConnectionId(bytes=List[UInt8](length=8, fill=UInt8(2))),
        payload_offset=0,
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(40000))
    var slot = w1._accept_initial(lh, peer)
    var cid = w1.connections[slot].local_cid.bytes.copy()
    # A 1-RTT packet for worker 1's connection that the kernel handed
    # to worker 0 (the client's 4-tuple changed).
    var pkt = List[UInt8]()
    pkt.append(UInt8(0x40))
    pkt.extend(Span[UInt8, _](cid))
    pkt.resize(64, UInt8(0xAB))
    assert_equal(w0.dispatch_datagram(Span[UInt8, _](pkt), peer), -1)
    assert_equal(len(inbox_at(table, 1)[].lens), 1, "forwarded to its owner")
    assert_equal(len(inbox_at(table, 0)[].lens), 0)
    _ = w1.tick(timeout_ms=1)
    assert_equal(len(inbox_at(table, 1)[].lens), 0, "the owner took it")
    w0.close()
    w1.close()
    free_inbox_table(table, 2)


@fieldwise_init
struct _Hello(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok("hi")


def test_four_workers_answer_spread_clients() raises:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.num_workers = 4
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
            srv.serve_http3[_Hello](_Hello())
        except:
            pass
        exit()
    var answered = 0
    for _ in range(8):
        var connector = RustlsQuicConnector(
            Path(_FIXDIR + "ca.pem").read_text(), _alpn()
        )
        var quic = QuicClientConnection.start(
            addr, connector, String("localhost")
        )
        for _ in range(100):
            _ = quic.poll(timeout_ms=20)
            if quic.is_established():
                break
        if not quic.is_established():
            continue
        var h3 = Http3ClientConnection(quic^)
        var sid = h3.request(
            "GET", "https", "localhost", "/", List[QpackHeader](), List[UInt8]()
        )
        var deadline = _monotonic_ms() + 5_000
        while _monotonic_ms() < deadline:
            _ = h3.poll_responses(10)
            var r = h3.take_if_complete(sid)
            if r:
                if r.value().status == 200:
                    answered += 1
                break
        h3.close()
    kill_forked_server(pid)
    assert_equal(answered, 8)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
