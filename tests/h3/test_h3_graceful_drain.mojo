"""Graceful HTTP/3 shutdown (RFC 9114 sec 5.2).

``begin_drain`` sends GOAWAY, refuses new connections, and
``drain_step`` closes each connection once its requests are answered.
The client reads the GOAWAY, finishes what is in flight, and stops
opening requests on that connection (so a pool will not reuse it).
Before, ``shutdown`` only flipped a flag and dropped everything.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.http.server import ok
from flare.http3 import Http3ClientConnection
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg)


def _client(mut server: QuicListener) raises -> QuicClientConnection:
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=10)
        _ = quic.poll(timeout_ms=10)
        if quic.is_established():
            break
    return quic^


def _pump(mut server: QuicListener, mut h3: Http3ClientConnection, n: Int):
    for _ in range(n):
        try:
            _ = server.tick(timeout_ms=2)
            _ = server.drain_all_egress()
            _ = h3.poll_responses(2)
        except:
            pass


def test_in_flight_request_finishes_then_the_connection_closes() raises:
    var server = _server()
    var h3 = Http3ClientConnection(_client(server))
    var sid = h3.request(
        "GET", "https", "localhost", "/", List[QpackHeader](), List[UInt8]()
    )
    var ready = List[Int]()
    for _ in range(40):
        _ = server.tick(timeout_ms=5)
        ready = server.take_http3_completed_streams(0)
        if len(ready) > 0:
            break
    assert_equal(len(ready), 1)
    _ = server.take_http3_request(0, ready[0])
    server.begin_drain(5_000)
    assert_false(server.drain_step(), "a request is still in flight")
    server.emit_http3_response(0, ready[0], ok("done"))
    _pump(server, h3, 20)
    assert_equal(h3.goaway_id, UInt64(4), "GOAWAY names the next stream")
    var resp = h3.take_if_complete(sid)
    assert_true(resp, "the in-flight request completed")
    assert_false(h3.is_usable(), "a GOAWAY'd connection is not reused")
    var refused = False
    try:
        _ = h3.request(
            "GET", "https", "localhost", "/", List[QpackHeader](), List[UInt8]()
        )
    except:
        refused = True
    assert_true(refused, "no new request after GOAWAY")
    assert_true(server.drain_step(), "the idle connection is closed")
    server.close()


def test_draining_server_refuses_new_connections() raises:
    var server = _server()
    server.begin_drain(5_000)
    var quic = _client(server)
    assert_false(quic.is_established())
    assert_equal(server.connection_count(), 0)
    server.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
