"""Unreliable DATAGRAM frames (RFC 9221).

They used to be accepted from any peer, whether or not
``max_datagram_frame_size`` was advertised, and neither end could send
one. Now a DATAGRAM we did not advertise, or larger than we advertised,
closes the connection with PROTOCOL_VIOLATION, and both ends exchange
datagrams once both advertise support.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.frame import DatagramFrame, encode_datagram
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import (
    CONN_STATE_CLOSING,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _frame(n: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    encode_datagram(DatagramFrame(List[UInt8](length=n, fill=7), True), out)
    return out^


def _refused(limit: UInt64, n: Int) raises -> Bool:
    var conn = new_connection()
    conn.max_datagram_recv = limit
    var events = empty_events()
    var f = _frame(n)
    try:
        _ = handle_frame_buf(conn, Span[UInt8, _](f), UInt64(0), events)
    except:
        assert_equal(conn.state, CONN_STATE_CLOSING)
        return True
    assert_equal(len(events.datagrams), 1)
    return False


def test_datagram_gated_by_advertised_size() raises:
    assert_true(_refused(0, 1), "not advertised")
    assert_true(_refused(20, 20), "frame larger than advertised")
    assert_false(_refused(20, 18), "1 type + 1 length + 18 bytes fits")


def _pair(
    server_max: UInt64, client_max: UInt64
) raises -> Tuple[QuicListener, QuicClientConnection]:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_datagram_frame_size = server_max
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var server = QuicListener.bind(cfg)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(
        server.local_addr(),
        connector,
        String("localhost"),
        max_datagram_frame_size=client_max,
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=20)
        _ = server.drain_all_egress()
        _ = quic.poll(timeout_ms=20)
        if quic.is_established():
            break
    assert_true(quic.is_established(), "handshake")
    # One more turn so the server has read the client's parameters.
    _ = server.tick(timeout_ms=20)
    return (server^, quic^)


def test_datagrams_flow_both_ways() raises:
    var p = _pair(1200, 1200)
    ref server = p[0]
    ref quic = p[1]
    for i in range(3):
        assert_true(
            quic.send_datagram(
                Span[UInt8, _](List[UInt8](length=100, fill=UInt8(i)))
            )
        )
    var got = List[List[UInt8]]()
    var deadline = _monotonic_ms() + 3_000
    while len(got) < 3 and _monotonic_ms() < deadline:
        _ = server.tick(timeout_ms=10)
        got.extend(server.take_datagrams(0))
    assert_equal(len(got), 3)
    assert_equal(got[2][99], UInt8(2))
    assert_true(
        server.send_datagram(0, Span[UInt8, _](List[UInt8](length=500, fill=9)))
    )
    assert_true(
        server.send_datagram(0, Span[UInt8, _](List[UInt8](length=500, fill=8)))
    )
    var back = 0
    deadline = _monotonic_ms() + 3_000
    while back < 2 and _monotonic_ms() < deadline:
        _ = server.drain_all_egress()
        back += len(quic.poll(timeout_ms=10).datagrams)
    assert_equal(back, 2)
    # Larger than the peer advertised: refused, nothing queued.
    assert_false(
        server.send_datagram(
            0, Span[UInt8, _](List[UInt8](length=1300, fill=1))
        )
    )
    server.close()
    quic.close()


def test_send_refused_when_peer_takes_none() raises:
    var p = _pair(0, 0)
    ref server = p[0]
    ref quic = p[1]
    assert_false(
        quic.send_datagram(Span[UInt8, _](List[UInt8](length=10, fill=1)))
    )
    assert_false(
        server.send_datagram(0, Span[UInt8, _](List[UInt8](length=10, fill=1)))
    )
    server.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
