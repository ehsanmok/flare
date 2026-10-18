"""ECN (RFC 9000 sec 13.4, RFC 9002 sec 7.1).

flare never read or reported ECN codepoints, so a client that marks
ECT(0) saw its ECN validation fail and lost the congestion signal, and
the server could not use ECN itself. Now the server counts the marks it
receives and reports them in ACK_ECN; with ``QuicServerConfig.ecn`` it
marks ECT(0), validates the client's counts, and a CE report is a
congestion event.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_false, assert_true

from flare.net import SocketAddr
from flare.quic._ecn import EcnValidator
from flare.quic.client import QuicClientConnection
from flare.quic.frame import EcnCounts
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector
from flare.udp import UdpSocket
from flare.udp.batch import BatchReceiver, send_segmented


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def test_batch_receiver_reads_the_codepoint() raises:
    var rx = UdpSocket.bind(SocketAddr.localhost(0))
    rx.set_ecn(0)
    rx.set_recv_timeout(1000)
    var tx = UdpSocket.bind(SocketAddr.localhost(0))
    var batch = BatchReceiver(capacity=4, max_payload=64)
    for cp in [2, 3, 0]:
        tx.set_ecn(cp)
        _ = tx.send_to("x".as_bytes(), rx.local_addr())
        assert_equal(batch.recv(rx.fd(), wait=True), 1)
        assert_equal(batch.ecn(0), cp)
    # Per packet, whatever the socket's own setting (now 0).
    _ = send_segmented(tx.fd(), rx.local_addr(), "x".as_bytes(), 0, 1)
    assert_equal(batch.recv(rx.fd(), wait=True), 1)
    assert_equal(batch.ecn(0), 1)
    _ = tx^
    _ = rx^


def _counts(ect0: UInt64, ect1: UInt64, ce: UInt64) -> List[EcnCounts]:
    var c = List[EcnCounts]()
    c.append(EcnCounts(ect0=ect0, ect1=ect1, ce=ce))
    return c^


def test_validator() raises:
    var v = EcnValidator()
    assert_false(v.on_ack(2, _counts(2, 0, 0)))
    assert_true(v.on_ack(2, _counts(3, 0, 1)), "new CE: congestion")
    assert_false(v.on_ack(0, List[EcnCounts]()), "a reordered ACK is skipped")
    assert_true(v.ok)
    var short = v.copy()
    assert_false(short.on_ack(3, _counts(4, 0, 2)))
    assert_false(short.ok, "counts grew by 2 for 3 newly acked packets")
    var none = v.copy()
    _ = none.on_ack(1, List[EcnCounts]())
    assert_false(none.ok, "ACK without counts")
    var ect1 = v.copy()
    _ = ect1.on_ack(1, _counts(4, 1, 1))
    assert_false(ect1.ok, "ECT(1) we never sent")


def _pair(ecn: Bool) raises -> Tuple[QuicListener, QuicClientConnection]:
    var alpn = List[String]()
    alpn.append(String("h3"))
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.ecn = ecn
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = alpn.copy()
    var listener = QuicListener.bind(cfg^)
    var quic = QuicClientConnection.start(
        listener.local_addr(),
        RustlsQuicConnector(Path(_FIXDIR + "ca.pem").read_text(), alpn^),
        String("localhost"),
    )
    quic.sock.set_ecn(3)  # every client packet arrives marked CE
    return (listener^, quic^)


def test_server_reports_the_marks_it_receives() raises:
    var p = _pair(False)
    ref listener = p[0]
    ref quic = p[1]
    var reported = UInt64(0)
    for _ in range(60):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        var ev = quic.poll(timeout_ms=10)
        for i in range(len(ev.ack_ecn)):
            reported = max(reported, ev.ack_ecn[i].ce)
        if quic.is_established() and reported > 0:
            break
    assert_true(listener.connections[0].ecn_rx[2] > 0)
    assert_true(reported > 0, "the client saw its CE marks in ACK_ECN")
    listener.close()
    quic.close()


def test_marking_stops_when_the_peer_reports_no_counts() raises:
    var p = _pair(True)
    ref listener = p[0]
    ref quic = p[1]
    var marked = False
    for _ in range(60):
        _ = listener.tick(timeout_ms=10)
        _ = listener.drain_all_egress()
        _ = quic.poll(timeout_ms=10)
        if listener.connection_count() == 0:
            continue
        marked = marked or listener.connections[0].ecn_mark
        if quic.is_established() and not listener.connections[0].ecn_mark:
            break
    assert_true(marked, "a connection starts out marking")
    # The peer sends plain ACKs: validation fails, this connection stops.
    assert_false(listener.connections[0].ecn_mark)
    listener.close()
    quic.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
