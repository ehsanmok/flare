"""A draining endpoint sends nothing (RFC 9000 sec 10.2.2; QUIC-23).

Loopback tests: a real ``QuicClientConnection`` against a ``QuicListener``
in lockstep on one thread (ephemeral ports). One side receives the other's
CONNECTION_CLOSE, which puts it in the draining state; from then on no
packet may leave it, whatever the trigger (ACK owed for a later packet, a
PING, a keep-alive, new stream data, a PTO).
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.quic.client import QuicClientConnection
from flare.quic.frame import ConnectionCloseFrame, encode_connection_close
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import CONN_STATE_DRAINING
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _established(
    mut server: QuicListener, connector: RustlsQuicConnector
) raises -> QuicClientConnection:
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(60):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    return client^


def _live_slot(server: QuicListener) -> Int:
    for i in range(len(server.connections)):
        if not server.slot_free[i]:
            return i
    return -1


def _count_rx(mut client: QuicClientConnection, wait_ms: Int) raises -> Int:
    """Datagrams that reach the client's socket within ``wait_ms``."""
    var buf = List[UInt8](length=2048, fill=UInt8(0))
    var n = 0
    client.sock.set_recv_timeout(wait_ms)
    while True:
        try:
            var got = client.sock.recv_from(Span[UInt8, _](buf))
            if got[0] <= 0:
                break
            n += 1
        except:
            break
    return n


def _send_1rtt(
    mut client: QuicClientConnection,
    var payload: List[UInt8],
    ack_eliciting: Bool,
) raises:
    while len(payload) < 16:
        payload.append(UInt8(0))
    var dg = client._build_1rtt(payload^, ack_eliciting=ack_eliciting)
    _ = client.sock.send_to(Span[UInt8, _](dg), client.peer)


def test_server_sends_nothing_after_the_peers_connection_close() raises:
    """QUIC-23: after the client's CONNECTION_CLOSE the server is DRAINING
    and answers neither later ack-eliciting packets nor timers."""
    var server = _bind()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _established(server, connector)
    var slot = _live_slot(server)
    assert_true(slot >= 0)

    # Control: an ack-eliciting packet in the established state is
    # acknowledged by the server.
    _send_1rtt(client, [UInt8(0x01)], True)
    _ = client.sock.set_recv_timeout(20)
    var before_pn = server.connections[slot].tx_1rtt_pn
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
    assert_true(
        server.connections[slot].tx_1rtt_pn > before_pn,
        "control: the established server must acknowledge a PING",
    )
    _ = _count_rx(client, 50)

    var cc = List[UInt8]()
    encode_connection_close(
        ConnectionCloseFrame(False, UInt64(0), UInt64(0), List[UInt8]()), cc
    )
    _send_1rtt(client, cc^, False)
    for _ in range(4):
        _ = server.tick(timeout_ms=30)
    assert_equal(server.connections[slot].conn.state, CONN_STATE_DRAINING)
    _ = _count_rx(client, 50)

    var pn = server.connections[slot].tx_1rtt_pn
    # More ack-eliciting packets from the (still sending) client, then
    # the delayed-ACK path driven directly.
    for _ in range(3):
        _send_1rtt(client, [UInt8(0x01)], True)
        _ = server.tick(timeout_ms=30)
    var peer = server.peer_addrs[slot]
    _ = server._drain_1rtt_coalesced(slot, peer)
    assert_equal(
        server.connections[slot].tx_1rtt_pn,
        pn,
        "the draining server built a packet",
    )
    assert_equal(
        _count_rx(client, 100),
        0,
        "a datagram reached the client while DRAINING",
    )
    server.close()
    client.close()


def main() raises:
    test_server_sends_nothing_after_the_peers_connection_close()
    print("test_quic_draining: 1 passed")
