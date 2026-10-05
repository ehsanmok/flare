"""The server's close sends CONNECTION_CLOSE and keeps a closing period
(RFC 9000 sec 10.2, 10.2.1, 11.1; QUIC-22).

Loopback tests: a real ``QuicClientConnection`` against a ``QuicListener``
in lockstep on one thread (ephemeral ports). The server closes the
connection through ``_close_for`` -- the path every connection error it
detects takes -- and the client must receive the CONNECTION_CLOSE with
the error code; packets arriving afterwards are answered with
CONNECTION_CLOSE, and the slot is reclaimed only after three PTOs.
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
    TIMER_KIND_PTO,
    encode_long_header,
    encode_timer_token,
    encode_varint,
)
from flare.quic._server_support import _monotonic_ms
from flare.quic.client import QuicClientConnection
from flare.quic.state import CONN_STATE_CLOSED
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind(with_tls: Bool = True) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    if with_tls:
        cfg.rustls_config.cert_chain_pem = Path(
            _FIXDIR + "cert.pem"
        ).read_text()
        cfg.rustls_config.private_key_pem = Path(
            _FIXDIR + "key.pem"
        ).read_text()
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


def _poll_close(mut client: QuicClientConnection) raises -> Bool:
    """Whether the next poll reports a CONNECTION_CLOSE; fills ``code``."""
    var ev = client.poll(timeout_ms=100)
    return ev.connection_closed


def _send_ping(mut client: QuicClientConnection) raises:
    """A 1-RTT PING straight onto the socket (no client-side guards)."""
    var payload: List[UInt8] = [0x01]
    while len(payload) < 16:
        payload.append(0)
    var dg = client._build_1rtt(payload^, ack_eliciting=True)
    _ = client.sock.send_to(Span[UInt8, _](dg), client.peer)


def test_close_reaches_the_client_as_connection_close() raises:
    """Every connection error the server detects ends with silence: the
    client learned nothing and sent on until its own idle timeout."""
    var server = _bind()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _established(server, connector)
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    server._close_for(slot, UInt64(0x05), String("stream id"))
    assert_false(server.connections[slot].alive)
    var ev = client.poll(timeout_ms=200)
    assert_true(ev.connection_closed, "no CONNECTION_CLOSE reached the client")
    assert_equal(Int(ev.error_code), 5)
    server.close()
    client.close()


def test_closing_state_answers_packets_and_lasts_three_ptos() raises:
    """RFC 9000 sec 10.2.1: in the closing state an endpoint answers
    incoming packets with CONNECTION_CLOSE; sec 10.2: the state lasts at
    least three PTOs, so the slot is not reclaimed by the next timer."""
    var server = _bind()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _established(server, connector)
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    server._close_for(slot, UInt64(0x05), String("stream id"))
    assert_true(client.poll(timeout_ms=200).connection_closed)
    # A packet from the peer is answered with CONNECTION_CLOSE again.
    _send_ping(client)
    _ = server.tick(timeout_ms=200)
    assert_true(
        client.poll(timeout_ms=200).connection_closed,
        "a packet in the closing state was not answered",
    )
    # A PTO or ACK-delay timer of the slot firing now must not end the
    # closing state (it used to reclaim the slot at once).
    _ = server.timer_wheel.schedule(
        after_ms=1, token=encode_timer_token(TIMER_KIND_PTO, slot)
    )
    _ = server.advance_timers(_monotonic_ms() + UInt64(100))
    assert_false(server.slot_free[slot], "closing ended before 3 PTOs")
    # Past the closing period the slot is reclaimed.
    _ = server.advance_timers(_monotonic_ms() + UInt64(20_000))
    assert_true(server.slot_free[slot], "closing slot never reclaimed")
    server.close()
    client.close()


def test_connection_close_answers_are_rate_limited() raises:
    """RFC 9000 sec 10.2.1: the closing endpoint limits the CONNECTION_CLOSE
    packets it sends; here the 1st, 2nd and 4th incoming packets are
    answered, not the 3rd."""
    var server = _bind()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _established(server, connector)
    var slot = _live_slot(server)
    server._close_for(slot, UInt64(0x05), String("stream id"))
    assert_true(client.poll(timeout_ms=200).connection_closed)
    var answered = List[Bool]()
    for _ in range(4):
        _send_ping(client)
        _ = server.tick(timeout_ms=200)
        answered.append(client.poll(timeout_ms=100).connection_closed)
    assert_true(answered[0] and answered[1])
    assert_false(answered[2], "the 3rd packet must not be answered")
    assert_true(answered[3])
    server.close()
    client.close()


def _initial(dcid: ConnectionId, scid: ConnectionId) raises -> List[UInt8]:
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid, type_specific_bits=0
    )
    var out = List[UInt8]()
    for i in range(len(hdr)):
        out.append(hdr[i])
    var token_len = encode_varint(UInt64(0))
    for i in range(len(token_len)):
        out.append(token_len[i])
    var payload_len = encode_varint(UInt64(1))
    for i in range(len(payload_len)):
        out.append(payload_len[i])
    out.append(UInt8(0))
    while len(out) < 1200:
        out.append(UInt8(0))
    return out^


def test_close_before_1rtt_keys_sends_nothing_and_does_not_linger() raises:
    """Without 1-RTT keys there is no packet to send a CONNECTION_CLOSE in:
    the slot is closed as before and reclaimed by its next timer."""
    var server = _bind(with_tls=False)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    var b = List[UInt8]()
    for i in range(8):
        b.append(UInt8(0x10 + i))
    var dcid = ConnectionId(b.copy())
    var scid = ConnectionId(b^)
    _ = server.dispatch_datagram(Span[UInt8, _](_initial(dcid, scid)), peer)
    assert_equal(server.connection_count(), 1)
    server._close_for(0, UInt64(0x0A), String("early"))
    assert_false(server.connections[0].alive)
    assert_false(server.connections[0].closing)
    # Its idle timer (30 s) is the next timer of the slot.
    _ = server.advance_timers(_monotonic_ms() + UInt64(40_000))
    assert_true(server.slot_free[0])
    server.close()


def main() raises:
    test_close_reaches_the_client_as_connection_close()
    test_closing_state_answers_packets_and_lasts_three_ptos()
    test_connection_close_answers_are_rate_limited()
    test_close_before_1rtt_keys_sends_nothing_and_does_not_linger()
    print("test_quic_server_close: 4 passed")
