"""The server's idle timer follows RFC 9000 sec 10.1 (QUIC-20).

* the effective timeout is the minimum of the two advertised non-zero
  values, the sole non-zero one, or none when both are 0, raised to at
  least three times the PTO;
* only a packet that decrypted and was processed restarts the timer, and
  so does the first ack-eliciting packet sent after one.

The unit tests cover :func:`_effective_idle_ms` and the accept path;
the loopback tests run a real ``QuicClientConnection`` against a
``QuicListener`` in lockstep on one thread (ephemeral ports).
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
    encode_long_header,
    encode_varint,
)
from flare.quic._server_support import _effective_idle_ms, _monotonic_ms
from flare.quic.client import QuicClientConnection
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind(idle_ms: UInt64, with_tls: Bool = False) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    if with_tls:
        cfg.rustls_config.cert_chain_pem = Path(
            _FIXDIR + "cert.pem"
        ).read_text()
        cfg.rustls_config.private_key_pem = Path(
            _FIXDIR + "key.pem"
        ).read_text()
        cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _cid(seed: UInt8) -> ConnectionId:
    var b = List[UInt8]()
    for i in range(8):
        b.append(seed + UInt8(i))
    return ConnectionId(b^)


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


def test_effective_idle_is_min_of_nonzero_values() raises:
    """RFC 9000 sec 10.1 / 18.2."""
    var pto = UInt64(10)
    assert_equal(
        Int(_effective_idle_ms(UInt64(30_000), UInt64(1_000), pto)), 1000
    )
    assert_equal(
        Int(_effective_idle_ms(UInt64(1_000), UInt64(30_000), pto)), 1000
    )
    # Only one side advertises a value: that value.
    assert_equal(Int(_effective_idle_ms(UInt64(0), UInt64(5_000), pto)), 5000)
    assert_equal(Int(_effective_idle_ms(UInt64(3_000), UInt64(0), pto)), 3000)
    # Neither: disabled.
    assert_equal(Int(_effective_idle_ms(UInt64(0), UInt64(0), pto)), 0)
    assert_equal(Int(_effective_idle_ms(UInt64(0), UInt64(0), UInt64(0))), 0)


def test_effective_idle_is_at_least_three_ptos() raises:
    assert_equal(
        Int(_effective_idle_ms(UInt64(50), UInt64(0), UInt64(250))), 750
    )
    assert_equal(
        Int(_effective_idle_ms(UInt64(50), UInt64(40), UInt64(100))), 300
    )
    assert_equal(Int(_effective_idle_ms(UInt64(0), UInt64(1), UInt64(7))), 21)


def test_no_idle_timer_when_both_sides_disable_it() raises:
    var listener = _bind(UInt64(0))
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    _ = listener.dispatch_datagram(
        Span[UInt8, _](_initial(_cid(0x10), _cid(0x20))), peer
    )
    assert_equal(listener.connection_count(), 1)
    assert_equal(
        Int(listener.connections[0].idle_timer_id),
        0,
        "max_idle_timeout 0 (and no peer value) must arm nothing",
    )


def test_undecryptable_packet_does_not_restart_idle_timer() raises:
    """A datagram that does not decrypt (anyone who knows the CID can send
    one) must not keep the connection alive (RFC 9000 sec 10.1)."""
    var listener = _bind(UInt64(30_000))
    var peer = SocketAddr(IpAddr.localhost(), UInt16(1234))
    var dcid = _cid(0x10)
    var scid = _cid(0x20)
    _ = listener.dispatch_datagram(Span[UInt8, _](_initial(dcid, scid)), peer)
    var armed = listener.connections[0].idle_timer_id
    assert_true(armed != UInt64(0))
    var again = listener.dispatch_datagram(
        Span[UInt8, _](_initial(dcid, scid)), peer
    )
    assert_equal(again, 0, "the junk Initial must reach the slot")
    assert_equal(
        Int(listener.connections[0].idle_timer_id),
        Int(armed),
        "an undecryptable packet re-armed the idle timer",
    )


def _handshake(
    mut server: QuicListener,
    connector: RustlsQuicConnector,
    client_idle_ms: UInt64,
) raises -> QuicClientConnection:
    var client = QuicClientConnection.start(
        server.local_addr(),
        connector,
        String("localhost"),
        max_idle_timeout_ms=client_idle_ms,
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


def _run_silent(mut server: QuicListener, slot: Int, ms: UInt64) raises -> Bool:
    """Tick the server for ``ms``; whether the slot closed meanwhile."""
    var start = _monotonic_ms()
    while _monotonic_ms() - start < ms:
        _ = server.tick(timeout_ms=20)
        _ = server.advance_timers(_monotonic_ms())
        if server.slot_free[slot] or not server.connections[slot].alive:
            return True
    return False


def test_peer_idle_timeout_shortens_the_server_timer() raises:
    """Client advertises 1000 ms, server 30000 ms: the server closes after
    about a second of silence, not 30 s (QUIC-20 A)."""
    var server = _bind(UInt64(30_000), with_tls=True)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _handshake(server, connector, UInt64(1_000))
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    assert_equal(Int(server.connections[slot].peer_idle_ms), 1000)
    assert_true(
        _run_silent(server, slot, UInt64(4_000)),
        "the client's 1000 ms idle timeout was ignored",
    )
    server.close()
    client.close()


def test_undecryptable_packets_do_not_keep_a_connection_open() raises:
    """QUIC-20 B: junk datagrams carrying the server's CID every 300 ms
    must not hold a 1000 ms idle timer open."""
    var server = _bind(UInt64(1_000), with_tls=True)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _handshake(server, connector, UInt64(30_000))
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    var junk = List[UInt8]()
    junk.append(UInt8(0x41))
    for i in range(len(client.dcid.bytes)):
        junk.append(client.dcid.bytes[i])
    for _ in range(30):
        junk.append(UInt8(0x5A))
    var start = _monotonic_ms()
    var last = start
    var closed = False
    while not closed and _monotonic_ms() - start < UInt64(4_000):
        if _monotonic_ms() - last >= UInt64(300):
            _ = client.sock.send_to(Span[UInt8, _](junk), client.peer)
            last = _monotonic_ms()
        _ = server.tick(timeout_ms=20)
        _ = server.advance_timers(_monotonic_ms())
        closed = server.slot_free[slot] or not server.connections[slot].alive
    assert_true(closed, "undecryptable packets kept the connection open")
    server.close()
    client.close()


def test_idle_timeout_zero_on_both_sides_never_closes() raises:
    """QUIC-20 C: max_idle_timeout 0 on both sides disables the timer; the
    old code clamped it to 1 ms and closed within a millisecond."""
    var server = _bind(UInt64(0), with_tls=True)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _handshake(server, connector, UInt64(0))
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    assert_false(_run_silent(server, slot, UInt64(1_500)), "closed idle at 0")
    server.close()
    client.close()


def test_first_ack_eliciting_send_after_receipt_restarts_timer() raises:
    """RFC 9000 sec 10.1: the timer also restarts on the first
    ack-eliciting packet sent after a packet was received, and only that
    one."""
    var server = _bind(UInt64(30_000), with_tls=True)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = _handshake(server, connector, UInt64(30_000))
    var slot = _live_slot(server)
    assert_true(slot >= 0)
    # A received, processed packet starts a new period.
    client.keepalive()
    _ = server.tick(timeout_ms=100)
    # The tick may already have sent (and so used the period's one
    # restart); start from "nothing sent since the receipt".
    server.connections[slot].idle_sent_since_rx = False
    var base = server.connections[slot].idle_timer_id
    var ping: List[UInt8] = [0x01]
    while len(ping) < 16:
        ping.append(0)  # PADDING: enough ciphertext for the HP sample
    _ = server._build_1rtt_response(slot, ping.copy(), ack_eliciting=True)
    var after_first = server.connections[slot].idle_timer_id
    assert_true(after_first != base, "first ack-eliciting send did not re-arm")
    _ = server._build_1rtt_response(slot, ping.copy(), ack_eliciting=True)
    assert_equal(
        Int(server.connections[slot].idle_timer_id),
        Int(after_first),
        "a second send in the same period must not re-arm",
    )
    # The next processed packet starts a new period.
    client.keepalive()
    _ = server.tick(timeout_ms=100)
    var after_rx = server.connections[slot].idle_timer_id
    assert_true(after_rx != after_first, "a processed packet must re-arm")
    server.close()
    client.close()


def main() raises:
    test_effective_idle_is_min_of_nonzero_values()
    test_effective_idle_is_at_least_three_ptos()
    test_no_idle_timer_when_both_sides_disable_it()
    test_undecryptable_packet_does_not_restart_idle_timer()
    test_peer_idle_timeout_shortens_the_server_timer()
    test_undecryptable_packets_do_not_keep_a_connection_open()
    test_idle_timeout_zero_on_both_sides_never_closes()
    test_first_ack_eliciting_send_after_receipt_restarts_timer()
    print("test_quic_idle_timeout: 8 passed")
