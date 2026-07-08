"""Integration tests for the QUIC server reactor
(``flare.quic.server.QuicListener``).

The dispatch loop wires `QuicListener.bind` (UDP socket open +
bind via :class:`flare.udp.UdpSocket`) to a per-datagram
dispatcher that routes by Destination Connection ID. Follow-up
work threads the per-packet decrypt + state-machine dispatch
through ``QuicConnection.handle_packet``, wires the PTO / idle /
ack-delay TimerWheel entries, and drives the CC reactor hooks.

Properties covered here:

1. :meth:`QuicListener.bind` opens a real UDP socket on
   ``127.0.0.1:0`` and reports the kernel-chosen port back via
   :meth:`local_addr`.
2. :meth:`QuicListener.tick` returns ``False`` cleanly when no
   datagram arrives within the timeout (so the event loop can
   poll the stop flag without spinning the CPU).
3. :meth:`QuicListener.dispatch_datagram` allocates a new slot
   when it sees an Initial packet for an unknown DCID, registers
   the DCID in the routing table, and returns the slot index.
4. A second Initial packet for the same DCID routes to the same
   slot (the accept-handshake stays put across retransmits).
5. A short-header packet with an unknown DCID drops cleanly
   (returns -1; the stateless-reset path lands later).
6. A short-header packet with a known DCID routes to the right
   slot.
7. :meth:`QuicListener.shutdown` flips the stop flag so
   :meth:`run` exits cleanly.
8. Live UDP loopback: send an Initial packet from a peer socket,
   :meth:`tick` receives + dispatches it, the connection slab
   grows.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
    cid_to_hex,
    encode_long_header,
    encode_short_header,
    encode_varint,
)
from flare.udp import UdpSocket


def _bind_loopback() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    return QuicListener.bind(cfg)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _make_initial_datagram(
    dcid: ConnectionId, scid: ConnectionId
) raises -> List[UInt8]:
    """Build the smallest valid Initial-packet prefix: long header +
    empty token (varint 0) + payload-length varint of 1 + a single
    payload byte. The dispatch layer only inspects the public
    header, so the payload byte is a no-op."""
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=0,
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
    return out^


def _make_handshake_datagram(
    dcid: ConnectionId, scid: ConnectionId
) raises -> List[UInt8]:
    """Build a Handshake long-header packet -- used to test that
    the dispatch loop drops Handshake packets with unknown DCIDs
    rather than accepting them (only Initials open new
    connections)."""
    var hdr = encode_long_header(
        PACKET_TYPE_HANDSHAKE,
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=0,
    )
    return hdr^


def _make_short_datagram(dcid: ConnectionId) raises -> List[UInt8]:
    """Build a short-header packet for the given DCID. The
    dispatch layer only inspects the public header plus the DCID;
    the rest of the bytes are filler the per-packet decrypt path
    will consume."""
    var prefix = encode_short_header(
        dcid, spin_bit=False, key_phase=False, pn_length=1
    )
    var out = List[UInt8]()
    for i in range(len(prefix)):
        out.append(prefix[i])
    for _ in range(4):
        out.append(UInt8(0))
    return out^


def test_bind_opens_real_udp_socket() raises:
    var listener = _bind_loopback()
    assert_true(listener.bound())
    var addr = listener.local_addr()
    assert_true(addr.port != UInt16(0), "kernel must assign ephemeral port")
    assert_equal(listener.connection_count(), 0)


def test_bind_honors_explicit_port_zero() raises:
    """Two listeners on port 0 land on different kernel-chosen
    ports without colliding."""
    var a = _bind_loopback()
    var b = _bind_loopback()
    assert_true(a.local_addr().port != UInt16(0))
    assert_true(b.local_addr().port != UInt16(0))
    assert_true(
        a.local_addr().port != b.local_addr().port,
        "two ephemeral ports should not collide",
    )


def test_tick_returns_false_on_timeout() raises:
    var listener = _bind_loopback()
    var got = listener.tick(timeout_ms=10)
    assert_false(got, "tick must return False when nothing arrives")


def test_shutdown_makes_run_exit() raises:
    var listener = _bind_loopback()
    listener.shutdown()
    listener.run()
    assert_true(True, "run must exit cleanly after shutdown")


def test_dispatch_initial_creates_new_slot() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0xA0), 8)
    var scid = _make_cid(UInt8(0xB0), 8)
    var datagram = _make_initial_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_equal(slot, 0)
    assert_equal(listener.connection_count(), 1)
    assert_equal(len(listener.cid_table), 1)
    assert_equal(listener.cid_table.lookup(cid_to_hex(dcid)), 0)


def test_dispatch_initial_retransmit_routes_to_same_slot() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0xA0), 8)
    var scid = _make_cid(UInt8(0xB0), 8)
    var datagram = _make_initial_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot1 = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    var slot2 = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_equal(slot1, 0)
    assert_equal(slot2, 0)
    assert_equal(
        listener.connection_count(),
        1,
        "retransmit must not allocate a second slot",
    )


def test_dispatch_handshake_with_unknown_dcid_drops() raises:
    """Only Initial packets open new connections; Handshake
    packets with an unknown DCID are silently dropped (the
    handshake state for them never existed -- they're routed via
    the server-chosen SCID after the first Initial completes)."""
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0xC0), 8)
    var scid = _make_cid(UInt8(0xD0), 8)
    var datagram = _make_handshake_datagram(dcid, scid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_equal(slot, -1)
    assert_equal(listener.connection_count(), 0)


def test_dispatch_short_unknown_dcid_drops() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0x10), 8)
    var datagram = _make_short_datagram(dcid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_equal(slot, -1)
    assert_equal(listener.connection_count(), 0)


def test_dispatch_short_known_dcid_routes() raises:
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0x20), 8)
    listener.cid_table.register(cid_to_hex(dcid), 42)
    var datagram = _make_short_datagram(dcid)
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](datagram), peer)
    assert_equal(
        slot, 42, "short-header packet must route to its registered slot"
    )


def test_dispatch_empty_datagram_drops() raises:
    var listener = _bind_loopback()
    var empty = List[UInt8]()
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](empty), peer)
    assert_equal(slot, -1)


def test_live_loopback_tick_routes_initial() raises:
    """End-to-end: open the listener, send an Initial datagram
    from a peer UDP socket, drain it via :meth:`tick`, and assert
    the connection slab grew by 1."""
    var listener = _bind_loopback()
    var listener_addr = listener.local_addr()

    var dcid = _make_cid(UInt8(0xE0), 8)
    var scid = _make_cid(UInt8(0xF0), 8)
    var datagram = _make_initial_datagram(dcid, scid)

    var sender = UdpSocket.unbound()
    var sent = sender.send_to(Span[UInt8, _](datagram), listener_addr)
    assert_equal(sent, len(datagram))

    var got = listener.tick(timeout_ms=500)
    assert_true(got, "listener must drain the inbound Initial datagram")
    assert_equal(listener.connection_count(), 1)
    assert_equal(listener.cid_table.lookup(cid_to_hex(dcid)), 0)


def test_cid_to_hex_round_trip() raises:
    var cid = _make_cid(UInt8(0x10), 4)
    var hex = cid_to_hex(cid)
    assert_equal(hex, String("10111213"))


def main() raises:
    test_bind_opens_real_udp_socket()
    test_bind_honors_explicit_port_zero()
    test_tick_returns_false_on_timeout()
    test_shutdown_makes_run_exit()
    test_dispatch_initial_creates_new_slot()
    test_dispatch_initial_retransmit_routes_to_same_slot()
    test_dispatch_handshake_with_unknown_dcid_drops()
    test_dispatch_short_unknown_dcid_drops()
    test_dispatch_short_known_dcid_routes()
    test_dispatch_empty_datagram_drops()
    test_live_loopback_tick_routes_initial()
    test_cid_to_hex_round_trip()
    print("test_quic_reactor: 12 passed")
