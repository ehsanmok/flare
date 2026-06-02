"""Loopback integration test for the QUIC server reactor --
Track Q3-W commit 5/5.

Drives the full server-side reactor over a real loopback UDP
socket: client sends a synth Initial -> kernel routes it to the
listener -> listener accepts the new slot + drives the state
machine + arms the idle timer. The packet round-trip exercises
the seams the prior four commits in this track wired up:

1. ``QuicListener.bind`` -- real UDP bind on 127.0.0.1, kernel-
   chosen ephemeral port (commit 1/5).
2. ``QuicListener.tick`` -- ``recv_from`` -> dispatch_datagram
   (commit 1/5).
3. ``QuicConnection.handle_packet`` -- the per-packet decrypt +
   state-machine drive (commit 2/5).
4. ``QuicListener.timer_wheel`` -- idle timer arms on accept
   (commit 3/5).
5. ``QuicConnection.update_on_ack`` / ``pacing_budget`` -- the
   CC drive (commit 4/5).

The test stays inside the Mojo process: a second
:class:`UdpSocket` is opened on the same loopback interface as
the client, sends one or more synth packets, and ticks the
listener forward. A vendored ``quinn-smoke`` Rust client that
drives a real TLS handshake against the listener is part of the
benchmark baselines track (Q7-W) -- this commit covers the
``flare``-side flow that quinn-smoke will plug into.

Two packets cover the full close path:

* Accept -- one synth Initial arrives; slot 0 is allocated,
  CID is registered, idle timer is armed.
* Retransmit -- a second synth Initial with the same DCID
  arrives; ``dispatch_datagram`` routes it to slot 0 (no new
  slot), idle timer re-arms.

Idle close is tested by advancing the timer wheel past the
configured idle window and asserting the slot's ``alive`` flag
flips False + the CID is retired from the routing table.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
    StreamFrame,
    cid_to_hex,
    encode_long_header,
    encode_stream,
    encode_varint,
    protect_initial_packet,
)
from flare.udp import UdpSocket


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _bytes(*items: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in items:
        out.append(UInt8(v))
    return out^


def _build_initial_prefix(
    dcid: ConnectionId,
    scid: ConnectionId,
    pn_length: Int,
    plaintext_len: Int,
) raises -> List[UInt8]:
    var first_bits = (pn_length - 1) & 0x3
    var hdr = encode_long_header(
        PACKET_TYPE_INITIAL,
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=first_bits,
    )
    var out = List[UInt8]()
    for i in range(len(hdr)):
        out.append(hdr[i])
    var token_len_var = encode_varint(UInt64(0))
    for i in range(len(token_len_var)):
        out.append(token_len_var[i])
    var aead_overhead = 16
    var payload_total = plaintext_len + pn_length + aead_overhead
    var payload_len_var = encode_varint(UInt64(payload_total))
    for i in range(len(payload_len_var)):
        out.append(payload_len_var[i])
    return out^


def _stream_frame_bytes(
    stream_id: UInt64, payload: List[UInt8]
) raises -> List[UInt8]:
    var frame = StreamFrame(
        stream_id=stream_id,
        offset=UInt64(0),
        data=payload.copy(),
        fin=False,
    )
    var out = List[UInt8]()
    encode_stream(frame, out)
    return out^


def _padded_plaintext(payload: List[UInt8], total: Int) raises -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(payload)):
        out.append(payload[i])
    while len(out) < total:
        out.append(UInt8(FRAME_TYPE_PADDING))
    return out^


def _build_synth_initial(
    dcid: ConnectionId,
    scid: ConnectionId,
    packet_number: UInt64,
    stream_id: UInt64,
    stream_payload: List[UInt8],
) raises -> List[UInt8]:
    """Compose the full encrypted Initial datagram a real QUIC
    client would put on the wire for its first ack-eliciting
    Initial. Plaintext is one STREAM frame + PADDING up to a
    64-byte ciphertext envelope (above the HP-sample lower
    bound)."""
    var stream_bytes = _stream_frame_bytes(stream_id, stream_payload.copy())
    var plaintext = _padded_plaintext(stream_bytes, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    return protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=packet_number,
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )


def _bind_listener(idle_ms: UInt64 = UInt64(30_000)) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    return QuicListener.bind(cfg)


def test_loopback_initial_handshake_round_trip() raises:
    """A synth Initial arrives over the kernel loopback, the
    listener accepts the new slot, and the state machine
    advances within one ``tick`` call."""
    var listener = _bind_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xA1), 8)
    var scid = _make_cid(UInt8(0xB2), 8)
    var datagram = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(4), _bytes(0x48, 0x49)
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got, "listener.tick must observe the inbound datagram")
    assert_equal(listener.connection_count(), 1)
    assert_equal(listener.cid_table.lookup(cid_to_hex(dcid)), 0)
    var qc = listener.connections[0].copy()
    assert_equal(qc.conn.largest_received_packet, UInt64(0))
    assert_equal(
        len(qc.conn.streams),
        1,
        "the STREAM frame must surface into the connection's stream slab",
    )
    assert_true(qc.alive, "freshly-accepted connection must be alive")
    assert_true(
        qc.idle_timer_id != UInt64(0),
        "idle timer must be armed after the accept path",
    )
    listener.shutdown()
    listener.close()


def test_loopback_retransmit_routes_to_existing_slot() raises:
    """A second Initial with the same DCID must route to slot 0
    (no new slot allocated); idle timer re-arms."""
    var listener = _bind_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xC3), 8)
    var scid = _make_cid(UInt8(0xD4), 8)
    var first = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x41)
    )
    _ = client.send_to(Span[UInt8, _](first), server_addr)
    _ = listener.tick(500)
    var first_timer = listener.connections[0].idle_timer_id
    var retransmit = _build_synth_initial(
        dcid, scid, UInt64(1), UInt64(0), _bytes(0x42)
    )
    _ = client.send_to(Span[UInt8, _](retransmit), server_addr)
    _ = listener.tick(500)
    assert_equal(
        listener.connection_count(),
        1,
        "retransmit with same DCID must reuse slot 0",
    )
    var qc = listener.connections[0].copy()
    assert_true(
        qc.idle_timer_id != UInt64(0),
        "idle timer stays armed across retransmits",
    )
    assert_true(
        qc.idle_timer_id != first_timer,
        "idle timer re-armed on every successful packet",
    )
    listener.shutdown()
    listener.close()


def test_loopback_idle_close_retires_cid() raises:
    """A connection that sits past its idle window gets reaped:
    ``alive`` flips False, CID is retired, and the slot count
    in the table drops to zero."""
    var listener = _bind_listener(idle_ms=UInt64(100))
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0xE5), 8)
    var scid = _make_cid(UInt8(0xF6), 8)
    var datagram = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x43)
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    _ = listener.tick(500)
    assert_equal(listener.connection_count(), 1)
    # Advance the wheel past the idle window to fire the idle
    # timer + sweep the slot.
    var fired = listener.advance_timers(now_ms=UInt64(200))
    assert_true(fired >= 1, "at least the idle timer must have fired")
    var qc = listener.connections[0].copy()
    assert_false(qc.alive, "idle expiry flips alive=False")
    assert_equal(
        listener.cid_table.lookup(cid_to_hex(dcid)),
        -1,
        "closed-slot CID must be retired from the routing table",
    )
    listener.shutdown()
    listener.close()


def test_loopback_unknown_short_header_dropped() raises:
    """Short-header datagrams with no registered DCID get
    silently dropped (no stateless-reset yet -- v0.9 line
    item). The listener stays usable."""
    var listener = _bind_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    # Short-header indicator (high bit clear) + 8-byte unknown DCID.
    var datagram = List[UInt8]()
    datagram.append(UInt8(0x40))
    for i in range(8):
        datagram.append(UInt8(0x99 + i))
    for _ in range(50):
        datagram.append(UInt8(0))
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    _ = listener.tick(500)
    assert_equal(
        listener.connection_count(),
        0,
        "unknown short-header datagrams do not allocate slots",
    )
    listener.shutdown()
    listener.close()


def main() raises:
    test_loopback_initial_handshake_round_trip()
    test_loopback_retransmit_routes_to_existing_slot()
    test_loopback_idle_close_retires_cid()
    test_loopback_unknown_short_header_dropped()
    print("test_quic_loopback_integration: 4 passed")
