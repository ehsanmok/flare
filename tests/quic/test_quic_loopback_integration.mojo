"""Loopback integration test for the QUIC server reactor,
extended with the egress + I/O-loop close cases.

Drives the full server-side reactor over a real loopback UDP
socket: client sends a synth Initial -> kernel routes it to the
listener -> listener accepts the new slot + drives the state
machine + arms the idle timer. The packet round-trip exercises
the seams wired up across the reactor:

1. ``QuicListener.bind`` -- real UDP bind on 127.0.0.1, kernel-
   chosen ephemeral port.
2. ``QuicListener.tick`` -- ``recv_from`` -> dispatch_datagram.
3. ``QuicConnection.handle_packet`` -- the per-packet decrypt +
   state-machine drive.
4. ``QuicListener.timer_wheel`` -- idle timer arms on accept.
5. Egress path:
   - ``QuicListener.send_to`` thin wrapper around
     ``UdpSocket.send_to``.
   - ``QuicListener._build_initial_response(slot)`` builds a
     server-side Initial packet from ``tls_egress_queues[slot]``
     using ``protect_initial_packet`` with the server-side
     Initial secret derived from ``local_cid``.
   - ``QuicListener._drain_and_send(slot)`` flushes the queue
     and emits one datagram.
   - ``QuicListener.drain_all_egress()`` sweeps every slot.
   - ``QuicListener.tick(timeout)`` runs the full
     ``recv -> dispatch -> handle -> drain -> protect ->
     sendto`` cycle on every tick.

The test stays inside the Mojo process: a second
:class:`UdpSocket` is opened on the same loopback interface as
the client, sends one or more synth packets + receives the
server's protected Initial response and verifies it decrypts
back to the originally-injected CRYPTO bytes.

Two packets cover the close path:

* Accept -- one synth Initial arrives; slot 0 is allocated,
  CID is registered, idle timer is armed.
* Retransmit -- a second synth Initial with the same DCID
  arrives; ``dispatch_datagram`` routes it to slot 0 (no new
  slot), idle timer re-arms.

Idle close is tested by advancing the timer wheel past the
configured idle window and asserting the slot's ``alive`` flag
flips False + the CID is retired from the routing table.
"""

from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    LongHeader,
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
    unprotect_initial_packet,
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


def test_loopback_unknown_short_header_stateless_reset() raises:
    """A short-header datagram with no registered DCID gets a
    stateless reset (RFC 9000 sec 10.3) rather than a silent drop:
    no slot is allocated, and the client receives a datagram whose
    trailing 16 bytes are the reset token derived from the DCID."""
    var listener = _bind_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    # Short-header indicator (high bit clear) + 8-byte unknown DCID.
    var dcid = _make_cid(UInt8(0x99), 8)
    var datagram = List[UInt8]()
    datagram.append(UInt8(0x40))
    for i in range(8):
        datagram.append(dcid.bytes[i])
    for _ in range(50):
        datagram.append(UInt8(0))
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    _ = listener.tick(500)
    assert_equal(
        listener.connection_count(),
        0,
        "unknown short-header datagrams do not allocate slots",
    )
    # The server should have sent a stateless reset back to us.
    client.set_recv_timeout(500)
    var buf = List[UInt8](capacity=128)
    for _ in range(128):
        buf.append(UInt8(0))
    var pair = client.recv_from(Span[UInt8, _](buf))
    var n = pair[0]
    assert_true(n >= 21, "stateless reset must be at least 21 bytes")
    assert_true(
        n < len(datagram), "reset must be shorter than the trigger (no loop)"
    )
    assert_equal(Int(buf[0]) & 0xC0, 0x40, "reset wears a short-header shape")
    var expected = listener._stateless_reset_token(dcid)
    for i in range(16):
        assert_equal(
            Int(buf[n - 16 + i]),
            Int(expected[i]),
            "reset token must be HMAC(reset_key, dcid)[:16]",
        )
    listener.shutdown()
    listener.close()


# -- Egress + UDP I/O loop close cases --------------------


def test_egress_build_initial_response_decrypts_at_client() raises:
    """``_build_initial_response(slot)`` produces an Initial
    packet that decrypts back at the client side using the
    server's initial-secret writer direction.

    Injects synthetic outbound bytes into ``tls_egress_queues``
    on an existing slot, calls ``_build_initial_response``, and
    feeds the result through ``unprotect_initial_packet`` with
    ``is_server=False`` (the client reader role). The recovered
    CRYPTO frame's data field must contain the originally-
    injected bytes byte-for-byte.
    """
    var listener = _bind_listener()
    var dcid = _make_cid(UInt8(0xAA), 8)
    var scid = _make_cid(UInt8(0xBB), 8)
    var first = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x10)
    )
    # Run the accept path inline (no UDP socket) so the
    # listener materializes slot 0 with a peer address.
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    _ = listener.dispatch_datagram(Span[UInt8, _](first), peer)
    assert_equal(listener.connection_count(), 1)
    # Inject server-side outbound CRYPTO bytes (synthetic
    # ServerHello + EncryptedExtensions placeholder).
    var injected = List[UInt8]()
    for i in range(48):
        injected.append(UInt8(0xA0 + (i % 16)))
    listener.tls_egress_queues[0] = injected.copy()
    var datagram = listener._build_initial_response(0)
    assert_true(
        len(datagram) > 0,
        "_build_initial_response must produce a non-empty datagram",
    )
    # The receiver (client perspective) recovers the plaintext
    # using the same DCID-derived schedule. The recovered
    # CRYPTO frame is the first frame in the plaintext.
    var up = unprotect_initial_packet(
        Span[UInt8, _](datagram),
        dcid=dcid,
        is_server=False,
        largest_received_pn=UInt64(0),
    )
    # Plaintext layout: frame-type byte (CRYPTO == 0x06) +
    # offset varint + length varint + the injected bytes.
    assert_equal(Int(up.payload[0]), 0x06)
    # Offset varint at index 1 should encode 0.
    assert_equal(Int(up.payload[1]), 0x00)
    # Length varint at index 2 (since offset=0 is 1 byte): the
    # first byte's two MSBs select varint length, low 6 bits +
    # any extension bytes encode the value. For length 48 the
    # encoding is 1 byte (< 64) so byte 2 carries the length
    # directly.
    assert_equal(Int(up.payload[2]), 48)
    # CRYPTO frame data follows immediately after.
    for i in range(48):
        assert_equal(Int(up.payload[3 + i]), Int(injected[i]))
    listener.shutdown()
    listener.close()


def test_egress_drain_clears_queue_and_advances_counters() raises:
    """A single :meth:`_drain_and_send` flushes
    ``tls_egress_queues[slot]`` and bumps the slot's
    ``tx_initial_pn`` + ``tx_initial_offset`` so the next call
    emits a fresh pn at the new offset."""
    var listener = _bind_listener()
    var dcid = _make_cid(UInt8(0xCC), 8)
    var scid = _make_cid(UInt8(0xDD), 8)
    var first = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x11)
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    _ = listener.dispatch_datagram(Span[UInt8, _](first), peer)
    listener.tls_egress_queues[0] = List[UInt8]()
    for i in range(24):
        listener.tls_egress_queues[0].append(UInt8(i))
    # The drain path uses send_to which requires the peer to be
    # reachable. We use a UDP socket bound to localhost so the
    # send succeeds without bouncing through the listener's own
    # socket recv-from loop (the drain just emits, recv is the
    # caller's job).
    var sink = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    listener.peer_addrs[0] = sink.local_addr()
    var emitted = listener._drain_and_send(0)
    assert_true(
        emitted,
        "_drain_and_send must return True after flushing a non-empty queue",
    )
    assert_equal(
        len(listener.tls_egress_queues[0]),
        0,
        "egress queue must be cleared after a successful flush",
    )
    assert_equal(
        listener.connections[0].tx_initial_pn,
        UInt64(1),
        "tx_initial_pn advances by one on each successful emit",
    )
    assert_equal(
        listener.connections[0].tx_initial_offset,
        UInt64(24),
        "tx_initial_offset advances by the CRYPTO byte count",
    )
    # The peer (sink) actually received the protected datagram.
    var recv_buf = List[UInt8]()
    recv_buf.resize(1200, 0)
    sink.set_recv_timeout(500)
    var pair = sink.recv_from(Span[UInt8, _](recv_buf))
    var got = pair[0]
    assert_true(
        got > 0,
        "sink must observe the server-emitted Initial datagram",
    )
    listener.shutdown()
    listener.close()


def test_egress_no_op_when_queue_empty() raises:
    """``_drain_and_send`` is a clean no-op when nothing is
    pending: returns False without raising and without
    incrementing pn / offset."""
    var listener = _bind_listener()
    var dcid = _make_cid(UInt8(0xEE), 8)
    var scid = _make_cid(UInt8(0xFF), 8)
    var first = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x12)
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    _ = listener.dispatch_datagram(Span[UInt8, _](first), peer)
    var emitted = listener._drain_and_send(0)
    assert_false(emitted, "no-op drain returns False")
    assert_equal(
        listener.connections[0].tx_initial_pn,
        UInt64(0),
        "no-op drain must not advance pn",
    )
    assert_equal(
        listener.connections[0].tx_initial_offset,
        UInt64(0),
        "no-op drain must not advance offset",
    )
    listener.shutdown()
    listener.close()


def test_io_loop_tick_drives_recv_dispatch_drain() raises:
    """One full ``tick`` cycle runs recv -> dispatch -> drain.

    Pre-injects bytes into the egress queue then sends a
    second Initial from a fresh client socket. The tick call
    receives the datagram, dispatches it (re-arming the idle
    timer), and drains the queue -- the client socket then
    observes the server's protected Initial response.
    """
    var listener = _bind_listener()
    var server_addr = listener.local_addr()
    var client = UdpSocket.bind(SocketAddr(IpAddr.localhost(), UInt16(0)))
    var dcid = _make_cid(UInt8(0x33), 8)
    var scid = _make_cid(UInt8(0x44), 8)
    var datagram = _build_synth_initial(
        dcid, scid, UInt64(0), UInt64(0), _bytes(0x55)
    )
    _ = client.send_to(Span[UInt8, _](datagram), server_addr)
    var got = listener.tick(500)
    assert_true(got, "first tick observes the inbound Initial")
    # Now stage outbound bytes + send a second Initial; the
    # second tick should drain.
    listener.tls_egress_queues[0] = List[UInt8]()
    for i in range(16):
        listener.tls_egress_queues[0].append(UInt8(0xC0 + (i % 16)))
    listener.peer_addrs[0] = client.local_addr()
    var retransmit = _build_synth_initial(
        dcid, scid, UInt64(1), UInt64(0), _bytes(0x56)
    )
    _ = client.send_to(Span[UInt8, _](retransmit), server_addr)
    _ = listener.tick(500)
    assert_equal(
        len(listener.tls_egress_queues[0]),
        0,
        "tick must drain the egress queue as part of the I/O loop",
    )
    # The client receives the protected Initial response.
    client.set_recv_timeout(500)
    var rbuf = List[UInt8]()
    rbuf.resize(1500, 0)
    var pair = client.recv_from(Span[UInt8, _](rbuf))
    var rgot = pair[0]
    assert_true(
        rgot > 0,
        "client must observe the server-emitted Initial",
    )
    listener.shutdown()
    listener.close()


def main() raises:
    test_loopback_initial_handshake_round_trip()
    test_loopback_retransmit_routes_to_existing_slot()
    test_loopback_idle_close_retires_cid()
    test_loopback_unknown_short_header_stateless_reset()
    test_egress_build_initial_response_decrypts_at_client()
    test_egress_drain_clears_queue_and_advances_counters()
    test_egress_no_op_when_queue_empty()
    test_io_loop_tick_drives_recv_dispatch_drain()
    print("test_quic_loopback_integration: 8 passed")
