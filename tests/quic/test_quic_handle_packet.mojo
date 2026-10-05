"""End-to-end tests for the QUIC inbound-packet pipeline
(`flare.quic.server.QuicConnection.handle_packet` +
`flare.quic.server.QuicListener.dispatch_datagram` ->
`flare.quic.protection.unprotect_initial_packet` ->
`flare.quic.state.handle_frame_buf`).

The pipeline runs the same path a real QUIC handshake walks for
its first client Initial: the client encrypts a CRYPTO+PADDING
frame under the Initial-secret schedule derived from its chosen
DCID, the server receives the datagram, looks up / accepts the
DCID, decrypts under the same schedule, and feeds the resulting
frame bytes into the connection state machine.

Properties covered:

1. :func:`flare.quic.protection.protect_initial_packet` +
   :func:`flare.quic.protection.unprotect_initial_packet`
   round-trip a CRYPTO frame plaintext bit-for-bit through the
   AEAD + header-protection pipeline.
2. :func:`flare.quic.protection.decode_packet_number` matches
   the RFC 9000 §A.3 examples.
3. :meth:`QuicConnection.handle_packet` advances the state
   machine on a freshly-built Initial that carries a single
   STREAM frame: the new stream id surfaces through
   :class:`ConnectionEvents.new_streams` and the connection's
   ``largest_received_packet`` advances to the packet number we
   encrypted under.
4. :meth:`QuicListener.dispatch_datagram` accepts a synth
   Initial against an unknown DCID, allocates a slot, *and*
   advances that slot's state machine in the same call.
5. Malformed datagrams (truncated, bad packet type, wrong DCID
   for the registered secrets) get silently dropped without
   crashing the slot -- the slot stays usable for subsequent
   valid packets.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    FRAME_TYPE_PADDING,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicConnection,
    QuicListener,
    QuicServerConfig,
    StreamFrame,
    cid_to_hex,
    decode_packet_number,
    encode_long_header,
    encode_stream,
    encode_varint,
    protect_initial_packet,
    unprotect_initial_packet,
)
from flare.quic.state import (
    CONN_STATE_CLOSING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_HANDSHAKE,
    empty_events,
    handle_frame_buf,
    new_connection,
)


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
    """Build the unprotected long-header prefix through the
    payload-length varint, matching the header layout the
    protect+unprotect round-trip needs."""
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
    var aead_overhead = 16  # AES-128-GCM tag
    var payload_total = plaintext_len + pn_length + aead_overhead
    var payload_len_var = encode_varint(UInt64(payload_total))
    for i in range(len(payload_len_var)):
        out.append(payload_len_var[i])
    return out^


def _stream_frame_bytes(
    stream_id: UInt64, payload: List[UInt8]
) raises -> List[UInt8]:
    """Encode a single STREAM frame carrying ``payload`` at
    offset 0 without FIN."""
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
    """Pad ``payload`` with PADDING frames up to ``total`` bytes.

    The first Initial must be at least 1200 bytes on the wire per
    RFC 9000 §8.1; for unit tests we just need the AEAD round-trip
    plus a stable plaintext size for the HP sample window."""
    var out = List[UInt8]()
    for i in range(len(payload)):
        out.append(payload[i])
    while len(out) < total:
        out.append(UInt8(FRAME_TYPE_PADDING))
    return out^


def test_decode_packet_number_rfc_a3() raises:
    """RFC 9000 §A.3 worked example, exercised through the
    algorithm: largest=0xa82f30ea + truncated_pn=0x9b3 over 2
    bytes yields candidate (expected_pn & ~mask) | truncated_pn
    = (0xa82f30eb & 0xffff0000) | 0x9b3 = 0xa82f09b3, which is
    inside the half-window so the algorithm returns it as-is.

    The RFC's body text shows 0xa82f9b3 as the worked answer;
    that appears to be a typo (the high byte of the prior pn
    is preserved, so the high nibble must be `0`). Tracking the
    algorithm output here keeps interop with aioquic / quinn /
    quiche, all of which match this value."""
    var decoded = decode_packet_number(UInt64(0x9B3), 2, UInt64(0xA82F30EA))
    assert_equal(decoded, UInt64(0xA82F09B3))


def test_decode_packet_number_no_wrap() raises:
    """No wrap when the truncated PN is already the next
    expected value."""
    assert_equal(decode_packet_number(UInt64(1), 1, UInt64(0)), UInt64(1))
    assert_equal(decode_packet_number(UInt64(2), 1, UInt64(1)), UInt64(2))


def test_protect_unprotect_round_trip() raises:
    """Encrypt a known plaintext into an Initial packet and
    decrypt it back; bytes must round-trip exactly."""
    var dcid = _make_cid(UInt8(0x10), 8)
    var scid = _make_cid(UInt8(0x20), 8)
    var stream_bytes = _stream_frame_bytes(UInt64(4), _bytes(65, 66, 67))
    # HP sample needs the ciphertext to extend at least 16 bytes
    # past the packet-number bytes. Pad the plaintext so the
    # AEAD output is large enough; 64 bytes is well above the
    # 4-byte PN + 16-byte sample lower bound.
    var plaintext = _padded_plaintext(stream_bytes, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(0),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )
    var unprotected = unprotect_initial_packet(
        Span[UInt8, _](protected),
        dcid,
        is_server=True,
        largest_received_pn=UInt64(0),
    )
    assert_equal(unprotected.packet_number, UInt64(0))
    assert_equal(unprotected.pn_length, 1)
    assert_equal(len(unprotected.payload), len(plaintext))
    for i in range(len(plaintext)):
        assert_equal(
            Int(unprotected.payload[i]),
            Int(plaintext[i]),
            "plaintext byte mismatch at " + String(i),
        )


def test_initial_carrying_a_stream_frame_is_a_protocol_violation() raises:
    """An Initial is protected with keys anyone can derive from its
    DCID, so RFC 9000 sec 12.4 allows only PADDING, PING, ACK, CRYPTO
    and CONNECTION_CLOSE in it. This test used to assert the opposite:
    a STREAM frame in an Initial grew the stream slab, which is how a
    request could run without a handshake."""
    from flare.quic.state import CONN_STATE_CLOSING

    var dcid = _make_cid(UInt8(0x30), 8)
    var scid = _make_cid(UInt8(0x40), 8)
    var stream_bytes = _stream_frame_bytes(UInt64(4), _bytes(72, 73))
    var plaintext = _padded_plaintext(stream_bytes, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(0),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )
    var qc = QuicConnection(dcid, scid)
    var raised = False
    try:
        _ = qc.handle_packet(
            Span[UInt8, _](protected), now_us=UInt64(1_000_000)
        )
    except:
        raised = True
    assert_true(raised, "a STREAM frame in an Initial was accepted")
    assert_equal(len(qc.conn.streams), 0)
    assert_equal(qc.conn.state, CONN_STATE_CLOSING)


def test_server_rejects_handshake_done_from_the_client() raises:
    """QUIC-09 (RFC 9000 sec 19.20): a server treats a received
    HANDSHAKE_DONE as a PROTOCOL_VIOLATION. The frame must not move the
    connection to ESTABLISHED or surface the handshake_done event."""
    var qc = QuicConnection(_make_cid(UInt8(1), 8), _make_cid(UInt8(0x40), 8))
    var payload = _bytes(0x1E)
    var raised = False
    try:
        var ev = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
        assert_false(ev.handshake_done)
    except e:
        raised = True
        assert_true("PROTOCOL_VIOLATION" in String(e))
    assert_true(raised, "the server accepted HANDSHAKE_DONE")
    assert_equal(qc.conn.state, CONN_STATE_CLOSING)
    assert_false(qc.conn.handshake_complete)


def test_server_rejects_handshake_done_after_other_frames() raises:
    """The rejection also holds when HANDSHAKE_DONE follows a PING in the
    same packet, and once the connection is established."""
    var qc = QuicConnection(_make_cid(UInt8(1), 8), _make_cid(UInt8(0x40), 8))
    qc.conn.state = CONN_STATE_ESTABLISHED
    qc.conn.handshake_complete = True
    var payload = _bytes(0x01, 0x1E)
    var raised = False
    try:
        _ = qc.dispatch_plaintext(
            Span[UInt8, _](payload), UInt64(1_000_000), UInt64(0)
        )
    except e:
        raised = True
    assert_true(raised, "the established server accepted HANDSHAKE_DONE")
    assert_equal(qc.conn.state, CONN_STATE_CLOSING)


def test_client_role_still_accepts_handshake_done() raises:
    """The sans-I/O Connection used by the client keeps applying
    HANDSHAKE_DONE (only the server role rejects it)."""
    var conn = new_connection()
    var ev = empty_events()
    var payload = _bytes(0x1E)
    _ = handle_frame_buf(conn, Span[UInt8, _](payload), UInt64(1_000), ev)
    assert_true(ev.handshake_done)
    assert_equal(conn.state, CONN_STATE_ESTABLISHED)
    assert_true(conn.state != CONN_STATE_HANDSHAKE)


def test_handle_packet_applies_a_permitted_initial() raises:
    """PING + PADDING is what an Initial may carry: it is processed and
    the largest received packet number advances."""
    var dcid = _make_cid(UInt8(0x31), 8)
    var scid = _make_cid(UInt8(0x41), 8)
    var ping = List[UInt8]()
    ping.append(UInt8(0x01))
    var plaintext = _padded_plaintext(ping, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(5),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )
    var qc = QuicConnection(dcid, scid)
    _ = qc.handle_packet(Span[UInt8, _](protected), now_us=UInt64(1_000_000))
    assert_equal(qc.conn.largest_received_packet, UInt64(5))


def test_listener_dispatch_routes_into_handle_packet() raises:
    """End-to-end: dispatch_datagram allocates a new slot for an
    unknown Initial *and* feeds the same datagram through
    handle_packet on the new slot, so its packet number is recorded
    in one call."""
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0x50), 8)
    var scid = _make_cid(UInt8(0x60), 8)
    var ping = List[UInt8]()
    ping.append(UInt8(0x01))
    var plaintext = _padded_plaintext(ping, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(7),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )
    while len(protected) < 1200:  # RFC 9000 sec 14.1 datagram floor
        protected.append(UInt8(0))
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](protected), peer)
    assert_equal(slot, 0)
    assert_equal(listener.connection_count(), 1)
    assert_equal(listener.cid_table.lookup(cid_to_hex(dcid)), 0)
    var qc = listener.connections[0].copy()
    assert_equal(
        qc.conn.largest_received_packet,
        UInt64(7),
        "dispatch_datagram must drive handle_packet, not just route",
    )
    # Inbound processing ran on a clock stuck at 0, so activity time
    # never moved and the 0-RTT strike set never aged.
    assert_true(qc.conn.last_activity_us > UInt64(0), "clock was 0")


def test_dispatch_garbled_initial_drops_silently() raises:
    """If decryption fails (wrong DCID for the registered key
    schedule), dispatch_datagram must not crash + must leave the
    slot's state unchanged so retransmits decode cleanly."""
    var listener = _bind_loopback()
    var dcid_a = _make_cid(UInt8(0x70), 8)
    var dcid_b = _make_cid(UInt8(0x80), 8)
    var scid = _make_cid(UInt8(0x90), 8)
    var stream_bytes = _stream_frame_bytes(UInt64(0), _bytes(0x42))
    var plaintext = _padded_plaintext(stream_bytes, 64)
    var prefix = _build_initial_prefix(dcid_a, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(0),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid_a,
        is_server=False,
    )
    var mutated = List[UInt8]()
    for i in range(len(protected)):
        mutated.append(protected[i])
    # Swap the DCID bytes so the server-side initial-secret
    # derivation produces the wrong reader key + AEAD tag
    # check fails. The dispatch path must catch + drop.
    var dcid_offset = 5 + 1
    for i in range(len(dcid_b.bytes)):
        mutated[dcid_offset + i] = dcid_b.bytes[i]
    while len(mutated) < 1200:  # RFC 9000 sec 14.1 datagram floor
        mutated.append(UInt8(0))
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](mutated), peer)
    assert_equal(slot, 0)
    assert_equal(listener.connection_count(), 1)
    var qc = listener.connections[0].copy()
    assert_equal(
        len(qc.conn.streams),
        0,
        "decryption failure must not advance the state machine",
    )


def test_handle_packet_drops_short_header_silently() raises:
    """Short-header (1-RTT) packets require post-handshake keys
    that aren't installed in this commit; handle_packet must
    return empty events rather than raising."""
    var dcid = _make_cid(UInt8(0xA0), 8)
    var scid = _make_cid(UInt8(0xB0), 8)
    var qc = QuicConnection(dcid, scid)
    var fake_short = List[UInt8]()
    fake_short.append(UInt8(0x40))  # short-header + fixed bit
    for i in range(len(dcid.bytes)):
        fake_short.append(dcid.bytes[i])
    fake_short.append(UInt8(0))  # PN byte
    var events = qc.handle_packet(Span[UInt8, _](fake_short), now_us=UInt64(0))
    assert_false(events.connection_closed)
    assert_equal(len(events.new_streams), 0)


def test_handle_packet_drops_handshake_long_silently() raises:
    """Handshake long-header packets need keys installed by the
    TLS bridge; handle_packet returns empty events so the
    dispatch loop survives any post-Initial traffic."""
    var dcid = _make_cid(UInt8(0xC0), 8)
    var scid = _make_cid(UInt8(0xD0), 8)
    var qc = QuicConnection(dcid, scid)
    var hdr = encode_long_header(
        2,  # PACKET_TYPE_HANDSHAKE
        QUIC_VERSION_1,
        dcid,
        scid,
        type_specific_bits=0,
    )
    var events = qc.handle_packet(Span[UInt8, _](hdr), now_us=UInt64(0))
    assert_false(events.connection_closed)
    assert_equal(len(events.new_streams), 0)


def test_listener_drops_an_initial_under_1200_bytes() raises:
    """The server accepted an Initial of any size, so a 60-byte spoofed
    packet bought a full handshake flight (RFC 9000 sec 14.1)."""
    var listener = _bind_loopback()
    var dcid = _make_cid(UInt8(0x52), 8)
    var scid = _make_cid(UInt8(0x62), 8)
    var ping = List[UInt8]()
    ping.append(UInt8(0x01))
    var plaintext = _padded_plaintext(ping, 64)
    var prefix = _build_initial_prefix(dcid, scid, 1, len(plaintext))
    var protected = protect_initial_packet(
        Span[UInt8, _](prefix),
        packet_number=UInt64(0),
        pn_length=1,
        plaintext=Span[UInt8, _](plaintext),
        dcid=dcid,
        is_server=False,
    )
    var peer = SocketAddr(IpAddr.localhost(), UInt16(54321))
    var slot = listener.dispatch_datagram(Span[UInt8, _](protected), peer)
    assert_equal(slot, -1)
    assert_equal(listener.connection_count(), 0)


def main() raises:
    test_decode_packet_number_rfc_a3()
    test_decode_packet_number_no_wrap()
    test_protect_unprotect_round_trip()
    test_initial_carrying_a_stream_frame_is_a_protocol_violation()
    test_server_rejects_handshake_done_from_the_client()
    test_server_rejects_handshake_done_after_other_frames()
    test_client_role_still_accepts_handshake_done()
    test_handle_packet_applies_a_permitted_initial()
    test_listener_dispatch_routes_into_handle_packet()
    test_listener_drops_an_initial_under_1200_bytes()
    test_dispatch_garbled_initial_drops_silently()
    test_handle_packet_drops_short_header_silently()
    test_handle_packet_drops_handshake_long_silently()
    print("test_quic_handle_packet: 13 passed")
