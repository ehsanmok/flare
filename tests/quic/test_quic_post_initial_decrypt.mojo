"""Structural gating + bounds tests for the post-Initial inbound
decrypt path on QuicListener.

Covers :meth:`QuicListener._decrypt_post_initial` and the
level-branching in :meth:`QuicListener._handle_inbound`:

* out-of-range slot raises (caller drops).
* a datagram too short for the HP sample window raises rather
  than reading out of bounds.
* a Handshake / 1-RTT datagram for a slot whose readiness
  sentinel is not installed drops silently (no raise, no crash,
  connection stays alive).

The full "decrypts a packet a real QUIC client sent" path needs
a live handshake (rustls only hands real keys after KeyChange);
that is the bench gate's job. These tests pin the gating + bounds
discipline that keeps the silent-drop contract honest.
"""

from std.collections import List
from std.pathlib import Path
from std.testing import assert_equal, assert_false, assert_true

from flare.net import IpAddr, SocketAddr
from flare.quic import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    QuicListener,
    QuicServerConfig,
    encode_long_header,
    encode_varint,
)
from flare.tls import QuicEncryptionLevel, RustlsQuicConfig
from flare.quic.server import _ack_record, _ack_from_ranges
from flare.quic._server_support import _ACK_MAX_RANGES, _ack_contains


def _load_fixture_pem() raises -> Tuple[String, String]:
    var cert = Path(
        String("tests/tls/fixtures/rustls-quic-cert/cert.pem")
    ).read_text()
    var key = Path(
        String("tests/tls/fixtures/rustls-quic-cert/key.pem")
    ).read_text()
    return (cert^, key^)


def _make_h3_config() raises -> RustlsQuicConfig:
    var cert_pem: String
    var key_pem: String
    cert_pem, key_pem = _load_fixture_pem()
    var cfg = RustlsQuicConfig()
    cfg.cert_chain_pem = cert_pem^
    cfg.private_key_pem = key_pem^
    cfg.alpn_protocols = List[String]()
    cfg.alpn_protocols.append(String("h3"))
    return cfg^


def _bind_real_pem() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = UInt64(30_000)
    cfg.rustls_config = _make_h3_config()
    return QuicListener.bind(cfg)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _synth_long_header(slot_seed: UInt8) -> LongHeader:
    return LongHeader(
        packet_type=PACKET_TYPE_INITIAL,
        version=QUIC_VERSION_1,
        dcid=_make_cid(UInt8(0x80) + slot_seed, 8),
        scid=_make_cid(UInt8(0xA0) + slot_seed, 8),
        payload_offset=0,
    )


def test_decrypt_post_initial_raises_slot_out_of_range() raises:
    var listener = _bind_real_pem()
    var dg = List[UInt8]()
    for i in range(64):
        dg.append(UInt8(i))
    var raised_neg = False
    try:
        _ = listener._decrypt_post_initial(
            -1, Span[UInt8, _](dg), QuicEncryptionLevel.HANDSHAKE, 8
        )
    except:
        raised_neg = True
    assert_true(raised_neg, "negative slot must raise")
    var raised_big = False
    try:
        _ = listener._decrypt_post_initial(
            99, Span[UInt8, _](dg), QuicEncryptionLevel.HANDSHAKE, 8
        )
    except:
        raised_big = True
    assert_true(raised_big, "out-of-range slot must raise")
    listener.shutdown()
    listener.close()


def test_decrypt_post_initial_raises_on_truncated_handshake() raises:
    """A long-header Handshake datagram too short for the
    pn_offset + 4 + 16 HP sample window must raise, not read out
    of bounds."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(0),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    # Stamp the handshake readiness sentinel so the bounds check
    # (not the sentinel gate) is what rejects.
    var conn = listener.connections[0].copy()
    conn.rx_handshake_secret.append(UInt8(0xFF))
    listener.connections[0] = conn^
    # Build a minimal Handshake long header + a tiny body that
    # cannot host the 20-byte (4 + 16) sample window.
    var hdr = encode_long_header(
        PACKET_TYPE_HANDSHAKE,
        QUIC_VERSION_1,
        _make_cid(UInt8(0x10), 8),
        _make_cid(UInt8(0x20), 8),
        type_specific_bits=1,
    )
    var dg = List[UInt8]()
    for i in range(len(hdr)):
        dg.append(hdr[i])
    var lenv = encode_varint(UInt64(4))
    for i in range(len(lenv)):
        dg.append(lenv[i])
    for _ in range(4):
        dg.append(UInt8(0))
    var raised = False
    try:
        _ = listener._decrypt_post_initial(
            0, Span[UInt8, _](dg), QuicEncryptionLevel.HANDSHAKE, 8
        )
    except:
        raised = True
    assert_true(raised, "truncated handshake packet must raise, not OOB")
    listener.shutdown()
    listener.close()


def test_handle_inbound_drops_handshake_without_sentinel() raises:
    """A Handshake-form datagram for a slot whose handshake
    readiness sentinel is not installed must drop silently:
    _handle_inbound returns without raising and the connection
    stays alive with no streams opened."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(1),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    assert_equal(len(listener.connections[0].rx_handshake_secret), 0)
    var hdr = encode_long_header(
        PACKET_TYPE_HANDSHAKE,
        QUIC_VERSION_1,
        _make_cid(UInt8(0x30), 8),
        _make_cid(UInt8(0x40), 8),
        type_specific_bits=1,
    )
    var dg = List[UInt8]()
    for i in range(len(hdr)):
        dg.append(hdr[i])
    var lenv = encode_varint(UInt64(40))
    for i in range(len(lenv)):
        dg.append(lenv[i])
    for i in range(40):
        dg.append(UInt8(i))
    # Must not raise (silent drop).
    _ = listener._handle_inbound(0, Span[UInt8, _](dg))
    assert_true(listener.connections[0].alive)
    assert_equal(len(listener.connections[0].conn.streams), 0)
    listener.shutdown()
    listener.close()


def test_handle_inbound_drops_1rtt_without_sentinel() raises:
    """Short-header 1-RTT datagram for a slot without the 1-RTT
    sentinel drops silently."""
    var listener = _bind_real_pem()
    _ = listener._accept_initial(
        _synth_long_header(2),
        SocketAddr(IpAddr.localhost(), UInt16(0)),
    )
    assert_equal(len(listener.connections[0].rx_1rtt_secret), 0)
    # Short header: high bit clear, then DCID (8 bytes) + body.
    var dg = List[UInt8]()
    dg.append(UInt8(0x40))  # short header, fixed bit set
    var dcid = _make_cid(UInt8(0x50), 8)
    for i in range(8):
        dg.append(dcid.bytes[i])
    for i in range(40):
        dg.append(UInt8(i))
    _ = listener._handle_inbound(0, Span[UInt8, _](dg))
    assert_true(listener.connections[0].alive)
    assert_equal(len(listener.connections[0].conn.streams), 0)
    listener.shutdown()
    listener.close()


def test_ack_ranges_exclude_skipped_pn() raises:
    """An ACK built from received pns 0,1,2,3,5,6,7 (the peer
    skipped pn 4 as an optimistic-ACK probe, RFC 9000 sec 21.4)
    must NOT acknowledge pn 4: it splits into two ranges with a
    one-packet gap, so the peer does not see its skipped number
    acked and the connection stays open."""
    var flat = List[UInt64]()
    for pn in [0, 1, 2, 3, 5, 6, 7]:
        _ack_record(flat, UInt64(pn))
    var ack = _ack_from_ranges(flat, UInt64(0))
    assert_equal(Int(ack.largest_acknowledged), 7)
    # First (highest) range [5, 7]: first_ack_range = 7 - 5 = 2.
    assert_equal(Int(ack.first_ack_range), 2)
    assert_equal(len(ack.ranges), 1)
    # gap 0 = exactly one unacked packet (pn 4); length 3 = [0, 3].
    assert_equal(Int(ack.ranges[0].gap), 0)
    assert_equal(Int(ack.ranges[0].length), 3)


def test_ack_ranges_contiguous_single_range() raises:
    """Contiguous receipt collapses to one range with no explicit
    sub-ranges, regardless of insertion order."""
    var flat = List[UInt64]()
    for pn in [3, 0, 4, 1, 2]:
        _ack_record(flat, UInt64(pn))
    var ack = _ack_from_ranges(flat, UInt64(0))
    assert_equal(Int(ack.largest_acknowledged), 4)
    assert_equal(Int(ack.first_ack_range), 4)
    assert_equal(len(ack.ranges), 0)


def test_ack_ranges_duplicate_pn_is_idempotent() raises:
    """Re-recording an already-tracked pn does not corrupt the
    range set (duplicate datagrams are common under loss)."""
    var flat = List[UInt64]()
    for pn in [5, 5, 6, 5, 7, 6]:
        _ack_record(flat, UInt64(pn))
    var ack = _ack_from_ranges(flat, UInt64(0))
    assert_equal(Int(ack.largest_acknowledged), 7)
    assert_equal(Int(ack.first_ack_range), 2)
    assert_equal(len(ack.ranges), 0)


def test_duplicate_packet_numbers_are_recognised() raises:
    """1-RTT packets were dispatched without a duplicate check, so a
    retransmit that crossed our ACK ran its request a second time."""
    var flat = List[UInt64]()
    for pn in [0, 1, 2, 5]:
        _ack_record(flat, UInt64(pn))
    assert_true(_ack_contains(flat, UInt64(1)))
    assert_true(_ack_contains(flat, UInt64(5)))
    assert_false(_ack_contains(flat, UInt64(3)))
    assert_false(_ack_contains(flat, UInt64(6)))
    # Once the range list is full, anything older than it counts as
    # seen: it can no longer be told apart from a replay.
    var full = List[UInt64]()
    for k in range(_ACK_MAX_RANGES + 4):
        _ack_record(full, UInt64(100 + 2 * k))
    assert_true(_ack_contains(full, UInt64(1)))


def test_packet_number_spaces_are_separate() raises:
    """One largest-received counter served Initial, Handshake and 1-RTT,
    so each space's truncated numbers were expanded against another
    space's largest (RFC 9000 sec 12.3)."""
    from flare.quic import QuicConnection
    from flare.quic.packet import ConnectionId

    var qc = QuicConnection(
        ConnectionId(bytes=List[UInt8](length=8, fill=UInt8(1))),
        ConnectionId(bytes=List[UInt8](length=8, fill=UInt8(2))),
    )
    qc._note_received(0, UInt64(900))
    qc._note_received(2, UInt64(3))
    assert_equal(Int(qc.rx_largest[0]), 900)
    assert_equal(Int(qc.rx_largest[1]), 0)
    assert_equal(Int(qc.rx_largest[2]), 3)


def main() raises:
    test_decrypt_post_initial_raises_slot_out_of_range()
    test_decrypt_post_initial_raises_on_truncated_handshake()
    test_handle_inbound_drops_handshake_without_sentinel()
    test_handle_inbound_drops_1rtt_without_sentinel()
    test_ack_ranges_exclude_skipped_pn()
    test_ack_ranges_contiguous_single_range()
    test_ack_ranges_duplicate_pn_is_idempotent()
    test_duplicate_packet_numbers_are_recognised()
    test_packet_number_spaces_are_separate()
    print("test_quic_post_initial_decrypt: 9 passed")
