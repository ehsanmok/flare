"""Unit tests for the QUIC v1 packet header codec.

Covers long-header round-trip with all four packet types
(Initial / 0-RTT / Handshake / Retry), version negotiation
detection, Initial-specific extras, short-header round-trip with
the spin bit + key phase, and rejection of malformed inputs
(missing fixed bit, oversized CID, truncated buffers).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.quic import (
    QUIC_VERSION_1,
    QUIC_VERSION_NEGOTIATION,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    MAX_CID_LENGTH,
    ConnectionId,
    encode_long_header,
    encode_short_header,
    parse_long_header,
    parse_initial_extras,
    parse_short_header,
    encode_varint,
)


def _cid(*bytes: Int) -> ConnectionId:
    var b = List[UInt8]()
    for v in bytes:
        b.append(UInt8(v))
    return ConnectionId(bytes=b^)


def test_long_header_initial_round_trip() raises:
    """Encode an Initial packet's public prefix, parse it back,
    and confirm every field round-trips."""
    var dcid = _cid(0x11, 0x22, 0x33, 0x44)
    var scid = _cid(0xAA, 0xBB)
    var enc = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid, type_specific_bits=0
    )
    # First byte: 1100 0000 -> long+fixed, type=Initial (0), reserved+PN=0.
    assert_equal(Int(enc[0]), 0xC0)
    # Version: 00 00 00 01.
    assert_equal(Int(enc[1]), 0x00)
    assert_equal(Int(enc[2]), 0x00)
    assert_equal(Int(enc[3]), 0x00)
    assert_equal(Int(enc[4]), 0x01)
    # DCID length + payload, SCID length + payload.
    assert_equal(Int(enc[5]), 4)
    assert_equal(Int(enc[10]), 2)
    var hdr = parse_long_header(Span[UInt8](enc))
    assert_equal(hdr.packet_type, PACKET_TYPE_INITIAL)
    assert_equal(Int(hdr.version), Int(QUIC_VERSION_1))
    assert_equal(hdr.dcid.length(), 4)
    assert_equal(hdr.scid.length(), 2)
    assert_equal(Int(hdr.dcid.bytes[0]), 0x11)
    assert_equal(Int(hdr.scid.bytes[0]), 0xAA)
    assert_equal(hdr.payload_offset, len(enc))


def test_long_header_all_packet_types() raises:
    """All four long-header packet types round-trip with the
    correct ``T T`` bits in the first byte."""
    var dcid = _cid(0x01)
    var scid = _cid()
    var types = List[Int]()
    types.append(PACKET_TYPE_INITIAL)
    types.append(PACKET_TYPE_ZERO_RTT)
    types.append(PACKET_TYPE_HANDSHAKE)
    types.append(PACKET_TYPE_RETRY)
    for i in range(len(types)):
        var t = types[i]
        var enc = encode_long_header(t, QUIC_VERSION_1, dcid, scid)
        # First byte: 0xC0 | (t << 4). Validate the bits explicitly.
        assert_equal(Int(enc[0]) & 0xC0, 0xC0)
        assert_equal((Int(enc[0]) >> 4) & 0x3, t)
        var hdr = parse_long_header(Span[UInt8](enc))
        assert_equal(hdr.packet_type, t)


def test_long_header_rejects_missing_long_bit() raises:
    """A first byte with bit 0x80 clear is a short-header packet
    and must be rejected by the long-header parser."""
    var buf = List[UInt8]()
    buf.append(UInt8(0x40))  # short-header indicator
    for _ in range(6):
        buf.append(UInt8(0))
    var raised = False
    try:
        _ = parse_long_header(Span[UInt8](buf))
    except _:
        raised = True
    assert_true(raised)


def test_long_header_rejects_missing_fixed_bit() raises:
    """RFC 9000 §17.2: the second-highest bit (0x40) is the
    "fixed bit" and must be 1. Greasing or zeroing it is a
    protocol violation."""
    var buf = List[UInt8]()
    buf.append(UInt8(0x80))  # long bit only; fixed bit cleared
    for _ in range(20):
        buf.append(UInt8(0))
    var raised = False
    try:
        _ = parse_long_header(Span[UInt8](buf))
    except _:
        raised = True
    assert_true(raised)


def test_long_header_rejects_oversized_cid() raises:
    """A CID length byte greater than 20 must be rejected at the
    parser boundary (§5.1.1)."""
    var buf = List[UInt8]()
    buf.append(UInt8(0xC0))  # long + fixed
    for _ in range(4):
        buf.append(UInt8(0))  # version 0
    buf.append(UInt8(21))  # DCID len = 21 — oversize
    for _ in range(21):
        buf.append(UInt8(0))
    buf.append(UInt8(0))  # SCID len = 0
    var raised = False
    try:
        _ = parse_long_header(Span[UInt8](buf))
    except _:
        raised = True
    assert_true(raised)


def test_version_negotiation_detection() raises:
    """Version-negotiation packets carry version=0. The parser
    surfaces this through the ``version`` field so callers can
    branch without magic numbers."""
    var dcid = _cid(0xFF)
    var scid = _cid(0xEE)
    var enc = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_NEGOTIATION, dcid, scid
    )
    var hdr = parse_long_header(Span[UInt8](enc))
    assert_equal(Int(hdr.version), Int(QUIC_VERSION_NEGOTIATION))


def test_initial_extras_round_trip() raises:
    """An Initial packet's token + payload-length round-trip
    through ``parse_initial_extras`` cleanly."""
    var dcid = _cid(0x01, 0x02)
    var scid = _cid(0x03, 0x04)
    var prefix = encode_long_header(
        PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid
    )
    # Build the wire form: prefix + token-length(varint=4) + 4 token bytes
    # + payload-length(varint=1200).
    var wire = List[UInt8]()
    for i in range(len(prefix)):
        wire.append(prefix[i])
    var tok_len = encode_varint(UInt64(4))
    for i in range(len(tok_len)):
        wire.append(tok_len[i])
    wire.append(UInt8(0xDE))
    wire.append(UInt8(0xAD))
    wire.append(UInt8(0xBE))
    wire.append(UInt8(0xEF))
    var pl_len = encode_varint(UInt64(1200))
    for i in range(len(pl_len)):
        wire.append(pl_len[i])
    var hdr = parse_long_header(Span[UInt8](wire))
    var extras = parse_initial_extras(Span[UInt8](wire), hdr.payload_offset)
    assert_equal(len(extras.token), 4)
    assert_equal(Int(extras.token[0]), 0xDE)
    assert_equal(Int(extras.token[3]), 0xEF)
    assert_equal(extras.payload_length, UInt64(1200))


def test_short_header_round_trip() raises:
    """Short-header (1-RTT) packets round-trip the spin bit, the
    key-phase bit, and the DCID payload (length-pinned)."""
    var dcid = _cid(0xCA, 0xFE, 0xBA, 0xBE)
    var enc = encode_short_header(
        dcid, spin_bit=True, key_phase=True, pn_length=1
    )
    # First byte: 0100 0100 + spin (0x20) + key-phase (0x04) = 0x64.
    assert_equal(Int(enc[0]), 0x64)
    var hdr = parse_short_header(Span[UInt8](enc), dcid_length=4)
    assert_true(hdr.spin_bit)
    assert_true(hdr.key_phase)
    assert_equal(hdr.dcid.length(), 4)
    assert_equal(Int(hdr.dcid.bytes[0]), 0xCA)
    assert_equal(Int(hdr.dcid.bytes[3]), 0xBE)


def test_short_header_rejects_long_bit() raises:
    """A first byte with 0x80 set is a long-header packet; the
    short-header parser must reject it."""
    var buf = List[UInt8]()
    buf.append(UInt8(0xC0))
    var raised = False
    try:
        _ = parse_short_header(Span[UInt8](buf), dcid_length=0)
    except _:
        raised = True
    assert_true(raised)


def test_short_header_rejects_bad_dcid_length() raises:
    """Negative or oversized DCID lengths are caller errors that
    the parser rejects rather than silently truncating."""
    var buf = List[UInt8]()
    buf.append(UInt8(0x40))
    var raised = False
    try:
        _ = parse_short_header(Span[UInt8](buf), dcid_length=21)
    except _:
        raised = True
    assert_true(raised)


def test_encoder_rejects_oversized_cid() raises:
    """The encoder mirrors the parser's CID length cap: 20
    octets max."""
    var too_long = List[UInt8]()
    for _ in range(21):
        too_long.append(UInt8(0))
    var dcid = ConnectionId(bytes=too_long^)
    var scid = _cid()
    var raised = False
    try:
        _ = encode_long_header(PACKET_TYPE_INITIAL, QUIC_VERSION_1, dcid, scid)
    except _:
        raised = True
    assert_true(raised)


def main() raises:
    test_long_header_initial_round_trip()
    test_long_header_all_packet_types()
    test_long_header_rejects_missing_long_bit()
    test_long_header_rejects_missing_fixed_bit()
    test_long_header_rejects_oversized_cid()
    test_version_negotiation_detection()
    test_initial_extras_round_trip()
    test_short_header_round_trip()
    test_short_header_rejects_long_bit()
    test_short_header_rejects_bad_dcid_length()
    test_encoder_rejects_oversized_cid()
    print("test_packet: OK")
