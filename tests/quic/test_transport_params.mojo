"""Unit tests for the QUIC transport-parameters codec
(``flare.quic.transport_params`` -- RFC 9000 §18).

Covers each parameter type's round-trip plus the structural rules
the codec enforces: zero-length flag, fixed-size stateless reset
token, varint-shaped values, duplicate-id rejection, unknown-id
silent drop, and the per-parameter validation thresholds (RFC
9000 §18.2).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.collections.span import Span
from std.collections import Optional

from flare.quic import (
    DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    TP_ID_ACK_DELAY_EXPONENT,
    TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
    TP_ID_DISABLE_ACTIVE_MIGRATION,
    TP_ID_INITIAL_MAX_DATA,
    TP_ID_INITIAL_SCID,
    TP_ID_MAX_IDLE_TIMEOUT,
    TP_ID_ORIGINAL_DCID,
    TP_ID_STATELESS_RESET_TOKEN,
    PeerSendLimits,
    TransportParameters,
    decode_transport_parameters,
    derive_peer_send_limits,
    empty_transport_parameters,
    encode_transport_parameters,
)


def test_round_trip_full_set() raises:
    var params = empty_transport_parameters()
    params.original_destination_connection_id.append(UInt8(1))
    params.original_destination_connection_id.append(UInt8(2))
    params.original_destination_connection_id.append(UInt8(3))
    params.max_idle_timeout = Optional[UInt64](UInt64(30000))
    for _ in range(16):
        params.stateless_reset_token.append(UInt8(0xCA))
    params.max_udp_payload_size = Optional[UInt64](UInt64(1452))
    params.initial_max_data = Optional[UInt64](UInt64(1 << 20))
    params.initial_max_stream_data_bidi_local = Optional[UInt64](
        UInt64(0x10000)
    )
    params.initial_max_stream_data_bidi_remote = Optional[UInt64](
        UInt64(0x20000)
    )
    params.initial_max_stream_data_uni = Optional[UInt64](UInt64(0x30000))
    params.initial_max_streams_bidi = Optional[UInt64](UInt64(100))
    params.initial_max_streams_uni = Optional[UInt64](UInt64(50))
    params.ack_delay_exponent = Optional[UInt64](UInt64(3))
    params.max_ack_delay = Optional[UInt64](UInt64(25))
    params.disable_active_migration = True
    params.active_connection_id_limit = Optional[UInt64](UInt64(4))
    for i in range(8):
        params.initial_source_connection_id.append(UInt8(i + 10))

    var encoded = encode_transport_parameters(params)
    var decoded = decode_transport_parameters(Span[UInt8, _](encoded))

    assert_equal(len(decoded.original_destination_connection_id), 3)
    assert_equal(decoded.max_idle_timeout.value(), UInt64(30000))
    assert_equal(len(decoded.stateless_reset_token), 16)
    assert_equal(decoded.max_udp_payload_size.value(), UInt64(1452))
    assert_equal(decoded.initial_max_data.value(), UInt64(1 << 20))
    assert_equal(
        decoded.initial_max_stream_data_bidi_local.value(),
        UInt64(0x10000),
    )
    assert_equal(
        decoded.initial_max_stream_data_bidi_remote.value(),
        UInt64(0x20000),
    )
    assert_equal(decoded.initial_max_stream_data_uni.value(), UInt64(0x30000))
    assert_equal(decoded.initial_max_streams_bidi.value(), UInt64(100))
    assert_equal(decoded.initial_max_streams_uni.value(), UInt64(50))
    assert_equal(decoded.ack_delay_exponent.value(), UInt64(3))
    assert_equal(decoded.max_ack_delay.value(), UInt64(25))
    assert_true(decoded.disable_active_migration)
    assert_equal(decoded.active_connection_id_limit.value(), UInt64(4))
    assert_equal(len(decoded.initial_source_connection_id), 8)


def test_empty_params_roundtrip() raises:
    var params = empty_transport_parameters()
    var encoded = encode_transport_parameters(params)
    assert_equal(len(encoded), 0)
    var decoded = decode_transport_parameters(Span[UInt8, _](encoded))
    assert_false(decoded.disable_active_migration)
    assert_false(Bool(decoded.max_idle_timeout))
    assert_equal(len(decoded.stateless_reset_token), 0)


def test_disable_active_migration_zero_length() raises:
    var params = empty_transport_parameters()
    params.disable_active_migration = True
    var encoded = encode_transport_parameters(params)
    # Wire shape: id(0x0c) || len(0x00). Both fit in 1 byte.
    assert_equal(len(encoded), 2)
    assert_equal(Int(encoded[0]), TP_ID_DISABLE_ACTIVE_MIGRATION)
    assert_equal(Int(encoded[1]), 0x00)
    var decoded = decode_transport_parameters(Span[UInt8, _](encoded))
    assert_true(decoded.disable_active_migration)


def test_stateless_reset_token_must_be_16_bytes() raises:
    var params = empty_transport_parameters()
    for _ in range(8):
        params.stateless_reset_token.append(UInt8(0xFF))
    var raised = False
    try:
        var _ = encode_transport_parameters(params)
    except:
        raised = True
    assert_true(raised)


def test_max_udp_payload_size_below_1200_rejected() raises:
    # Build wire with TP_ID_MAX_UDP_PAYLOAD_SIZE = 1199 -- below
    # the §18.2 floor.
    var buf = List[UInt8]()
    buf.append(UInt8(0x03))  # id varint = 0x03
    buf.append(UInt8(0x02))  # len varint = 2
    buf.append(UInt8(0x44))  # varint header for 14-bit form
    buf.append(UInt8(0xAF))  # 0x4af = 1199
    var raised = False
    try:
        var _ = decode_transport_parameters(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_ack_delay_exponent_above_20_rejected() raises:
    var params = empty_transport_parameters()
    params.ack_delay_exponent = Optional[UInt64](UInt64(21))
    var raised = False
    try:
        var _ = encode_transport_parameters(params)
    except:
        raised = True
    assert_true(raised)


def test_active_connection_id_limit_below_2_rejected() raises:
    var params = empty_transport_parameters()
    params.active_connection_id_limit = Optional[UInt64](UInt64(1))
    var raised = False
    try:
        var _ = encode_transport_parameters(params)
    except:
        raised = True
    assert_true(raised)


def test_duplicate_id_rejected() raises:
    # Wire: emit max_idle_timeout (0x01) twice.
    var buf = List[UInt8]()
    buf.append(UInt8(TP_ID_MAX_IDLE_TIMEOUT))
    buf.append(UInt8(0x01))  # length 1
    buf.append(UInt8(0x05))  # value 5
    buf.append(UInt8(TP_ID_MAX_IDLE_TIMEOUT))
    buf.append(UInt8(0x01))
    buf.append(UInt8(0x06))
    var raised = False
    try:
        var _ = decode_transport_parameters(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_unknown_id_silently_dropped() raises:
    # Wire: TP id 0x80 (reserved for future use, single byte after
    # varint encode), payload 4 bytes.
    var buf = List[UInt8]()
    # 0x80 needs 2-byte varint form: 0x4080.
    buf.append(UInt8(0x40))
    buf.append(UInt8(0x80))
    buf.append(UInt8(0x04))  # length 4
    buf.append(UInt8(0xAA))
    buf.append(UInt8(0xBB))
    buf.append(UInt8(0xCC))
    buf.append(UInt8(0xDD))
    # Followed by a known param.
    buf.append(UInt8(TP_ID_MAX_IDLE_TIMEOUT))
    buf.append(UInt8(0x01))
    buf.append(UInt8(0x07))
    var decoded = decode_transport_parameters(Span[UInt8, _](buf))
    assert_equal(decoded.max_idle_timeout.value(), UInt64(7))


def test_truncated_value_rejected() raises:
    var buf = List[UInt8]()
    buf.append(UInt8(TP_ID_INITIAL_MAX_DATA))
    buf.append(UInt8(0x08))  # claim 8 byte value
    buf.append(UInt8(0xAA))  # only 1 byte present
    var raised = False
    try:
        var _ = decode_transport_parameters(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def _streams_blob(id: UInt8, last: UInt8) -> List[UInt8]:
    """``id`` with an 8-byte varint value 2^60 + ``last``."""
    var b = List[UInt8]()
    b.append(id)
    b.append(0x08)
    b.append(0xD0)
    for _ in range(6):
        b.append(0x00)
    b.append(last)
    return b^


def test_initial_max_streams_above_2p60_rejected() raises:
    """QUIC-10 (RFC 9000 sec 18.2): initial_max_streams_bidi / _uni above
    2^60 is a TRANSPORT_PARAMETER_ERROR; 2^60 itself is allowed."""
    for id in [UInt8(0x08), UInt8(0x09)]:
        var over = _streams_blob(id, 0x01)
        var raised = False
        try:
            _ = decode_transport_parameters(Span[UInt8, _](over))
        except:
            raised = True
        assert_true(raised, "2^60 + 1 accepted for id " + String(Int(id)))
        var at = _streams_blob(id, 0x00)
        var tp = decode_transport_parameters(Span[UInt8, _](at))
        var v = (
            tp.initial_max_streams_bidi.value() if id
            == 0x08 else tp.initial_max_streams_uni.value()
        )
        assert_equal(v, UInt64(1) << 60)


def _pa_blob(cid_len: Int, total: Int) -> List[UInt8]:
    """A preferred_address TLV whose CID length byte is ``cid_len`` and
    whose value is ``total`` bytes long."""
    var v = List[UInt8]()
    for _ in range(24):
        v.append(0)
    v.append(UInt8(cid_len))
    while len(v) < total:
        v.append(0x55)
    while len(v) > total:
        _ = v.pop()
    var b = List[UInt8]()
    b.append(0x0D)
    b.append(UInt8(len(v)))
    for i in range(len(v)):
        b.append(v[i])
    return b^


def _decodes(blob: List[UInt8]) -> Bool:
    try:
        _ = decode_transport_parameters(Span[UInt8, _](blob))
        return True
    except:
        return False


def test_preferred_address_layout_validated() raises:
    """QUIC-13 (RFC 9000 sec 18.2, 7.4): preferred_address has a fixed
    layout with a 1..20-byte CID; anything else is a
    TRANSPORT_PARAMETER_ERROR."""
    assert_false(_decodes(_pa_blob(0, 0)), "empty value accepted")
    assert_false(_decodes(_pa_blob(0, 5)), "5-byte value accepted")
    assert_false(_decodes(_pa_blob(0, 41)), "zero-length CID accepted")
    assert_false(_decodes(_pa_blob(21, 62)), "CID length 21 accepted")
    assert_false(_decodes(_pa_blob(8, 48)), "value one byte short accepted")
    assert_false(_decodes(_pa_blob(8, 50)), "value one byte long accepted")
    assert_true(_decodes(_pa_blob(1, 42)), "1-byte CID rejected")
    assert_true(_decodes(_pa_blob(8, 49)), "8-byte CID rejected")
    assert_true(_decodes(_pa_blob(20, 61)), "20-byte CID rejected")


def test_max_datagram_frame_size_roundtrip() raises:
    var params = empty_transport_parameters()
    params.max_datagram_frame_size = Optional[UInt64](UInt64(65535))
    var encoded = encode_transport_parameters(params)
    var decoded = decode_transport_parameters(Span[UInt8, _](encoded))
    assert_true(Bool(decoded.max_datagram_frame_size))
    assert_equal(decoded.max_datagram_frame_size.value(), UInt64(65535))
    # Absent by default.
    var empty = decode_transport_parameters(
        Span[UInt8, _](
            encode_transport_parameters(empty_transport_parameters())
        )
    )
    assert_false(Bool(empty.max_datagram_frame_size))


def test_derive_peer_send_limits_defaults() raises:
    # Absent flow-control params -> 0 allowance; max_udp_payload defaults
    # to 65527; datagrams disabled.
    var limits = derive_peer_send_limits(empty_transport_parameters())
    assert_equal(limits.max_data, UInt64(0))
    assert_equal(limits.max_stream_data_bidi_remote, UInt64(0))
    assert_equal(limits.max_stream_data_uni, UInt64(0))
    assert_equal(limits.max_udp_payload_size, DEFAULT_MAX_UDP_PAYLOAD_SIZE)
    assert_equal(limits.max_datagram_frame_size, UInt64(0))


def test_derive_peer_send_limits_set() raises:
    # A populated set round-trips through encode/decode and projects onto
    # the send-limit view with the explicit values.
    var p = empty_transport_parameters()
    p.initial_max_data = Optional[UInt64](UInt64(1 << 20))
    p.initial_max_stream_data_bidi_remote = Optional[UInt64](UInt64(65536))
    p.initial_max_stream_data_uni = Optional[UInt64](UInt64(4096))
    p.max_udp_payload_size = Optional[UInt64](UInt64(1350))
    p.max_datagram_frame_size = Optional[UInt64](UInt64(1200))
    p.initial_max_streams_bidi = Optional[UInt64](UInt64(100))
    p.initial_max_streams_uni = Optional[UInt64](UInt64(3))
    var decoded = decode_transport_parameters(
        Span[UInt8, _](encode_transport_parameters(p))
    )
    var limits = derive_peer_send_limits(decoded)
    assert_equal(limits.max_data, UInt64(1 << 20))
    assert_equal(limits.max_stream_data_bidi_remote, UInt64(65536))
    assert_equal(limits.max_stream_data_uni, UInt64(4096))
    assert_equal(limits.max_udp_payload_size, UInt64(1350))
    assert_equal(limits.max_datagram_frame_size, UInt64(1200))
    assert_equal(limits.max_streams_bidi, UInt64(100))
    assert_equal(limits.max_streams_uni, UInt64(3))


def main() raises:
    test_round_trip_full_set()
    test_initial_max_streams_above_2p60_rejected()
    test_preferred_address_layout_validated()
    test_max_datagram_frame_size_roundtrip()
    test_empty_params_roundtrip()
    test_disable_active_migration_zero_length()
    test_stateless_reset_token_must_be_16_bytes()
    test_max_udp_payload_size_below_1200_rejected()
    test_ack_delay_exponent_above_20_rejected()
    test_active_connection_id_limit_below_2_rejected()
    test_duplicate_id_rejected()
    test_unknown_id_silently_dropped()
    test_truncated_value_rejected()
    test_derive_peer_send_limits_defaults()
    test_derive_peer_send_limits_set()
    print("test_quic_transport_params: 15 passed")
