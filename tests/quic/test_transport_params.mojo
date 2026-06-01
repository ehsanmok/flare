"""Unit tests for the QUIC transport-parameters codec
(``flare.quic.transport_params`` -- RFC 9000 §18).

Covers each parameter type's round-trip plus the structural rules
the codec enforces: zero-length flag, fixed-size stateless reset
token, varint-shaped values, duplicate-id rejection, unknown-id
silent drop, and the per-parameter validation thresholds (RFC
9000 §18.2).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span
from std.collections import Optional

from flare.quic import (
    TP_ID_ACK_DELAY_EXPONENT,
    TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
    TP_ID_DISABLE_ACTIVE_MIGRATION,
    TP_ID_INITIAL_MAX_DATA,
    TP_ID_INITIAL_SCID,
    TP_ID_MAX_IDLE_TIMEOUT,
    TP_ID_ORIGINAL_DCID,
    TP_ID_STATELESS_RESET_TOKEN,
    TransportParameters,
    decode_transport_parameters,
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


def main() raises:
    test_round_trip_full_set()
    test_empty_params_roundtrip()
    test_disable_active_migration_zero_length()
    test_stateless_reset_token_must_be_16_bytes()
    test_max_udp_payload_size_below_1200_rejected()
    test_ack_delay_exponent_above_20_rejected()
    test_active_connection_id_limit_below_2_rejected()
    test_duplicate_id_rejected()
    test_unknown_id_silently_dropped()
    test_truncated_value_rejected()
    print("test_quic_transport_params: 10 passed")
