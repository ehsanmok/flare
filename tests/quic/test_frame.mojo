"""Unit tests for the QUIC v1 transport-frame codec
(``flare.quic.frame`` -- RFC 9000 §19).

Each test locks one frame type's wire format with a hand-computed
encoding cross-checked against an in-line recording
:trait:`FrameHandler`; the encode + decode + dispatch are
asserted as a single end-to-end identity per type.
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.quic import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    CryptoFrame,
    DataBlockedFrame,
    EcnCounts,
    FRAME_TYPE_ACK,
    FRAME_TYPE_ACK_ECN,
    FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_DATA_BLOCKED,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_DATAGRAM_LEN,
    FRAME_TYPE_DATAGRAM_NOLEN,
    FRAME_TYPE_MAX_STREAM_DATA,
    FRAME_TYPE_MAX_STREAMS_BIDI,
    FRAME_TYPE_MAX_STREAMS_UNI,
    FRAME_TYPE_NEW_CONNECTION_ID,
    FRAME_TYPE_NEW_TOKEN,
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PATH_CHALLENGE,
    FRAME_TYPE_PATH_RESPONSE,
    FRAME_TYPE_PING,
    FRAME_TYPE_RESET_STREAM,
    FRAME_TYPE_RETIRE_CONNECTION_ID,
    FRAME_TYPE_STOP_SENDING,
    FRAME_TYPE_STREAM_BASE,
    FRAME_TYPE_STREAM_DATA_BLOCKED,
    FRAME_TYPE_STREAMS_BLOCKED_BIDI,
    FRAME_TYPE_STREAMS_BLOCKED_UNI,
    DatagramFrame,
    FrameHandler,
    HandshakeDoneFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    NewTokenFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ResetStreamFrame,
    RetireConnectionIdFrame,
    StopSendingFrame,
    StreamFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    encode_ack,
    encode_connection_close,
    encode_crypto,
    encode_data_blocked,
    encode_datagram,
    encode_handshake_done,
    encode_max_data,
    encode_max_stream_data,
    encode_max_streams,
    encode_new_connection_id,
    encode_new_token,
    encode_padding,
    encode_path_challenge,
    encode_path_response,
    encode_ping,
    encode_reset_stream,
    encode_retire_connection_id,
    encode_stop_sending,
    encode_stream,
    encode_stream_data_blocked,
    encode_streams_blocked,
    parse_frame_into,
)


def _bytes(*hex: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in hex:
        out.append(UInt8(v))
    return out^


# ── Recording handler ────────────────────────────────────────────────────


@fieldwise_init
struct _Recorder(FrameHandler, Movable):
    """In-line :trait:`FrameHandler` that captures the dispatched
    payload of one frame so the tests can assert on it.

    Fields default to sentinel values; the test inspects the
    populated field corresponding to the frame type it encoded.
    """

    var padding_count: Int
    var ping_count: Int
    var handshake_done_count: Int
    var unknown_type: Int

    var ack: AckFrame
    var ack_seen: Bool

    var reset_stream: ResetStreamFrame
    var reset_stream_seen: Bool

    var stop_sending: StopSendingFrame
    var stop_sending_seen: Bool

    var crypto: CryptoFrame
    var crypto_seen: Bool

    var new_token: NewTokenFrame
    var new_token_seen: Bool

    var stream: StreamFrame
    var stream_seen: Bool

    var max_data: MaxDataFrame
    var max_data_seen: Bool

    var max_stream_data: MaxStreamDataFrame
    var max_stream_data_seen: Bool

    var max_streams: MaxStreamsFrame
    var max_streams_seen: Bool

    var data_blocked: DataBlockedFrame
    var data_blocked_seen: Bool

    var stream_data_blocked: StreamDataBlockedFrame
    var stream_data_blocked_seen: Bool

    var streams_blocked: StreamsBlockedFrame
    var streams_blocked_seen: Bool

    var new_connection_id: NewConnectionIdFrame
    var new_connection_id_seen: Bool

    var retire_connection_id: RetireConnectionIdFrame
    var retire_connection_id_seen: Bool

    var path_challenge: PathChallengeFrame
    var path_challenge_seen: Bool

    var path_response: PathResponseFrame
    var path_response_seen: Bool

    var connection_close: ConnectionCloseFrame
    var connection_close_seen: Bool

    var datagram: DatagramFrame
    var datagram_seen: Bool

    def on_padding(mut self, count: Int) raises:
        self.padding_count += count

    def on_ping(mut self) raises:
        self.ping_count += 1

    def on_ack(mut self, ack: AckFrame) raises:
        self.ack = ack.copy()
        self.ack_seen = True

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        self.reset_stream = rs
        self.reset_stream_seen = True

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        self.stop_sending = ss
        self.stop_sending_seen = True

    def on_crypto(mut self, c: CryptoFrame) raises:
        self.crypto = c.copy()
        self.crypto_seen = True

    def on_new_token(mut self, t: NewTokenFrame) raises:
        self.new_token = t.copy()
        self.new_token_seen = True

    def on_stream(mut self, sf: StreamFrame) raises:
        self.stream = sf.copy()
        self.stream_seen = True

    def on_max_data(mut self, m: MaxDataFrame) raises:
        self.max_data = m
        self.max_data_seen = True

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        self.max_stream_data = m
        self.max_stream_data_seen = True

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        self.max_streams = m
        self.max_streams_seen = True

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        self.data_blocked = db
        self.data_blocked_seen = True

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        self.stream_data_blocked = sdb
        self.stream_data_blocked_seen = True

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        self.streams_blocked = sb
        self.streams_blocked_seen = True

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        self.new_connection_id = ncid.copy()
        self.new_connection_id_seen = True

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        self.retire_connection_id = rcid
        self.retire_connection_id_seen = True

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        self.path_challenge = pc.copy()
        self.path_challenge_seen = True

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        self.path_response = pr.copy()
        self.path_response_seen = True

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        self.connection_close = cc.copy()
        self.connection_close_seen = True

    def on_handshake_done(mut self) raises:
        self.handshake_done_count += 1

    def on_datagram(mut self, dg: DatagramFrame) raises:
        self.datagram = dg.copy()
        self.datagram_seen = True

    def on_unknown(mut self, type_id: UInt64) raises:
        self.unknown_type = Int(type_id)
        # Reject unknown codepoints — strict policy for tests.
        raise Error("unknown frame type " + String(Int(type_id)))


def _empty_recorder() -> _Recorder:
    return _Recorder(
        padding_count=0,
        ping_count=0,
        handshake_done_count=0,
        unknown_type=-1,
        ack=AckFrame(
            largest_acknowledged=UInt64(0),
            ack_delay=UInt64(0),
            first_ack_range=UInt64(0),
            ranges=List[AckRange](),
            ecn=List[EcnCounts](),
        ),
        ack_seen=False,
        reset_stream=ResetStreamFrame(
            stream_id=UInt64(0),
            application_error_code=UInt64(0),
            final_size=UInt64(0),
        ),
        reset_stream_seen=False,
        stop_sending=StopSendingFrame(
            stream_id=UInt64(0), application_error_code=UInt64(0)
        ),
        stop_sending_seen=False,
        crypto=CryptoFrame(offset=UInt64(0), data=List[UInt8]()),
        crypto_seen=False,
        new_token=NewTokenFrame(token=List[UInt8]()),
        new_token_seen=False,
        stream=StreamFrame(
            stream_id=UInt64(0),
            offset=UInt64(0),
            data=List[UInt8](),
            fin=False,
        ),
        stream_seen=False,
        max_data=MaxDataFrame(maximum_data=UInt64(0)),
        max_data_seen=False,
        max_stream_data=MaxStreamDataFrame(
            stream_id=UInt64(0), maximum_stream_data=UInt64(0)
        ),
        max_stream_data_seen=False,
        max_streams=MaxStreamsFrame(
            unidirectional=False, maximum_streams=UInt64(0)
        ),
        max_streams_seen=False,
        data_blocked=DataBlockedFrame(maximum_data=UInt64(0)),
        data_blocked_seen=False,
        stream_data_blocked=StreamDataBlockedFrame(
            stream_id=UInt64(0), maximum_stream_data=UInt64(0)
        ),
        stream_data_blocked_seen=False,
        streams_blocked=StreamsBlockedFrame(
            unidirectional=False, maximum_streams=UInt64(0)
        ),
        streams_blocked_seen=False,
        new_connection_id=NewConnectionIdFrame(
            sequence_number=UInt64(0),
            retire_prior_to=UInt64(0),
            connection_id=List[UInt8](),
            stateless_reset_token=List[UInt8](),
        ),
        new_connection_id_seen=False,
        retire_connection_id=RetireConnectionIdFrame(sequence_number=UInt64(0)),
        retire_connection_id_seen=False,
        path_challenge=PathChallengeFrame(data=List[UInt8]()),
        path_challenge_seen=False,
        path_response=PathResponseFrame(data=List[UInt8]()),
        path_response_seen=False,
        connection_close=ConnectionCloseFrame(
            application=False,
            error_code=UInt64(0),
            frame_type=UInt64(0),
            reason_phrase=List[UInt8](),
        ),
        connection_close_seen=False,
        datagram=DatagramFrame(data=List[UInt8](), has_length=False),
        datagram_seen=False,
    )


# ── Round-trip tests ─────────────────────────────────────────────────────


def test_padding_single_byte() raises:
    var out = List[UInt8]()
    encode_padding(3, out)
    assert_equal(len(out), 3)
    for i in range(3):
        assert_equal(Int(out[i]), 0x00)
    var rec = _empty_recorder()
    var consumed = parse_frame_into(Span[UInt8, _](out), rec)
    assert_equal(consumed, 1)
    assert_equal(rec.padding_count, 1)


def test_ping_round_trip() raises:
    var out = List[UInt8]()
    encode_ping(out)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0]), 0x01)
    var rec = _empty_recorder()
    var consumed = parse_frame_into(Span[UInt8, _](out), rec)
    assert_equal(consumed, 1)
    assert_equal(rec.ping_count, 1)


def test_ack_round_trip() raises:
    var ranges = List[AckRange]()
    ranges.append(AckRange(gap=UInt64(1), length=UInt64(2)))
    var ack = AckFrame(
        largest_acknowledged=UInt64(100),
        ack_delay=UInt64(50),
        first_ack_range=UInt64(10),
        ranges=ranges^,
        ecn=List[EcnCounts](),
    )
    var out = List[UInt8]()
    encode_ack(ack, out)
    assert_equal(Int(out[0]), 0x02)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.ack_seen)
    assert_equal(rec.ack.largest_acknowledged, UInt64(100))
    assert_equal(rec.ack.ack_delay, UInt64(50))
    assert_equal(rec.ack.first_ack_range, UInt64(10))
    assert_equal(len(rec.ack.ranges), 1)
    assert_equal(rec.ack.ranges[0].gap, UInt64(1))
    assert_equal(rec.ack.ranges[0].length, UInt64(2))


def test_ack_ecn_round_trip() raises:
    var ecn = List[EcnCounts]()
    ecn.append(EcnCounts(ect0=UInt64(7), ect1=UInt64(8), ce=UInt64(9)))
    var ack = AckFrame(
        largest_acknowledged=UInt64(5),
        ack_delay=UInt64(0),
        first_ack_range=UInt64(2),
        ranges=List[AckRange](),
        ecn=ecn^,
    )
    var out = List[UInt8]()
    encode_ack(ack, out)
    assert_equal(Int(out[0]), 0x03)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.ack_seen)
    assert_equal(len(rec.ack.ecn), 1)
    assert_equal(rec.ack.ecn[0].ect0, UInt64(7))
    assert_equal(rec.ack.ecn[0].ect1, UInt64(8))
    assert_equal(rec.ack.ecn[0].ce, UInt64(9))


def test_reset_stream_round_trip() raises:
    var out = List[UInt8]()
    encode_reset_stream(
        ResetStreamFrame(
            stream_id=UInt64(4),
            application_error_code=UInt64(0x10),
            final_size=UInt64(0xC0FFEE),
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.reset_stream_seen)
    assert_equal(rec.reset_stream.stream_id, UInt64(4))
    assert_equal(rec.reset_stream.application_error_code, UInt64(0x10))
    assert_equal(rec.reset_stream.final_size, UInt64(0xC0FFEE))


def test_stop_sending_round_trip() raises:
    var out = List[UInt8]()
    encode_stop_sending(
        StopSendingFrame(
            stream_id=UInt64(8), application_error_code=UInt64(0x20)
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.stop_sending_seen)
    assert_equal(rec.stop_sending.stream_id, UInt64(8))
    assert_equal(rec.stop_sending.application_error_code, UInt64(0x20))


def test_crypto_round_trip() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x16))  # TLS handshake byte
    data.append(UInt8(0x03))
    data.append(UInt8(0x03))
    var out = List[UInt8]()
    encode_crypto(CryptoFrame(offset=UInt64(0), data=data^), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.crypto_seen)
    assert_equal(rec.crypto.offset, UInt64(0))
    assert_equal(len(rec.crypto.data), 3)
    assert_equal(Int(rec.crypto.data[0]), 0x16)


def test_new_token_round_trip() raises:
    var token = List[UInt8]()
    token.append(UInt8(0xDE))
    token.append(UInt8(0xAD))
    token.append(UInt8(0xBE))
    token.append(UInt8(0xEF))
    var out = List[UInt8]()
    encode_new_token(NewTokenFrame(token=token^), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.new_token_seen)
    assert_equal(len(rec.new_token.token), 4)
    assert_equal(Int(rec.new_token.token[3]), 0xEF)


def test_new_token_empty_rejected() raises:
    var out = List[UInt8]()
    var raised = False
    try:
        encode_new_token(NewTokenFrame(token=List[UInt8]()), out)
    except:
        raised = True
    assert_true(raised)


def test_stream_round_trip_with_offset_and_fin() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x41))  # 'A'
    data.append(UInt8(0x42))  # 'B'
    var out = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(0),
            offset=UInt64(7),
            data=data^,
            fin=True,
        ),
        out,
    )
    # First byte: 0x08 | OFF (0x04) | LEN (0x02) | FIN (0x01) = 0x0F.
    assert_equal(Int(out[0]), 0x0F)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.stream_seen)
    assert_equal(rec.stream.stream_id, UInt64(0))
    assert_equal(rec.stream.offset, UInt64(7))
    assert_equal(len(rec.stream.data), 2)
    assert_true(rec.stream.fin)


def test_stream_round_trip_no_offset_no_fin() raises:
    var data = List[UInt8]()
    data.append(UInt8(0x58))  # 'X'
    var out = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(4),
            offset=UInt64(0),
            data=data^,
            fin=False,
        ),
        out,
    )
    # First byte: 0x08 | LEN (0x02) = 0x0A.
    assert_equal(Int(out[0]), 0x0A)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.stream_seen)
    assert_equal(rec.stream.stream_id, UInt64(4))
    assert_equal(rec.stream.offset, UInt64(0))
    assert_false(rec.stream.fin)


def test_max_data_round_trip() raises:
    var out = List[UInt8]()
    encode_max_data(MaxDataFrame(maximum_data=UInt64(1 << 20)), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.max_data_seen)
    assert_equal(rec.max_data.maximum_data, UInt64(1 << 20))


def test_max_stream_data_round_trip() raises:
    var out = List[UInt8]()
    encode_max_stream_data(
        MaxStreamDataFrame(
            stream_id=UInt64(12), maximum_stream_data=UInt64(0x1234)
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.max_stream_data_seen)
    assert_equal(rec.max_stream_data.stream_id, UInt64(12))
    assert_equal(rec.max_stream_data.maximum_stream_data, UInt64(0x1234))


def test_max_streams_bidi_and_uni() raises:
    var out_bidi = List[UInt8]()
    encode_max_streams(
        MaxStreamsFrame(unidirectional=False, maximum_streams=UInt64(8)),
        out_bidi,
    )
    assert_equal(Int(out_bidi[0]), 0x12)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out_bidi), rec)
    assert_true(rec.max_streams_seen)
    assert_false(rec.max_streams.unidirectional)

    var out_uni = List[UInt8]()
    encode_max_streams(
        MaxStreamsFrame(unidirectional=True, maximum_streams=UInt64(4)),
        out_uni,
    )
    assert_equal(Int(out_uni[0]), 0x13)
    var rec2 = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out_uni), rec2)
    assert_true(rec2.max_streams_seen)
    assert_true(rec2.max_streams.unidirectional)


def test_data_blocked_round_trip() raises:
    var out = List[UInt8]()
    encode_data_blocked(DataBlockedFrame(maximum_data=UInt64(0xFF)), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.data_blocked_seen)
    assert_equal(rec.data_blocked.maximum_data, UInt64(0xFF))


def test_stream_data_blocked_round_trip() raises:
    var out = List[UInt8]()
    encode_stream_data_blocked(
        StreamDataBlockedFrame(
            stream_id=UInt64(2), maximum_stream_data=UInt64(64)
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.stream_data_blocked_seen)
    assert_equal(rec.stream_data_blocked.stream_id, UInt64(2))


def test_streams_blocked_bidi_and_uni() raises:
    var out_bidi = List[UInt8]()
    encode_streams_blocked(
        StreamsBlockedFrame(unidirectional=False, maximum_streams=UInt64(2)),
        out_bidi,
    )
    assert_equal(Int(out_bidi[0]), 0x16)

    var out_uni = List[UInt8]()
    encode_streams_blocked(
        StreamsBlockedFrame(unidirectional=True, maximum_streams=UInt64(1)),
        out_uni,
    )
    assert_equal(Int(out_uni[0]), 0x17)


def test_new_connection_id_round_trip() raises:
    var cid = List[UInt8]()
    for i in range(8):
        cid.append(UInt8(i + 1))
    var token = List[UInt8]()
    for _ in range(16):
        token.append(UInt8(0xAA))
    var out = List[UInt8]()
    encode_new_connection_id(
        NewConnectionIdFrame(
            sequence_number=UInt64(3),
            retire_prior_to=UInt64(1),
            connection_id=cid^,
            stateless_reset_token=token^,
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.new_connection_id_seen)
    assert_equal(rec.new_connection_id.sequence_number, UInt64(3))
    assert_equal(rec.new_connection_id.retire_prior_to, UInt64(1))
    assert_equal(len(rec.new_connection_id.connection_id), 8)
    assert_equal(len(rec.new_connection_id.stateless_reset_token), 16)


def test_retire_connection_id_round_trip() raises:
    var out = List[UInt8]()
    encode_retire_connection_id(
        RetireConnectionIdFrame(sequence_number=UInt64(7)), out
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.retire_connection_id_seen)
    assert_equal(rec.retire_connection_id.sequence_number, UInt64(7))


def test_path_challenge_round_trip() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i + 100))
    var out = List[UInt8]()
    encode_path_challenge(PathChallengeFrame(data=data^), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.path_challenge_seen)
    assert_equal(len(rec.path_challenge.data), 8)


def test_path_response_round_trip() raises:
    var data = List[UInt8]()
    for i in range(8):
        data.append(UInt8(i))
    var out = List[UInt8]()
    encode_path_response(PathResponseFrame(data=data^), out)
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.path_response_seen)
    assert_equal(len(rec.path_response.data), 8)


def test_connection_close_transport_round_trip() raises:
    var reason = List[UInt8]()
    for b in String("oops").as_bytes():
        reason.append(b)
    var out = List[UInt8]()
    encode_connection_close(
        ConnectionCloseFrame(
            application=False,
            error_code=UInt64(0x100),
            frame_type=UInt64(FRAME_TYPE_STREAM_BASE),
            reason_phrase=reason^,
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.connection_close_seen)
    assert_false(rec.connection_close.application)
    assert_equal(rec.connection_close.error_code, UInt64(0x100))
    assert_equal(
        rec.connection_close.frame_type, UInt64(FRAME_TYPE_STREAM_BASE)
    )


def test_connection_close_application_round_trip() raises:
    var reason = List[UInt8]()
    for b in String("bye").as_bytes():
        reason.append(b)
    var out = List[UInt8]()
    encode_connection_close(
        ConnectionCloseFrame(
            application=True,
            error_code=UInt64(0x42),
            frame_type=UInt64(0),
            reason_phrase=reason^,
        ),
        out,
    )
    var rec = _empty_recorder()
    _ = parse_frame_into(Span[UInt8, _](out), rec)
    assert_true(rec.connection_close_seen)
    assert_true(rec.connection_close.application)
    assert_equal(rec.connection_close.error_code, UInt64(0x42))


def test_handshake_done_round_trip() raises:
    var out = List[UInt8]()
    encode_handshake_done(out)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0]), 0x1E)
    var rec = _empty_recorder()
    var consumed = parse_frame_into(Span[UInt8, _](out), rec)
    assert_equal(consumed, 1)
    assert_equal(rec.handshake_done_count, 1)


def test_unknown_frame_type_rejected() raises:
    var rec = _empty_recorder()
    var raised = False
    try:
        # 0x1F decodes as a 1-byte varint (high bits 00) but is
        # outside the v1 master table (last codepoint is 0x1E).
        # The dispatcher fires ``on_unknown`` and the strict
        # recorder raises to terminate the connection.
        _ = parse_frame_into(Span[UInt8, _](_bytes(0x1F)), rec)
    except:
        raised = True
    assert_true(raised)


def test_truncated_crypto_rejected() raises:
    # 0x06 (CRYPTO) + offset varint 0 + length varint 8, then only
    # 2 payload bytes -- parser must reject.
    var buf = _bytes(0x06, 0x00, 0x08, 0xAA, 0xBB)
    var rec = _empty_recorder()
    var raised = False
    try:
        _ = parse_frame_into(Span[UInt8, _](buf), rec)
    except:
        raised = True
    assert_true(raised)


def test_datagram_with_length_round_trip() raises:
    var payload = _bytes(0xDE, 0xAD, 0xBE, 0xEF)
    var out = List[UInt8]()
    encode_datagram(DatagramFrame(data=payload.copy(), has_length=True), out)
    assert_equal(Int(out[0]), FRAME_TYPE_DATAGRAM_LEN)
    assert_equal(Int(out[1]), 4)  # explicit length varint
    var rec = _empty_recorder()
    var consumed = parse_frame_into(Span[UInt8, _](out), rec)
    assert_equal(consumed, len(out))
    assert_true(rec.datagram_seen)
    assert_true(rec.datagram.has_length)
    assert_equal(len(rec.datagram.data), 4)
    assert_equal(Int(rec.datagram.data[0]), 0xDE)


def test_datagram_no_length_runs_to_end() raises:
    var payload = _bytes(0x01, 0x02, 0x03)
    var out = List[UInt8]()
    encode_datagram(DatagramFrame(data=payload.copy(), has_length=False), out)
    assert_equal(Int(out[0]), FRAME_TYPE_DATAGRAM_NOLEN)
    assert_equal(len(out), 4)  # type byte + 3 payload, no length prefix
    var rec = _empty_recorder()
    var consumed = parse_frame_into(Span[UInt8, _](out), rec)
    assert_equal(consumed, len(out))
    assert_true(rec.datagram_seen)
    assert_false(rec.datagram.has_length)
    assert_equal(len(rec.datagram.data), 3)


def main() raises:
    test_padding_single_byte()
    test_ping_round_trip()
    test_ack_round_trip()
    test_ack_ecn_round_trip()
    test_reset_stream_round_trip()
    test_stop_sending_round_trip()
    test_crypto_round_trip()
    test_new_token_round_trip()
    test_new_token_empty_rejected()
    test_stream_round_trip_with_offset_and_fin()
    test_stream_round_trip_no_offset_no_fin()
    test_max_data_round_trip()
    test_max_stream_data_round_trip()
    test_max_streams_bidi_and_uni()
    test_data_blocked_round_trip()
    test_stream_data_blocked_round_trip()
    test_streams_blocked_bidi_and_uni()
    test_new_connection_id_round_trip()
    test_retire_connection_id_round_trip()
    test_path_challenge_round_trip()
    test_path_response_round_trip()
    test_connection_close_transport_round_trip()
    test_connection_close_application_round_trip()
    test_handshake_done_round_trip()
    test_unknown_frame_type_rejected()
    test_truncated_crypto_rejected()
    test_datagram_with_length_round_trip()
    test_datagram_no_length_runs_to_end()
    print("test_quic_frame: 28 passed")
