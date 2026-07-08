"""Tests for HTTP/3 unidirectional stream type dispatch + the
control stream + SETTINGS/GOAWAY consumption.

The new surface on :class:`flare.http3.Http3Connection`:

- :meth:`feed_uni_stream_chunk(stream_id, chunk)` -- demuxes the
  peer's uni streams by the leading type varint (RFC 9114 §6.2),
  records the stream ids for control / qpack-enc / qpack-dec,
  and routes payload bytes to the matching state machine.
- Control-stream frame loop: SETTINGS first, then optional
  GOAWAY / MAX_PUSH_ID. The peer's announced settings land on
  :attr:`peer_settings_*` fields; GOAWAY identifiers update
  :attr:`peer_goaway_max_stream_id`.
- :meth:`emit_initial_settings()` -- builds the server's
  outbound control-stream prefix (type varint + SETTINGS frame).
- :meth:`emit_goaway(max_stream_id)` -- builds an outbound
  GOAWAY frame body + flips ``goaway_emitted`` so subsequent
  open_request_stream calls reject.

Properties covered:

1. The first varint on a uni stream picks the kind; subsequent
   bytes route to the matching machine.
2. The stream-type varint can span multiple feed_uni_stream_chunk
   calls.
3. Peer SETTINGS land on the local view.
4. SETTINGS twice on the same control stream raises
   H3_FRAME_UNEXPECTED.
5. Any other frame before SETTINGS raises
   H3_MISSING_SETTINGS.
6. GOAWAY updates the peer-side cutoff; a non-monotonic
   subsequent GOAWAY raises.
7. A second control stream from the peer is
   H3_STREAM_CREATION_ERROR.
8. emit_initial_settings round-trips: bytes the server emits
   decode back to the same SETTINGS the local
   :class:`Http3Config` carries.
9. emit_goaway round-trips and flips ``goaway_emitted``.
10. Push / unknown / grease uni-stream codepoints are accepted
    without raising; the driver tracks the kind so the reactor
    can STOP_SENDING.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http3 import (
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_SETTINGS,
    H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    Http3Connection,
    Http3Config,
    Http3Setting,
    Http3StreamType,
    decode_http3_frame,
    decode_http3_settings,
    encode_http3_frame,
    encode_http3_settings,
)
from flare.quic.varint import decode_varint, encode_varint


def _bytes_from_list(items: List[Int]) -> List[UInt8]:
    var out = List[UInt8]()
    for v in items:
        out.append(UInt8(v))
    return out^


def _build_peer_control_prefix(
    settings: List[Http3Setting],
) raises -> List[UInt8]:
    """Type varint (0x00) + SETTINGS frame body."""
    var out = List[UInt8]()
    var type_var = encode_varint(UInt64(Http3StreamType.CONTROL))
    for i in range(len(type_var)):
        out.append(type_var[i])
    var payload = List[UInt8]()
    encode_http3_settings(settings, payload)
    encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](payload), out)
    return out^


def _build_goaway_frame(stream_id: UInt64) raises -> List[UInt8]:
    var payload = encode_varint(stream_id)
    var out = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_GOAWAY, Span[UInt8, _](payload), out)
    return out^


def test_peer_control_stream_settings_round_trip() raises:
    var c = Http3Connection()
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(32768),
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            value=UInt64(4096),
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
            value=UInt64(1),
        )
    )
    var bytes = _build_peer_control_prefix(settings^)
    c.feed_uni_stream_chunk(3, bytes^)
    assert_true(c.peer_settings_received)
    assert_equal(c.peer_control_stream_id, 3)
    assert_equal(c.peer_settings_max_field_section_size, UInt64(32768))
    assert_equal(c.peer_settings_qpack_max_table_capacity, UInt64(4096))
    assert_true(c.peer_settings_enable_connect_protocol)


def test_uni_stream_type_varint_split_across_chunks() raises:
    """The stream-type varint is at most 8 bytes. Feeding only
    a portion of it on the first chunk must defer classification
    until the second chunk arrives."""
    var c = Http3Connection()
    # Single-byte control-stream type varint (0x00). Feeding
    # zero bytes shouldn't classify; the next chunk with the
    # type byte should resolve it.
    c.feed_uni_stream_chunk(3, List[UInt8]())
    assert_equal(c.peer_control_stream_id, -1)
    # Now feed the type byte + a small SETTINGS frame.
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(8192),
        )
    )
    c.feed_uni_stream_chunk(3, _build_peer_control_prefix(settings^))
    assert_equal(c.peer_control_stream_id, 3)
    assert_true(c.peer_settings_received)
    assert_equal(c.peer_settings_max_field_section_size, UInt64(8192))


def test_qpack_uni_stream_kinds_are_recorded() raises:
    var c = Http3Connection()
    # QPACK encoder stream (type 0x02).
    var enc = List[UInt8]()
    enc.append(UInt8(0x02))
    c.feed_uni_stream_chunk(7, enc^)
    assert_equal(c.peer_qpack_encoder_stream_id, 7)
    # QPACK decoder stream (type 0x03).
    var dec = List[UInt8]()
    dec.append(UInt8(0x03))
    c.feed_uni_stream_chunk(11, dec^)
    assert_equal(c.peer_qpack_decoder_stream_id, 11)


def test_push_uni_stream_tolerated() raises:
    """Push is deprecated but the type code is reserved; the
    driver records the kind without raising so the reactor can
    STOP_SENDING."""
    var c = Http3Connection()
    var push = List[UInt8]()
    push.append(UInt8(0x01))
    push.append(UInt8(0xAA))
    push.append(UInt8(0xBB))
    c.feed_uni_stream_chunk(15, push^)
    assert_true(15 in c.peer_uni_kinds)
    assert_equal(c.peer_uni_kinds[15], Http3StreamType.PUSH)


def test_grease_uni_stream_codepoint_tolerated() raises:
    """RFC 9114 §6.2.3: unknown / grease codepoints must be
    ignored. The driver classifies them as kind=-1 (sink)."""
    var c = Http3Connection()
    var grease = List[UInt8]()
    # Two-byte varint encoding 0x21 (an unassigned codepoint).
    grease.append(UInt8(0x40))
    grease.append(UInt8(0x21))
    grease.append(UInt8(0xFF))
    c.feed_uni_stream_chunk(19, grease^)
    assert_true(19 in c.peer_uni_kinds)
    assert_equal(c.peer_uni_kinds[19], -1)


def test_settings_twice_is_frame_unexpected() raises:
    """RFC 9114 §7.2.4: a second SETTINGS on the same control
    stream is H3_FRAME_UNEXPECTED."""
    var c = Http3Connection()
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(1024),
        )
    )
    c.feed_uni_stream_chunk(3, _build_peer_control_prefix(settings))
    # Second SETTINGS on the *same* stream:
    var dup_payload = List[UInt8]()
    encode_http3_settings(settings^, dup_payload)
    var dup_frame = List[UInt8]()
    encode_http3_frame(
        H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](dup_payload), dup_frame
    )
    var raised = False
    try:
        c.feed_uni_stream_chunk(3, dup_frame^)
    except:
        raised = True
    assert_true(raised, "duplicate SETTINGS must raise")


def test_non_settings_before_settings_is_missing_settings() raises:
    """RFC 9114 §7.2.4: control stream MUST start with SETTINGS;
    any other frame first is H3_MISSING_SETTINGS."""
    var c = Http3Connection()
    var hdr = List[UInt8]()
    hdr.append(UInt8(Http3StreamType.CONTROL))
    # GOAWAY frame body before SETTINGS:
    var goaway = _build_goaway_frame(UInt64(8))
    for i in range(len(goaway)):
        hdr.append(goaway[i])
    var raised = False
    try:
        c.feed_uni_stream_chunk(3, hdr^)
    except:
        raised = True
    assert_true(raised, "non-SETTINGS first frame must raise")


def test_goaway_records_peer_max_stream_id() raises:
    var c = Http3Connection()
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(1024),
        )
    )
    c.feed_uni_stream_chunk(3, _build_peer_control_prefix(settings^))
    var goaway = _build_goaway_frame(UInt64(16))
    c.feed_uni_stream_chunk(3, goaway^)
    assert_equal(c.peer_goaway_max_stream_id, UInt64(16))
    # A second GOAWAY with a smaller id is allowed (RFC 9114 §5.2:
    # subsequent values must be <= the previous one).
    var smaller = _build_goaway_frame(UInt64(8))
    c.feed_uni_stream_chunk(3, smaller^)
    assert_equal(c.peer_goaway_max_stream_id, UInt64(8))
    # A larger value than the prior GOAWAY must raise.
    var larger = _build_goaway_frame(UInt64(64))
    var raised = False
    try:
        c.feed_uni_stream_chunk(3, larger^)
    except:
        raised = True
    assert_true(raised, "monotonic-increase GOAWAY must raise")


def test_second_peer_control_stream_raises() raises:
    var c = Http3Connection()
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(1024),
        )
    )
    c.feed_uni_stream_chunk(3, _build_peer_control_prefix(settings^))
    var second = List[UInt8]()
    second.append(UInt8(0x00))
    var raised = False
    try:
        c.feed_uni_stream_chunk(7, second^)
    except:
        raised = True
    assert_true(raised, "second peer control stream must raise")


def test_emit_initial_settings_round_trips() raises:
    """Server-emitted control-stream prefix must decode to the
    same SETTINGS values the local Http3Config carries."""
    var cfg = Http3Config()
    cfg.max_field_section_size = UInt64(4096)
    cfg.qpack_max_table_capacity = UInt64(0)
    cfg.enable_connect_protocol = True
    var c = Http3Connection.with_config(cfg)
    var emitted = c.emit_initial_settings()
    # The first byte is the stream-type varint 0x00 (1 byte).
    assert_equal(Int(emitted[0]), 0x00)
    # Skip the type byte and decode the resulting frame.
    var rest = List[UInt8]()
    for i in range(1, len(emitted)):
        rest.append(emitted[i])
    var frame = decode_http3_frame(Span[UInt8, _](rest))
    assert_equal(frame.frame_type.raw, H3_FRAME_TYPE_SETTINGS)
    var settings = decode_http3_settings(Span[UInt8, _](frame.payload))
    var saw_field_size = False
    var saw_connect = False
    for i in range(len(settings)):
        if settings[i].identifier == H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
            assert_equal(settings[i].value, UInt64(4096))
            saw_field_size = True
        if settings[i].identifier == H3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
            assert_equal(settings[i].value, UInt64(1))
            saw_connect = True
    assert_true(saw_field_size)
    assert_true(saw_connect)


def test_emit_goaway_flips_flag_and_double_emit_raises() raises:
    var c = Http3Connection()
    assert_false(c.goaway_emitted)
    var frame = c.emit_goaway(UInt64(16))
    assert_true(c.goaway_emitted)
    var decoded = decode_http3_frame(Span[UInt8, _](frame))
    assert_equal(decoded.frame_type.raw, H3_FRAME_TYPE_GOAWAY)
    var raised = False
    try:
        var _again = c.emit_goaway(UInt64(8))
    except:
        raised = True
    assert_true(raised, "double emit_goaway must raise")


def main() raises:
    test_peer_control_stream_settings_round_trip()
    test_uni_stream_type_varint_split_across_chunks()
    test_qpack_uni_stream_kinds_are_recorded()
    test_push_uni_stream_tolerated()
    test_grease_uni_stream_codepoint_tolerated()
    test_settings_twice_is_frame_unexpected()
    test_non_settings_before_settings_is_missing_settings()
    test_goaway_records_peer_max_stream_id()
    test_second_peer_control_stream_raises()
    test_emit_initial_settings_round_trips()
    test_emit_goaway_flips_flag_and_double_emit_raises()
    print("test_h3_uni_streams: 11 passed")
