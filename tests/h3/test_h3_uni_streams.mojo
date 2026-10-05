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
from flare.http3.server import (
    H3_FRAME_UNEXPECTED,
    H3_SETTINGS_ERROR,
    H3_STREAM_CREATION_ERROR,
    h3_error_code,
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


def test_client_push_stream_is_refused() raises:
    """H3-05: a push stream (type 0x01) opened by a client was recorded
    and its bytes dropped. A server that receives one MUST treat it as a
    connection error of type H3_STREAM_CREATION_ERROR (RFC 9114 sec
    6.2.2). This test used to assert the stream was tolerated."""
    var c = Http3Connection()
    var push = List[UInt8]()
    push.append(UInt8(0x01))
    push.append(UInt8(0xAA))
    push.append(UInt8(0xBB))
    var msg = _raises_with(c, 15, push^)
    assert_true("H3_STREAM_CREATION_ERROR" in msg, "push stream accepted")
    assert_equal(Int(h3_error_code(msg)), Int(H3_STREAM_CREATION_ERROR))
    assert_false(15 in c.peer_uni_kinds)


def test_second_qpack_stream_of_either_type_is_refused() raises:
    """H3-05: a second QPACK encoder (or decoder) stream overwrote the
    recorded stream id. RFC 9204 sec 4.2: it MUST be a connection error of
    type H3_STREAM_CREATION_ERROR."""
    var c = Http3Connection()
    var enc = List[UInt8]()
    enc.append(UInt8(0x02))
    c.feed_uni_stream_chunk(2, enc.copy())
    var msg = _raises_with(c, 6, enc.copy())
    assert_true("H3_STREAM_CREATION_ERROR" in msg, "second encoder accepted")
    assert_equal(Int(h3_error_code(msg)), Int(H3_STREAM_CREATION_ERROR))
    assert_equal(c.peer_qpack_encoder_stream_id, 2)

    var d = Http3Connection()
    var dec = List[UInt8]()
    dec.append(UInt8(0x03))
    d.feed_uni_stream_chunk(2, dec.copy())
    var dmsg = _raises_with(d, 6, dec.copy())
    assert_true("H3_STREAM_CREATION_ERROR" in dmsg, "second decoder accepted")
    assert_equal(d.peer_qpack_decoder_stream_id, 2)
    # More data on the first stream is not a second stream.
    var more = List[UInt8]()
    more.append(UInt8(0x00))
    d.feed_uni_stream_chunk(2, more^)
    assert_equal(d.peer_qpack_decoder_stream_id, 2)


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


def test_take_control_stream_start_is_once_and_decodes_at_the_peer() raises:
    """H3-07: the server initiates its control stream (stream 3) and
    sends type 0x00 + SETTINGS first (RFC 9114 sec 6.2.1, 7.2.4). The
    bytes are handed over once, and a peer driver reading them as stream 3
    classifies it as the control stream and learns the settings."""
    var cfg = Http3Config()
    cfg.max_field_section_size = UInt64(4096)
    cfg.qpack_max_table_capacity = UInt64(512)
    cfg.qpack_blocked_streams = UInt64(7)
    cfg.enable_connect_protocol = True
    var server = Http3Connection.with_config(cfg)
    assert_equal(server.control_stream_id, -1)
    var start = server.take_control_stream_start()
    assert_equal(server.control_stream_id, 3)
    var expected = server.emit_initial_settings()
    assert_equal(len(start), len(expected))
    for i in range(len(start)):
        assert_equal(Int(start[i]), Int(expected[i]))
    assert_equal(Int(start[0]), 0x00)
    assert_equal(len(server.take_control_stream_start()), 0)

    var peer = Http3Connection()
    peer.feed_uni_stream_chunk(3, start^)
    assert_equal(peer.peer_control_stream_id, 3)
    assert_true(peer.peer_settings_received)
    assert_equal(peer.peer_settings_max_field_section_size, UInt64(4096))
    assert_equal(peer.peer_settings_qpack_max_table_capacity, UInt64(512))
    assert_equal(peer.peer_settings_qpack_blocked_streams, UInt64(7))
    assert_true(peer.peer_settings_enable_connect_protocol)


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


def _settings_prefix() raises -> List[UInt8]:
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(1024),
        )
    )
    return _build_peer_control_prefix(settings^)


def test_control_frame_header_split_across_chunks() raises:
    """A frame whose length varint straddled two chunks made
    decode_varint raise out of the control-stream parser, ending the
    connection. It now waits for the rest."""
    var c = Http3Connection()
    c.feed_uni_stream_chunk(3, _settings_prefix())
    # A reserved (grease) frame type with a 100-byte payload: its length
    # is a two-byte varint, 0x40 0x64.
    var frame = List[UInt8]()
    frame.append(UInt8(0x21))
    frame.append(UInt8(0x40))
    frame.append(UInt8(0x64))
    for _ in range(100):
        frame.append(UInt8(0))
    var head = List[UInt8](Span[UInt8, _](frame)[:2])  # splits the length
    var tail = List[UInt8](Span[UInt8, _](frame)[2:])
    c.feed_uni_stream_chunk(3, head^)
    c.feed_uni_stream_chunk(3, tail^)
    c.feed_uni_stream_chunk(3, _build_goaway_frame(UInt64(16)))
    assert_equal(c.peer_goaway_max_stream_id, UInt64(16))


def test_oversized_control_frame_is_refused_from_its_header() raises:
    """The control-stream carry grew for as long as a declared frame
    length stayed unmet."""
    var c = Http3Connection()
    c.feed_uni_stream_chunk(3, _settings_prefix())
    var frame = List[UInt8]()
    frame.append(UInt8(0x21))
    var ln = encode_varint(UInt64(1 << 30))
    for b in ln:
        frame.append(b)
    var raised = False
    try:
        c.feed_uni_stream_chunk(3, frame^)
    except:
        raised = True
    assert_true(raised, "a 1 GiB control frame header was accepted")


def _raises_with(
    mut c: Http3Connection, stream_id: Int, var chunk: List[UInt8]
) -> String:
    """The error text ``feed_uni_stream_chunk`` raised, or ""."""
    try:
        c.feed_uni_stream_chunk(stream_id, chunk^)
    except e:
        return String(e)
    return String("")


def test_forbidden_frame_types_on_the_control_stream_are_refused() raises:
    """H3-03: after SETTINGS, DATA (0x00), HEADERS (0x01), PUSH_PROMISE
    (0x05) and the HTTP/2-reserved types 0x02 / 0x06 / 0x08 / 0x09 were
    silently dropped. Each is a connection error of type
    H3_FRAME_UNEXPECTED (RFC 9114 sec 7.2.1, 7.2.2, 7.2.5, 7.2.8)."""
    var forbidden = _bytes_from_list([0x00, 0x01, 0x05, 0x02, 0x06, 0x08, 0x09])
    for i in range(len(forbidden)):
        var c = Http3Connection()
        c.feed_uni_stream_chunk(3, _settings_prefix())
        var frame = List[UInt8]()
        frame.append(forbidden[i])
        frame.append(UInt8(0))  # empty payload
        var msg = _raises_with(c, 3, frame^)
        assert_true(
            "H3_FRAME_UNEXPECTED" in msg,
            "forbidden control frame type " + String(Int(forbidden[i])),
        )
        assert_equal(Int(h3_error_code(msg)), Int(H3_FRAME_UNEXPECTED))


def test_allowed_control_frames_are_still_accepted() raises:
    """The H3-03 check is not a blanket rejection: CANCEL_PUSH, MAX_PUSH_ID,
    GOAWAY and unknown / grease types stay legal on the control stream."""
    var c = Http3Connection()
    c.feed_uni_stream_chunk(3, _settings_prefix())
    var frames = List[UInt8]()
    frames.append(UInt8(0x03))  # CANCEL_PUSH, push id 0
    frames.append(UInt8(1))
    frames.append(UInt8(0))
    frames.append(UInt8(0x0D))  # MAX_PUSH_ID, id 4
    frames.append(UInt8(1))
    frames.append(UInt8(4))
    frames.append(UInt8(0x21))  # grease, empty
    frames.append(UInt8(0))
    c.feed_uni_stream_chunk(3, frames^)
    c.feed_uni_stream_chunk(3, _build_goaway_frame(UInt64(8)))
    assert_equal(Int(c.peer_goaway_max_stream_id), 8)


def test_http2_reserved_setting_identifiers_are_refused() raises:
    """H3-04: SETTINGS identifiers 0x02..0x05 (HTTP/2 ENABLE_PUSH,
    MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE) were
    ignored like unknown ones. Their receipt is a connection error of
    type H3_SETTINGS_ERROR (RFC 9114 sec 7.2.4.1, 11.2.2)."""
    for sid in range(2, 6):
        var c = Http3Connection()
        var settings = List[Http3Setting]()
        settings.append(
            Http3Setting(
                identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
                value=UInt64(1024),
            )
        )
        settings.append(Http3Setting(identifier=UInt64(sid), value=UInt64(1)))
        var msg = _raises_with(c, 3, _build_peer_control_prefix(settings))
        assert_true(
            "H3_SETTINGS_ERROR" in msg,
            "reserved setting identifier " + String(sid) + " was accepted",
        )
        assert_equal(Int(h3_error_code(msg)), Int(H3_SETTINGS_ERROR))
        assert_false(c.peer_settings_received)


def test_unknown_and_known_setting_identifiers_are_still_accepted() raises:
    """The H3-04 check is exactly 0x02..0x05: the neighbours 0x01 and 0x06,
    greased identifiers and unknown ones keep working."""
    var c = Http3Connection()
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            value=UInt64(256),
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE, value=UInt64(2048)
        )
    )
    settings.append(Http3Setting(identifier=UInt64(0x0A), value=UInt64(9)))
    settings.append(Http3Setting(identifier=UInt64(0x21), value=UInt64(7)))
    c.feed_uni_stream_chunk(3, _build_peer_control_prefix(settings))
    assert_true(c.peer_settings_received)
    assert_equal(Int(c.peer_settings_qpack_max_table_capacity), 256)
    assert_equal(Int(c.peer_settings_max_field_section_size), 2048)


def main() raises:
    test_peer_control_stream_settings_round_trip()
    test_uni_stream_type_varint_split_across_chunks()
    test_qpack_uni_stream_kinds_are_recorded()
    test_client_push_stream_is_refused()
    test_second_qpack_stream_of_either_type_is_refused()
    test_grease_uni_stream_codepoint_tolerated()
    test_settings_twice_is_frame_unexpected()
    test_non_settings_before_settings_is_missing_settings()
    test_goaway_records_peer_max_stream_id()
    test_second_peer_control_stream_raises()
    test_emit_initial_settings_round_trips()
    test_emit_goaway_flips_flag_and_double_emit_raises()
    test_control_frame_header_split_across_chunks()
    test_oversized_control_frame_is_refused_from_its_header()
    test_take_control_stream_start_is_once_and_decodes_at_the_peer()
    test_forbidden_frame_types_on_the_control_stream_are_refused()
    test_allowed_control_frames_are_still_accepted()
    test_http2_reserved_setting_identifiers_are_refused()
    test_unknown_and_known_setting_identifiers_are_still_accepted()
    print("test_h3_uni_streams: 19 passed")
