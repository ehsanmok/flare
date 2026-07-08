"""Unit tests for the HTTP/3 frame codec (RFC 9114 §7).

Covers:
- DATA frame round-trip (the most common shape).
- HEADERS frame round-trip.
- SETTINGS frame payload codec (the only structured payload at
  this layer; the others are opaque bytes).
- Empty payload round-trip.
- Unknown frame type acceptance (RFC 9114 §9 says receivers must
  ignore unknown types; the codec must not reject them).
- Grease frame-type detection (RFC 9114 §7.2.8).
- Rejection of truncated payloads.
- Rejection of malformed SETTINGS (identifier without value).
"""

from std.testing import assert_equal, assert_true, assert_false
from std.memory import Span

from flare.http3 import (
    Http3FrameType,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_SETTINGS,
    H3_FRAME_TYPE_GOAWAY,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    Http3Setting,
    decode_http3_frame,
    decode_http3_settings,
    encode_http3_frame,
    encode_http3_settings,
)


def _bytes(*vals: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for v in vals:
        out.append(UInt8(v))
    return out^


def test_data_frame_round_trip() raises:
    """The canonical DATA frame: type=0x00, length=5, payload
    "hello". Encoded form is ``00 05 68 65 6c 6c 6f``."""
    var payload = _bytes(0x68, 0x65, 0x6C, 0x6C, 0x6F)
    var enc = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_DATA, Span[UInt8](payload), enc)
    assert_equal(len(enc), 7)
    assert_equal(Int(enc[0]), 0x00)
    assert_equal(Int(enc[1]), 0x05)
    var dec = decode_http3_frame(Span[UInt8](enc))
    assert_equal(dec.frame_type.raw, H3_FRAME_TYPE_DATA)
    assert_equal(len(dec.payload), 5)
    assert_equal(Int(dec.payload[0]), 0x68)
    assert_equal(Int(dec.payload[4]), 0x6F)


def test_headers_frame_round_trip() raises:
    """HEADERS frame type=0x01. Payload is opaque to the frame
    codec (QPACK-encoded; QPACK is a separate codec module)."""
    var payload = _bytes(0xC0, 0xC1, 0xC2)  # placeholder QPACK bytes
    var enc = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_HEADERS, Span[UInt8](payload), enc)
    var dec = decode_http3_frame(Span[UInt8](enc))
    assert_equal(dec.frame_type.raw, H3_FRAME_TYPE_HEADERS)
    assert_equal(len(dec.payload), 3)


def test_settings_frame_payload_round_trip() raises:
    """Three SETTINGS pairs round-trip through encode_http3_settings
    + decode_http3_settings."""
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            value=UInt64(4096),
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
            value=UInt64(65536),
        )
    )
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_BLOCKED_STREAMS,
            value=UInt64(0),
        )
    )
    var payload = List[UInt8]()
    encode_http3_settings(settings, payload)
    var decoded = decode_http3_settings(Span[UInt8](payload))
    assert_equal(len(decoded), 3)
    assert_equal(decoded[0].identifier, H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    assert_equal(decoded[0].value, UInt64(4096))
    assert_equal(decoded[1].identifier, H3_SETTINGS_MAX_FIELD_SECTION_SIZE)
    assert_equal(decoded[1].value, UInt64(65536))
    assert_equal(decoded[2].identifier, H3_SETTINGS_QPACK_BLOCKED_STREAMS)
    assert_equal(decoded[2].value, UInt64(0))


def test_settings_frame_complete_wrap() raises:
    """Full SETTINGS frame: encode payload, wrap in a frame, decode
    back through ``decode_http3_frame`` + ``decode_http3_settings``."""
    var settings = List[Http3Setting]()
    settings.append(
        Http3Setting(
            identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            value=UInt64(1024),
        )
    )
    var payload = List[UInt8]()
    encode_http3_settings(settings, payload)
    var enc = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8](payload), enc)
    var dec = decode_http3_frame(Span[UInt8](enc))
    assert_equal(dec.frame_type.raw, H3_FRAME_TYPE_SETTINGS)
    var pairs = decode_http3_settings(Span[UInt8](dec.payload))
    assert_equal(len(pairs), 1)
    assert_equal(pairs[0].value, UInt64(1024))


def test_empty_payload_round_trip() raises:
    """A frame with a zero-length payload is legal (e.g. an
    empty DATA frame trailer)."""
    var empty = List[UInt8]()
    var enc = List[UInt8]()
    encode_http3_frame(H3_FRAME_TYPE_DATA, Span[UInt8](empty), enc)
    assert_equal(len(enc), 2)  # type + length, no payload
    assert_equal(Int(enc[0]), 0x00)
    assert_equal(Int(enc[1]), 0x00)
    var dec = decode_http3_frame(Span[UInt8](enc))
    assert_equal(dec.frame_type.raw, H3_FRAME_TYPE_DATA)
    assert_equal(len(dec.payload), 0)


def test_unknown_frame_type_accepted() raises:
    """RFC 9114 §9 — receivers MUST ignore (not reject) unknown
    frame types. The codec surfaces them as ``Http3Frame`` with
    ``frame_type.is_known() == False``."""
    var payload = _bytes(0xAA)
    var enc = List[UInt8]()
    encode_http3_frame(UInt64(0x42), Span[UInt8](payload), enc)
    var dec = decode_http3_frame(Span[UInt8](enc))
    assert_equal(dec.frame_type.raw, UInt64(0x42))
    assert_false(dec.frame_type.is_known())


def test_grease_frame_type_detection() raises:
    """Grease types fit ``0x1f * N + 0x21`` per RFC 9114 §7.2.8.
    0x21 (N=0), 0x40 (N=1), 0x5F (N=2) are the first three."""
    var grease0 = Http3FrameType(raw=UInt64(0x21))
    var grease1 = Http3FrameType(raw=UInt64(0x40))
    var grease2 = Http3FrameType(raw=UInt64(0x5F))
    assert_true(grease0.is_reserved_grease())
    assert_true(grease1.is_reserved_grease())
    assert_true(grease2.is_reserved_grease())
    # DATA (0x00) is not grease.
    var data = Http3FrameType(raw=H3_FRAME_TYPE_DATA)
    assert_false(data.is_reserved_grease())
    # HEADERS (0x01) is not grease.
    var hdr = Http3FrameType(raw=H3_FRAME_TYPE_HEADERS)
    assert_false(hdr.is_reserved_grease())


def test_decoder_rejects_truncated_payload() raises:
    """Declared length 10 but only 3 payload bytes available
    must raise rather than returning a short payload."""
    var buf = _bytes(0x00, 0x0A, 0x01, 0x02, 0x03)
    var raised = False
    try:
        _ = decode_http3_frame(Span[UInt8](buf))
    except _:
        raised = True
    assert_true(raised)


def test_decoder_rejects_empty_buffer() raises:
    var raised = False
    var empty = List[UInt8]()
    try:
        _ = decode_http3_frame(Span[UInt8](empty))
    except _:
        raised = True
    assert_true(raised)


def test_settings_decoder_rejects_dangling_identifier() raises:
    """A payload with an identifier varint but no value varint
    must be rejected."""
    var buf = _bytes(0x01)  # identifier=1, no value
    var raised = False
    try:
        _ = decode_http3_settings(Span[UInt8](buf))
    except _:
        raised = True
    assert_true(raised)


def main() raises:
    test_data_frame_round_trip()
    test_headers_frame_round_trip()
    test_settings_frame_payload_round_trip()
    test_settings_frame_complete_wrap()
    test_empty_payload_round_trip()
    test_unknown_frame_type_accepted()
    test_grease_frame_type_detection()
    test_decoder_rejects_truncated_payload()
    test_decoder_rejects_empty_buffer()
    test_settings_decoder_rejects_dangling_identifier()
    print("test_h3_frame: OK")
