"""Tests for ``flare.http2.state`` (RFC 9113 state machines, — Track J).

Covers:

- Initial SETTINGS frame from the server is well-formed.
- Inbound SETTINGS frame is ACK'd.
- HEADERS on stream 0 raises (RFC 9113 §5.1.1).
- HEADERS + END_STREAM transitions to ``HALF_CLOSED_REMOTE``.
- DATA appends to the stream's body and emits a WINDOW_UPDATE.
- WINDOW_UPDATE adjusts the connection / stream send window.
- PING auto-replies with ACK.
- ``make_response`` produces ``HEADERS [+ DATA]`` with the right
  flags (``END_HEADERS`` always; ``END_STREAM`` on the last frame).
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http2.frame import (
    Frame,
    FrameFlags,
    FrameType,
    encode_frame,
    parse_frame,
)
from flare.http2.hpack import HpackEncoder, HpackHeader
from flare.http2.state import Connection, StreamState


def _bytes(b: List[Int]) -> List[UInt8]:
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(UInt8(b[i]))
    return out^


def test_initial_settings_is_one_setting() raises:
    var c = Connection()
    var f = c.initial_settings()
    assert_equal(Int(f.header.type.value), 0x4)
    assert_equal(f.header.stream_id, 0)
    assert_equal(len(f.payload), 6)
    var id = (Int(f.payload[0]) << 8) | Int(f.payload[1])
    assert_equal(id, 0x3)  # SETTINGS_MAX_CONCURRENT_STREAMS


def test_inbound_settings_acks() raises:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.SETTINGS()
    var out = c.handle_frame(f^)
    assert_equal(len(out), 1)
    assert_true(out[0].header.flags.has(FrameFlags.ACK()))
    assert_equal(Int(out[0].header.type.value), 0x4)


def test_settings_ack_recorded() raises:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.SETTINGS()
    f.header.flags = FrameFlags(FrameFlags.ACK())
    _ = c.handle_frame(f^)
    assert_true(c.settings_acked)


def test_headers_on_stream_0_raises() raises:
    var c = Connection()
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":path", "/"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 0
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    with assert_raises():
        _ = c.handle_frame(f^)


def test_headers_end_stream_transitions_to_half_closed_remote() raises:
    var c = Connection()
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":path", "/api"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    _ = c.handle_frame(f^)
    assert_true(1 in c.streams)
    var s = c.streams[1].copy()
    assert_equal(s.state.value, StreamState.HALF_CLOSED_REMOTE().value)
    assert_true(s.headers_complete)
    assert_true(s.data_complete)
    assert_equal(len(s.headers), 2)


def test_data_appends_and_emits_window_update() raises:
    var c = Connection()
    # Open the stream first via HEADERS.
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "POST"))
    hdrs.append(HpackHeader(":path", "/upload"))
    var hf = Frame()
    hf.header.type = FrameType.HEADERS()
    hf.header.stream_id = 3
    hf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    hf.payload = enc.encode(Span[HpackHeader, _](hdrs))
    _ = c.handle_frame(hf^)

    var df = Frame()
    df.header.type = FrameType.DATA()
    df.header.stream_id = 3
    df.header.flags = FrameFlags(FrameFlags.END_STREAM())
    df.payload = List[UInt8]("hello".as_bytes())
    var out = c.handle_frame(df^)
    var s = c.streams[3].copy()
    assert_equal(len(s.data), 5)
    assert_true(s.data_complete)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0].header.type.value), 0x8)  # WINDOW_UPDATE


def test_window_update_adjusts_send_window() raises:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.WINDOW_UPDATE()
    f.header.stream_id = 0
    f.payload = List[UInt8]()
    f.payload.append(UInt8(0x00))
    f.payload.append(UInt8(0x00))
    f.payload.append(UInt8(0x10))
    f.payload.append(UInt8(0x00))  # +4096
    var before = c.send_window
    _ = c.handle_frame(f^)
    assert_equal(c.send_window, before + 4096)


def test_ping_auto_replies_with_ack() raises:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.PING()
    f.header.stream_id = 0
    var pdat = List[Int]()
    pdat.append(1)
    pdat.append(2)
    pdat.append(3)
    pdat.append(4)
    pdat.append(5)
    pdat.append(6)
    pdat.append(7)
    pdat.append(8)
    f.payload = _bytes(pdat)
    var out = c.handle_frame(f^)
    assert_equal(len(out), 1)
    assert_true(out[0].header.flags.has(FrameFlags.ACK()))
    assert_equal(Int(out[0].header.type.value), 0x6)
    assert_equal(len(out[0].payload), 8)


def test_make_response_no_body_sets_end_stream_on_headers() raises:
    var c = Connection()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader("content-length", "0"))
    var body = List[UInt8]()
    var frames = c.make_response(
        1, 200, Span[HpackHeader, _](hdrs), Span[UInt8, _](body)
    )
    assert_equal(len(frames), 1)
    assert_true(frames[0].header.flags.has(FrameFlags.END_HEADERS()))
    assert_true(frames[0].header.flags.has(FrameFlags.END_STREAM()))


def test_make_response_with_body_emits_two_frames() raises:
    var c = Connection()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader("content-type", "text/plain"))
    var body = List[UInt8]("ok".as_bytes())
    var frames = c.make_response(
        1, 200, Span[HpackHeader, _](hdrs), Span[UInt8, _](body)
    )
    assert_equal(len(frames), 2)
    assert_equal(Int(frames[0].header.type.value), 0x1)  # HEADERS
    assert_true(frames[0].header.flags.has(FrameFlags.END_HEADERS()))
    assert_false(frames[0].header.flags.has(FrameFlags.END_STREAM()))
    assert_equal(Int(frames[1].header.type.value), 0x0)  # DATA
    assert_true(frames[1].header.flags.has(FrameFlags.END_STREAM()))
    assert_equal(len(frames[1].payload), 2)


def test_priority_accepted_and_ignored() raises:
    var c = Connection()
    var f = Frame()
    f.header.type = FrameType.PRIORITY()
    f.header.stream_id = 1
    var pdat = List[Int]()
    pdat.append(0)
    pdat.append(0)
    pdat.append(0)
    pdat.append(0)
    pdat.append(0)
    f.payload = _bytes(pdat)
    var out = c.handle_frame(f^)
    assert_equal(len(out), 0)


def main() raises:
    test_initial_settings_is_one_setting()
    test_inbound_settings_acks()
    test_settings_ack_recorded()
    test_headers_on_stream_0_raises()
    test_headers_end_stream_transitions_to_half_closed_remote()
    test_data_appends_and_emits_window_update()
    test_window_update_adjusts_send_window()
    test_ping_auto_replies_with_ack()
    test_make_response_no_body_sets_end_stream_on_headers()
    test_make_response_with_body_emits_two_frames()
    test_priority_accepted_and_ignored()
    print("test_h2_state: 11 passed")
