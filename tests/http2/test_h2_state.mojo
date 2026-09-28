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
    hdrs.append(HpackHeader(":scheme", "http"))
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
    hdrs.append(HpackHeader(":scheme", "http"))
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
    assert_equal(len(s.headers), 3)


def test_data_appends_and_emits_window_update() raises:
    var c = Connection()
    # Open the stream first via HEADERS.
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "POST"))
    hdrs.append(HpackHeader(":scheme", "http"))
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
    assert_equal(len(out), 2)  # Credit both the stream and the connection.
    assert_equal(Int(out[0].header.type.value), 0x8)  # WINDOW_UPDATE
    assert_equal(Int(out[1].header.type.value), 0x8)
    assert_equal(out[0].header.stream_id, 3)
    assert_equal(out[1].header.stream_id, 0)
    assert_equal(s.recv_window, 65535)


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


def test_oversized_header_list_rsts_enhance_your_calm() raises:
    var c = Connection()
    c.max_header_list_size = 100
    var big = String()
    for _ in range(200):
        big += "x"
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":path", big))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    var out = c.handle_frame(f^)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0].header.type.value), 0x3)  # RST_STREAM
    assert_equal(Int(out[0].payload[3]), 0xB)  # ENHANCE_YOUR_CALM
    var s = c.streams[1].copy()
    assert_equal(s.state.value, StreamState.CLOSED().value)


def test_continuation_flood_rsts() raises:
    var c = Connection()
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "http"))
    var hf = Frame()
    hf.header.type = FrameType.HEADERS()
    hf.header.stream_id = 1
    hf.header.flags = FrameFlags(UInt8(0))  # END_HEADERS not set
    hf.payload = enc.encode(Span[HpackHeader, _](hdrs))
    _ = c.handle_frame(hf^)
    # The flood is answered with GOAWAY, not RST_STREAM: an
    # unterminated header block leaves the connection-wide HPACK
    # context unresynchronisable, so there is no safe way to keep
    # serving the other streams.
    var goaway_seen = False
    for _ in range(70):
        var cf = Frame()
        cf.header.type = FrameType.CONTINUATION()
        cf.header.stream_id = 1
        cf.header.flags = FrameFlags(UInt8(0))
        cf.payload = List[UInt8]()
        var out = c.handle_frame(cf^)
        if len(out) > 0 and Int(out[0].header.type.value) == 0x7:
            assert_equal(Int(out[0].payload[7]), 0xB)
            goaway_seen = True
            break
    assert_true(goaway_seen)


def test_rst_flood_triggers_goaway() raises:
    var c = Connection()
    # The peer opened stream 1 before flooding. Without this the very
    # first RST_STREAM is a connection error under RFC 9113 sec 6.4
    # (RST on an idle stream), which is a different -- and stricter --
    # rejection than the rapid-reset guard being tested here.
    c.last_peer_stream_id = 1
    var goaway_seen = False
    for _ in range(501):
        var rf = Frame()
        rf.header.type = FrameType.RST_STREAM()
        rf.header.stream_id = 1
        var rp = List[UInt8]()
        rp.append(UInt8(0))
        rp.append(UInt8(0))
        rp.append(UInt8(0))
        rp.append(UInt8(0x8))  # CANCEL
        rf.payload = rp^
        var out = c.handle_frame(rf^)
        for i in range(len(out)):
            if Int(out[i].header.type.value) == 0x7:  # GOAWAY
                assert_equal(Int(out[i].payload[7]), 0xB)
                goaway_seen = True
    assert_true(goaway_seen)
    assert_true(c.goaway_sent)


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


def _goaway_code(frames: List[Frame]) -> Int:
    for j in range(len(frames)):
        if Int(frames[j].header.type.value) == 0x7:
            return Int(frames[j].payload[7])
    return -1


def test_hpack_decode_bomb_is_stopped_before_it_expands() raises:
    """One ~4 KiB literal indexed into the dynamic table, then thousands
    of one-byte references to it: 16 KiB of block, ~40 MiB of headers.
    The list-size cap used to be checked only after the whole list had
    been allocated."""
    var c = Connection()
    var b = List[UInt8]()
    b.append(UInt8(0x40))  # literal w/ incremental indexing, new name
    b.append(UInt8(0x01))
    b.append(UInt8(ord("x")))
    # value length 4000: 0x7F then 4000-127 = 3873 as 7-bit varint
    b.append(UInt8(0x7F))
    var rest = 4000 - 127
    while rest >= 128:
        b.append(UInt8((rest % 128) + 128))
        rest //= 128
    b.append(UInt8(rest))
    for _ in range(4000):
        b.append(UInt8(ord("v")))
    for _ in range(10000):
        b.append(UInt8(0xBE))  # indexed: dynamic entry 62
    var hf = Frame()
    hf.header.type = FrameType.HEADERS()
    hf.header.stream_id = 1
    hf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    hf.payload = b^
    var out = c.handle_frame(hf^)
    assert_equal(_goaway_code(out), 0xB)  # ENHANCE_YOUR_CALM


def test_oversized_continuation_frame_is_a_frame_size_error() raises:
    var c = Connection()
    var hf = Frame()
    hf.header.type = FrameType.HEADERS()
    hf.header.stream_id = 1
    hf.header.flags = FrameFlags(UInt8(0))
    hf.payload = List[UInt8]()
    hf.payload.append(UInt8(0x82))  # :method GET
    _ = c.handle_frame(hf^)
    var cf = Frame()
    cf.header.type = FrameType.CONTINUATION()
    cf.header.stream_id = 1
    cf.header.flags = FrameFlags(UInt8(0))
    cf.payload = List[UInt8](
        length=c.local_max_frame_size + 1, fill=UInt8(0x82)
    )
    var out = c.handle_frame(cf^)
    assert_equal(_goaway_code(out), 0x6)  # FRAME_SIZE_ERROR


def _settings_frame(id: Int, v: Int) -> Frame:
    var f = Frame()
    f.header.type = FrameType.SETTINGS()
    f.header.stream_id = 0
    f.header.flags = FrameFlags(UInt8(0))
    f.payload = List[UInt8]()
    f.payload.append(UInt8((id >> 8) & 0xFF))
    f.payload.append(UInt8(id & 0xFF))
    f.payload.append(UInt8((v >> 24) & 0xFF))
    f.payload.append(UInt8((v >> 16) & 0xFF))
    f.payload.append(UInt8((v >> 8) & 0xFF))
    f.payload.append(UInt8(v & 0xFF))
    f.header.length = 6
    return f^


def test_peer_header_table_size_does_not_resize_our_decoder() raises:
    """The setting bounds the peer's decoder (our encoder). Applied to our
    decoder, 0 evicted entries the peer still referenced and 2^32-1
    removed the decoder's memory bound."""
    var c = Connection()
    var before = c.hpack_decoder.max_size
    _ = c.handle_frame(_settings_frame(0x1, 0))
    assert_equal(c.hpack_decoder.max_size, before)
    assert_equal(c.peer_header_table_size, 0)
    _ = c.handle_frame(_settings_frame(0x1, 0xFFFFFFFF))
    assert_equal(c.hpack_decoder.max_size, before)


def test_refused_stream_block_still_updates_hpack() raises:
    """A block on a stream refused for concurrency was dropped undecoded,
    losing its dynamic-table inserts; every later block then decoded
    against the wrong table."""
    var c = Connection()
    c.max_concurrent_streams = 1
    var h1 = Frame()
    h1.header.type = FrameType.HEADERS()
    h1.header.stream_id = 1
    h1.header.flags = FrameFlags(FrameFlags.END_HEADERS())  # stays open
    h1.payload = List[UInt8]()
    # A complete request head, so stream 1 stays open and takes the one
    # concurrency slot: :method GET, :scheme http, :path /, :authority x.
    h1.payload.append(UInt8(0x82))
    h1.payload.append(UInt8(0x86))
    h1.payload.append(UInt8(0x84))
    h1.payload.append(UInt8(0x01))
    h1.payload.append(UInt8(0x01))
    h1.payload.append(UInt8(ord("x")))
    _ = c.handle_frame(h1^)
    var before = c.hpack_decoder.dynamic_size
    var h3 = Frame()
    h3.header.type = FrameType.HEADERS()
    h3.header.stream_id = 3
    h3.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    h3.payload = List[UInt8]()
    h3.payload.append(UInt8(0x40))  # literal, incremental indexing
    h3.payload.append(UInt8(0x03))
    for ch in String("x-a").as_bytes():
        h3.payload.append(ch)
    h3.payload.append(UInt8(0x01))
    h3.payload.append(UInt8(ord("1")))
    var out = c.handle_frame(h3^)
    assert_equal(len(out), 1)
    assert_equal(Int(out[0].header.type.value), 0x3)  # RST_STREAM
    assert_equal(Int(out[0].payload[3]), 0x7)  # REFUSED_STREAM
    assert_equal(c.hpack_decoder.dynamic_size, before + 3 + 1 + 32)


def test_local_and_peer_initial_windows_are_separate() raises:
    """The peer's INITIAL_WINDOW_SIZE sets how much we may *send* on a
    new stream; ours sets how much it may send us. One field used to
    serve both, so each overwrote the other."""
    var c = Connection()
    c.initial_window_size = 1 << 20  # we advertise 1 MiB
    _ = c.handle_frame(_settings_frame(0x4, 1000))
    assert_equal(c.initial_window_size, 1 << 20)
    assert_equal(c.peer_initial_window_size, 1000)
    var s = c._ensure_stream(1)
    assert_equal(s.send_window, 1000)
    assert_equal(s.recv_window, 1 << 20)


def _request_verdict(
    var extra: List[HpackHeader], path: String = "/"
) raises -> Int:
    """Send one request on stream 1; return the RST_STREAM code, or -1
    when it was accepted."""
    var c = Connection()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", path))
    hdrs.append(HpackHeader(":authority", "example.com"))
    for h in extra:
        hdrs.append(h.copy())
    var enc = HpackEncoder()
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    var out = c.handle_frame(f^)
    for j in range(len(out)):
        if Int(out[j].header.type.value) == 0x3:
            return Int(out[j].payload[3])
    return -1


def test_malformed_field_values_are_refused() raises:
    var cr = List[HpackHeader]()
    cr.append(HpackHeader("x-a", "one\r\nx-b: two"))
    assert_equal(_request_verdict(cr^), 0x1)
    var lead = List[HpackHeader]()
    lead.append(HpackHeader("x-a", " padded"))
    assert_equal(_request_verdict(lead^), 0x1)
    var name_sp = List[HpackHeader]()
    name_sp.append(HpackHeader("x a", "v"))
    assert_equal(_request_verdict(name_sp^), 0x1)


def test_pseudo_header_forms_are_checked() raises:
    assert_equal(_request_verdict(List[HpackHeader](), "index.html"), 0x1)
    var host = List[HpackHeader]()
    host.append(HpackHeader("host", "other.example"))
    assert_equal(_request_verdict(host^), 0x1)
    var proto = List[HpackHeader]()
    proto.append(HpackHeader(":protocol", "websocket"))
    assert_equal(_request_verdict(proto^), 0x1)
    var ok_host = List[HpackHeader]()
    ok_host.append(HpackHeader("host", "example.com"))
    assert_equal(_request_verdict(ok_host^), -1)
    assert_equal(_request_verdict(List[HpackHeader]()), -1)


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
    test_oversized_header_list_rsts_enhance_your_calm()
    test_continuation_flood_rsts()
    test_rst_flood_triggers_goaway()
    test_priority_accepted_and_ignored()
    test_hpack_decode_bomb_is_stopped_before_it_expands()
    test_oversized_continuation_frame_is_a_frame_size_error()
    test_peer_header_table_size_does_not_resize_our_decoder()
    test_refused_stream_block_still_updates_hpack()
    test_local_and_peer_initial_windows_are_separate()
    test_malformed_field_values_are_refused()
    test_pseudo_header_forms_are_checked()
    print("test_h2_state: 21 passed")
