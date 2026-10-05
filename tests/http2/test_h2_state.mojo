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


def _open_request(
    mut c: Connection, sid: Int, end_stream: Bool
) raises -> List[Frame]:
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "POST"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    var enc = HpackEncoder()
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = sid
    var flags = FrameFlags.END_HEADERS()
    if end_stream:
        flags = flags | FrameFlags.END_STREAM()
    f.header.flags = FrameFlags(flags)
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return c.handle_frame(f^)


def test_data_in_flight_for_a_refused_stream_is_ignored() raises:
    """The client sent a body behind a HEADERS we refused. That DATA was
    a connection-level STREAM_CLOSED, killing every other stream."""
    var c = Connection()
    c.max_concurrent_streams = 1
    _ = _open_request(c, 1, False)
    var refused = _open_request(c, 3, False)
    assert_equal(Int(refused[0].payload[3]), 0x7)  # REFUSED_STREAM
    var d = Frame()
    d.header.type = FrameType.DATA()
    d.header.stream_id = 3
    d.payload = List[UInt8](length=100, fill=UInt8(0x61))
    d.header.length = 100
    var out = c.handle_frame(d^)
    assert_equal(
        _goaway_code(out), -1, "a refused stream's DATA killed the connection"
    )
    assert_equal(len(out), 1)
    assert_equal(Int(out[0].header.type.value), 0x8)  # WINDOW_UPDATE
    assert_equal(out[0].header.stream_id, 0)


def test_zero_window_update_closes_the_stream_it_resets() raises:
    var c = Connection()
    _ = _open_request(c, 1, False)
    var w = Frame()
    w.header.type = FrameType.WINDOW_UPDATE()
    w.header.stream_id = 1
    w.payload = List[UInt8](length=4, fill=UInt8(0))
    w.header.length = 4
    var out = c.handle_frame(w^)
    assert_equal(Int(out[0].header.type.value), 0x3)
    assert_equal(c.streams[1].state.value, StreamState.CLOSED().value)


def _data_frame(sid: Int, n: Int, end_stream: Bool = False) -> Frame:
    var d = Frame()
    d.header.type = FrameType.DATA()
    d.header.stream_id = sid
    if end_stream:
        d.header.flags = FrameFlags(FrameFlags.END_STREAM())
    d.payload = List[UInt8](length=n, fill=UInt8(0x61))
    d.header.length = n
    return d^


def test_connection_receive_window_is_enforced() raises:
    """H2-01: DATA past the connection receive window is a connection
    error of type FLOW_CONTROL_ERROR (RFC 9113 sec 6.9.1)."""
    var c = Connection()
    _ = _open_request(c, 1, False)
    c.recv_window = 100
    var out = c.handle_frame(_data_frame(1, 101))
    assert_equal(_goaway_code(out), 3)  # FLOW_CONTROL_ERROR
    assert_true(c.goaway_sent)
    assert_equal(len(c.streams[1].data), 0)


def test_connection_receive_window_is_debited_and_credited() raises:
    """H2-01: every DATA payload is debited, and every WINDOW_UPDATE(0)
    flare emits is added back, so the window tracks what the peer sees."""
    var c = Connection()
    _ = _open_request(c, 1, False)
    var out = c.handle_frame(_data_frame(1, 1000))
    assert_equal(_goaway_code(out), -1)
    assert_equal(c.recv_window, 65535)  # 1000 debited, 1000 credited back
    # A peer that ignores withheld credit: with the window used up exactly
    # the next byte is an error.
    c.recv_window = 0
    out = c.handle_frame(_data_frame(1, 1))
    assert_equal(_goaway_code(out), 3)


def test_withheld_connection_credit_restores_the_receive_window() raises:
    """H2-01: credit withheld above the buffer cap is added to the
    window only when it is released to the peer."""
    var c = Connection()
    c.recv_window = 0
    c.withheld_conn_credit = 500
    var out = c.release_request_credit(0)
    assert_equal(len(out), 1)
    assert_equal(c.withheld_conn_credit, 0)
    assert_equal(c.recv_window, 500)


def _post_with_content_lengths(sid: Int, values: List[String]) -> Frame:
    """HEADERS for a POST carrying one content-length field per value."""
    var b = List[UInt8]()
    b.append(0x83)  # :method POST
    b.append(0x86)  # :scheme http
    b.append(0x84)  # :path /
    for v in values:
        # Literal without indexing, name = static index 28 (content-length).
        b.append(0x0F)
        b.append(0x0D)
        b.append(UInt8(v.byte_length()))
        for c in v.as_bytes():
            b.append(c)
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.header.stream_id = sid
    f.header.length = len(b)
    f.payload = b^
    return f^


def _five_byte_body_completes(
    mut c: Connection, sid: Int, var values: List[String]
) raises -> Bool:
    """Open ``sid`` with the given content-length fields, send a 5-byte
    body with END_STREAM; ``True`` when flare accepts it as complete."""
    var rst_code = -1
    for f in c.handle_frame(_post_with_content_lengths(sid, values)):
        if f.header.type.value == FrameType.RST_STREAM().value:
            rst_code = Int(f.payload[3])
    if rst_code < 0:
        for f in c.handle_frame(_data_frame(sid, 5, True)):
            if f.header.type.value == FrameType.RST_STREAM().value:
                rst_code = Int(f.payload[3])
    if rst_code >= 0:
        assert_equal(rst_code, 1, "a bad content-length is PROTOCOL_ERROR")
    return rst_code < 0 and c.streams[sid].copy().data_complete


def test_content_length_overflow_and_duplicates_are_rejected() raises:
    """H2-05: a content-length that wraps Int64 (2^64 + 5 read as 5), one
    that is empty or not 1*DIGIT, and differing duplicate fields are
    malformed (RFC 9110 sec 8.6, RFC 9113 sec 8.1.1): the stream is reset
    with PROTOCOL_ERROR instead of a 5-byte body completing."""
    var bad = List[List[String]]()
    bad.append([String("18446744073709551621")])
    bad.append([String("9223372036854775808")])  # 2^63, one past Int.MAX
    bad.append([String("5"), String("10")])
    bad.append([String("10"), String("5")])
    bad.append([String("5"), String("18446744073709551621")])
    bad.append([String("")])
    bad.append([String("5x")])
    var c = Connection()
    c.max_concurrent_streams = 1000
    var sid = 1
    for i in range(len(bad)):
        assert_false(
            _five_byte_body_completes(c, sid, bad[i].copy()),
            "malformed content-length accepted: case " + String(i),
        )
        assert_equal(c.streams[sid].state.value, StreamState.CLOSED().value)
        sid += 2


def test_content_length_valid_forms_still_complete() raises:
    """H2-05: the largest in-range value and repeated equal values are
    still accepted; a 5-byte body completes under ``content-length: 5``,
    ``05`` and a repeated ``5``."""
    var c = Connection()
    c.max_concurrent_streams = 1000
    assert_true(_five_byte_body_completes(c, 1, [String("5")]))
    assert_true(_five_byte_body_completes(c, 3, [String("5"), String("5")]))
    assert_true(_five_byte_body_completes(c, 5, [String("05")]))
    # Int.MAX itself parses (and then the body is too short: PROTOCOL_ERROR
    # for the mismatch, not for the parse).
    var out = c.handle_frame(
        _post_with_content_lengths(7, [String("9223372036854775807")])
    )
    for f in out:
        assert_false(f.header.type.value == FrameType.RST_STREAM().value)


def _conn_credit(frames: List[Frame]) -> Int:
    """Total WINDOW_UPDATE(0) credit in ``frames``."""
    var n = 0
    for f in frames:
        if (
            f.header.type.value == FrameType.WINDOW_UPDATE().value
            and f.header.stream_id == 0
        ):
            n += (
                (Int(f.payload[0]) << 24)
                | (Int(f.payload[1]) << 16)
                | (Int(f.payload[2]) << 8)
                | Int(f.payload[3])
            )
    return n


def test_content_length_reset_returns_connection_credit() raises:
    """H2-09: four requests reset for a content-length mismatch at
    END_STREAM (65535 DATA octets in all) must give the connection credit
    back, or the peer's window is 0 for good (RFC 9113 sec 6.9)."""
    var c = Connection()
    var sizes: List[Int] = [16384, 16384, 16384, 16383]
    var w = 65535
    for i in range(4):
        var sid = 2 * i + 1
        _ = c.handle_frame(_post_with_content_lengths(sid, [String("100000")]))
        w -= sizes[i]
        var out = c.handle_frame(_data_frame(sid, sizes[i], True))
        assert_equal(Int(out[0].header.type.value), 0x3)  # RST_STREAM
        assert_equal(Int(out[0].payload[3]), 1)  # PROTOCOL_ERROR
        w += _conn_credit(out)
    assert_equal(w, 65535)
    assert_equal(c.recv_window, 65535)


def test_stream_window_overrun_reset_returns_connection_credit() raises:
    """H2-09: DATA past the stream's receive window resets the stream with
    FLOW_CONTROL_ERROR and still returns its connection credit."""
    var c = Connection()
    _ = _open_request(c, 1, False)
    var s = c.streams[1].copy()
    s.recv_window = 10
    c.streams[1] = s^
    var out = c.handle_frame(_data_frame(1, 100))
    assert_equal(Int(out[0].header.type.value), 0x3)  # RST_STREAM
    assert_equal(Int(out[0].payload[3]), 3)  # FLOW_CONTROL_ERROR
    assert_equal(_conn_credit(out), 100)
    assert_equal(c.recv_window, 65535)


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
    test_data_in_flight_for_a_refused_stream_is_ignored()
    test_zero_window_update_closes_the_stream_it_resets()
    test_connection_receive_window_is_enforced()
    test_connection_receive_window_is_debited_and_credited()
    test_withheld_connection_credit_restores_the_receive_window()
    test_content_length_overflow_and_duplicates_are_rejected()
    test_content_length_valid_forms_still_complete()
    test_content_length_reset_returns_connection_credit()
    test_stream_window_overrun_reset_returns_connection_credit()
    print("test_h2_state: 30 passed")
