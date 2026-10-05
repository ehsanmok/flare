"""End-to-end driver tests for ``flare.http2.server``.

Drives an :class:`Http2Connection` synchronously: feeds the RFC 9113
preface + a single GET request frame, takes the parsed
:class:`flare.http.Request`, builds a :class:`flare.http.Response`,
calls :meth:`emit_response`, and asserts the drain stream contains a
well-formed HEADERS [+ DATA] response frame.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http import HeaderMap, Method, Request, Response
from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    Http2Config,
    Http2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    detect_h2c_upgrade,
    encode_frame,
    is_h2_alpn,
    parse_frame,
)


def _raw_preface() -> List[UInt8]:
    """Just the 24-octet client magic."""
    return List[UInt8](String(H2_PREFACE).as_bytes())


def _preface_bytes() -> List[UInt8]:
    """The magic followed by the empty SETTINGS frame RFC 9113 sec 3.4
    requires as the client's first frame."""
    var out = _raw_preface()
    var st = Frame()
    st.header.type = FrameType.SETTINGS()
    out.extend(Span[UInt8, _](encode_frame(st)))
    return out^


def _build_get_request_frame() raises -> List[UInt8]:
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/api/users"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader("user-agent", "h2-test"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return encode_frame(f)


def test_alpn_dispatch() raises:
    assert_true(is_h2_alpn("h2"))
    assert_false(is_h2_alpn("http/1.1"))
    assert_false(is_h2_alpn(""))


def test_h2c_upgrade_detection() raises:
    var h = HeaderMap()
    assert_false(detect_h2c_upgrade(h))
    h.set("Upgrade", "h2c")
    assert_false(detect_h2c_upgrade(h))
    h.set("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")
    assert_true(detect_h2c_upgrade(h))
    var h2 = HeaderMap()
    h2.set("Upgrade", "websocket")
    h2.set("HTTP2-Settings", "AAMAAABkAAQAoAAAAAIAAAAA")
    assert_false(detect_h2c_upgrade(h2))


def test_preface_only_emits_settings() raises:
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var bytes = c.drain()
    assert_true(len(bytes) >= 9)
    var maybe = parse_frame(Span[UInt8, _](bytes))
    assert_true(Bool(maybe))
    var f = maybe.value().copy()
    assert_equal(Int(f.header.type.value), 0x4)  # SETTINGS


def test_bad_preface_goaways() raises:
    """RFC 9113 sec 3.4: a bad preface is answered with
    GOAWAY(PROTOCOL_ERROR) and a close, not a bare disconnect. Raising
    left the peer to time out with no idea why."""
    var c = Http2Connection()
    var bad = String("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")
    var bytes = List[UInt8](bad.as_bytes())
    c.feed(Span[UInt8, _](bytes))
    assert_true(c.conn.goaway_sent)
    var out = c.drain()
    var frames = _walk_frames(out)
    assert_true(len(frames) >= 1)
    var last = frames[len(frames) - 1].copy()
    assert_equal(Int(last.header.type.value), 0x7)  # GOAWAY
    assert_equal(Int(last.payload[7]), 0x1)  # PROTOCOL_ERROR


def test_request_round_trip() raises:
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var hf = _build_get_request_frame()
    c.feed(Span[UInt8, _](hf))
    var ids = c.take_completed_streams()
    assert_equal(len(ids), 1)
    assert_equal(ids[0], 1)

    var req = c.take_request(1)
    assert_equal(req.method, "GET")
    assert_equal(req.url, "/api/users")
    assert_equal(req.version, "HTTP/2")
    assert_equal(req.headers.get("host"), "example.com")
    assert_equal(req.headers.get("user-agent"), "h2-test")

    var resp = Response(status=200)
    resp.headers.set("Content-Type", "application/json")
    resp.body = List[UInt8](String('{"ok":true}').as_bytes())
    c.emit_response(1, resp^)

    var bytes = c.drain()
    # Initial SETTINGS and the ACK of the client's SETTINGS, then HEADERS,
    # then DATA.
    var frames = _walk_frames(bytes)
    assert_equal(len(frames), 4)
    assert_equal(Int(frames[0].header.type.value), 0x4)
    assert_equal(Int(frames[1].header.type.value), 0x4)
    assert_true(frames[1].header.flags.has(FrameFlags.ACK()))

    var headers_frame = frames[2].copy()
    assert_equal(Int(headers_frame.header.type.value), 0x1)
    assert_equal(headers_frame.header.stream_id, 1)
    assert_true(headers_frame.header.flags.has(FrameFlags.END_HEADERS()))
    assert_false(headers_frame.header.flags.has(FrameFlags.END_STREAM()))

    var data_frame = frames[3].copy()
    assert_equal(Int(data_frame.header.type.value), 0x0)
    assert_equal(data_frame.header.stream_id, 1)
    assert_true(data_frame.header.flags.has(FrameFlags.END_STREAM()))
    assert_equal(len(data_frame.payload), 11)


def _walk_frames(bytes: List[UInt8]) raises -> List[Frame]:
    """Parse every complete frame in ``bytes`` into a list."""
    var out = List[Frame]()
    var off = 0
    while off < len(bytes):
        var rest = List[UInt8](capacity=len(bytes) - off)
        for i in range(off, len(bytes)):
            rest.append(bytes[i])
        var m = parse_frame(Span[UInt8, _](rest))
        if not m:
            break
        var f = m.value().copy()
        off += 9 + f.header.length
        out.append(f^)
    return out^


def _drive_get(mut c: Http2Connection) raises -> Int:
    """Feed the preface + a GET on stream 1 and return the stream id."""
    c.feed(Span[UInt8, _](_preface_bytes()))
    c.feed(Span[UInt8, _](_build_get_request_frame()))
    _ = c.drain()  # discard preface SETTINGS
    var ids = c.take_completed_streams()
    return ids[0]


def test_stream_response_incremental_frames() raises:
    """Incremental begin/queue/end emit HEADERS (no END_STREAM), DATA
    chunks, then trailing HEADERS(END_STREAM) carrying trailers."""
    var c = Http2Connection()
    var sid = _drive_get(c)
    var resp = Response(status=200)
    resp.headers.set("Content-Type", "text/plain")
    resp.trailers.set("grpc-status", "0")
    c.begin_stream_response(sid, resp^)
    _ = c.queue_stream_data(
        sid, Span[UInt8, _](List[UInt8](String("AB").as_bytes()))
    )
    _ = c.queue_stream_data(
        sid, Span[UInt8, _](List[UInt8](String("CDE").as_bytes()))
    )
    var tk = List[String]()
    tk.append("grpc-status")
    var tv = List[String]()
    tv.append("0")
    c.end_stream_response(sid, tk, tv)

    var frames = _walk_frames(c.drain())
    assert_equal(len(frames), 4)
    # Leading HEADERS: END_HEADERS, not END_STREAM.
    assert_equal(Int(frames[0].header.type.value), 0x1)
    assert_true(frames[0].header.flags.has(FrameFlags.END_HEADERS()))
    assert_false(frames[0].header.flags.has(FrameFlags.END_STREAM()))
    # Two DATA frames, neither END_STREAM.
    assert_equal(Int(frames[1].header.type.value), 0x0)
    assert_equal(len(frames[1].payload), 2)
    assert_false(frames[1].header.flags.has(FrameFlags.END_STREAM()))
    assert_equal(Int(frames[2].header.type.value), 0x0)
    assert_equal(len(frames[2].payload), 3)
    # Trailing HEADERS: END_STREAM closes the stream.
    assert_equal(Int(frames[3].header.type.value), 0x1)
    assert_true(frames[3].header.flags.has(FrameFlags.END_STREAM()))


def test_stream_response_no_trailers_ends_with_empty_data() raises:
    """Without trailers the stream closes on an empty DATA(END_STREAM)."""
    var c = Http2Connection()
    var sid = _drive_get(c)
    var resp = Response(status=200)
    c.begin_stream_response(sid, resp^)
    _ = c.queue_stream_data(
        sid, Span[UInt8, _](List[UInt8](String("x").as_bytes()))
    )
    c.end_stream_response(sid, List[String](), List[String]())

    var frames = _walk_frames(c.drain())
    assert_equal(len(frames), 3)
    assert_equal(Int(frames[2].header.type.value), 0x0)  # DATA
    assert_equal(len(frames[2].payload), 0)
    assert_true(frames[2].header.flags.has(FrameFlags.END_STREAM()))


def test_stream_data_bounded_by_send_window() raises:
    """The queue_stream_data path sends only up to the send window and
    reports the consumed byte count so the caller can stash the tail."""
    var c = Http2Connection()
    var sid = _drive_get(c)
    # Shrink the per-stream + connection send windows to 3 bytes.
    c.conn.send_window = 3
    var s = c.conn.streams[sid].copy()
    s.send_window = 3
    c.conn.streams[sid] = s^
    var resp = Response(status=200)
    c.begin_stream_response(sid, resp^)
    var big = List[UInt8](String("HELLO").as_bytes())
    var n = c.queue_stream_data(sid, Span[UInt8, _](big))
    assert_equal(n, 3)  # only the window's worth went out
    var n2 = c.queue_stream_data(sid, Span[UInt8, _](big))
    assert_equal(n2, 0)  # window now exhausted


def test_partial_feed_buffers_frames() raises:
    """A frame split across two ``feed`` calls must be parsed exactly once."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var hf = _build_get_request_frame()
    var first = List[UInt8](capacity=5)
    for i in range(5):
        first.append(hf[i])
    var second = List[UInt8](capacity=len(hf) - 5)
    for i in range(5, len(hf)):
        second.append(hf[i])
    c.feed(Span[UInt8, _](first))
    var ids = c.take_completed_streams()
    assert_equal(len(ids), 0)
    c.feed(Span[UInt8, _](second))
    var ids2 = c.take_completed_streams()
    assert_equal(len(ids2), 1)


def test_repeated_fields_and_cookie_crumbs_survive() raises:
    """Browsers split cookies into one field per crumb (RFC 9113 sec
    8.2.3); take_request used ``set`` and kept only the last one."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader("cookie", "a=1"))
    hdrs.append(HpackHeader("x-a", "one"))
    hdrs.append(HpackHeader("cookie", "b=2"))
    hdrs.append(HpackHeader("x-a", "two"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    c.feed(Span[UInt8, _](encode_frame(f)))
    var ready = c.take_completed_streams()
    assert_equal(len(ready), 1)
    var req = c.take_request(1)
    assert_equal(req.headers.get("cookie"), "a=1; b=2")
    assert_equal(len(req.headers.get_all("x-a")), 2)
    var jar = req.cookies()
    assert_equal(jar.get("a"), "1")
    assert_equal(jar.get("b"), "2")


def _raw_headers_frame(sid: Int, block: List[UInt8]) -> List[UInt8]:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = sid
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = block.copy()
    return encode_frame(f)


def _get_block(tail: List[UInt8]) -> List[UInt8]:
    """``GET http /`` as indexed static fields, followed by ``tail``."""
    var b = List[UInt8]()
    b.append(0x82)
    b.append(0x86)
    b.append(0x84)
    for x in tail:
        b.append(x)
    return b^


def _insert_xa_b() -> List[UInt8]:
    """Literal with incremental indexing, new name: ``x-a: b``."""
    var t = List[UInt8]()
    t.append(0x40)
    t.append(0x03)
    t.append(UInt8(ord("x")))
    t.append(UInt8(ord("-")))
    t.append(UInt8(ord("a")))
    t.append(0x01)
    t.append(UInt8(ord("b")))
    return t^


def _goaway_code(bytes: List[UInt8]) raises -> Int:
    for f in _walk_frames(bytes):
        if f.header.type.value == 7:
            return (
                (Int(f.payload[4]) << 24)
                | (Int(f.payload[5]) << 16)
                | (Int(f.payload[6]) << 8)
                | Int(f.payload[7])
            )
    return -1


def _stream_has(
    c: Http2Connection, sid: Int, name: String, value: String
) raises -> Bool:
    if sid not in c.conn.streams:
        return False
    for h in c.conn.streams[sid].headers:
        if h.name == name and h.value == value:
            return True
    return False


def _small_table_server() raises -> Http2Connection:
    var cfg = Http2Config()
    cfg.header_table_size = 0
    var c = Http2Connection.with_config(cfg^)
    c.feed(Span[UInt8, _](_preface_bytes()))
    return c^


def test_reduced_table_size_applies_only_after_the_peers_size_update() raises:
    """HPACK-03: we advertise SETTINGS_HEADER_TABLE_SIZE = 0, but the peer's
    encoder keeps its 4096-octet table until it has seen the SETTINGS and
    sent a size update (RFC 7541 sec 4.2). Shrinking our decoder at
    construction discarded the first insert, so the peer's next index was
    out of range and a legal connection died with COMPRESSION_ERROR."""
    var c = _small_table_server()
    # We still tell the peer 0, so its encoder will shrink and signal it.
    var first = _walk_frames(c.drain())
    var advertised = False
    for f in first:
        if f.header.type.value == 4 and len(f.payload) >= 6:
            if Int(f.payload[0]) == 0 and Int(f.payload[1]) == 1:
                advertised = True
    assert_true(advertised)
    # Before the peer has applied it: insert on stream 1, index on stream 3.
    c.feed(Span[UInt8, _](_raw_headers_frame(1, _get_block(_insert_xa_b()))))
    var idx = List[UInt8]()
    idx.append(UInt8(0x80 | 62))
    c.feed(Span[UInt8, _](_raw_headers_frame(3, _get_block(idx))))
    assert_equal(_goaway_code(c.drain()), -1)
    assert_true(_stream_has(c, 3, "x-a", "b"))


def test_peer_size_update_to_the_advertised_size_is_honoured() raises:
    """After the peer's size update to 0 the table is empty and capped at the
    advertised size: the earlier entry is gone and a larger update is a
    COMPRESSION_ERROR."""
    var c = _small_table_server()
    c.feed(Span[UInt8, _](_raw_headers_frame(1, _get_block(_insert_xa_b()))))
    var upd = List[UInt8]()
    upd.append(0x20)  # dynamic table size update to 0
    upd.append(0x82)
    upd.append(0x86)
    upd.append(0x84)
    upd.append(UInt8(0x80 | 62))  # nothing left to index
    _ = c.drain()
    c.feed(Span[UInt8, _](_raw_headers_frame(3, upd)))
    assert_equal(_goaway_code(c.drain()), 9)  # COMPRESSION_ERROR

    var c2 = _small_table_server()
    var big = List[UInt8]()
    big.append(0x3F)  # size update, prefix 31 saturated
    big.append(0x01)  # 31 + 1 = 32 > advertised 0
    big.append(0x82)
    big.append(0x86)
    big.append(0x84)
    _ = c2.drain()
    c2.feed(Span[UInt8, _](_raw_headers_frame(1, big)))
    assert_equal(_goaway_code(c2.drain()), 9)


def _first_frame_verdict(ty: FrameType, flags: UInt8, n: Int) raises -> Int:
    """GOAWAY code the server answers when ``ty`` is the first frame after the
    preface, or -1 when it does not send a GOAWAY."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_raw_preface()))
    _ = c.drain()
    var f = Frame()
    f.header.type = ty.copy()
    f.header.flags = FrameFlags(flags)
    f.header.stream_id = 0
    f.payload = List[UInt8](length=n, fill=UInt8(0))
    f.header.length = n
    c.feed(Span[UInt8, _](encode_frame(f)))
    return _goaway_code(c.drain())


def test_first_frame_after_the_preface_must_be_settings() raises:
    """H2-08: the client preface "MUST be followed by a SETTINGS frame"
    (RFC 9113 sec 3.4). Any other first frame, a PING, a SETTINGS ACK or a
    WINDOW_UPDATE, is GOAWAY(PROTOCOL_ERROR), and nothing is answered
    before it (no PING ACK)."""
    assert_equal(_first_frame_verdict(FrameType.PING(), UInt8(0), 8), 1)
    assert_equal(
        _first_frame_verdict(FrameType.SETTINGS(), FrameFlags.ACK(), 0), 1
    )
    assert_equal(
        _first_frame_verdict(FrameType.WINDOW_UPDATE(), UInt8(0), 4), 1
    )
    # No PING ACK went out.
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_raw_preface()))
    _ = c.drain()
    var ping = Frame()
    ping.header.type = FrameType.PING()
    ping.payload = List[UInt8](length=8, fill=UInt8(0))
    ping.header.length = 8
    c.feed(Span[UInt8, _](encode_frame(ping)))
    for f in _walk_frames(c.drain()):
        assert_false(f.header.type.value == 6, "PING answered before SETTINGS")


def test_settings_first_then_other_frames_are_served() raises:
    """H2-08: an (empty) SETTINGS first, then PING, is fine; and so is a
    SETTINGS with content."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](_raw_preface()))
    _ = c.drain()
    var st = Frame()
    st.header.type = FrameType.SETTINGS()
    c.feed(Span[UInt8, _](encode_frame(st)))
    var ping = Frame()
    ping.header.type = FrameType.PING()
    ping.payload = List[UInt8](length=8, fill=UInt8(0))
    ping.header.length = 8
    c.feed(Span[UInt8, _](encode_frame(ping)))
    var out = c.drain()
    assert_equal(_goaway_code(out), -1)
    var acked = False
    for f in _walk_frames(out):
        if f.header.type.value == 6 and (f.header.flags.bits & 1) != 0:
            acked = True
    assert_true(acked)


def main() raises:
    test_alpn_dispatch()
    test_h2c_upgrade_detection()
    test_preface_only_emits_settings()
    test_bad_preface_goaways()
    test_request_round_trip()
    test_stream_response_incremental_frames()
    test_stream_response_no_trailers_ends_with_empty_data()
    test_stream_data_bounded_by_send_window()
    test_partial_feed_buffers_frames()
    test_repeated_fields_and_cookie_crumbs_survive()
    test_reduced_table_size_applies_only_after_the_peers_size_update()
    test_peer_size_update_to_the_advertised_size_is_honoured()
    test_first_frame_after_the_preface_must_be_settings()
    test_settings_first_then_other_frames_are_served()
    print("test_h2_server: 14 passed")
