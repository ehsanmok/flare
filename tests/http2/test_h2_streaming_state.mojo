"""HTTP/2 streaming response state and flow-control contracts."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite
from flare.http2 import (
    Http2ClientConnection,
    HpackHeader,
    HpackEncoder,
    Frame,
    FrameType,
    FrameFlags,
    encode_frame,
    parse_frame,
)


def _h2_head(
    mut conn: Http2ClientConnection,
    mut encoder: HpackEncoder,
    fields: List[HpackHeader],
    end: Bool = False,
) raises:
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS()
        | (FrameFlags.END_STREAM() if end else UInt8(0))
    )
    f.payload = encoder.encode(Span(fields))
    f.header.length = len(f.payload)
    var wire = encode_frame(f^)
    conn.feed(Span(wire))


def test_h2_informationals_and_length_survives_body_drains() raises:
    var conn = Http2ClientConnection()
    var empty = List[UInt8]()
    conn.send_request(
        1, "GET", "https", "example.test", "/", List[HpackHeader](), Span(empty)
    )
    conn.enable_response_streaming(1)
    _ = conn.drain()
    var encoder = HpackEncoder()
    _h2_head(conn, encoder, [HpackHeader(":status", "103")])
    assert_false(conn.headers_received(1))
    _h2_head(
        conn,
        encoder,
        [HpackHeader(":status", "200"), HpackHeader("content-length", "80000")],
    )
    for _ in range(10):
        var f = Frame()
        f.header.type = FrameType.DATA()
        f.header.stream_id = 1
        f.payload.resize(8000, 97)
        f.header.length = len(f.payload)
        var wire = encode_frame(f^)
        conn.feed(Span(wire))
        assert_equal(len(conn.drain_body(1)), 8000)
        _ = conn.drain()
    _h2_head(conn, encoder, [HpackHeader("x-end", "yes")], True)
    assert_false(Bool(conn.stream_error(1)))
    assert_true(conn.stream_ended(1))
    assert_equal(len(conn.initial_response_headers(1)), 2)
    assert_equal(len(conn.response_trailers(1)), 1)


def test_h2_head_metadata_does_not_require_data() raises:
    var conn = Http2ClientConnection()
    var empty = List[UInt8]()
    conn.send_request(
        1,
        "HEAD",
        "https",
        "example.test",
        "/",
        List[HpackHeader](),
        Span(empty),
    )
    var encoder = HpackEncoder()
    _h2_head(
        conn,
        encoder,
        [HpackHeader(":status", "200"), HpackHeader("content-length", "12345")],
        True,
    )
    assert_false(Bool(conn.stream_error(1)))
    assert_true(conn.stream_ended(1))
    assert_equal(len(conn.drain_body(1)), 0)


def test_h2_truncated_content_length_is_a_stream_error() raises:
    var conn = Http2ClientConnection()
    var empty = List[UInt8]()
    conn.send_request(
        1, "GET", "https", "example.test", "/", List[HpackHeader](), Span(empty)
    )
    var encoder = HpackEncoder()
    _h2_head(
        conn,
        encoder,
        [HpackHeader(":status", "200"), HpackHeader("content-length", "12345")],
        True,
    )
    assert_true(Bool(conn.stream_error(1)))


def _h2_data(
    mut conn: Http2ClientConnection, size: Int, padding: Int = 0
) raises:
    var f = Frame()
    f.header.type = FrameType.DATA()
    f.header.stream_id = 1
    if padding > 0:
        f.header.flags = FrameFlags(FrameFlags.PADDED())
        f.payload.append(UInt8(padding))
    for _ in range(size):
        f.payload.append(97)
    for _ in range(padding):
        f.payload.append(0)
    f.header.length = len(f.payload)
    var wire = encode_frame(f^)
    conn.feed(Span(wire))


def _h2_credit(wire: List[UInt8], sid: Int) raises -> Int:
    var pos = 0
    var credit = 0
    while pos < len(wire):
        var f = parse_frame(Span(wire)[pos:]).value().copy()
        if f.header.type.value == FrameType.WINDOW_UPDATE().value and (
            f.header.stream_id == sid
        ):
            credit += (
                (Int(f.payload[0]) << 24)
                | (Int(f.payload[1]) << 16)
                | (Int(f.payload[2]) << 8)
                | Int(f.payload[3])
            )
        pos += 9 + f.header.length
    return credit


def test_h2_streaming_credit_follows_body_drains() raises:
    var conn = Http2ClientConnection()
    var empty = List[UInt8]()
    conn.send_request(
        1, "GET", "https", "example.test", "/", List[HpackHeader](), Span(empty)
    )
    conn.enable_response_streaming(1)
    var encoder = HpackEncoder()
    _h2_head(conn, encoder, [HpackHeader(":status", "200")])
    _ = conn.drain()

    _h2_data(conn, 3, padding=2)
    assert_equal(conn.conn.streams[1].recv_window, 65532)
    var updates = conn.drain()
    assert_equal(_h2_credit(updates, 1), 3)  # Pad Length + padding only.
    assert_equal(_h2_credit(updates, 0), 6)  # Other streams can progress.
    assert_equal(len(conn.drain_body(1)), 3)
    updates = conn.drain()
    assert_equal(_h2_credit(updates, 1), 3)
    assert_equal(_h2_credit(updates, 0), 0)
    assert_equal(len(conn.drain_body(1)), 0)
    assert_equal(len(conn.drain()), 0)  # No duplicate credit on empty drains.

    # Many receive windows can pass without retaining prior body chunks.
    for _ in range(32):
        _h2_data(conn, 8192)
        assert_equal(_h2_credit(conn.drain(), 1), 0)
        assert_equal(len(conn.drain_body(1)), 8192)
        assert_equal(_h2_credit(conn.drain(), 1), 8192)
        assert_equal(conn.conn.streams[1].recv_window, 65535)
    assert_false(Bool(conn.stream_error(1)))


def test_h2_undrained_stream_cannot_exceed_receive_window() raises:
    var conn = Http2ClientConnection()
    var empty = List[UInt8]()
    conn.send_request(
        1, "GET", "https", "example.test", "/", List[HpackHeader](), Span(empty)
    )
    conn.enable_response_streaming(1)
    var encoder = HpackEncoder()
    _h2_head(conn, encoder, [HpackHeader(":status", "200")])
    for size in [16384, 16384, 16384, 16383]:
        _h2_data(conn, size)
    assert_equal(conn.conn.streams[1].recv_window, 0)
    _h2_data(conn, 1)
    assert_equal(conn.stream_error(1).value(), 3)  # FLOW_CONTROL_ERROR.
    assert_equal(len(conn.conn.streams[1].data), 65535)


def test_h2_rejects_data_before_final_response_headers() raises:
    for informational in [False, True]:
        var conn = Http2ClientConnection()
        var empty = List[UInt8]()
        conn.send_request(
            1,
            "GET",
            "https",
            "example.test",
            "/",
            List[HpackHeader](),
            Span(empty),
        )
        if informational:
            var encoder = HpackEncoder()
            _h2_head(conn, encoder, [HpackHeader(":status", "103")])
        _h2_data(conn, 8192)
        assert_true(conn.conn.goaway_sent)
        assert_equal(len(conn.conn.streams[1].data), 0)


def test_h2_no_error_reset_only_preserves_complete_response() raises:
    for complete in [False, True]:
        for code in [0, 8]:
            var conn = Http2ClientConnection()
            conn.send_request_open(
                1, "POST", "https", "example.test", "/", List[HpackHeader]()
            )
            var body = List[UInt8]()
            body.resize(65536, 97)
            conn.send_data(1, Span(body), False)
            assert_true(conn.has_pending_body(1))
            var encoder = HpackEncoder()
            _h2_head(conn, encoder, [HpackHeader(":status", "413")], complete)
            var rst = Frame()
            rst.header.type = FrameType.RST_STREAM()
            rst.header.stream_id = 1
            rst.payload.resize(4, 0)
            rst.payload[3] = UInt8(code)
            rst.header.length = 4
            var wire = encode_frame(rst^)
            conn.feed(Span(wire))
            assert_equal(Bool(conn.stream_error(1)), code != 0 or not complete)
            assert_false(conn.has_pending_body(1))


def test_h2_window_update_before_rejection_does_not_resume_upload() raises:
    var conn = Http2ClientConnection()
    conn.send_request_open(
        1, "POST", "https", "example.test", "/", List[HpackHeader]()
    )
    var body = List[UInt8]()
    body.resize(65536, 97)
    conn.send_data(1, Span(body), False)
    _ = conn.drain()
    assert_true(conn.has_pending_body(1))
    var wire = List[UInt8]()
    for sid in [0, 1]:
        var update = Frame()
        update.header.type = FrameType.WINDOW_UPDATE()
        update.header.stream_id = sid
        update.payload = [0, 0, 4, 0]
        update.header.length = 4
        wire.extend(encode_frame(update^))
    var encoder = HpackEncoder()
    var fields: List[HpackHeader] = [HpackHeader(":status", "413")]
    var head = Frame()
    head.header.type = FrameType.HEADERS()
    head.header.stream_id = 1
    head.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    head.payload = encoder.encode(Span(fields))
    head.header.length = len(head.payload)
    wire.extend(encode_frame(head^))
    var rst = Frame()
    rst.header.type = FrameType.RST_STREAM()
    rst.header.stream_id = 1
    rst.payload.resize(4, 0)
    rst.header.length = 4
    wire.extend(encode_frame(rst^))
    conn.feed(Span(wire))
    assert_false(Bool(conn.stream_error(1)))
    assert_true(conn.response_ready(1))
    assert_false(conn.has_pending_body(1))
    assert_equal(len(conn.drain()), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
