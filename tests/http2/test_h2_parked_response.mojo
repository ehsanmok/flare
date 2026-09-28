"""A response larger than the peer's send window must be sent once.

When a response body does not fit the peer's flow-control window the
server frames what fits, parks the rest in ``pending_body`` and leaves
the stream open until a WINDOW_UPDATE unblocks it. That open stream is
the hazard: ``take_completed_streams`` is called on every readable
event, a WINDOW_UPDATE *is* a readable event, and the request's
``headers_complete`` / ``data_complete`` flags stay set for the life of
the stream. Guarding only on stream state therefore re-dispatched the
handler and re-sent the response head once per WINDOW_UPDATE.

The peer is right to reject that: a second HEADERS block on a stream
already carrying a response, without END_STREAM, is a protocol error
(RFC 9113 sec 8.1). Every client that advertises the default
65535-byte window -- which is every client that has not opted out --
hit it on the first response larger than that. flare's own h2 client
did; curl did not, because curl opens with a 32 MiB window and the
server never has to park anything.

These are sans-io: an ``Http2Connection`` driven by hand, no sockets.
"""

from std.testing import assert_equal, assert_true, TestSuite

from flare.http import Response, Status
from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    Http2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    encode_frame,
    parse_frame,
)


comptime _BODY: Int = 100_000
"""Comfortably past the 65535-byte default window, so the send parks."""


def _get_frame(sid: Int) raises -> List[UInt8]:
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/big"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = sid
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    return encode_frame(f)


def _window_update(sid: Int, inc: Int) -> List[UInt8]:
    var f = Frame()
    f.header.type = FrameType.WINDOW_UPDATE()
    f.header.stream_id = sid
    f.header.flags = FrameFlags(UInt8(0))
    f.payload.append(UInt8((inc >> 24) & 0x7F))
    f.payload.append(UInt8((inc >> 16) & 0xFF))
    f.payload.append(UInt8((inc >> 8) & 0xFF))
    f.payload.append(UInt8(inc & 0xFF))
    f.header.length = 4
    return encode_frame(f)


@fieldwise_init
struct _Tally(Copyable):
    """What one drain contained, by frame type."""

    var headers: Int
    var data_bytes: Int
    var end_stream: Bool


def _tally(bytes: List[UInt8]) raises -> _Tally:
    var rest = bytes.copy()
    var headers = 0
    var data_bytes = 0
    var end_stream = False
    while True:
        var got = parse_frame(Span[UInt8, _](rest))
        if not got:
            break
        var f = got.value().copy()
        if f.header.type.value == FrameType.HEADERS().value:
            headers += 1
        elif f.header.type.value == FrameType.DATA().value:
            data_bytes += f.header.length
        if f.header.flags.has(FrameFlags.END_STREAM()):
            end_stream = True
        var consumed = 9 + f.header.length
        var tail = List[UInt8](capacity=len(rest) - consumed)
        for i in range(consumed, len(rest)):
            tail.append(rest[i])
        rest = tail^
    return _Tally(headers, data_bytes, end_stream)


def _served_connection() raises -> Http2Connection:
    """A connection whose stream 1 has a parked 100 KB response."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](List[UInt8](String(H2_PREFACE).as_bytes())))
    c.feed(Span[UInt8, _](_get_frame(1)))
    var ready = c.take_completed_streams()
    assert_equal(len(ready), 1)
    var body = List[UInt8](capacity=_BODY)
    for i in range(_BODY):
        body.append(UInt8(97 + (i % 26)))
    c.emit_response(1, Response(Status.OK, body=body^))
    return c^


def test_parked_response_is_not_redispatched() raises:
    """The regression itself: one dispatch, not one per WINDOW_UPDATE."""
    var c = _served_connection()
    assert_equal(
        len(c.take_completed_streams()),
        0,
        (
            "a stream with a response already scheduled must not be"
            " dispatched again"
        ),
    )
    # A WINDOW_UPDATE is what re-enters the reactor, so ask again after
    # one: this is the exact sequence that used to re-send the head.
    c.feed(Span[UInt8, _](_window_update(1, 65535)))
    c.feed(Span[UInt8, _](_window_update(0, 65535)))
    assert_equal(len(c.take_completed_streams()), 0)


def test_parked_response_sends_one_head() raises:
    """Exactly one HEADERS block reaches the wire for one response."""
    var c = _served_connection()
    var first = _tally(c.drain())
    assert_equal(first.headers, 1)
    assert_equal(first.data_bytes, 65535, "the window is what fits")
    assert_true(not first.end_stream, "the body is not finished yet")

    c.feed(Span[UInt8, _](_window_update(1, 65535)))
    c.feed(Span[UInt8, _](_window_update(0, 65535)))
    c.pump_pending()
    var second = _tally(c.drain())
    assert_equal(second.headers, 0, "the response head must not be sent twice")
    assert_equal(second.data_bytes, _BODY - 65535)
    assert_true(second.end_stream, "the last pump closes the stream")


def test_whole_body_survives_the_park() raises:
    """Parking must not drop or duplicate a byte."""
    var c = _served_connection()
    var sent = _tally(c.drain()).data_bytes
    var guard = 0
    while sent < _BODY:
        c.feed(Span[UInt8, _](_window_update(1, 16384)))
        c.feed(Span[UInt8, _](_window_update(0, 16384)))
        c.pump_pending()
        sent += _tally(c.drain()).data_bytes
        guard += 1
        if guard > 64:
            raise Error("pump made no progress")
    assert_equal(sent, _BODY)


def _connection_with_stream(sid: Int) raises -> Http2Connection:
    var c = Http2Connection()
    var preface = List[UInt8](String(H2_PREFACE).as_bytes())
    c.feed(Span[UInt8, _](preface))
    var settings = Frame()
    settings.header.type = FrameType.SETTINGS()
    c.feed(Span[UInt8, _](encode_frame(settings)))
    c.feed(Span[UInt8, _](_get_frame(sid)))
    _ = c.take_completed_streams()
    _ = c.drain()
    return c^


def _largest_data_frame(bytes: List[UInt8]) raises -> Int:
    var rest = bytes.copy()
    var biggest = 0
    while True:
        var got = parse_frame(Span[UInt8, _](rest))
        if not got:
            break
        var f = got.value().copy()
        if f.header.type.value == FrameType.DATA().value:
            biggest = max(biggest, f.header.length)
        var consumed = 9 + f.header.length
        var tail = List[UInt8](capacity=len(rest) - consumed)
        for k in range(consumed, len(rest)):
            tail.append(rest[k])
        rest = tail^
    return biggest


def test_response_with_trailers_is_flow_controlled() raises:
    """Every gRPC response has trailers, and trailers used to force the
    one-shot framing: one oversized DATA frame, window ignored."""
    var c = _connection_with_stream(1)
    var resp = Response(Status.OK)
    resp.body = List[UInt8](length=_BODY, fill=UInt8(0x61))
    resp.trailers.set("grpc-status", "0")
    c.emit_response(1, resp^)
    var first = c.drain()
    var t1 = _tally(first)
    assert_equal(t1.data_bytes, 65535, "sent more than the window allowed")
    assert_true(_largest_data_frame(first) <= 16384, "oversized DATA frame")
    assert_true(not t1.end_stream)
    c.feed(Span[UInt8, _](_window_update(1, 65535)))
    c.feed(Span[UInt8, _](_window_update(0, 65535)))
    c.pump_pending()
    var t2 = _tally(c.drain())
    assert_equal(t2.data_bytes, _BODY - 65535)
    assert_equal(t2.headers, 1, "the trailers go out after the body")
    assert_true(t2.end_stream)


def test_small_responses_spend_the_window() raises:
    """A body that fits still consumes the window; otherwise concurrent
    responses all passed against the same stale budget."""
    var c = _connection_with_stream(1)
    var before = c.conn.send_window
    var resp = Response(Status.OK)
    resp.body = List[UInt8](length=1000, fill=UInt8(0x61))
    c.emit_response(1, resp^)
    assert_equal(c.conn.send_window, before - 1000)


def test_frames_after_a_connection_error_are_not_processed() raises:
    """After GOAWAY the connection is over. A request that arrived in the
    same read as the error used to be dispatched anyway."""
    var c = Http2Connection()
    var buf = List[UInt8](String(H2_PREFACE).as_bytes())
    var settings = Frame()
    settings.header.type = FrameType.SETTINGS()
    buf.extend(Span[UInt8, _](encode_frame(settings)))
    var ping = Frame()  # PING on a stream is a connection error
    ping.header.type = FrameType.PING()
    ping.header.stream_id = 1
    ping.payload = List[UInt8](length=8, fill=UInt8(0))
    ping.header.length = 8
    buf.extend(Span[UInt8, _](encode_frame(ping)))
    buf.extend(Span[UInt8, _](_get_frame(3)))
    c.feed(Span[UInt8, _](buf))
    assert_true(c.conn.goaway_sent)
    assert_equal(len(c.take_completed_streams()), 0)


def test_parked_body_is_released_when_the_peer_resets() raises:
    var c = _served_connection()
    _ = c.drain()
    assert_equal(len(c.pending_body), 1)
    var rst = Frame()
    rst.header.type = FrameType.RST_STREAM()
    rst.header.stream_id = 1
    rst.payload = List[UInt8](length=4, fill=UInt8(0))
    rst.payload[3] = UInt8(0x8)  # CANCEL
    rst.header.length = 4
    c.feed(Span[UInt8, _](encode_frame(rst)))
    c.feed(Span[UInt8, _](_window_update(0, 65535)))
    c.pump_pending()
    assert_equal(len(c.pending_body), 0, "parked bytes outlived the stream")
    assert_equal(_tally(c.drain()).data_bytes, 0)


def test_closed_streams_do_not_accumulate() raises:
    """Every stream a connection served used to stay in its table for the
    connection's life; memory and per-HEADERS work grew with its age."""
    var c = Http2Connection()
    c.feed(Span[UInt8, _](List[UInt8](String(H2_PREFACE).as_bytes())))
    for k in range(400):
        var sid = 2 * k + 1
        c.feed(Span[UInt8, _](_get_frame(sid)))
        var ready = c.take_completed_streams()
        assert_equal(len(ready), 1)
        _ = c.take_request(sid)
        c.emit_response(sid, Response(Status.OK))
        _ = c.drain()
    assert_true(
        len(c.conn.streams) <= 257,
        "stream table grew to " + String(len(c.conn.streams)),
    )


def test_many_small_frames_in_one_read() raises:
    """feed copied the rest of the inbox after every frame; a burst of
    small frames was quadratic. 3000 PINGs in one read must all be
    answered."""
    var c = Http2Connection()
    var buf = List[UInt8](String(H2_PREFACE).as_bytes())
    for _ in range(3000):
        var p = Frame()
        p.header.type = FrameType.PING()
        p.payload = List[UInt8](length=8, fill=UInt8(1))
        p.header.length = 8
        buf.extend(Span[UInt8, _](encode_frame(p)))
    c.feed(Span[UInt8, _](buf))
    var out = c.drain()
    var acks = 0
    var rest = out^
    var off = 0
    while off + 9 <= len(rest):
        var ln = (
            (Int(rest[off]) << 16)
            | (Int(rest[off + 1]) << 8)
            | Int(rest[off + 2])
        )
        if Int(rest[off + 3]) == 0x6:
            acks += 1
        off += 9 + ln
    assert_equal(acks, 3000)


def test_oversized_frame_is_refused_from_its_header() raises:
    """The size check ran after the whole declared payload had been
    buffered, up to 16 MiB of it."""
    var c = Http2Connection()
    var buf = List[UInt8](String(H2_PREFACE).as_bytes())
    # DATA header declaring 1 MiB, with no payload sent at all.
    buf.append(UInt8(0x10))
    buf.append(UInt8(0x00))
    buf.append(UInt8(0x00))
    buf.append(UInt8(0x0))
    buf.append(UInt8(0x0))
    for _ in range(4):
        buf.append(UInt8(0))
    c.feed(Span[UInt8, _](buf))
    assert_true(c.conn.goaway_sent, "waited for 1 MiB before refusing it")


def test_content_length_overrun_is_caught_on_the_frame() raises:
    var c = Http2Connection()
    c.feed(Span[UInt8, _](List[UInt8](String(H2_PREFACE).as_bytes())))
    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "POST"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader("content-length", "5"))
    var h = Frame()
    h.header.type = FrameType.HEADERS()
    h.header.stream_id = 1
    h.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    h.payload = enc.encode(Span[HpackHeader, _](hdrs))
    c.feed(Span[UInt8, _](encode_frame(h)))
    var d = Frame()
    d.header.type = FrameType.DATA()
    d.header.stream_id = 1
    d.payload = List[UInt8](length=50, fill=UInt8(0x61))
    d.header.length = 50
    c.feed(Span[UInt8, _](encode_frame(d)))
    var out = c.drain()
    var rst = False
    var off = 0
    while off + 9 <= len(out):
        var ln = (
            (Int(out[off]) << 16) | (Int(out[off + 1]) << 8) | Int(out[off + 2])
        )
        if Int(out[off + 3]) == 0x3:
            rst = True
        off += 9 + ln
    assert_true(rst, "50 bytes against content-length 5 were accepted")


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
