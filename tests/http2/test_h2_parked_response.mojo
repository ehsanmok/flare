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


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
