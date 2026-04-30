"""End-to-end driver tests for ``flare.http2.server``.

Drives an :class:`H2Connection` synchronously: feeds the RFC 9113
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
    H2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    detect_h2c_upgrade,
    encode_frame,
    is_h2_alpn,
    parse_frame,
)


def _preface_bytes() -> List[UInt8]:
    return List[UInt8](String(H2_PREFACE).as_bytes())


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
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var bytes = c.drain()
    assert_true(len(bytes) >= 9)
    var maybe = parse_frame(Span[UInt8, _](bytes))
    assert_true(Bool(maybe))
    var f = maybe.value().copy()
    assert_equal(Int(f.header.type.value), 0x4)  # SETTINGS


def test_bad_preface_raises() raises:
    var c = H2Connection()
    var bad = String("PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n")
    var bytes = List[UInt8](bad.as_bytes())
    var raised = False
    try:
        c.feed(Span[UInt8, _](bytes))
    except:
        raised = True
    assert_true(raised)


def test_request_round_trip() raises:
    var c = H2Connection()
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
    # Skip the initial SETTINGS frame written on preface.
    var off = 0
    var maybe1 = parse_frame(Span[UInt8, _](bytes))
    assert_true(Bool(maybe1))
    var settings = maybe1.value().copy()
    off = 9 + settings.header.length

    # Next is HEADERS.
    var rest = List[UInt8](capacity=len(bytes) - off)
    for i in range(off, len(bytes)):
        rest.append(bytes[i])
    var hmaybe = parse_frame(Span[UInt8, _](rest))
    assert_true(Bool(hmaybe))
    var headers_frame = hmaybe.value().copy()
    assert_equal(Int(headers_frame.header.type.value), 0x1)
    assert_equal(headers_frame.header.stream_id, 1)
    assert_true(headers_frame.header.flags.has(FrameFlags.END_HEADERS()))
    assert_false(headers_frame.header.flags.has(FrameFlags.END_STREAM()))

    # Then DATA with the body.
    var consumed = 9 + headers_frame.header.length
    var rest2 = List[UInt8](capacity=len(rest) - consumed)
    for i in range(consumed, len(rest)):
        rest2.append(rest[i])
    var dmaybe = parse_frame(Span[UInt8, _](rest2))
    assert_true(Bool(dmaybe))
    var data_frame = dmaybe.value().copy()
    assert_equal(Int(data_frame.header.type.value), 0x0)
    assert_equal(data_frame.header.stream_id, 1)
    assert_true(data_frame.header.flags.has(FrameFlags.END_STREAM()))
    assert_equal(len(data_frame.payload), 11)


def test_partial_feed_buffers_frames() raises:
    """A frame split across two ``feed`` calls must be parsed exactly once."""
    var c = H2Connection()
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


def main() raises:
    test_alpn_dispatch()
    test_h2c_upgrade_detection()
    test_preface_only_emits_settings()
    test_bad_preface_raises()
    test_request_round_trip()
    test_partial_feed_buffers_frames()
    print("test_h2_server: 6 passed")
