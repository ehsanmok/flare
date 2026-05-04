"""Tests for RFC 8441 Extended CONNECT (WebSocket-over-HTTP/2 bootstrap).

Covers two slices of the server-side state machine:

1. ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` (RFC 8441 §3) is
   advertised in the server's initial SETTINGS only when the
   :attr:`Http2Config.enable_connect_protocol` flag is set;
   absent otherwise (existing behaviour preserved).

2. A HEADERS frame whose pseudo-headers carry ``:method = CONNECT``
   plus ``:protocol = websocket`` (RFC 8441 §4) lands on the
   stream with ``stream.extended_connect_protocol == "websocket"``,
   so the unified server's WebSocket-over-h2 dispatcher
   (:mod:`flare.ws.server`, Phase 6) can route it to the WS
   handler instead of treating it as a regular CONNECT proxy
   request.

These exercise the byte-driver primitive directly; the WS-over-h2
end-to-end round-trip through the unified WsServer / WsClient
lands in :mod:`tests.test_ws_over_h2`.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    H2Connection,
    H2_PREFACE,
    HpackEncoder,
    HpackHeader,
    Http2Config,
    encode_frame,
    parse_frame,
)


def _preface_bytes() -> List[UInt8]:
    return List[UInt8](String(H2_PREFACE).as_bytes())


def _settings_payload(bytes: List[UInt8]) raises -> List[UInt8]:
    """Skip the SETTINGS frame header and return the raw payload."""
    var maybe = parse_frame(Span[UInt8, _](bytes))
    assert_true(Bool(maybe))
    var f = maybe.value().copy()
    var ftype = Int(f.header.type.value)
    var payload = f.payload.copy()
    assert_equal(ftype, 0x4)  # SETTINGS
    return payload^


def _has_setting(payload: List[UInt8], id: Int) -> Bool:
    """Walk a SETTINGS payload and return True iff the (id, ...) pair
    is present (RFC 9113 §6.5.1: 6 bytes per pair, big-endian)."""
    var i = 0
    while i + 6 <= len(payload):
        var pid = (Int(payload[i]) << 8) | Int(payload[i + 1])
        if pid == id:
            return True
        i += 6
    return False


def test_settings_enable_connect_protocol_off_by_default() raises:
    """A default-constructed H2Connection MUST NOT advertise
    SETTINGS_ENABLE_CONNECT_PROTOCOL. The pre-RFC-8441 wire shape
    must round-trip byte-for-byte."""
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    var bytes = c.drain()
    var payload = _settings_payload(bytes)
    assert_false(
        _has_setting(payload, 0x8),
        "default Http2Config must not advertise ENABLE_CONNECT_PROTOCOL",
    )


def test_settings_enable_connect_protocol_when_opted_in() raises:
    """``Http2Config(enable_connect_protocol=True)`` ->
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 in the initial SETTINGS."""
    var cfg = Http2Config()
    cfg.enable_connect_protocol = True
    var c = H2Connection.with_config(cfg^)
    c.feed(Span[UInt8, _](_preface_bytes()))
    var bytes = c.drain()
    var payload = _settings_payload(bytes)
    assert_true(
        _has_setting(payload, 0x8),
        "enable_connect_protocol=True must advertise SETTINGS id 0x8",
    )


def test_extended_connect_headers_landed_on_stream() raises:
    """Feeding a HEADERS frame with ``:method=CONNECT`` +
    ``:protocol=websocket`` (RFC 8441 §4) leaves the stream in
    a state where ``stream.extended_connect_protocol == "websocket"``.
    """
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    _ = c.drain()  # discard server SETTINGS

    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "CONNECT"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/chat"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    hdrs.append(HpackHeader(":protocol", "websocket"))
    hdrs.append(HpackHeader("sec-websocket-version", "13"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    # END_HEADERS only -- the CONNECT stream stays open for the
    # bidirectional byte tunnel; END_STREAM would close it
    # immediately.
    f.header.flags = FrameFlags(FrameFlags.END_HEADERS())
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    var hf_bytes = encode_frame(f)
    c.feed(Span[UInt8, _](hf_bytes))

    assert_true(1 in c.conn.streams)
    var s = c.conn.streams[1].copy()
    assert_equal(s.extended_connect_protocol, "websocket")
    # The :method on a CONNECT request shows up in the headers
    # list verbatim too -- the unified dispatcher uses the
    # combination (CONNECT + :protocol=websocket) to recognise
    # the bootstrap.
    var saw_method_connect = False
    for i in range(len(s.headers)):
        if s.headers[i].name == ":method" and s.headers[i].value == "CONNECT":
            saw_method_connect = True
    assert_true(saw_method_connect)


def test_extended_connect_protocol_empty_for_plain_get() raises:
    """A regular HEADERS frame (no ``:protocol``) leaves
    ``extended_connect_protocol`` empty, so the dispatcher
    routes it as a normal request."""
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    _ = c.drain()

    var enc = HpackEncoder()
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(":method", "GET"))
    hdrs.append(HpackHeader(":scheme", "https"))
    hdrs.append(HpackHeader(":path", "/api/users"))
    hdrs.append(HpackHeader(":authority", "example.com"))
    var f = Frame()
    f.header.type = FrameType.HEADERS()
    f.header.stream_id = 1
    f.header.flags = FrameFlags(
        FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
    )
    f.payload = enc.encode(Span[HpackHeader, _](hdrs))
    c.feed(Span[UInt8, _](encode_frame(f)))

    var s = c.conn.streams[1].copy()
    assert_equal(s.extended_connect_protocol, "")


def test_peer_enable_connect_protocol_latched_on_settings_recv() raises:
    """Peer SETTINGS_ENABLE_CONNECT_PROTOCOL=1 latches the
    Connection's ``peer_enable_connect_protocol`` flag to True.

    The HTTP/2 client side gates its Extended CONNECT issuance
    on this latch per RFC 8441 §3."""
    var c = H2Connection()
    c.feed(Span[UInt8, _](_preface_bytes()))
    _ = c.drain()

    # Hand-craft a SETTINGS frame with id=0x8, value=1.
    var sf = Frame()
    sf.header.type = FrameType.SETTINGS()
    sf.header.stream_id = 0
    sf.header.flags = FrameFlags(UInt8(0))
    var p = List[UInt8]()
    # id = 0x8 (big-endian 16-bit)
    p.append(UInt8(0))
    p.append(UInt8(0x8))
    # value = 1 (big-endian 32-bit)
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(1))
    sf.payload = p^
    c.feed(Span[UInt8, _](encode_frame(sf)))

    assert_true(c.conn.peer_enable_connect_protocol)


def main() raises:
    test_settings_enable_connect_protocol_off_by_default()
    test_settings_enable_connect_protocol_when_opted_in()
    test_extended_connect_headers_landed_on_stream()
    test_extended_connect_protocol_empty_for_plain_get()
    test_peer_enable_connect_protocol_latched_on_settings_recv()
    print("test_h2_extended_connect: 5 passed")
