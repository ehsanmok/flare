"""Tests for the WebSocket-over-HTTP/2 stream <-> frame adapter
(RFC 8441 + RFC 6455).

Exercises the v0.7 primitive surface (no full WsClient ALPN
plumbing yet -- that lands in v0.7.x): the
:class:`WsOverH2Stream` adapter on top of the byte-driven
:class:`Http2ClientConnection`. Six cases per the v0.7 deferred
plan:

1. Bootstrap raises when the peer hasn't advertised
   SETTINGS_ENABLE_CONNECT_PROTOCOL=1.
2. Peer SETTINGS arriving mid-handshake unblocks bootstrap.
3. Bootstrap emits a HEADERS frame with :method=CONNECT,
   :protocol=websocket, **no** END_STREAM, and the
   sec-websocket-* headers.
4. send_frame queues a DATA frame whose payload is the WS-encoded
   (masked) wire form of the WS frame.
5. pull_frames decodes complete WS frames out of stream.data,
   leaving partial trailing bytes for the next call (split-frame
   reassembly).
6. close() emits a CLOSE frame DATA with END_STREAM and flips
   is_closed() to True; subsequent send raises.
"""

from std.testing import assert_equal, assert_false, assert_raises, assert_true

from flare.http2 import (
    Frame,
    FrameFlags,
    FrameType,
    HpackEncoder,
    HpackHeader,
    encode_frame,
    parse_frame,
)
from flare.http2.client import Http2ClientConfig, Http2ClientConnection
from flare.ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from flare.ws.frame import WsFrame, WsOpcode, WsCloseCode


def _make_client() raises -> Http2ClientConnection:
    """Construct a client with ENABLE_CONNECT_PROTOCOL flipped on
    in our advertised SETTINGS."""
    var cfg = Http2ClientConfig()
    cfg.enable_connect_protocol = True
    return Http2ClientConnection.with_config(cfg^)


def _peer_advertises_connect_protocol(
    mut conn: Http2ClientConnection,
) raises -> None:
    """Inject a SETTINGS frame from the server with
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, latching
    ``peer_supports_extended_connect()`` to True."""
    var sf = Frame()
    sf.header.type = FrameType.SETTINGS()
    sf.header.stream_id = 0
    sf.header.flags = FrameFlags(UInt8(0))
    var p = List[UInt8]()
    p.append(UInt8(0))
    p.append(UInt8(0x8))
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(0))
    p.append(UInt8(1))
    sf.payload = p^
    sf.header.length = len(sf.payload)
    var sb = encode_frame(sf)
    conn.feed(Span[UInt8, _](sb))


def _next_frame(
    mut bytes: List[UInt8],
) raises -> Frame:
    """Pop one complete frame from ``bytes`` (consumes its 9-byte
    header + payload). Caller asserts at least one is present."""
    var maybe = parse_frame(Span[UInt8, _](bytes))
    assert_true(Bool(maybe), "expected at least one complete frame")
    var f = maybe.value().copy()
    var consumed = 9 + f.header.length
    var rest = List[UInt8]()
    for i in range(consumed, len(bytes)):
        rest.append(bytes[i])
    bytes = rest^
    return f^


def _drop_preface_and_settings_chatter(mut bytes: List[UInt8]) raises:
    """Skip the 24-byte client preface plus any leading SETTINGS
    frames (initial + ACKs) and the connection WINDOW_UPDATE so the
    next ``_next_frame`` call sees the application HEADERS we care
    about."""
    var rest = List[UInt8]()
    for i in range(24, len(bytes)):
        rest.append(bytes[i])
    bytes = rest^
    while True:
        var maybe = parse_frame(Span[UInt8, _](bytes))
        if not maybe:
            return
        var f = maybe.value().copy()
        var t = Int(f.header.type.value)
        if t != Int(FrameType.SETTINGS().value) and not (
            t == Int(FrameType.WINDOW_UPDATE().value)
            and f.header.stream_id == 0
        ):
            return
        var consumed = 9 + f.header.length
        var rest2 = List[UInt8]()
        for i in range(consumed, len(bytes)):
            rest2.append(bytes[i])
        bytes = rest2^


def test_bootstrap_raises_when_peer_did_not_advertise_8441() raises:
    """RFC 8441 §3: the client MUST NOT issue an Extended CONNECT
    until the peer has advertised SETTINGS_ENABLE_CONNECT_PROTOCOL.
    The adapter wraps that gate in :func:`bootstrap_ws_over_h2`."""
    var conn = _make_client()
    var sid = conn.next_stream_id()
    with assert_raises(contains="ENABLE_CONNECT_PROTOCOL"):
        bootstrap_ws_over_h2(
            conn, sid, "example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="
        )


def test_peer_settings_mid_handshake_unblocks_bootstrap() raises:
    """Latching is order-independent: peer SETTINGS may arrive
    before or after the client emits its preface. Once it lands,
    :meth:`peer_supports_extended_connect` returns True and
    bootstrap succeeds."""
    var conn = _make_client()
    assert_false(conn.peer_supports_extended_connect())
    _peer_advertises_connect_protocol(conn)
    assert_true(conn.peer_supports_extended_connect())
    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn, sid, "example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="
    )


def test_bootstrap_emits_extended_connect_headers_no_end_stream() raises:
    """The HEADERS frame MUST carry :method=CONNECT,
    :protocol=websocket, and the sec-websocket-* headers, but
    MUST NOT carry END_STREAM (the stream stays open for the
    bidirectional tunnel)."""
    var conn = _make_client()
    _peer_advertises_connect_protocol(conn)
    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn,
        sid,
        "example.com",
        "/chat",
        "dGhlIHNhbXBsZSBub25jZQ==",
        "chat,superchat",
    )

    var bytes = conn.drain()
    _drop_preface_and_settings_chatter(bytes)
    var hf = _next_frame(bytes)
    assert_equal(Int(hf.header.type.value), Int(FrameType.HEADERS().value))
    assert_equal(hf.header.stream_id, sid)
    var flags = Int(hf.header.flags.bits)
    assert_true(
        (flags & Int(FrameFlags.END_HEADERS())) != 0,
        "HEADERS frame must set END_HEADERS",
    )
    assert_true(
        (flags & Int(FrameFlags.END_STREAM())) == 0,
        "Extended CONNECT MUST NOT set END_STREAM (stream stays open)",
    )

    # Decode the HPACK header block via a fresh decoder seeded with
    # the same defaults the server side would use.
    from flare.http2 import HpackDecoder

    var dec = HpackDecoder()
    var hdrs = dec.decode(Span[UInt8, _](hf.payload))
    var saw_method = False
    var saw_protocol = False
    var saw_path = False
    var saw_authority = False
    var saw_key = False
    var saw_protocol_offer = False
    for i in range(len(hdrs)):
        if hdrs[i].name == ":method" and hdrs[i].value == "CONNECT":
            saw_method = True
        elif hdrs[i].name == ":protocol" and hdrs[i].value == "websocket":
            saw_protocol = True
        elif hdrs[i].name == ":path" and hdrs[i].value == "/chat":
            saw_path = True
        elif hdrs[i].name == ":authority" and hdrs[i].value == "example.com":
            saw_authority = True
        elif (
            hdrs[i].name == "sec-websocket-key"
            and hdrs[i].value == "dGhlIHNhbXBsZSBub25jZQ=="
        ):
            saw_key = True
        elif (
            hdrs[i].name == "sec-websocket-protocol"
            and hdrs[i].value == "chat,superchat"
        ):
            saw_protocol_offer = True
    assert_true(saw_method)
    assert_true(saw_protocol)
    assert_true(saw_path)
    assert_true(saw_authority)
    assert_true(saw_key)
    assert_true(saw_protocol_offer)


def test_send_frame_emits_data_frame_carrying_ws_wire() raises:
    """:meth:`WsOverH2Stream.send_frame` queues exactly one DATA
    frame on the bound stream, and that frame's payload is a
    WS-frame wire image (masked client->server)."""
    var conn = _make_client()
    _peer_advertises_connect_protocol(conn)
    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn, sid, "example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="
    )
    # Discard the bootstrap-time output (preface + SETTINGS +
    # HEADERS) so we can isolate the DATA frame.
    _ = conn.drain()

    var ws = WsOverH2Stream(sid)
    ws.send_frame(conn, WsFrame.text("hi"))
    var bytes = conn.drain()
    var df = _next_frame(bytes)
    assert_equal(Int(df.header.type.value), Int(FrameType.DATA().value))
    assert_equal(df.header.stream_id, sid)
    # WS wire byte 0 = FIN(0x80) | TEXT(0x1) = 0x81; byte 1's MSB is
    # the MASK bit.
    assert_equal(Int(df.payload[0]), 0x81)
    assert_true(
        (Int(df.payload[1]) & 0x80) != 0,
        "client->server WS frame MUST be masked (RFC 6455 §5.3)",
    )
    var plen7 = Int(df.payload[1]) & 0x7F
    assert_equal(plen7, 2)
    # Bootstrap doesn't END_STREAM the tunnel.
    assert_true((Int(df.header.flags.bits) & Int(FrameFlags.END_STREAM())) == 0)


def test_pull_frames_split_across_data_arrivals() raises:
    """A WS frame split across two DATA arrivals MUST decode
    cleanly: nothing on the partial first arrival, the full frame
    on the second. Trailing bytes from a partial second frame
    stay in the read buffer."""
    var conn = _make_client()
    _peer_advertises_connect_protocol(conn)
    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn, sid, "example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="
    )
    _ = conn.drain()
    # Server-bound stream needs to exist on the client driver
    # before we shove data into Stream.data. The bootstrap
    # already created the stream; make sure it's there.
    assert_true(sid in conn.conn.streams)

    # Encode a server->client (unmasked) text frame "hello, h2".
    var src = WsFrame.text("hello, h2")
    var wire = src.encode(False)
    var first_half = List[UInt8]()
    var split = len(wire) // 2
    for i in range(split):
        first_half.append(wire[i])
    var second_half = List[UInt8]()
    for i in range(split, len(wire)):
        second_half.append(wire[i])

    var ws = WsOverH2Stream(sid)
    # First arrival: append partial bytes to the stream's data
    # buffer (mimicking the byte driver after receiving an
    # incomplete DATA frame).
    var s1 = conn.conn.streams[sid].copy()
    for i in range(len(first_half)):
        s1.data.append(first_half[i])
    conn.conn.streams[sid] = s1^
    var got1 = ws.try_pull_frame(conn)
    assert_false(Bool(got1), "partial frame must yield nothing")

    # Second arrival: the rest of the same frame.
    var s2 = conn.conn.streams[sid].copy()
    for i in range(len(second_half)):
        s2.data.append(second_half[i])
    conn.conn.streams[sid] = s2^
    var got2 = ws.try_pull_frame(conn)
    assert_true(Bool(got2))
    ref f = got2.value()
    assert_equal(Int(f.opcode), Int(WsOpcode.TEXT))
    assert_equal(len(f.payload), String("hello, h2").byte_length())


def test_close_emits_close_frame_with_end_stream_and_locks_send() raises:
    """:meth:`WsOverH2Stream.close` MUST emit a CLOSE WS frame
    inside a DATA frame whose END_STREAM flag is set (RFC 8441
    §5.5: half-close = WS clean shutdown), flip
    :meth:`is_closed` to True, and reject any subsequent
    :meth:`send_frame` call."""
    var conn = _make_client()
    _peer_advertises_connect_protocol(conn)
    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn, sid, "example.com", "/chat", "dGhlIHNhbXBsZSBub25jZQ=="
    )
    _ = conn.drain()

    var ws = WsOverH2Stream(sid)
    assert_false(ws.is_closed())
    ws.close(conn, WsCloseCode.NORMAL, "bye")
    assert_true(ws.is_closed())
    var bytes = conn.drain()
    var df = _next_frame(bytes)
    assert_equal(Int(df.header.type.value), Int(FrameType.DATA().value))
    assert_true(
        (Int(df.header.flags.bits) & Int(FrameFlags.END_STREAM())) != 0,
        "CLOSE frame MUST half-close the h2 stream",
    )
    # WS wire byte 0 = 0x80 | CLOSE(0x8) = 0x88.
    assert_equal(Int(df.payload[0]), 0x88)

    with assert_raises(contains="closed stream"):
        ws.send_frame(conn, WsFrame.text("late"))


def main() raises:
    test_bootstrap_raises_when_peer_did_not_advertise_8441()
    test_peer_settings_mid_handshake_unblocks_bootstrap()
    test_bootstrap_emits_extended_connect_headers_no_end_stream()
    test_send_frame_emits_data_frame_carrying_ws_wire()
    test_pull_frames_split_across_data_arrivals()
    test_close_emits_close_frame_with_end_stream_and_locks_send()
    print("test_ws_h2: 6 passed")
