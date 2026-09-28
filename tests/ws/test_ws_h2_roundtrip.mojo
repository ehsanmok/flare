"""WebSocket-over-HTTP/2 full round-trip (RFC 8441), sans-I/O.

Pairs a client :class:`Http2ClientConnection` with a server
:class:`Http2Connection` (enable_connect_protocol) and shuttles bytes
between them -- no sockets. Proves the complete server bridge: the client
opens an Extended CONNECT tunnel, the server surfaces + accepts it with a
200 (stream stays open), a client-masked WS frame is read + unmasked
server-side, and an unmasked server reply is read client-side.
"""

from std.testing import assert_equal, assert_true

from flare.http2 import Http2Connection, Http2Config
from flare.http2.client import Http2ClientConfig, Http2ClientConnection
from flare.ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from flare.ws.server_h2 import WsOverH2ServerStream
from flare.ws.frame import WsFrame, WsOpcode


def _shuttle(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises:
    var iters = 0
    while True:
        if iters > 64:
            raise Error("shuttle: too many iterations")
        iters += 1
        var made = False
        var c_out = client.drain()
        if len(c_out) > 0:
            server.feed(Span[UInt8, _](c_out))
            made = True
        var s_out = server.drain()
        if len(s_out) > 0:
            client.feed(Span[UInt8, _](s_out))
            made = True
        if not made:
            return


def test_ws_h2_roundtrip() raises:
    print("test_ws_h2_roundtrip")
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)

    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    var server = Http2Connection.with_config(scfg^)

    # SETTINGS exchange -> client learns the peer supports Extended CONNECT.
    _shuttle(client, server)
    assert_true(
        client.peer_supports_extended_connect(),
        "server must advertise SETTINGS_ENABLE_CONNECT_PROTOCOL",
    )

    # Client opens the WS tunnel (Extended CONNECT, no END_STREAM).
    var sid = client.next_stream_id()
    bootstrap_ws_over_h2(
        client, sid, String("example.com"), String("/chat"), String("AAAA")
    )
    _shuttle(client, server)

    # Server surfaces + accepts the tunnel (200, stream stays open).
    var pending = server.take_extended_connect_streams()
    assert_equal(len(pending), 1)
    assert_equal(pending[0], sid)
    server.accept_ws_over_h2(sid)
    # Accepted tunnels are not re-surfaced.
    assert_equal(len(server.take_extended_connect_streams()), 0)
    _shuttle(client, server)

    # Client -> server: a masked TEXT frame.
    var client_ws = WsOverH2Stream(sid)
    client_ws.send_frame(client, WsFrame.text("ping"))
    _shuttle(client, server)

    var server_ws = WsOverH2ServerStream(sid)
    var got = server_ws.try_pull_frame(server)
    assert_true(Bool(got), "server must decode the client frame")
    assert_equal(got.value().opcode, WsOpcode.TEXT)
    assert_equal(got.value().text_payload(), "ping")

    # Server -> client: an unmasked TEXT reply.
    server_ws.send_frame(server, WsFrame.text("pong"))
    _shuttle(client, server)

    var back = client_ws.try_pull_frame(client)
    assert_true(Bool(back), "client must decode the server reply")
    assert_equal(back.value().opcode, WsOpcode.TEXT)
    assert_equal(back.value().text_payload(), "pong")

    print("test_ws_h2_roundtrip: 1 passed")


def _open_tunnel(
    mut client: Http2ClientConnection, mut server: Http2Connection
) raises -> Int:
    _shuttle(client, server)
    var sid = client.next_stream_id()
    bootstrap_ws_over_h2(
        client, sid, String("example.com"), String("/chat"), String("AAAA")
    )
    _shuttle(client, server)
    _ = server.take_extended_connect_streams()
    server.accept_ws_over_h2(sid)
    _shuttle(client, server)
    return sid


def test_ws_h2_message_larger_than_the_window() raises:
    """``send_frame`` discarded whatever queue_stream_data refused, so a
    message over the 65535-byte window arrived cut off and every later
    frame was misframed."""
    print("test_ws_h2_message_larger_than_the_window")
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)
    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    var server = Http2Connection.with_config(scfg^)
    var sid = _open_tunnel(client, server)
    var client_ws = WsOverH2Stream(sid)
    var server_ws = WsOverH2ServerStream(sid)
    var big = List[UInt8](length=200_000, fill=UInt8(0x5A))
    server_ws.send_frame(server, WsFrame.binary(big^))
    server_ws.send_frame(server, WsFrame.text("after"))
    var sizes = List[Int]()
    var last_text = String("")
    for _ in range(40):
        _shuttle(client, server)
        _ = server_ws.try_pull_frame(server)  # flushes what is parked
        _shuttle(client, server)
        while True:
            var f = client_ws.try_pull_frame(client)
            if not f:
                break
            sizes.append(len(f.value().payload))
            last_text = f.value().text_payload()
        if len(sizes) >= 2:
            break
    assert_equal(len(sizes), 2)
    assert_equal(sizes[0], 200_000)
    assert_equal(last_text, "after")
    print("test_ws_h2_message_larger_than_the_window: passed")


def test_ws_h2_unmasked_client_frame_is_refused() raises:
    print("test_ws_h2_unmasked_client_frame_is_refused")
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)
    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    var server = Http2Connection.with_config(scfg^)
    var sid = _open_tunnel(client, server)
    var zero = SIMD[DType.uint8, 4](0, 0, 0, 0)
    var raw = WsFrame.text("hi").encode_with_key(False, zero)
    client.send_data(sid, Span[UInt8, _](raw), False)
    _shuttle(client, server)
    var server_ws = WsOverH2ServerStream(sid)
    var raised = False
    try:
        _ = server_ws.try_pull_frame(server)
    except:
        raised = True
    assert_true(raised, "an unmasked client frame was accepted")
    print("test_ws_h2_unmasked_client_frame_is_refused: passed")


def test_ws_h2_client_mask_keys_are_not_a_counter() raises:
    """The h2 client masked with 1, 2, 3, ... -- a key the RFC requires
    to be unpredictable."""
    print("test_ws_h2_client_mask_keys_are_not_a_counter")
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)
    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    var server = Http2Connection.with_config(scfg^)
    var sid = _open_tunnel(client, server)
    var client_ws = WsOverH2Stream(sid)
    client_ws.send_frame(client, WsFrame.text("a"))
    var wire = client.drain()
    # Last DATA frame's payload: 2-byte WS header, then the key.
    var ws = List[UInt8](Span[UInt8, _](wire)[len(wire) - 7 :])
    var key = (
        (Int(ws[2]) << 24) | (Int(ws[3]) << 16) | (Int(ws[4]) << 8) | Int(ws[5])
    )
    assert_true(key > 16, "mask key looks like the old counter: " + String(key))
    print("test_ws_h2_client_mask_keys_are_not_a_counter: passed")


def test_ws_h2_oversized_frame_is_closed_with_1009() raises:
    """A tunnel frame header declaring 20 MiB is refused from the header
    alone, and the client gets CLOSE 1009 back."""
    print("test_ws_h2_oversized_frame_is_closed_with_1009")
    var ccfg = Http2ClientConfig()
    ccfg.enable_connect_protocol = True
    var client = Http2ClientConnection.with_config(ccfg^)
    var scfg = Http2Config()
    scfg.enable_connect_protocol = True
    var server = Http2Connection.with_config(scfg^)
    var sid = _open_tunnel(client, server)
    var h = List[UInt8]()
    h.append(0x82)
    h.append(0x80 | 127)
    var declared = 20 * 1024 * 1024
    for i in range(8):
        h.append(UInt8((declared >> (8 * (7 - i))) & 0xFF))
    for _ in range(4):
        h.append(0x11)
    client.send_data(sid, Span[UInt8, _](h), False)
    _shuttle(client, server)
    var server_ws = WsOverH2ServerStream(sid)
    var raised = False
    try:
        _ = server_ws.try_pull_frame(server)
    except:
        raised = True
    assert_true(raised, "a 20 MiB frame header was accepted")
    assert_true(server_ws.is_closed())
    _shuttle(client, server)
    var client_ws = WsOverH2Stream(sid)
    var f = client_ws.try_pull_frame(client)
    assert_true(Bool(f), "no CLOSE reached the client")
    var close = f.take()
    assert_equal(close.opcode, WsOpcode.CLOSE)
    assert_equal((Int(close.payload[0]) << 8) | Int(close.payload[1]), 1009)
    print("test_ws_h2_oversized_frame_is_closed_with_1009: passed")


def main() raises:
    test_ws_h2_roundtrip()
    test_ws_h2_message_larger_than_the_window()
    test_ws_h2_unmasked_client_frame_is_refused()
    test_ws_h2_client_mask_keys_are_not_a_counter()
    test_ws_h2_oversized_frame_is_closed_with_1009()
