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


def main() raises:
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
