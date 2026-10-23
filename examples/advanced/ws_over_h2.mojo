"""WebSocket-over-HTTP/2 (RFC 8441) primitive demo.

Drives the stream <-> frame adapter
:class:`flare.ws.client_h2.WsOverH2Stream` against a synthetic
HTTP/2 peer (no socket -- we hand-craft the server's SETTINGS so
the demo runs without a real h2 backend).

What the example shows:

1. Configuring a :class:`Http2ClientConnection` to advertise
   ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`` (RFC 8441 §3).
2. Latching the peer's matching SETTINGS so
   :meth:`Http2ClientConnection.peer_supports_extended_connect`
   flips to ``True``.
3. Bootstrapping a WebSocket tunnel over a fresh stream id via
   :func:`bootstrap_ws_over_h2`.
4. Sending a WS frame (which the adapter masks per RFC 6455 §5.3
   and queues as a DATA frame on the bound stream).
5. Receiving WS frames out of the stream's buffered DATA -- the
   demo seeds a server-bound (unmasked) text frame so the
   adapter's :meth:`try_pull_frame` returns a complete decode.
6. Closing the tunnel, which emits a CLOSE WS frame with the h2
   ``END_STREAM`` flag set (RFC 8441 §5.5).

For a real WS-over-h2 deployment, ``WsClient.prefer_h2`` ALPN
dispatch will replace the synthetic peer; the primitive surface
stays identical.
"""

from flare.http2 import Frame, FrameFlags, FrameType, encode_frame
from flare.http2.client import Http2ClientConfig, Http2ClientConnection
from flare.ws.client_h2 import WsOverH2Stream, bootstrap_ws_over_h2
from flare.ws.frame import WsFrame, WsOpcode, WsCloseCode


def _peer_settings_advertise_8441(mut conn: Http2ClientConnection) raises:
    """Inject a server SETTINGS frame with
    SETTINGS_ENABLE_CONNECT_PROTOCOL=1 to satisfy the RFC 8441 §3
    gate. A real client receives this on the wire."""
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


def _seed_server_text_frame(
    mut conn: Http2ClientConnection, sid: Int, text: String
) raises:
    """Append an unmasked WS text frame onto the stream's data
    buffer to mimic a DATA frame the byte driver would have
    handed off."""
    var sf = WsFrame.text(text)
    var wire = sf.encode(False)
    var s = conn.conn.streams[sid].copy()
    for i in range(len(wire)):
        s.data.append(wire[i])
    conn.conn.streams[sid] = s^


def main() raises:
    var cfg = Http2ClientConfig()
    cfg.enable_connect_protocol = True
    var conn = Http2ClientConnection.with_config(cfg^)

    print("[1] peer_supports_extended_connect():", end=" ")
    print(conn.peer_supports_extended_connect())

    _peer_settings_advertise_8441(conn)
    print("[2] after server SETTINGS feed():", end=" ")
    print(conn.peer_supports_extended_connect())

    var sid = conn.next_stream_id()
    bootstrap_ws_over_h2(
        conn,
        sid,
        "example.com",
        "/chat",
        "dGhlIHNhbXBsZSBub25jZQ==",
        "chat",
    )
    print("[3] bootstrap queued Extended CONNECT on stream", sid)

    var ws = WsOverH2Stream(sid)
    ws.send_frame(conn, WsFrame.text("hello, h2"))
    print("[4] sent 1 WS text frame ('hello, h2') as a DATA frame")

    _seed_server_text_frame(conn, sid, "pong over h2")
    var got = ws.try_pull_frame(conn)
    if got:
        ref f = got.value()
        if f.opcode == WsOpcode.TEXT:
            print("[5] received WS text frame: '", end="")
            for i in range(len(f.payload)):
                print(chr(Int(f.payload[i])), end="")
            print("'")

    ws.close(conn, WsCloseCode.NORMAL, "demo done")
    print("[6] sent CLOSE; stream half-closed,", end=" ")
    print("is_closed =", ws.is_closed())
