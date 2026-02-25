"""Example 09 — WebSocket server with flare.ws.WsServer.

Demonstrates:
  - Binding a WsServer on an OS-assigned port
  - The connection handler callback receives a WsConnection
  - Receiving a masked TEXT frame from the client
  - Sending an unmasked TEXT frame back (server → client direction)
  - Receiving a masked BINARY frame and echoing it
  - Graceful close with WsCloseCode

Real-world usage:

    fn on_connect(conn: WsConnection) raises:
        while True:
            var frame = conn.recv()
            if frame.opcode == WsOpcode.CLOSE:
                break
            conn.send_text(frame.text_payload())  # echo

    var srv = WsServer.bind(SocketAddr.localhost(9001))
    srv.serve(on_connect)   # ← blocks indefinitely

Here we drive the server one connection at a time using the internal
helpers (_read_upgrade_request, _compute_accept_srv, _send_upgrade_response)
so the example exits cleanly.

Run:
    pixi run example-ws-server
"""

from flare.ws import WsServer, WsConnection, WsFrame, WsOpcode, WsCloseCode
from flare.ws.server import (
    _read_upgrade_request,
    _send_upgrade_response,
    _compute_accept_srv,
)
from flare.net import SocketAddr
from flare.tcp import TcpStream


# ── Test WebSocket key ────────────────────────────────────────────────────────

# RFC 6455 well-known test key/accept pair used throughout this example
comptime TEST_KEY = "dGhlIHNhbXBsZSBub25jZQ=="
comptime TEST_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


# ── Helper: send HTTP Upgrade request from raw TCP client ─────────────────────


fn send_upgrade_request(mut stream: TcpStream) raises:
    """Send a minimal WebSocket HTTP Upgrade request.

    Args:
        stream: Raw TCP stream connected to the server.
    """
    var req = (
        "GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Key: "
        + TEST_KEY
        + "\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "\r\n"
    )
    var b = req.as_bytes()
    stream.write_all(Span[UInt8](b))


# ── Helper: read and return the 101 status line ───────────────────────────────


fn drain_101(mut stream: TcpStream) raises -> String:
    """Consume the 101 Switching Protocols response.

    Args:
        stream: Raw TCP stream (client side).

    Returns:
        The first line of the HTTP response.
    """
    var buf = List[UInt8](capacity=512)
    buf.resize(512, 0)
    var acc = List[UInt8]()
    while True:
        var n = stream.read(buf.unsafe_ptr(), 512)
        if n == 0:
            break
        for i in range(n):
            acc.append(buf[i])
        # Stop once we see \r\n\r\n (end of HTTP headers)
        var nn = len(acc)
        if nn >= 4:
            for i in range(nn - 3):
                if (
                    acc[i] == 13
                    and acc[i + 1] == 10
                    and acc[i + 2] == 13
                    and acc[i + 3] == 10
                ):
                    # Extract status line
                    var line = String(capacity=32)
                    for j in range(len(acc)):
                        if acc[j] == 13 or acc[j] == 10:
                            break
                        line += chr(Int(acc[j]))
                    return line^
    return "<no 101>"


# ── Helper: read raw bytes from client after upgrade ─────────────────────────


fn recv_raw(mut stream: TcpStream, n: Int) raises -> List[UInt8]:
    """Read exactly n bytes from stream.

    Args:
        stream: TCP stream to read from.
        n:      Number of bytes to read.

    Returns:
        A List[UInt8] with the received bytes.
    """
    var buf = List[UInt8](capacity=n)
    buf.resize(n, 0)
    var total = 0
    while total < n:
        var got = stream.read(buf.unsafe_ptr() + total, n - total)
        if got == 0:
            break
        total += got
    buf.resize(total, 0)
    return buf^


# ── Perform one loopback connection ───────────────────────────────────────────


fn accept_and_upgrade(
    srv: WsServer, mut raw_client: TcpStream
) raises -> WsConnection:
    """Accept one TCP connection and perform the WebSocket handshake.

    Args:
        srv:        Bound WsServer.
        raw_client: Raw TCP client that sent the upgrade request.

    Returns:
        A ``WsConnection`` ready to send/receive WebSocket frames.
    """
    var server_stream = srv._listener.accept()
    var peer = server_stream.peer_addr()
    var key = _read_upgrade_request(server_stream)
    var accept = _compute_accept_srv(key)
    _send_upgrade_response(server_stream, accept)
    return WsConnection(server_stream^, peer)


# ── Main ──────────────────────────────────────────────────────────────────────


fn main() raises:
    print("=== flare Example 09: WebSocket Server ===")
    print()

    # ── 1. Bind the server ────────────────────────────────────────────────────
    print("── 1. Bind WsServer ──")
    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    print("  Bound on 127.0.0.1:" + String(port))
    print()

    # ── 2. Handshake: 101 Switching Protocols ─────────────────────────────────
    print("── 2. WebSocket handshake (101 Switching Protocols) ──")
    var client1 = TcpStream.connect(SocketAddr.localhost(port))
    send_upgrade_request(client1)
    var conn1 = accept_and_upgrade(srv, client1)
    var status_line = drain_101(client1)
    print("  Server response: " + status_line)
    print()

    # ── 3. Server receives masked TEXT, echoes back ───────────────────────────
    print("── 3. Recv masked TEXT frame → echo ──")
    var text_frame = WsFrame.text("hello from client")
    var wire = text_frame.encode(mask=True)  # client frames MUST be masked
    client1.write_all(Span[UInt8](wire))

    var received = conn1.recv()
    print("  Server received opcode:", received.opcode, "(expect 1 = TEXT)")
    print("  Payload:", received.text_payload())

    conn1.send_text("echo: " + received.text_payload())

    # Client reads the unmasked server frame
    var echo_bytes = recv_raw(client1, 64)
    print(
        "  Client received",
        len(echo_bytes),
        "bytes from server (unmasked)",
    )
    print()

    # ── 4. Server receives masked BINARY, echoes back ─────────────────────────
    print("── 4. Recv masked BINARY frame ──")
    # New connection for clean state
    var client2 = TcpStream.connect(SocketAddr.localhost(port))
    send_upgrade_request(client2)
    var conn2 = accept_and_upgrade(srv, client2)
    _ = drain_101(client2)

    var binary_payload = List[UInt8]()
    for i in range(8):
        binary_payload.append(UInt8(i))
    var bin_frame = WsFrame.binary(binary_payload)
    var bin_wire = bin_frame.encode(mask=True)
    client2.write_all(Span[UInt8](bin_wire))

    var bin_received = conn2.recv()
    print("  opcode:", bin_received.opcode, "(expect 2 = BINARY)")
    print("  payload bytes:", len(bin_received.payload))
    conn2.send_binary(bin_received.payload)  # echo
    _ = recv_raw(client2, 16)
    print("  BINARY echo complete")
    print()

    # ── 5. Server sends PING, expects PONG from client ────────────────────────
    print("── 5. Server PING ──")
    var client3 = TcpStream.connect(SocketAddr.localhost(port))
    send_upgrade_request(client3)
    var conn3 = accept_and_upgrade(srv, client3)
    _ = drain_101(client3)

    conn3.send_frame(WsFrame.ping())
    # Client receives PING and should PONG back
    var ping_bytes = recv_raw(client3, 2)
    print("  Client got PING bytes:", len(ping_bytes))

    # Send PONG from client
    var pong_wire = WsFrame.pong().encode(mask=True)
    client3.write_all(Span[UInt8](pong_wire))
    # Server: recv() swallows PONG and waits; send a text so it returns
    var dummy = WsFrame.text("done")
    var dummy_wire = dummy.encode(mask=True)
    client3.write_all(Span[UInt8](dummy_wire))
    var done_frame = conn3.recv()
    print("  Received after PONG:", done_frame.text_payload())
    print()

    # ── 6. Graceful close from server ─────────────────────────────────────────
    print("── 6. Close connection ──")
    var client4 = TcpStream.connect(SocketAddr.localhost(port))
    send_upgrade_request(client4)
    var conn4 = accept_and_upgrade(srv, client4)
    _ = drain_101(client4)

    conn4.close(WsCloseCode.NORMAL)
    print("  Server sent CLOSE frame with code NORMAL (1000)")

    # Client reads the CLOSE frame
    var close_bytes = recv_raw(client4, 8)
    print("  Client received", len(close_bytes), "bytes (CLOSE frame)")
    print()

    # ── 7. WsServer.bind() + serve() pattern ─────────────────────────────────
    print("── 7. WsServer.bind() + serve() pattern ──")
    var srv2 = WsServer.bind(SocketAddr.localhost(0))
    print("  WsServer.bind() → " + String(srv2.local_addr()))
    print(
        "  In production: srv2.serve(on_connect)  ← blocks, handles all"
        " connections"
    )
    print()

    client1.close()
    client2.close()
    client3.close()
    client4.close()
    srv.close()
    print("=== Example 09 complete ===")
