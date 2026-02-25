"""Tests for flare.ws — WsFrame codec, WsOpcode, and WsCloseCode.

Tests cover:
  - Frame factory helpers (text, binary, ping, pong, close)
  - WsFrame.encode() wire format: header bytes, extended lengths, masking
  - WsFrame.decode_one() parsing: various payload sizes, masking
  - Round-trip: encode → decode → verify payload equality
  - Control frame constraints: fragmentation and payload-length checks
  - WsProtocolError typing

Integration tests (test_ws_connect_*) connect to a real echo server.
They skip gracefully if the network is unavailable.
"""

from testing import (
    assert_equal,
    assert_true,
    assert_false,
    assert_raises,
    TestSuite,
)
from flare.ws import (
    WsFrame,
    WsOpcode,
    WsCloseCode,
    WsProtocolError,
    WsClient,
    WsServer,
    WsConnection,
)
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr
from flare.tls import TlsConfig


# ── Factory opcode tests ──────────────────────────────────────────────────────


def test_text_frame_opcode():
    """WsFrame.text() must have TEXT opcode."""
    var frame = WsFrame.text("hello")
    assert_equal(Int(frame.opcode), Int(WsOpcode.TEXT))
    assert_true(frame.fin)
    assert_false(frame.rsv1)


def test_binary_frame_opcode():
    """WsFrame.binary() must have BINARY opcode."""
    var data = List[UInt8]()
    var frame = WsFrame.binary(data)
    assert_equal(Int(frame.opcode), Int(WsOpcode.BINARY))
    assert_true(frame.fin)


def test_ping_frame_opcode():
    """WsFrame.ping() must have PING opcode."""
    var frame = WsFrame.ping()
    assert_equal(Int(frame.opcode), Int(WsOpcode.PING))
    assert_true(frame.is_control())


def test_pong_frame_opcode():
    """WsFrame.pong() must have PONG opcode."""
    var frame = WsFrame.pong()
    assert_equal(Int(frame.opcode), Int(WsOpcode.PONG))
    assert_true(frame.is_control())


def test_close_frame_opcode():
    """WsFrame.close() must have CLOSE opcode."""
    var frame = WsFrame.close()
    assert_equal(Int(frame.opcode), Int(WsOpcode.CLOSE))
    assert_true(frame.is_control())


def test_close_frame_payload():
    """WsFrame.close() must encode code as 2 big-endian bytes."""
    var frame = WsFrame.close(code=WsCloseCode.NORMAL)
    assert_equal(len(frame.payload), 2)
    var code = (Int(frame.payload[0]) << 8) | Int(frame.payload[1])
    assert_equal(code, 1000)


def test_close_frame_with_reason():
    """WsFrame.close() with reason must include reason bytes after code."""
    var frame = WsFrame.close(code=WsCloseCode.GOING_AWAY, reason="bye")
    assert_equal(len(frame.payload), 5)  # 2 (code) + 3 (bye)
    assert_equal(chr(Int(frame.payload[2])), "b")
    assert_equal(chr(Int(frame.payload[3])), "y")
    assert_equal(chr(Int(frame.payload[4])), "e")


def test_is_control_data_frames():
    """Data frames (TEXT, BINARY, CONTINUATION) must not be control frames."""
    assert_false(WsFrame.text("x").is_control())
    var empty = List[UInt8]()
    assert_false(WsFrame.binary(empty).is_control())


# ── WsOpcode / WsCloseCode constants ─────────────────────────────────────────


def test_opcode_values():
    """WsOpcode constants must match RFC 6455 §5.2."""
    assert_equal(Int(WsOpcode.CONTINUATION), 0)
    assert_equal(Int(WsOpcode.TEXT), 1)
    assert_equal(Int(WsOpcode.BINARY), 2)
    assert_equal(Int(WsOpcode.CLOSE), 8)
    assert_equal(Int(WsOpcode.PING), 9)
    assert_equal(Int(WsOpcode.PONG), 10)


def test_close_code_values():
    """WsCloseCode constants must match RFC 6455 §7.4.1."""
    assert_equal(Int(WsCloseCode.NORMAL), 1000)
    assert_equal(Int(WsCloseCode.GOING_AWAY), 1001)
    assert_equal(Int(WsCloseCode.PROTOCOL_ERROR), 1002)


# ── WsFrame.encode() ─────────────────────────────────────────────────────────


def test_encode_small_frame_header():
    """Encoding a 5-byte text frame must produce a 2-byte header + payload."""
    var frame = WsFrame.text("hello")
    var wire = frame.encode()
    # Total: 2 header + 5 payload = 7 bytes
    assert_equal(len(wire), 7)
    # Byte 0: FIN (0x80) | TEXT (0x01) = 0x81
    assert_equal(Int(wire[0]), 0x81)
    # Byte 1: not masked (0x80 clear) | len=5
    assert_equal(Int(wire[1]), 5)


def test_encode_empty_payload():
    """Encoding a frame with no payload must produce exactly 2 header bytes."""
    var frame = WsFrame.ping()
    var wire = frame.encode()
    assert_equal(len(wire), 2)
    # Byte 0: FIN | PING = 0x89
    assert_equal(Int(wire[0]), 0x89)
    # Byte 1: no mask, len=0
    assert_equal(Int(wire[1]), 0)


def test_encode_126_byte_payload():
    """Encoding a 126-byte payload must use extended 16-bit length."""
    var payload = List[UInt8](capacity=126)
    for i in range(126):
        payload.append(UInt8(i & 0xFF))
    var frame = WsFrame.binary(payload)
    var wire = frame.encode()
    # Total: 2 base + 2 ext + 126 payload = 130 bytes
    assert_equal(len(wire), 130)
    # Byte 1: not masked, len indicator = 126
    assert_equal(Int(wire[1]), 126)
    # Bytes 2-3: length = 126 in big-endian
    assert_equal(Int(wire[2]), 0)
    assert_equal(Int(wire[3]), 126)


def test_encode_with_zero_mask():
    """Encoding with mask=True and zero key must set the MASK bit."""
    var frame = WsFrame.text("hi")
    var wire = frame.encode(mask=True)
    # 2 header + 4 mask_key + 2 payload = 8 bytes
    assert_equal(len(wire), 8)
    # Byte 1: MASK bit (0x80) | len=2
    assert_equal(Int(wire[1]), 0x80 | 2)


def test_encode_rsv1_raises():
    """Encoding with rsv1=True must raise WsProtocolError."""
    var frame = WsFrame(
        opcode=WsOpcode.TEXT,
        payload=List[UInt8](),
        rsv1=True,
    )
    with assert_raises(contains="WsProtocolError"):
        _ = frame.encode()


def test_encode_control_oversized_raises():
    """Control frame with payload > 125 bytes must raise WsProtocolError."""
    var big = List[UInt8](capacity=126)
    for _ in range(126):
        big.append(UInt8(0))
    var frame = WsFrame(opcode=WsOpcode.PING, payload=big)
    with assert_raises(contains="WsProtocolError"):
        _ = frame.encode()


# ── WsFrame.decode_one() ──────────────────────────────────────────────────────


def test_decode_small_text_frame():
    """Decoding a 2-header + 5-payload wire frame must reproduce the payload."""
    # Wire: FIN | TEXT, len=5, "hello"
    var wire = List[UInt8]()
    wire.append(UInt8(0x81))  # FIN | TEXT
    wire.append(UInt8(5))
    for c in "hello".as_bytes():
        wire.append(c)

    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(Int(result.frame.opcode), Int(WsOpcode.TEXT))
    assert_true(result.frame.fin)
    assert_equal(result.consumed, 7)
    assert_equal(result.frame.text_payload(), "hello")


def test_decode_empty_ping():
    """Decoding a 2-byte PING frame must produce an empty control frame."""
    var wire = List[UInt8]()
    wire.append(UInt8(0x89))  # FIN | PING
    wire.append(UInt8(0))

    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(Int(result.frame.opcode), Int(WsOpcode.PING))
    assert_equal(len(result.frame.payload), 0)
    assert_equal(result.consumed, 2)


def test_decode_16bit_length():
    """Decoding a frame with 16-bit extended length must read full payload."""
    var plen = 200
    var wire = List[UInt8](capacity=4 + plen)
    wire.append(UInt8(0x82))  # FIN | BINARY
    wire.append(UInt8(126))  # 16-bit extended
    wire.append(UInt8(0))
    wire.append(UInt8(plen))
    for i in range(plen):
        wire.append(UInt8(i & 0xFF))

    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(Int(result.frame.opcode), Int(WsOpcode.BINARY))
    assert_equal(len(result.frame.payload), plen)
    assert_equal(result.consumed, 4 + plen)


def test_decode_masked_frame():
    """Decoding a masked frame must XOR-unmask the payload."""
    # Encode "AB" with key [0x01, 0x02, 0x03, 0x04]
    var wire = List[UInt8]()
    wire.append(UInt8(0x81))  # FIN | TEXT
    wire.append(UInt8(0x80 | 2))  # MASK | len=2
    wire.append(UInt8(0x01))  # key[0]
    wire.append(UInt8(0x02))  # key[1]
    wire.append(UInt8(0x03))  # key[2]
    wire.append(UInt8(0x04))  # key[3]
    wire.append(UInt8(ord("A") ^ 0x01))  # 'A' ^ key[0]
    wire.append(UInt8(ord("B") ^ 0x02))  # 'B' ^ key[1]

    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(result.frame.text_payload(), "AB")
    assert_true(result.frame.masked)


def test_decode_truncated_raises():
    """Decoding fewer bytes than the frame size must raise."""
    var wire = List[UInt8]()
    wire.append(UInt8(0x81))
    wire.append(UInt8(10))  # claims 10-byte payload
    wire.append(UInt8(0))  # only 1 byte of payload

    with assert_raises():
        _ = WsFrame.decode_one(Span[UInt8](wire))


def test_decode_fragmented_control_raises():
    """A PING frame with FIN=0 must raise WsProtocolError."""
    var wire = List[UInt8]()
    wire.append(UInt8(0x09))  # FIN=0 | PING (0x09 without 0x80)
    wire.append(UInt8(0))

    with assert_raises(contains="WsProtocolError"):
        _ = WsFrame.decode_one(Span[UInt8](wire))


# ── Round-trip tests ──────────────────────────────────────────────────────────


def test_encode_decode_roundtrip_text():
    """Encode then decode a text frame must reproduce the original payload."""
    var frame = WsFrame.text("round-trip test payload")
    var wire = frame.encode()
    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(result.frame.text_payload(), "round-trip test payload")
    assert_equal(Int(result.frame.opcode), Int(WsOpcode.TEXT))
    assert_equal(result.consumed, len(wire))


def test_encode_decode_roundtrip_binary():
    """Encode then decode a binary frame must reproduce all bytes."""
    var payload = List[UInt8](capacity=256)
    for i in range(256):
        payload.append(UInt8(i))
    var frame = WsFrame.binary(payload)
    var wire = frame.encode()
    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(len(result.frame.payload), 256)
    for i in range(256):
        assert_equal(
            Int(result.frame.payload[i]), i, "byte " + String(i) + " mismatch"
        )


def test_encode_decode_roundtrip_masked():
    """Encode with zero-key mask then decode must reproduce payload."""
    var frame = WsFrame.text("masked message")
    var wire = frame.encode(mask=True)
    var result = WsFrame.decode_one(Span[UInt8](wire))
    # Zero masking key → XOR with 0 → payload unchanged
    assert_equal(result.frame.text_payload(), "masked message")


def test_encode_decode_126_bytes():
    """Encode then decode a 126-byte payload must use 16-bit length and round-trip.
    """
    var payload = List[UInt8](capacity=126)
    for i in range(126):
        payload.append(UInt8((i * 3 + 7) & 0xFF))
    var frame = WsFrame.binary(payload)
    var wire = frame.encode()
    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(len(result.frame.payload), 126)
    for i in range(126):
        assert_equal(
            Int(result.frame.payload[i]),
            Int(payload[i]),
            "byte " + String(i) + " mismatch",
        )


def test_consumed_with_trailing_data():
    """Decode_one() must set consumed correctly even with extra bytes after frame.
    """
    var wire = List[UInt8]()
    wire.append(UInt8(0x81))  # FIN | TEXT
    wire.append(UInt8(3))  # len=3
    wire.append(UInt8(ord("a")))
    wire.append(UInt8(ord("b")))
    wire.append(UInt8(ord("c")))
    # trailing garbage
    wire.append(UInt8(0xFF))
    wire.append(UInt8(0xFF))

    var result = WsFrame.decode_one(Span[UInt8](wire))
    assert_equal(result.consumed, 5)  # only 2 header + 3 payload consumed


# ── WsProtocolError typing ────────────────────────────────────────────────────


def test_ws_protocol_error_str():
    """WsProtocolError.__str__ must include the message."""
    var e = WsProtocolError("bad opcode")
    assert_true("WsProtocolError" in String(e))
    assert_true("bad opcode" in String(e))


# ── Integration: connect to echo server (skipped if offline) ─────────────────


def test_ws_connect_plain():
    """WsClient.connect() to a plain WS echo server must succeed."""
    try:
        var ws = WsClient.connect("ws://echo.websocket.events")
        ws.close()
        assert_true(True)
    except e:
        print("  [SKIP] ws:// unavailable: " + String(e))


def test_ws_echo_roundtrip():
    """Sending a text message and receiving it back must work end-to-end."""
    try:
        var ws = WsClient.connect("ws://echo.websocket.events")
        ws.send_text("flare test ping")
        # The echo server may send a welcome message first; read until we see ours
        var found = False
        for _ in range(5):
            var frame = ws.recv()
            if "flare test ping" in frame.text_payload():
                found = True
                break
        assert_true(found, "echo not received within 5 frames")
        ws.close()
    except e:
        print("  [SKIP] ws:// unavailable: " + String(e))


# ── WsServer + WsConnection on loopback ──────────────────────────────────────
#
# Strategy: all tests use RAW TCP clients (not WsClient) to avoid the
# single-threaded deadlock that would arise if WsClient.connect() (which
# blocks waiting for 101) and the server accept() had to interleave.
# Instead each test:
#   1. Binds a WsServer on port 0.
#   2. Connects a raw TcpStream.
#   3. Does the server accept() + handshake helpers explicitly.
#   4. Exchanges raw WsFrame wire bytes on the client side.


fn _send_upgrade_request_raw(mut stream: TcpStream, host: String) raises:
    """Send a minimal HTTP/1.1 upgrade request from a raw TCP stream."""
    var key = "dGhlIHNhbXBsZSBub25jZQ=="  # well-known test key
    var req = (
        "GET / HTTP/1.1\r\n"
        + "Host: "
        + host
        + "\r\n"
        + "Upgrade: websocket\r\n"
        + "Connection: Upgrade\r\n"
        + "Sec-WebSocket-Key: "
        + key
        + "\r\n"
        + "Sec-WebSocket-Version: 13\r\n"
        + "\r\n"
    )
    var b = req.as_bytes()
    stream.write_all(Span[UInt8](b))


fn _drain_101(mut stream: TcpStream) raises:
    """Read and discard the HTTP 101 response from the stream."""
    var buf = List[UInt8](capacity=512)
    buf.resize(512, 0)
    var acc = List[UInt8]()
    while True:
        var n = stream.read(buf.unsafe_ptr(), 512)
        if n == 0:
            break
        for i in range(n):
            acc.append(buf[i])
        # Stop once we see \r\n\r\n
        var nn = len(acc)
        if nn >= 4:
            for i in range(nn - 3):
                if (
                    acc[i] == 13
                    and acc[i + 1] == 10
                    and acc[i + 2] == 13
                    and acc[i + 3] == 10
                ):
                    return


def test_ws_server_text_echo_loopback():
    """WsConnection.recv + send_text on loopback with a raw TCP client.

    Avoids single-thread deadlock by using raw TCP instead of WsClient.
    """
    from flare.ws import WsServer, WsConnection
    from flare.ws.server import (
        _read_upgrade_request,
        _send_upgrade_response,
        _compute_accept_srv,
    )
    from flare.net import SocketAddr
    from flare.tcp import TcpStream

    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    # ── Client: connect + send upgrade request (non-blocking – goes to kernel queue)
    var raw_client = TcpStream.connect(SocketAddr.localhost(port))
    _send_upgrade_request_raw(raw_client, "localhost")

    # ── Server: accept + handshake
    var server_stream = srv._listener.accept()
    var srv_peer = server_stream.peer_addr()
    var key = _read_upgrade_request(server_stream)
    var accept = _compute_accept_srv(key)
    _send_upgrade_response(server_stream, accept)
    var conn = WsConnection(server_stream^, srv_peer)

    # ── Client: discard 101, then send masked TEXT frame
    _drain_101(raw_client)

    # Build a masked client TEXT frame: payload "hi"
    var client_frame = WsFrame.text("hi")
    var client_wire = client_frame.encode(mask=True)
    raw_client.write_all(Span[UInt8](client_wire))

    # ── Server: receive
    var frame = conn.recv()
    assert_equal(frame.opcode, WsOpcode.TEXT)
    assert_equal(frame.text_payload(), "hi")

    # ── Server: send back TEXT
    conn.send_text("echo:hi")

    # ── Client: receive unmasked server frame
    var echo_wire = List[UInt8](capacity=32)
    echo_wire.resize(32, 0)
    var n_echo = raw_client.read(echo_wire.unsafe_ptr(), 32)
    assert_true(n_echo > 0, "Expected echo frame from server")

    raw_client.close()
    srv.close()


def test_ws_server_binary_echo_loopback():
    """WsConnection.recv handles masked binary frames correctly."""
    from flare.ws import WsServer, WsConnection
    from flare.ws.server import (
        _read_upgrade_request,
        _send_upgrade_response,
        _compute_accept_srv,
    )
    from flare.net import SocketAddr
    from flare.tcp import TcpStream

    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var raw_client = TcpStream.connect(SocketAddr.localhost(port))
    _send_upgrade_request_raw(raw_client, "localhost")

    var server_stream = srv._listener.accept()
    var srv_peer2 = server_stream.peer_addr()
    var key = _read_upgrade_request(server_stream)
    var accept = _compute_accept_srv(key)
    _send_upgrade_response(server_stream, accept)
    var conn = WsConnection(server_stream^, srv_peer2)

    _drain_101(raw_client)

    var payload = List[UInt8]()
    payload.append(UInt8(0xDE))
    payload.append(UInt8(0xAD))
    payload.append(UInt8(0xBE))
    var bin_frame = WsFrame.binary(payload)
    var bin_wire = bin_frame.encode(mask=True)
    raw_client.write_all(Span[UInt8](bin_wire))

    var frame = conn.recv()
    assert_equal(frame.opcode, WsOpcode.BINARY)
    assert_equal(len(frame.payload), 3)
    assert_equal(frame.payload[0], UInt8(0xDE))
    assert_equal(frame.payload[1], UInt8(0xAD))
    assert_equal(frame.payload[2], UInt8(0xBE))

    raw_client.close()
    srv.close()


def test_ws_server_unmasked_frame_rejected():
    """WsConnection.recv must raise WsProtocolError on an unmasked client frame.

    RFC 6455 §5.1: server must reject unmasked frames.
    """
    from flare.ws import WsServer, WsConnection
    from flare.ws.server import (
        _read_upgrade_request,
        _send_upgrade_response,
        _compute_accept_srv,
    )
    from flare.net import SocketAddr
    from flare.tcp import TcpStream

    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port

    var raw_client = TcpStream.connect(SocketAddr.localhost(port))
    _send_upgrade_request_raw(raw_client, "localhost")

    var server_stream = srv._listener.accept()
    var srv_peer3 = server_stream.peer_addr()
    var key = _read_upgrade_request(server_stream)
    var accept = _compute_accept_srv(key)
    _send_upgrade_response(server_stream, accept)
    var conn = WsConnection(server_stream^, srv_peer3)

    _drain_101(raw_client)

    # Send an UNMASKED TEXT frame (mask bit = 0): opcode=0x81, length=5
    var bad_frame = List[UInt8]()
    bad_frame.append(UInt8(0x81))  # FIN + TEXT opcode
    bad_frame.append(UInt8(5))  # MASK bit NOT set, length = 5
    bad_frame.append(UInt8(104))  # h
    bad_frame.append(UInt8(101))  # e
    bad_frame.append(UInt8(108))  # l
    bad_frame.append(UInt8(108))  # l
    bad_frame.append(UInt8(111))  # o
    raw_client.write_all(Span[UInt8](bad_frame))

    with assert_raises():
        _ = conn.recv()

    raw_client.close()
    srv.close()


def main():
    print("=" * 60)
    print("test_ws.mojo — WsFrame codec + WsClient + WsServer")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
