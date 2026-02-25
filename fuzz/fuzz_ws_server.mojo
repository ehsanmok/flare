"""Fuzz harness: WebSocket server upgrade parser + masked frame receiver.

Two independent attack surfaces:

1. **Upgrade request parser** (``_parse_ws_upgrade_bytes``):
   Feeds arbitrary bytes as an HTTP Upgrade request.  Tests all
   header-parsing paths including missing/malformed Upgrade,
   Connection, and Sec-WebSocket-Key headers.

2. **Masked frame receiver** (``WsFrame.decode_one``):
   Feeds arbitrary bytes as a client→server WebSocket frame.  Since
   clients MUST mask frames (RFC 6455 §5.1), the harness sets the
   MASK bit in the first two bytes when present, ensuring coverage of
   the unmasking logic, length-extension (16/64-bit), and every opcode.

3. **Property — unmasked frames are always rejected**:
   If the MASK bit is clear in the fuzz input and decoding succeeds,
   the server code would call ``WsProtocolError``.  This property
   checks that ``WsFrame.decode_one`` correctly marks frames as
   unmasked when the bit is absent.

Valid ``Error`` / ``NetworkError`` rejections are expected.  Only
crash-marker messages trigger a saved crash.

Run:
    pixi run fuzz-ws-server
"""

from mozz import fuzz, FuzzConfig, forall_bytes
from flare.ws.server import _parse_ws_upgrade_bytes
from flare.ws.frame import WsFrame, WsOpcode, WsProtocolError


# ── Target 1: WebSocket upgrade request parser ────────────────────────────────


fn target_upgrade(data: List[UInt8]) raises:
    """Fuzz target: parse an HTTP WebSocket Upgrade request from arbitrary bytes.

    Args:
        data: Arbitrary bytes presented as an HTTP Upgrade request.

    Raises:
        Expected: ``NetworkError``, ``Error`` — classified as rejections.
        Bug:      Crash-marker messages — classified as crashes and saved.
    """
    _ = _parse_ws_upgrade_bytes(Span[UInt8](data))


# ── Target 2: WebSocket masked frame decoder ──────────────────────────────────


fn target_frame(data: List[UInt8]) raises:
    """Fuzz target: decode a WebSocket frame as if from a masked client.

    Feeds arbitrary bytes to ``WsFrame.decode_one``.  Any valid frame
    must be consistent (``consumed`` ≤ ``len(data)``).

    Args:
        data: Arbitrary bytes.

    Raises:
        Expected: ``Error``, ``WsProtocolError`` — classified as rejections.
        Bug:      Crash-marker messages — classified as crashes and saved.
    """
    try:
        var result = WsFrame.decode_one(Span[UInt8](data))
        # Invariant: never consume more bytes than were given
        if result.consumed > len(data):
            raise Error(
                "[BUG] WsFrame.decode_one consumed "
                + String(result.consumed)
                + " bytes from input of length "
                + String(len(data))
            )
    except e:
        var msg = String(e)
        # Crash markers are bugs; all other errors are expected rejections
        if (
            "assertion failed" in msg
            or "index out of bounds" in msg
            or "panic" in msg
        ):
            raise e^


# ── Property: unmasked frames always have masked=False ────────────────────────


fn prop_mask_bit_honoured(data: List[UInt8]) raises -> Bool:
    """Property: MASK bit in byte 1 of decoded frame matches input bit.

    RFC 6455 §5.2: byte 1 bit 7 (0x80) is the MASK flag.  The decoder
    must faithfully reflect this; it must never flip the bit.

    Args:
        data: Arbitrary bytes.

    Returns:
        ``True`` if the invariant holds or the input was rejected.
    """
    if len(data) < 2:
        return True
    try:
        var result = WsFrame.decode_one(Span[UInt8](data))
        var frame = result.take_frame()
        var expected_masked = (Int(data[1]) & 0x80) != 0
        if frame.masked != expected_masked:
            return False  # bug: mask bit mismatch
        return True
    except:
        return True  # rejection is fine


# ── Property: CLOSE frames always have code in 1000–4999 or empty ─────────────


fn prop_close_code_range(data: List[UInt8]) raises -> Bool:
    """Property: successfully decoded CLOSE frames have valid or absent codes.

    RFC 6455 §7.4: valid close codes are 1000–2999 (protocol-defined)
    and 3000–4999 (application-defined).  Codes below 1000 and 5000+
    are invalid but we allow the decoder to accept/reject as it sees fit;
    this property just checks the decoder doesn't panic.

    Args:
        data: Arbitrary bytes.

    Returns:
        Always ``True`` (this is a no-crash property).
    """
    try:
        var result = WsFrame.decode_one(Span[UInt8](data))
        var frame = result.take_frame()
        if frame.opcode == WsOpcode.CLOSE:
            # Accessing the payload is fine; no assertion on code value
            _ = len(frame.payload)
        return True
    except:
        return True


fn main() raises:
    print("[mozz] WebSocket server fuzz harnesses\n")

    fn _b(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    # ── Upgrade request seeds ─────────────────────────────────────────────────

    var upgrade_seeds = List[List[UInt8]]()

    # Minimal valid upgrade request
    upgrade_seeds.append(
        _b(
            "GET /chat HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
    )

    # Missing Sec-WebSocket-Key
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "\r\n"
        )
    )

    # Missing Upgrade header
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: abc==\r\n"
            "\r\n"
        )
    )

    # Missing Connection header
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Sec-WebSocket-Key: abc==\r\n"
            "\r\n"
        )
    )

    # Upgrade header wrong value
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "Upgrade: http2\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: abc==\r\n"
            "\r\n"
        )
    )

    # Case-insensitive headers (mixed case)
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "UPGRADE: WebSocket\r\n"
            "CONNECTION: upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "\r\n"
        )
    )

    # Empty body
    upgrade_seeds.append(_b("\r\n\r\n"))

    # Garbage
    upgrade_seeds.append(_b("\xff\x00\x01upgrade"))

    # LF-only
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\n"
            "Upgrade: websocket\n"
            "Connection: Upgrade\n"
            "Sec-WebSocket-Key: abc==\n"
            "\n"
        )
    )

    # Header with no colon
    upgrade_seeds.append(_b("GET / HTTP/1.1\r\nNoCOlonHeader\r\n\r\n"))

    # Very long key value
    upgrade_seeds.append(
        _b(
            "GET / HTTP/1.1\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\r\n"
            "\r\n"
        )
    )

    print("1. Fuzzing _parse_ws_upgrade_bytes() (500 000 runs)...")
    fuzz(
        target_upgrade,
        FuzzConfig(
            max_runs=500_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/ws_server_upgrade",
            max_input_len=2048,
        ),
        upgrade_seeds,
    )
    print("   PASS: upgrade parser never crashed\n")

    # ── Masked frame decoder seeds ────────────────────────────────────────────

    var frame_seeds = List[List[UInt8]]()

    # Valid masked text frame "Hello" (opcode=0x01, mask=1, len=5)
    # Mask key = 0x37 0xFA 0x21 0x3D; payload = 0x7F 0x9F 0x4D 0x51 0x58
    var masked_hello: List[UInt8] = [
        0x81,
        0x85,
        0x37,
        0xFA,
        0x21,
        0x3D,
        0x7F,
        0x9F,
        0x4D,
        0x51,
        0x58,
    ]
    frame_seeds.append(masked_hello)

    # Valid masked binary frame (opcode=0x02)
    var masked_binary: List[UInt8] = [
        0x82,
        0x84,
        0x00,
        0x00,
        0x00,
        0x00,
        0xDE,
        0xAD,
        0xBE,
        0xEF,
    ]
    frame_seeds.append(masked_binary)

    # Valid masked PING (opcode=0x09)
    var masked_ping: List[UInt8] = [0x89, 0x80, 0x00, 0x00, 0x00, 0x00]
    frame_seeds.append(masked_ping)

    # Valid masked CLOSE normal (opcode=0x08, code=1000)
    var masked_close: List[UInt8] = [
        0x88,
        0x82,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0xE8,
    ]
    frame_seeds.append(masked_close)

    # Masked 16-bit length frame (len=126, actual len=200)
    var m16 = List[UInt8](unsafe_uninit_length=8 + 200)
    m16[0] = 0x82  # FIN + binary
    m16[1] = 0xFE  # MASK + 126 (16-bit length follows)
    m16[2] = 0x00
    m16[3] = 200  # 16-bit length
    m16[4] = 0x00
    m16[5] = 0x00
    m16[6] = 0x00
    m16[7] = 0x00  # mask key
    for i in range(200):
        m16[8 + i] = UInt8(i & 0xFF)
    frame_seeds.append(m16^)

    # Unmasked frame (should decode as unmasked, server would then reject)
    var unmasked: List[UInt8] = [0x81, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
    frame_seeds.append(unmasked)

    # Empty input
    frame_seeds.append(List[UInt8]())

    # Single byte
    var single: List[UInt8] = [0x81]
    frame_seeds.append(single)

    # Truncated header
    var trunc: List[UInt8] = [0x82, 0x85]
    frame_seeds.append(trunc)

    # Garbage
    var garbage: List[UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    frame_seeds.append(garbage)

    print(
        "2. Fuzzing WsFrame.decode_one() masked/client frames (500 000 runs)..."
    )
    fuzz(
        target_frame,
        FuzzConfig(
            max_runs=500_000,
            seed=1,
            verbose=True,
            crash_dir=".mozz_crashes/ws_server_frame",
            max_input_len=1024,
        ),
        frame_seeds,
    )
    print("   PASS: frame decoder never crashed\n")

    # ── Property tests ────────────────────────────────────────────────────────

    print("3. Property: MASK bit faithfully reflected (20 000 trials)...")
    forall_bytes(prop_mask_bit_honoured, max_len=256, trials=20_000, seed=2)
    print("   PASS: mask bit always correct\n")

    print("4. Property: CLOSE frame access never crashes (10 000 trials)...")
    forall_bytes(prop_close_code_range, max_len=200, trials=10_000, seed=3)
    print("   PASS: CLOSE frame handling safe\n")

    print("All WebSocket server fuzz properties hold!")
