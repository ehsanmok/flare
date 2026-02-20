"""Example 06 — WebSocket echo client with flare.ws.

Demonstrates:
  - Connecting to a plain WebSocket server (ws://)
  - Sending a text message and receiving the echo
  - Manual ping/pong (recv() handles pong automatically)
  - Graceful close with a status code
  - WsFrame inspection: opcode, fin, payload

Run:
    pixi run example-ws

The integration steps (connect / send / recv) skip gracefully when the
echo server is unreachable.
"""

from flare.ws import WsClient, WsFrame, WsOpcode


def _show_frame(f: WsFrame):
    """Pretty-print a frame's header and payload."""
    var opname = String("UNKNOWN")
    if f.opcode == WsOpcode.TEXT:
        opname = "TEXT"
    elif f.opcode == WsOpcode.BINARY:
        opname = "BINARY"
    elif f.opcode == WsOpcode.PING:
        opname = "PING"
    elif f.opcode == WsOpcode.PONG:
        opname = "PONG"
    elif f.opcode == WsOpcode.CLOSE:
        opname = "CLOSE"
    elif f.opcode == WsOpcode.CONTINUATION:
        opname = "CONTINUATION"
    print(
        "  frame opcode=" + opname,
        "fin=" + String(f.fin),
        "len=" + String(len(f.payload)),
        'payload="' + f.text_payload() + '"',
    )


def main():
    print("=== flare Example 06: WebSocket Echo Client ===")
    print()

    # ── Section 1: Frame construction (offline, always works) ─────────────────
    print("── 1. Frame construction ──")
    var text_frame = WsFrame.text("Hello, flare WebSocket!")
    print(
        "  WsFrame.text() opcode:",
        text_frame.opcode,
        "(expect 1 =",
        WsOpcode.TEXT,
        ")",
    )
    print("  fin:", text_frame.fin, " payload:", text_frame.text_payload())

    var ping = WsFrame.ping()
    print("  WsFrame.ping() opcode:", ping.opcode, "(expect 9)")

    var close = WsFrame.close()
    print("  WsFrame.close() opcode:", close.opcode, "(expect 8)")
    print()

    # ── Section 2: Frame encode → decode round-trip ────────────────────────────
    print("── 2. Encode → decode round-trip ──")
    var original = WsFrame.text("round-trip test OK")
    var wire = original.encode()
    print("  encoded size:", len(wire), "bytes")

    try:
        var result = WsFrame.decode_one(Span[UInt8](wire))
        var decoded = result^.take_frame()
        print("  decoded payload:", decoded.text_payload())
        print(
            "  round-trip OK:", decoded.text_payload() == "round-trip test OK"
        )
    except e:
        print("  decode error:", String(e))
    print()

    # ── Section 3: Live echo (skipped when offline) ────────────────────────────
    print("── 3. Live WebSocket echo (ws://echo.websocket.events) ──")
    try:
        var ws = WsClient.connect("ws://echo.websocket.events")
        print("  Connected!")

        # Send a text message and wait for the echo
        ws.send_text("flare says hello!")
        print("  Sent: 'flare says hello!'")

        # The server may send a welcome banner; read until we get our echo.
        var found = False
        for _ in range(5):
            var frame = ws.recv()
            _show_frame(frame)
            if "flare says hello!" in frame.text_payload():
                found = True
                break

        if found:
            print("  ✓ Echo received")
        else:
            print("  ✗ Echo not received within 5 frames")

        # Clean close
        ws.close()
        print("  Connection closed cleanly")

    except e:
        print("  [SKIP] echo server unavailable:", String(e))

    print()
    print("=== Example 06 complete ===")
