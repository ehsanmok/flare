"""Property test: WebSocket frame encode → decode round-trip.

For any valid encoded frame the following must hold:
    decode_one(encode(frame)).payload == frame.payload

Invalid or too-large frames are expected to raise and are treated as
not-a-counterexample.

Run:
    pixi run prop-ws

Increase ``trials`` to improve coverage:
    mojo -I . fuzz/prop_ws_roundtrip.mojo
"""

from mozz import forall_bytes
from flare.ws.frame import WsFrame


fn roundtrip_safe(data: List[UInt8]) raises -> Bool:
    """Property: encode→decode preserves the payload for any valid frame.

    Args:
        data: Raw bytes to attempt decoding as a WebSocket frame.

    Returns:
        ``True`` if the round-trip is consistent or the input is invalid.
        ``False`` only if the payload is corrupted after a successful
        round-trip.
    """
    var span = Span[UInt8](data)

    # Try to decode an incoming frame
    var original_payload: List[UInt8]
    try:
        var f = WsFrame.decode_one(span).take_frame()
        original_payload = f.payload.copy()
    except:
        return True  # invalid input: not a counterexample

    # Re-encode (unmasked — server→client direction)
    var re_encoded: List[UInt8]
    try:
        var tmp_frame = WsFrame.decode_one(span).take_frame()
        re_encoded = tmp_frame.encode(mask=False)
    except:
        return True  # valid rejection (e.g. control frame too large)

    # Decode again
    var frame2_payload: List[UInt8]
    try:
        var f2 = WsFrame.decode_one(Span[UInt8](re_encoded)).take_frame()
        frame2_payload = f2.payload.copy()
    except:
        # If re-encoding produced invalid bytes that's a bug
        return False

    # Payload must be identical
    if len(frame2_payload) != len(original_payload):
        return False
    for i in range(len(original_payload)):
        if frame2_payload[i] != original_payload[i]:
            return False

    return True


fn no_over_read(data: List[UInt8]) raises -> Bool:
    """Property: consumed bytes must not exceed input length.

    Args:
        data: Raw bytes for the decoder.

    Returns:
        ``True`` if consumed ≤ len(data) or input was rejected.
    """
    try:
        var dr = WsFrame.decode_one(Span[UInt8](data))
        return dr.consumed <= len(data)
    except:
        return True  # rejection is fine


fn control_frame_payload_limit(data: List[UInt8]) raises -> Bool:
    """Property: control frames with payload > 125 bytes always raise.

    Args:
        data: Input bytes.

    Returns:
        ``True`` if the invariant holds (payload ≤ 125 for control frames,
        or parsing raised an error).
    """
    try:
        var frame = WsFrame.decode_one(Span[UInt8](data)).take_frame()
        var is_ctrl = frame.is_control()
        var plen = len(frame.payload)
        if is_ctrl:
            return plen <= 125
        return True
    except:
        return True  # error is fine


fn main() raises:
    print("[mozz] WebSocket frame round-trip property tests\n")

    print("1. encode→decode round-trip (10 000 trials)...")
    forall_bytes(roundtrip_safe, max_len=131, trials=10_000, seed=1)
    print("   PASS: round-trip preserves payload\n")

    print("2. No over-read: consumed <= len(data) (20 000 trials)...")
    forall_bytes(no_over_read, max_len=256, trials=20_000, seed=2)
    print("   PASS: decoder never reads past input\n")

    print("3. Control frame payload <= 125 bytes (10 000 trials)...")
    forall_bytes(
        control_frame_payload_limit, max_len=200, trials=10_000, seed=3
    )
    print("   PASS: control frame payload limit honoured\n")

    print("All WebSocket properties hold!")
