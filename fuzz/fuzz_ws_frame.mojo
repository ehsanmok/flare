"""Fuzz harness: WebSocket frame decoder.

Tests ``WsFrame.decode_one()`` for crashes on arbitrary byte inputs.
Valid rejections (``WsProtocolError``, ``Error``) are expected and not
reported as bugs.  Only error messages matching mozz's crash markers
(``"assertion failed"``, ``"index out of bounds"``, etc.) trigger a crash.

Run:
    pixi run fuzz-ws

Replay a crash:
    mojo -I . fuzz/fuzz_ws_frame.mojo  # with seed from crash filename
"""

from mozz import fuzz, FuzzConfig
from flare.ws.frame import WsFrame


fn target(data: List[UInt8]) raises:
    """Fuzz target: parse one WebSocket frame.

    Args:
        data: Arbitrary bytes from the mutator.

    Raises:
        Any exception from ``decode_one`` is caught by the runner and
        classified as valid rejection (not a crash) unless the message
        contains a crash marker.
    """
    _ = WsFrame.decode_one(Span[UInt8](data))


fn main() raises:
    print("[mozz] fuzzing WsFrame.decode_one()...")

    # Seed corpus with real-world WS frames:
    var seeds = List[List[UInt8]]()

    # Unmasked text "hello" (server→client)
    var s1: List[UInt8] = [0x81, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F]
    seeds.append(s1^)

    # Masked PING (client→server, mask key = 0x00000000)
    var s2: List[UInt8] = [0x89, 0x80, 0x00, 0x00, 0x00, 0x00]
    seeds.append(s2^)

    # CLOSE frame
    var s3: List[UInt8] = [0x88, 0x02, 0x03, 0xE8]
    seeds.append(s3^)

    # Frame with 16-bit extended length (empty payload, len=126)
    var s4: List[UInt8] = [0x82, 0x7E, 0x00, 0x7E]
    seeds.append(s4^)

    # Truncated frame (too short)
    var s5: List[UInt8] = [0x81]
    seeds.append(s5^)

    # Empty input
    var s6: List[UInt8] = []
    seeds.append(s6^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=500_000,
            seed=0,  # non-deterministic: use wall-clock entropy
            verbose=True,
            crash_dir=".mozz_crashes/ws_frame",
            corpus_dir="fuzz/corpus/ws_frame",
            max_input_len=1024,  # keep fast; real max is 65540
        ),
        seeds,
    )
