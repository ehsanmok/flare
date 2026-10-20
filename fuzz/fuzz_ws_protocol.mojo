"""Fuzz harness: sans-I/O WebSocket protocol core.

Feeds arbitrary bytes to ``WsProtocol`` in chunks whose size the first
byte picks, the way a socket splits them, and checks after every event:
no message exceeds the cap, a text message is UTF-8, nothing follows the
end of the session, and the outbox stays bounded.

Run:
    pixi run fuzz-ws-protocol
"""

from mozz import fuzz, FuzzConfig
from flare.ws.frame import _is_valid_utf8
from flare.ws.protocol import WS_EVENT_MESSAGE, WsProtocol

comptime _MAX_MESSAGE = 256
comptime _MAX_OUTBOX = 1024


def target(data: List[UInt8]) raises:
    if len(data) == 0:
        return
    var chunk = Int(data[0] % 17) + 1
    var p = WsProtocol(max_message=_MAX_MESSAGE, max_outbox=_MAX_OUTBOX)
    var off = 1
    var ended = False
    while off < len(data):
        var end = min(off + chunk, len(data))
        p.inbox.extend(Span[UInt8, _](data)[off:end])
        off = end
        while True:
            var ev = p.next_event()
            if not ev:
                break
            if ended:
                raise Error("assertion failed: event after the session ended")
            if ev.value().kind == WS_EVENT_MESSAGE:
                if len(ev.value().payload) > _MAX_MESSAGE:
                    raise Error("assertion failed: message over the cap")
                if ev.value().is_text and not _is_valid_utf8(
                    ev.value().payload
                ):
                    raise Error("assertion failed: text message not UTF-8")
            else:
                ended = True
        if len(p.outbox) > _MAX_OUTBOX + _MAX_MESSAGE + 14:
            raise Error("assertion failed: outbox unbounded")
        if p.finished():
            ended = True


def main() raises:
    print("[mozz] fuzzing WsProtocol...")
    var seeds = List[List[UInt8]]()
    # chunk byte, masked TEXT "hi" (key 0), masked PING, masked CLOSE 1000
    var s1: List[UInt8] = [
        0x03,
        0x81,
        0x82,
        0,
        0,
        0,
        0,
        0x68,
        0x69,
        0x89,
        0x80,
        0,
        0,
        0,
        0,
        0x88,
        0x82,
        0,
        0,
        0,
        0,
        0x03,
        0xE8,
    ]
    seeds.append(s1^)
    # chunk byte, fragmented TEXT then CONTINUATION
    var s2: List[UInt8] = [
        0x00,
        0x01,
        0x81,
        0,
        0,
        0,
        0,
        0x61,
        0x80,
        0x81,
        0,
        0,
        0,
        0,
        0x62,
    ]
    seeds.append(s2^)
    fuzz(
        target,
        FuzzConfig(
            max_runs=500_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/ws_protocol",
            corpus_dir="fuzz/corpus/ws_protocol",
            max_input_len=2048,
        ),
        seeds,
    )
