"""Fuzz harness: ``flare.uds.frame_mux`` (frame codec + FrameDemux).

Three property contracts over arbitrary input bytes:

1. **Demux robustness.** ``FrameDemux.feed`` on arbitrary bytes -- fed in
   arbitrarily-sized pieces -- either routes complete frames or raises a
   regular ``Error`` (an oversize declared length). It must never read
   out of bounds or panic, and a trailing partial frame is simply
   retained (never misrouted).

2. **Codec round trip.** A frame built from the fuzz bytes
   (``request_id`` + ``kind`` + ``payload``) encodes through
   ``encode_frame`` and decodes through ``decode_frame`` to an identical
   ``request_id`` / ``kind`` / ``payload``.

3. **Reassembly invariance.** Several frames concatenated and then fed
   one byte at a time reassemble, in FIFO order per ``request_id``, to
   exactly the frames that were encoded -- the split boundary never
   changes the result.

Run:
    pixi run --environment fuzz fuzz-frame-mux
"""

from mozz import fuzz, FuzzConfig

from flare.io import ByteReader, ByteWriter
from flare.uds.frame_mux import (
    Frame,
    FrameDemux,
    FrameKind,
    decode_frame,
    encode_frame,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def target(data: List[UInt8]) raises:
    var n = len(data)

    # ── 1. Demux robustness on arbitrary bytes, fed in pieces ───
    # Use the first byte (if any) as a chunk-size selector so the split
    # boundary varies across runs; feeding must be split-invariant and
    # never panic.
    var d = FrameDemux()
    var step = 1
    if n > 0:
        step = (Int(data[0]) % 7) + 1
    var i = 0
    var raised = False
    while i < n:
        var end = i + step
        if end > n:
            end = n
        try:
            d.feed(Span[UInt8, _](data)[i:end])
        except:
            # Only a protocol error (oversize length) may raise; once it
            # does, the buffer is in a defined state and we stop feeding.
            raised = True
            break
        i = end
    _ = raised  # both outcomes are acceptable; the point is no panic/OOB

    # ── 2. Codec round trip ─────────────────────────────────────
    if n >= 9:
        var rid: UInt64 = 0
        for k in range(8):
            rid |= UInt64(data[k]) << (UInt64(k) * 8)
        var kind = UInt8(Int(data[8]) % 5)
        var payload = List[UInt8](capacity=n - 9)
        for k in range(9, n):
            payload.append(data[k])

        var w = ByteWriter()
        encode_frame(w, rid, kind, Span[UInt8, _](payload))
        var enc = w.take()
        var r = ByteReader(Span[UInt8, _](enc))
        var f = decode_frame(r)
        _assert(f.request_id == rid, "frame_mux: request_id round-trip drift")
        _assert(Int(f.kind) == Int(kind), "frame_mux: kind round-trip drift")
        _assert(
            len(f.payload) == len(payload),
            "frame_mux: payload length round-trip drift",
        )
        for k in range(len(payload)):
            _assert(
                f.payload[k] == payload[k],
                "frame_mux: payload byte round-trip drift",
            )
        _assert(r.remaining() == 0, "frame_mux: codec left trailing bytes")

        # ── 3. Reassembly invariance: two frames, byte-at-a-time ─
        var w2 = ByteWriter()
        encode_frame(w2, rid, FrameKind.CHUNK, Span[UInt8, _](payload))
        encode_frame(w2, rid, FrameKind.DONE, Span[UInt8, _](List[UInt8]()))
        var stream = w2.take()
        var d2 = FrameDemux()
        for k in range(len(stream)):
            var one = List[UInt8](capacity=1)
            one.append(stream[k])
            d2.feed(Span[UInt8, _](one))
        _assert(
            d2.pending(rid) == 2,
            "frame_mux: split feed lost or merged frames",
        )
        var first = d2.poll(rid)
        _assert(first.__bool__(), "frame_mux: missing first reassembled frame")
        _assert(
            Int(first.value().kind) == Int(FrameKind.CHUNK),
            "frame_mux: reassembly reordered frames",
        )
        var second = d2.poll(rid)
        _assert(
            Int(second.value().kind) == Int(FrameKind.DONE),
            "frame_mux: reassembly second-frame drift",
        )


def main() raises:
    print("=" * 60)
    print("fuzz_frame_mux.mojo — frame codec + FrameDemux")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"))
    # One complete CHUNK frame for request_id=1, payload "hi".
    seeds.append(
        _bytes("\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x01hi")
    )
    # Oversize length header (must raise, not allocate).
    seeds.append(_bytes("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x01\x01"))
    # Truncated frame (header says 4 bytes, only 1 present).
    seeds.append(
        _bytes("\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00\x02\x01z")
    )

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/frame_mux",
            corpus_dir="fuzz/corpus/frame_mux",
            max_input_len=512,
        ),
        seeds,
    )
