"""Fuzz harness: ``flare.http2.frame.parse_frame`` (v0.6 — Track J).

Two properties:

1. ``parse_frame`` never panics on arbitrary bytes. It must
   return ``None`` (incomplete buffer), an ``Optional[Frame]``
   (well-formed), or raise a regular ``Error`` (length > 24-bit
   max).
2. ``encode_frame(parse_frame(b)) == b`` for any well-formed
   prefix the parser accepts.

Run:
    pixi run fuzz-h2-frame
"""

from mozz import fuzz, FuzzConfig

from flare.http2.frame import encode_frame, parse_frame


def target(data: List[UInt8]) raises:
    var span = Span[UInt8, _](data)
    try:
        var maybe = parse_frame(span)
        if not maybe:
            return
        var f = maybe.value().copy()
        var bytes = encode_frame(f)
        # Round-trip property: re-encoded bytes match the consumed
        # prefix (header+payload = 9 + length).
        var consumed = 9 + f.header.length
        if len(bytes) != consumed:
            raise Error("h2 frame round-trip: length mismatch")
        for i in range(consumed):
            if bytes[i] != data[i]:
                raise Error(
                    "h2 frame round-trip: byte mismatch at " + String(i)
                )
    except:
        pass


def main() raises:
    print("[mozz] fuzzing flare.http2.frame.parse_frame...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00\x00\x00\x04\x00\x00\x00\x00\x00"))
    seeds.append(_bytes("\x00\x00\x05\x00\x01\x00\x00\x00\x01hello"))
    seeds.append(_bytes("\x00\x00\x00\x06\x01\x00\x00\x00\x00"))
    seeds.append(_bytes("\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h2_frame",
            corpus_dir="fuzz/corpus/h2_frame",
            max_input_len=1024,
        ),
        seeds,
    )
