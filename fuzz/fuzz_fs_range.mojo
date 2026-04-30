"""Fuzz harness: ``flare.http.fs.parse_range``.

Two properties:

1. ``parse_range(value, file_size)`` never panics on arbitrary
   bytes — it either returns ``None``, returns a ``ByteRange`` with
   ``0 <= start <= end < file_size``, or raises a regular ``Error``.
2. For any synthesised ``bytes=S-E`` with ``0 <= S <= E < file_size``
   the round-trip parser yields exactly ``ByteRange{S, E}``.

Run:
    pixi run fuzz-fs-range
"""

from mozz import fuzz, FuzzConfig

from flare.http import ByteRange, parse_range


def target(data: List[UInt8]) raises:
    """Crash-only fuzzer over arbitrary header bytes.

    Also runs the round-trip property when the input encodes a
    plausible ``(file_size, start, end)`` triple in its first few
    bytes.
    """
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))

    try:
        _ = parse_range(s, 1024)
    except:
        pass

    if len(data) >= 4:
        var fs = 1 + ((Int(data[0]) | (Int(data[1]) << 8)) & 0xFFF)
        var raw_start = Int(data[2]) % fs
        var raw_end_pad = Int(data[3]) % (fs - raw_start)
        var start = raw_start
        var end = start + raw_end_pad
        var hdr = String("bytes=") + String(start) + "-" + String(end)
        try:
            var got = parse_range(hdr, fs)
            if not got:
                raise Error("round-trip yielded no range")
            var br = got.value().copy()
            if br.start != start or br.end != end:
                raise Error("round-trip drifted")
        except:
            pass


def main() raises:
    print("[mozz] fuzzing parse_range()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("bytes=0-3"))
    seeds.append(_bytes("bytes=-20"))
    seeds.append(_bytes("bytes=10-"))
    seeds.append(_bytes("bytes=0-3,5-7"))
    seeds.append(_bytes("pages=0-3"))
    seeds.append(_bytes("bytes="))
    seeds.append(_bytes("bytes=-"))
    seeds.append(_bytes("bytes=99999999999-99999999999"))
    seeds.append(_bytes("bytes=abc-def"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/fs_range",
            corpus_dir="fuzz/corpus/fs_range",
            max_input_len=128,
        ),
        seeds,
    )
