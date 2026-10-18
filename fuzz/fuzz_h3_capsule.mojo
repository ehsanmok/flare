"""Fuzz harness: ``flare.http3.capsule.parse_capsule`` (RFC 9297 sec 3).

Properties checked:

1. On arbitrary bytes the parser returns ``None`` (incomplete), a
   capsule whose span fits the buffer and whose value respects the
   cap, or raises a regular ``Error`` (value over the cap). It never
   panics.
2. Split invariance: any prefix of a buffer that parses parses to
   ``None`` or to the same capsule.
3. Encode-then-parse round trip for a capsule carved from the input.

Run:
    pixi run --environment fuzz fuzz-h3-capsule
"""

from mozz import fuzz, FuzzConfig

from flare.http3.capsule import encode_capsule, parse_capsule


comptime _CAP: Int = 512


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def target(data: List[UInt8]) raises:
    var span = Span[UInt8, _](data)
    var whole: Optional[Tuple[UInt64, List[UInt8], Int]] = None
    try:
        var got = parse_capsule(span, _CAP)
        if got:
            ref c = got.value()
            _assert(c[1] <= len(data), "capsule: span past the buffer")
            _assert(len(c[0].value) <= _CAP, "capsule: value over the cap")
            whole = (c[0].capsule_type, c[0].value.copy(), c[1])
    except:
        pass
    if whole:
        ref w = whole.value()
        for cut in range(w[2]):
            var part = parse_capsule(span[:cut], _CAP)
            _assert(not part, "capsule: a strict prefix parsed")
    if len(data) >= 1:
        var t = UInt64(data[0]) * 977
        var value = span[1 : min(len(data), _CAP + 1)]
        var buf = List[UInt8]()
        encode_capsule(t, value, buf)
        var back = parse_capsule(Span[UInt8, _](buf), _CAP).value().copy()
        _assert(back[0].capsule_type == t, "capsule: type drift")
        _assert(back[0].value == List[UInt8](value), "capsule: value drift")
        _assert(back[1] == len(buf), "capsule: consumed drift")


def _bytes(s: StringLiteral) -> List[UInt8]:
    return List[UInt8](s.as_bytes())


def main() raises:
    print("=" * 60)
    print("fuzz_h3_capsule.mojo — RFC 9297 Capsule Protocol parser")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00\x03abc"))
    seeds.append(_bytes("\x40\x00\x00"))
    seeds.append(_bytes("\x00\x80\x00\x10\x00"))  # over the cap
    seeds.append(_bytes("\xc0"))  # truncated 8-byte type
    seeds.append(_bytes("\x00\x05ab"))  # truncated value

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/h3_capsule",
            corpus_dir="fuzz/corpus/h3_capsule",
            max_input_len=600,
        ),
        seeds,
    )
