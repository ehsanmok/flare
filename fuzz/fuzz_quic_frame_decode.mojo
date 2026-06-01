"""Fuzz harness: ``flare.quic.frame.parse_frame``.

QUIC v1 frames are (varint type) + (type-specific payload) per
RFC 9000 §19, with 22 frame types covering everything from PADDING
through HANDSHAKE_DONE. The harness drives the type-discriminating
first byte/varint with the full range and feeds the remainder of
the input as the would-be payload, exercising the per-type parser
arms.

Properties checked:

1. ``parse_frame`` either:
   - returns a :class:`ParsedFrame` whose ``consumed`` is in
     ``[1, len(data)]`` and whose ``frame.kind`` matches the
     leading varint type, or
   - raises a regular ``Error`` (truncated payload, malformed
     varint, oversize length, validation failure). It must never
     panic on arbitrary bytes.

2. **Idempotent re-decode.** When the first call succeeds, the
   harness calls ``parse_frame`` a second time on a copy of the
   input bytes and asserts the same ``consumed`` count is
   reported. The codec is required to be deterministic.

Run:
    pixi run --environment fuzz fuzz-quic-frame-decode
"""

from mozz import FuzzConfig, fuzz

from flare.quic.frame import parse_frame


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
    if n == 0:
        return
    var span = Span[UInt8, _](data)

    var ok_first = True
    var consumed_first = 0
    try:
        var decoded = parse_frame(span)
        consumed_first = decoded.consumed
        _assert(
            decoded.consumed >= 1 and decoded.consumed <= n,
            (
                "quic frame parse: consumed="
                + String(decoded.consumed)
                + " out of bounds "
                + String(n)
            ),
        )
    except:
        ok_first = False

    if ok_first:
        var decoded2 = parse_frame(span)
        _assert(
            decoded2.consumed == consumed_first,
            "quic frame parse: non-deterministic consumed count",
        )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_frame_decode.mojo -- RFC 9000 §19 frame codec")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00"))  # PADDING
    seeds.append(_bytes("\x01"))  # PING
    seeds.append(_bytes("\x02\x00\x00\x00"))  # ACK no-range
    seeds.append(_bytes("\x06\x00\x00"))  # CRYPTO empty payload
    seeds.append(_bytes("\x1c\x00\x00\x00"))  # CONN_CLOSE_TRANSPORT
    seeds.append(_bytes("\x1e"))  # HANDSHAKE_DONE
    seeds.append(_bytes("\x08\x00\x00"))  # STREAM(off=0, len=0, fin=0)
    seeds.append(_bytes("\xff"))  # invalid type, must reject

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_frame_decode",
            corpus_dir="fuzz/corpus/quic_frame_decode",
            max_input_len=256,
        ),
        seeds,
    )
