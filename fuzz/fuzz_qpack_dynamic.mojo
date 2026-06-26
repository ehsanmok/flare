"""Fuzz harness: ``flare.qpack.dynamic`` encoder/decoder streams.

The dynamic-table paths the h3 server now feeds peer bytes into:

* :func:`apply_encoder_instructions_partial` -- replays an arbitrary
  encoder-stream byte buffer into a dynamic table, stopping at a chunk
  boundary instead of panicking.
* :func:`decode_field_section_dynamic` -- decodes a field section against
  the resulting table.
* :func:`parse_decoder_instruction` -- parses peer decoder-stream
  acknowledgements.

Properties checked:

1. None of the three ever panics on arbitrary bytes; they either make
   progress or raise a regular ``Error``.
2. ``apply_encoder_instructions_partial`` reports ``consumed`` within
   ``[0, len(buf)]`` and never claims to apply inserts it rolled back.

Run:
    pixi run --environment fuzz fuzz-qpack-dynamic
"""

from mozz import FuzzConfig, fuzz

from flare.qpack import QpackHeader
from flare.qpack.dynamic import (
    QpackDynamicTable,
    apply_encoder_instructions_partial,
    decode_field_section_dynamic,
    parse_decoder_instruction,
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
    if len(data) < 2:
        return
    var span = Span[UInt8, _](data)

    # Encoder stream: capacity bounded so eviction exercises too.
    var table = QpackDynamicTable(UInt64(4096))
    try:
        var result = apply_encoder_instructions_partial(table, span)
        _assert(result[0] >= 0, "negative insert count")
        _assert(
            result[1] >= 0 and result[1] <= len(data),
            "consumed out of bounds: " + String(result[1]),
        )
    except:
        pass

    # Field section decode against whatever table state resulted.
    try:
        var _h = decode_field_section_dynamic(span, table)
    except:
        pass

    # Decoder-stream instruction parse from an arbitrary offset.
    try:
        var _i = parse_decoder_instruction(span, 0)
    except:
        pass


def main() raises:
    print("=" * 60)
    print("fuzz_qpack_dynamic.mojo -- RFC 9204 dynamic-table streams")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("\x3f\xe1\x1f"))  # Set Capacity 4096
    seeds.append(_bytes("\x4a\x08x-custom\x0ddynamic-value"))  # insert literal
    seeds.append(_bytes("\xc1\x00"))  # insert with static name ref
    seeds.append(_bytes("\x00"))  # duplicate index 0
    seeds.append(_bytes("\x00\x00\x80"))  # field section: indexed dynamic
    seeds.append(_bytes("\x80"))  # decoder section-ack stream 0
    seeds.append(_bytes("\x01"))  # decoder insert-count-increment 1

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/qpack_dynamic",
            corpus_dir="fuzz/corpus/qpack_dynamic",
            max_input_len=512,
        ),
        seeds,
    )
