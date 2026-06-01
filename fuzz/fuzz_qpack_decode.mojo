"""Fuzz harness: ``flare.qpack.decode_field_section``.

QPACK static-only decoder per RFC 9204: parses the field-section
prefix (required-insert-count + sign+delta-base) and the
following field lines (indexed-static, literal-with-static-name,
literal-with-literal-name) into a list of header pairs.

Properties checked:

1. ``decode_field_section`` either returns a list of headers, or
   raises a regular ``Error`` (truncated input, dynamic-table
   reference rejection, oversize index, malformed integer, etc.).
   It must never panic on arbitrary bytes.

2. **Round trip.** When decoding succeeds, ``encode_field_section``
   on the result MUST itself be decodable; the second decode must
   produce the same header list as the first. Encoders sometimes
   pick a different wire shape (Huffman fallback) but the
   meaningful payload is the header pair list.

Run:
    pixi run --environment fuzz fuzz-qpack-decode
"""

from mozz import FuzzConfig, fuzz

from flare.qpack import (
    QpackHeader,
    decode_field_section,
    encode_field_section,
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

    var headers_opt: Optional[List[QpackHeader]] = None
    try:
        var headers = decode_field_section(span)
        headers_opt = Optional[List[QpackHeader]](headers^)
    except:
        return

    var headers = headers_opt.value().copy()
    # Round trip: re-encode + re-decode must produce the same
    # header list.
    var encoded = encode_field_section(headers)
    var headers2 = decode_field_section(Span[UInt8, _](encoded))
    _assert(
        len(headers2) == len(headers),
        (
            "qpack round trip: len drift "
            + String(len(headers2))
            + " vs "
            + String(len(headers))
        ),
    )
    for i in range(len(headers)):
        _assert(
            headers2[i].name == headers[i].name,
            "qpack round trip: name drift at " + String(i),
        )
        _assert(
            headers2[i].value == headers[i].value,
            "qpack round trip: value drift at " + String(i),
        )


def main() raises:
    print("=" * 60)
    print("fuzz_qpack_decode.mojo -- RFC 9204 static-only decoder")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("\x00\x00"))  # empty field section
    seeds.append(_bytes("\x00\x00\xd1"))  # :method GET
    seeds.append(_bytes("\x00\x00\xd1\xd7\xd9"))  # :method/:scheme/:status
    seeds.append(_bytes("\x00\x00\x80"))  # indexed dynamic, must reject
    seeds.append(_bytes("\x01\x00\xd1"))  # RIC=1, must reject
    seeds.append(_bytes("\x00\x00\x40"))  # literal-with-name-ref dynamic
    seeds.append(_bytes("\x00\x00\x21\x01x\x01y"))  # literal name "x" "y"

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/qpack_decode",
            corpus_dir="fuzz/corpus/qpack_decode",
            max_input_len=512,
        ),
        seeds,
    )
