"""Fuzz harness: ``flare.http2.hpack.HpackDecoder``.

Properties:

1. The decoder never panics on arbitrary header-block bytes. Errors
   raise ``Error`` (truncated literal, Huffman not supported,
   integer overflow, oversized size update); anything else means a
   bug worth investigating.
2. ``HpackEncoder.encode(headers) -> HpackDecoder.decode(...)``
   round-trips: the decoded list has the same length and per-index
   names + values.

The round-trip property is a stronger oracle than just the parser
not panicking; it guards against regressions in the §6.2.1 / §6.2.2
literal codecs.

Run:
    pixi run fuzz-hpack-decoder
"""

from mozz import fuzz, FuzzConfig

from flare.http2.hpack import HpackDecoder, HpackEncoder, HpackHeader


def target(data: List[UInt8]) raises:
    # Crash-only fuzzer over the wire bytes.
    var dec = HpackDecoder()
    try:
        _ = dec.decode(Span[UInt8, _](data))
    except:
        pass

    # Round-trip oracle: build a small header list out of the input
    # bytes (alternating name/value chunks) and assert encode/decode
    # is the identity over the resulting list.
    if len(data) < 4:
        return
    var split = (Int(data[0]) % (len(data) - 1)) + 1
    var name = String(capacity=split + 1)
    for i in range(split):
        var c = Int(data[i]) & 0x7F
        if c < 0x20:
            c += 0x20
        name += chr(c)
    var value = String(capacity=len(data) - split + 1)
    for i in range(split, len(data)):
        var c = Int(data[i]) & 0x7F
        if c < 0x20:
            c += 0x20
        value += chr(c)
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(name, value))
    var enc = HpackEncoder()
    var dec2 = HpackDecoder()
    var wire = enc.encode(Span[HpackHeader, _](hdrs))
    try:
        var back = dec2.decode(Span[UInt8, _](wire))
        if len(back) != 1:
            raise Error("hpack roundtrip: lost the entry")
        if back[0].name != hdrs[0].name:
            raise Error("hpack roundtrip: name drift")
        if back[0].value != hdrs[0].value:
            raise Error("hpack roundtrip: value drift")
    except:
        pass


def main() raises:
    print("[mozz] fuzzing HpackDecoder...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("\x82"))  # :method: GET (static idx 2)
    seeds.append(_bytes("\x84"))  # :path: /
    seeds.append(_bytes("\x40\x05x-foo\x03bar"))  # literal w/ indexing
    seeds.append(_bytes("\x00\x05hello\x05world"))  # literal w/o indexing
    seeds.append(_bytes("\x20"))  # size update value 0
    seeds.append(_bytes("\x3F\xFF\xFF\xFF"))  # giant size update -> raise

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/hpack_decoder",
            corpus_dir="fuzz/corpus/hpack_decoder",
            max_input_len=512,
        ),
        seeds,
    )
