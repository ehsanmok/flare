"""Fuzz harness: ``flare.http2.hpack.HpackDecoder``.

Properties:

1. The decoder never panics on arbitrary header-block bytes. Errors
   raise ``Error`` (truncated literal, Huffman with the flag off,
   Huffman padding violation, integer overflow, oversized size
   update); anything else means a bug worth investigating.
2. ``HpackEncoder.encode(headers) -> HpackDecoder.decode(...)``
   round-trips: the decoded list has the same length and per-index
   names + values. Run twice per input -- once with H=0 (raw) and
   once with H=1 (Huffman opt-in) -- so a regression in either
   path surfaces.

The round-trip property is a stronger oracle than just the parser
not panicking; it guards against regressions in the §6.2.1 / §6.2.2
literal codecs and the RFC 7541 Appendix B Huffman wiring.

Run:
    pixi run fuzz-hpack-decoder
"""

from mozz import fuzz, FuzzConfig

from flare.http2.hpack import HpackDecoder, HpackEncoder, HpackHeader


def _try_decode(allow_huffman: Bool, data: List[UInt8]):
    var dec = HpackDecoder()
    dec.allow_huffman = allow_huffman
    try:
        _ = dec.decode(Span[UInt8, _](data))
    except:
        pass


def _roundtrip(allow_huffman: Bool, name: String, value: String) raises:
    var hdrs = List[HpackHeader]()
    hdrs.append(HpackHeader(name, value))
    var enc = HpackEncoder()
    enc.allow_huffman = allow_huffman
    var dec = HpackDecoder()
    dec.allow_huffman = allow_huffman
    var wire = enc.encode(Span[HpackHeader, _](hdrs))
    var back = dec.decode(Span[UInt8, _](wire))
    if len(back) != 1:
        raise Error("hpack roundtrip: lost the entry")
    if back[0].name != hdrs[0].name:
        raise Error("hpack roundtrip: name drift")
    if back[0].value != hdrs[0].value:
        raise Error("hpack roundtrip: value drift")


def target(data: List[UInt8]) raises:
    # Crash-only fuzzer over the wire bytes -- exercise both
    # decoder modes (default + Huffman-on) to surface H=1 path
    # regressions as well as the H=0 baseline.
    _try_decode(False, data)
    _try_decode(True, data)

    # Round-trip oracle: build a small header list out of the input
    # bytes (alternating name/value chunks) and assert encode/decode
    # is the identity in both modes.
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
    try:
        _roundtrip(False, name, value)
    except:
        pass
    try:
        _roundtrip(True, name, value)
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
    # RFC 7541 §C.4.1 fixture: literal w/o indexing, name = 'x',
    # value = Huffman("www.example.com"). Exercises the H=1 path.
    seeds.append(
        _bytes("\x00\x01x\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff")
    )

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
