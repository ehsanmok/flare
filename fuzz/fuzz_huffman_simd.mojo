"""Fuzz harness: differential ``flare.http.hpack_huffman_simd``.

Properties:

1. The SIMD shim never panics on arbitrary input: every input
   either decodes successfully or raises a typed
   :class:`HuffmanError`. Anything else means a bug worth
   investigating.
2. Differential parity: when both the SIMD shim and the scalar
   codec succeed on the same input, the byte output MUST match
   exactly. This is the strongest oracle the harness can apply
   without requiring an external reference decoder.
3. Round-trip parity: encoding ``input`` with the scalar encoder
   then decoding via the SIMD shim returns the original bytes.

Run:
    pixi run fuzz-huffman-simd
"""

from mozz import fuzz, FuzzConfig

from flare.http.hpack_huffman import (
    HuffmanError,
    huffman_decode,
    huffman_encode,
)
from flare.http.hpack_huffman_simd import huffman_decode_simd


def _decode(decoder_is_simd: Bool, data: List[UInt8]) raises -> List[UInt8]:
    var out = List[UInt8]()
    if decoder_is_simd:
        huffman_decode_simd(Span[UInt8, _](data), out)
    else:
        huffman_decode(Span[UInt8, _](data), out)
    return out^


def target(data: List[UInt8]) raises:
    # 1. Crash-only on the SIMD path -- ensure no panic on arbitrary
    # bytes (the whole point of the parity-fallback design).
    var simd_ok = True
    var simd_out = List[UInt8]()
    try:
        simd_out = _decode(True, data)
    except:
        simd_ok = False

    # 2. Differential parity: scalar decode the same input.
    var scalar_ok = True
    var scalar_out = List[UInt8]()
    try:
        scalar_out = _decode(False, data)
    except:
        scalar_ok = False

    if simd_ok != scalar_ok:
        raise Error(
            "huffman_simd: parity mismatch on success/error: simd_ok="
            + String(simd_ok)
            + " scalar_ok="
            + String(scalar_ok)
        )
    if simd_ok and scalar_ok:
        if len(simd_out) != len(scalar_out):
            raise Error(
                "huffman_simd: output length drift: simd="
                + String(len(simd_out))
                + " scalar="
                + String(len(scalar_out))
            )
        for i in range(len(simd_out)):
            if Int(simd_out[i]) != Int(scalar_out[i]):
                raise Error(
                    "huffman_simd: byte mismatch at "
                    + String(i)
                    + ": simd="
                    + String(Int(simd_out[i]))
                    + " scalar="
                    + String(Int(scalar_out[i]))
                )

    # 3. Round-trip oracle: encode-then-SIMD-decode must equal the
    # original.
    var enc = List[UInt8]()
    huffman_encode(Span[UInt8, _](data), enc)
    var rt = List[UInt8]()
    try:
        huffman_decode_simd(Span[UInt8, _](enc), rt)
    except:
        # The encoder always produces a valid stream; a decode
        # failure here is a real bug.
        raise Error("huffman_simd: encoder output failed SIMD decode")
    if len(rt) != len(data):
        raise Error("huffman_simd: round-trip length drift")
    for i in range(len(rt)):
        if Int(rt[i]) != Int(data[i]):
            raise Error("huffman_simd: round-trip byte drift at " + String(i))


def main() raises:
    print("[mozz] fuzzing huffman_simd (differential vs scalar)...")
    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("hello"))
    seeds.append(_bytes("Content-Type: application/json"))
    seeds.append(_bytes(":authority: api.example.com"))
    # RFC 7541 §C.4.1 huffman-coded ``www.example.com``.
    var c4 = List[UInt8]()
    c4.append(0xF1)
    c4.append(0xE3)
    c4.append(0xC2)
    c4.append(0xE5)
    c4.append(0xF2)
    c4.append(0x3A)
    c4.append(0x6B)
    c4.append(0xA0)
    c4.append(0xAB)
    c4.append(0x90)
    c4.append(0xF4)
    c4.append(0xFF)
    seeds.append(c4^)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/huffman_simd",
            corpus_dir="fuzz/corpus/huffman_simd",
            max_input_len=256,
        ),
        seeds,
    )
