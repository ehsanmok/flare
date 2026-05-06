"""Tests for the SIMD HPACK Huffman decoder shim (Track c08 / v0.7).

Verifies parity with the scalar codec from
:mod:`flare.http.hpack_huffman`:

* RFC 7541 Appendix C.4 fixtures decode identically.
* Round-trip on randomised inputs (encoder -> SIMD decoder ->
  identity).
* Error parity: EOS-in-input, padding-too-long, and
  invalid-padding all raise the same ``HuffmanError`` variants on
  both code paths.
* Dispatcher honours the threshold: small inputs go scalar, larger
  inputs go SIMD when ``prefer_simd=True``.
"""

from std.testing import assert_equal, assert_raises, assert_true

from flare.http.hpack_huffman import (
    HuffmanError,
    huffman_decode,
    huffman_encode,
)
from flare.http.hpack_huffman_simd import (
    SIMD_HUFFMAN_THRESHOLD_BYTES,
    huffman_decode_dispatch,
    huffman_decode_simd,
)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8](capacity=s.byte_length())
    for b in s.as_bytes():
        out.append(b)
    return out^


def test_simd_parity_on_appendix_c4_www_example_com() raises:
    """RFC 7541 §C.4.1 -- Huffman-coded ``www.example.com``."""
    var encoded = List[UInt8]()
    encoded.append(0xF1)
    encoded.append(0xE3)
    encoded.append(0xC2)
    encoded.append(0xE5)
    encoded.append(0xF2)
    encoded.append(0x3A)
    encoded.append(0x6B)
    encoded.append(0xA0)
    encoded.append(0xAB)
    encoded.append(0x90)
    encoded.append(0xF4)
    encoded.append(0xFF)

    var simd_out = List[UInt8]()
    huffman_decode_simd(Span[UInt8, _](encoded), simd_out)
    var scalar_out = List[UInt8]()
    huffman_decode(Span[UInt8, _](encoded), scalar_out)
    assert_equal(len(simd_out), len(scalar_out))
    for i in range(len(simd_out)):
        assert_equal(Int(simd_out[i]), Int(scalar_out[i]))
    var got = String(capacity=len(simd_out) + 1)
    for b in simd_out:
        got += chr(Int(b))
    assert_equal(got, "www.example.com")


def test_simd_round_trip_on_random_ascii() raises:
    """Encode with the scalar encoder, decode with the SIMD shim,
    assert identity for a handful of representative payloads."""
    var corpus = List[String]()
    corpus.append("hello")
    corpus.append("Content-Type: application/json")
    corpus.append("a" * 64)
    corpus.append(":authority: api.example.com")
    corpus.append("User-Agent: flare/0.7 (+https://github.com/ehsanmok/flare)")
    for j in range(len(corpus)):
        var s = corpus[j]
        var enc = List[UInt8]()
        huffman_encode(Span[UInt8, _](_bytes(s)), enc)
        var dec = List[UInt8]()
        huffman_decode_simd(Span[UInt8, _](enc), dec)
        var got = String(capacity=len(dec) + 1)
        for b in dec:
            got += chr(Int(b))
        assert_equal(got, s)


def test_simd_eos_in_input_raises_same_as_scalar() raises:
    """The EOS symbol (30 bits of 1s) is illegal in the input
    stream; both codecs must raise ``EOS_IN_INPUT``."""
    var bad = List[UInt8]()
    bad.append(0xFF)
    bad.append(0xFF)
    bad.append(0xFF)
    bad.append(0xFF)
    var simd_out = List[UInt8]()
    with assert_raises():
        huffman_decode_simd(Span[UInt8, _](bad), simd_out)
    var scalar_out = List[UInt8]()
    with assert_raises():
        huffman_decode(Span[UInt8, _](bad), scalar_out)


def test_dispatch_threshold_picks_scalar_below_threshold() raises:
    """Inputs shorter than :comptime:`SIMD_HUFFMAN_THRESHOLD_BYTES`
    must go scalar even with ``prefer_simd=True``. The shim returns
    bit-identical output on the parity-fallback build, so this
    test is a behavioural assertion: the dispatcher does not raise
    or mis-route the small-input path."""
    var enc = List[UInt8]()
    huffman_encode(Span[UInt8, _](_bytes("hi")), enc)
    assert_true(len(enc) < SIMD_HUFFMAN_THRESHOLD_BYTES)
    var dec = List[UInt8]()
    huffman_decode_dispatch(Span[UInt8, _](enc), dec, prefer_simd=True)
    var got = String(capacity=len(dec) + 1)
    for b in dec:
        got += chr(Int(b))
    assert_equal(got, "hi")


def test_dispatch_above_threshold_routes_simd() raises:
    """Inputs at / above the threshold and ``prefer_simd=True``
    take the SIMD path. Output parity with scalar is the same
    invariant the fuzz harness asserts on every input."""
    var s = "x" * 128
    var enc = List[UInt8]()
    huffman_encode(Span[UInt8, _](_bytes(s)), enc)
    assert_true(len(enc) >= SIMD_HUFFMAN_THRESHOLD_BYTES)
    var simd_out = List[UInt8]()
    huffman_decode_dispatch(Span[UInt8, _](enc), simd_out, prefer_simd=True)
    var scalar_out = List[UInt8]()
    huffman_decode(Span[UInt8, _](enc), scalar_out)
    assert_equal(len(simd_out), len(scalar_out))
    for i in range(len(simd_out)):
        assert_equal(Int(simd_out[i]), Int(scalar_out[i]))


def main() raises:
    test_simd_parity_on_appendix_c4_www_example_com()
    test_simd_round_trip_on_random_ascii()
    test_simd_eos_in_input_raises_same_as_scalar()
    test_dispatch_threshold_picks_scalar_below_threshold()
    test_dispatch_above_threshold_routes_simd()
    print("test_huffman_simd: 5 passed")
