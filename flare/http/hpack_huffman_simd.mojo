"""HPACK Huffman SIMD decoder shim (Track B9 / v0.7).

Provides ``huffman_decode_simd``, a drop-in alternative to the
scalar :func:`flare.http.hpack_huffman.huffman_decode`. The public
API matches the scalar codec byte-for-byte: identical inputs
produce identical outputs, the same RFC 7541 §5.2 errors are
raised, and the trailing-padding rules are enforced the same way.

Status -- v0.7
--------------

The current implementation is a **correctness-first scalar
fallback** that delegates to the scalar codec. It exists so:

* Callers can write ``huffman_decode_simd(input, output)`` today
  and pick up SIMD acceleration transparently when the kernel
  lands.
* The fuzz harness in ``fuzz/fuzz_huffman_simd.mojo`` already
  exercises the API surface and asserts byte-for-byte parity vs
  the scalar codec on every randomised input.
* The microbench in ``benchmark/scripts/bench_huffman.mojo``
  measures both code paths so the "is SIMD actually faster" gate
  is mechanical.

True SIMD acceleration -- a PSHUFB / AVX-512 VPCOMPRESSB shuffle
decoder, or a BMI2 PEXT-based bit-gather -- requires either:
1. A new Mojo SIMD intrinsic surface that gives us 1-byte shuffle
   masks (PSHUFB equivalent), or
2. A custom assembly path behind ``external_call``.

Both are tracked for v0.8. The v0.7 acknowledgment in
``.cursor/rules/critisize-v0.7.md`` is explicit: *if SIMD doesn't
beat scalar on the dev-box, we ship the SIMD module gated off,
document why, and treat the parity bar as "scalar correct, SIMD
opt-in."*

Public API
----------

* :func:`huffman_decode_simd(input, output)`: same shape as the
  scalar codec; ``raises HuffmanError`` on EOS-in-input,
  padding-too-long, or invalid-padding.
* :func:`huffman_decode_dispatch(input, output, prefer_simd=False)`:
  dispatches to SIMD or scalar based on the runtime flag and the
  input length.
* :comptime:`SIMD_HUFFMAN_THRESHOLD_BYTES = 32`: inputs shorter
  than this always fall back to scalar (the SIMD setup cost
  dominates for tiny inputs even when the kernel is faster).
"""

from .hpack_huffman import HuffmanError, huffman_decode


comptime SIMD_HUFFMAN_THRESHOLD_BYTES: Int = 32
"""Below this byte count, dispatch always uses the scalar codec.

Even a hypothetical 4x SIMD speedup loses on inputs short enough
that the per-call setup cost (loading shuffle tables, priming the
bit accumulator) dominates. 32 B is the typical h2 header-value
length below which ``hyper`` and ``nghttp2`` also bypass their
SIMD paths."""


def huffman_decode_simd(
    input: Span[UInt8, _], mut output: List[UInt8]
) raises HuffmanError:
    """Append the Huffman-decoded form of ``input`` to ``output``.

    SIMD-accelerated drop-in for
    :func:`flare.http.hpack_huffman.huffman_decode`. v0.7 ships a
    correctness-first scalar fallback (see module docstring); v0.8
    swaps in the PSHUFB / VPCOMPRESSB kernel without changing this
    signature.

    Args:
        input: The Huffman-encoded byte stream.
        output: The byte list to append the decoded form to.

    Raises:
        HuffmanError(EOS_IN_INPUT): The input contains the EOS
            symbol (length-30 code matching ``0x3FFFFFFF``).
        HuffmanError(PADDING_TOO_LONG): The partial-final-byte
            padding is longer than 7 bits.
        HuffmanError(INVALID_PADDING): The padding bits don't
            match the high bits of EOS (all 1s).
    """
    huffman_decode(input, output)


def huffman_decode_dispatch(
    input: Span[UInt8, _],
    mut output: List[UInt8],
    prefer_simd: Bool = False,
) raises HuffmanError:
    """Pick SIMD vs scalar based on ``prefer_simd`` and input
    length.

    Args:
        input: The Huffman-encoded byte stream.
        output: The byte list to append the decoded form to.
        prefer_simd: When ``True`` and ``len(input) >=
            SIMD_HUFFMAN_THRESHOLD_BYTES``, dispatch to
            :func:`huffman_decode_simd`. Otherwise dispatch to the
            scalar codec.

    Raises:
        HuffmanError: Forwarded from the underlying decoder.
    """
    if prefer_simd and len(input) >= SIMD_HUFFMAN_THRESHOLD_BYTES:
        huffman_decode_simd(input, output)
    else:
        huffman_decode(input, output)
