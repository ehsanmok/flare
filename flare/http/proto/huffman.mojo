"""Canonical sans-I/O HPACK / QPACK Huffman codec surface
(``flare.http.proto.huffman``) -- RFC 7541 §5.2 + Appendix B.

This module is the single canonical entry point for Huffman
encode/decode in the ``flare.http.proto`` sublayer. The HTTP/2
HPACK and HTTP/3 QPACK codecs route their string literals through
the symbols re-exported here so the codec surface stays unified
across protocol versions.

Three decoder variants are exposed today:

* :func:`huffman_decode` -- scalar bit-walker. The reference
  implementation; matches the per-symbol decode loop the RFC
  pseudo-code prescribes. Always available; no thresholds.
* :func:`huffman_decode_simd` -- 256-entry 8-bit fast-table
  decoder. Despite the historical "simd" suffix, the implementation
  is scalar (no shuffle intrinsics; see "real SIMD kernel"
  below). The table resolves every code of length ≤ 8 in a single
  load; codes 9..30 fall through to the bit-walker.
* :func:`huffman_decode_dispatch` -- dispatch wrapper. Picks the
  fast-table path above ``SIMD_HUFFMAN_THRESHOLD_BYTES`` and the
  scalar path otherwise, matching the short-string bypass the
  reference implementations cite as their non-SIMD floor.

Encoder path is scalar-only (see :func:`huffman_encode` /
:func:`huffman_encoded_length`); RFC 7541 encoders always run
on a single Huffman pass per literal so the bit-packed write
loop is the bottleneck shape, not the read loop.

Real SIMD kernel (32 bytes/cycle) -- gated on language intrinsics
-----------------------------------------------------------------

The 32-bytes/cycle SIMD shape that ``hyper`` and ``nghttp2`` ship
on their fast paths uses a 1-byte shuffle instruction (PSHUFB on
x86-64, TBL/TBX on AArch64 NEON) to decode 4-bit nibbles in
parallel. Mojo's stdlib does not yet expose those intrinsics
(neither `LLVM.shufflevector` over byte-typed vectors with
runtime indices nor a portable `simd.shuffle` over 16-byte
chunks); without them, the only SIMD-shaped fast path that
compiles in this Mojo toolchain is the table-lookup variant
shipped here. The kernel slot is reserved: the moment the
intrinsic surface lands upstream the kernel drops in behind the
:func:`huffman_decode_simd` symbol with no public API change. Until
then, the dispatcher's ``use_table`` flag is the honest knob
operators wire on the codec hot paths.

Sans-I/O contract
-----------------

This file holds zero I/O imports (no ``flare.runtime`` /
``flare.io`` / socket / TLS surface). It is registered in
``tests/tools/check_sans_io.sh`` so the contract is lint-enforced.
"""

from flare.http.hpack_huffman import (
    HuffmanError,
    huffman_decode,
    huffman_decoded_length,
    huffman_encode,
    huffman_encoded_length,
)

from flare.http.hpack_huffman_simd import (
    SIMD_HUFFMAN_THRESHOLD_BYTES,
    huffman_decode_dispatch,
    huffman_decode_simd,
)
