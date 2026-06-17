"""HPACK Huffman fast decoder.

Drop-in replacement for
:func:`flare.http.hpack_huffman.huffman_decode` that runs a
**256-entry 8-bit fast table** over the leading byte of the bit
accumulator. Codes whose Huffman length is <= 8 bits resolve in a
single table lookup; codes of length 9..30 bits fall through to
the same bit-walking slow path as the scalar codec.

The table is a canonical-Huffman expansion of the RFC 7541
Appendix B subset: every 256-entry slot covers the leading bits
of exactly one short code (the prefix property guarantees no
collisions), so the lookup encodes ``(symbol << 8) | code_len``
in one ``UInt16`` per index, with ``code_len == 0`` as the
"no short match -- fall through to slow path" sentinel.

Why this is the right shape today
---------------------------------

Mojo's stdlib does not yet expose a 1-byte shuffle intrinsic
(PSHUFB on x86, TBL on ARM NEON) that would let us decode 4-bit
nibbles in parallel the way ``hyper``'s and ``nghttp2``'s SIMD
paths do. Falling back to the scalar bit-walker that the
earlier shim used means a linear scan over all 257 Huffman
symbols for every output byte -- the gate "is SIMD actually
faster" turns into "do we have a usable fast table at all". A table-driven
fast path was always the bar both reference implementations cite
as their non-SIMD floor (see ``hpack/src/huffman.rs`` in
``hyperium/hpack`` and ``lib/nghttp2_hd_huffman.c`` in
``nghttp2/nghttp2``).

The table-build cost is ~256 iterations of trivial work per
call. The dispatcher threshold (see ``SIMD_HUFFMAN_THRESHOLD_BYTES``)
keeps tiny inputs on the scalar path so the build never
dominates; for inputs above the threshold, the table pays for
itself within ~32 bytes of decoded output and from there
compounds linearly.

Correctness
-----------

Every error mode mirrors :func:`flare.http.hpack_huffman.huffman_decode`
exactly:

* ``HuffmanError(EOS_IN_INPUT)`` -- the EOS symbol (length 30,
  ``0x3FFFFFFF``) appears in the input.
* ``HuffmanError(PADDING_TOO_LONG)`` -- the trailing partial byte
  carries more than 7 bits.
* ``HuffmanError(INVALID_PADDING)`` -- the padding bits don't
  match the high bits of EOS (all 1s).

The fuzz harness in ``fuzz/fuzz_huffman_simd.mojo`` enforces
byte-for-byte parity with the scalar codec on every randomised
input; the unit test suite covers RFC 7541 Appendix C.4 fixtures
plus the three error variants.
"""

from std.collections import InlineArray

from .hpack_huffman import (
    HuffmanError,
    _build_decode_lookup,
    _hpack_table_code,
    _hpack_table_length,
    huffman_decode,
)


comptime SIMD_HUFFMAN_THRESHOLD_BYTES: Int = 32
"""Below this byte count, dispatch always uses the scalar codec.

The fast-table construction is ~256 trivial iterations per call.
For inputs at least 32 bytes that cost amortises to roughly
zero; below 32 bytes the bit-walker's per-byte cost is already
small enough that the table build is a net loss. The threshold
matches ``hyper`` and ``nghttp2``'s typical short-string bypass.
"""


@always_inline
def _build_fast_table() -> List[UInt16]:
    """Construct the 256-entry 8-bit fast lookup.

    Each entry is ``(symbol << 8) | code_len`` for the unique
    Huffman code whose top bits match the entry's index, OR
    ``0`` if no code of length <= 8 covers that index.

    Canonical-Huffman codes are prefix-free, so for every entry
    there is at most one short code matching that prefix; the
    explicit ``code_len == 0`` sentinel encodes "long code --
    use the bit-walker".

    The construction iterates the 256 symbols (0..255, excluding
    EOS at index 256); for each short code of length ``L`` it
    expands to ``2**(8 - L)`` adjacent entries.
    """
    var table = List[UInt16](capacity=256)
    for _ in range(256):
        table.append(UInt16(0))
    for sym in range(256):
        var clen = _hpack_table_length(sym)
        if clen <= 8:
            var code = _hpack_table_code(sym)
            var shift = 8 - clen
            var base = code << shift
            var fanout = 1 << shift
            for j in range(fanout):
                table[base + j] = UInt16((sym << 8) | clen)
    return table^


def _make_root_table() -> InlineArray[UInt16, 256]:
    """Comptime-foldable twin of :func:`_build_fast_table`.

    Returns the same 256-entry 8-bit fast lookup as an
    ``InlineArray`` so it can be materialized once into the
    :data:`_ROOT_TABLE` alias at compile time -- the decoder then
    pays zero per-call table-build cost (the build was previously
    ~256 iterations of canonical-table accessors on every header
    string, which dominated QPACK decode under load).
    """
    var table = InlineArray[UInt16, 256](fill=UInt16(0))
    for sym in range(256):
        var clen = _hpack_table_length(sym)
        if clen <= 8:
            var code = _hpack_table_code(sym)
            var shift = 8 - clen
            var base = code << shift
            var fanout = 1 << shift
            for j in range(fanout):
                table[base + j] = UInt16((sym << 8) | clen)
    return table^


comptime _ROOT_TABLE = _make_root_table()
"""The 256-entry 8-bit fast lookup, built once at compile time."""


def huffman_decode_simd(
    input: Span[UInt8, _], mut output: List[UInt8]
) raises HuffmanError:
    """Append the Huffman-decoded form of ``input`` to ``output``.

    Table-driven fast-path drop-in for
    :func:`flare.http.hpack_huffman.huffman_decode`. Codes of
    length <= 8 bits resolve in a single 256-entry lookup; codes
    of length 9..30 bits fall through to the same bit-walking
    slow path as the scalar codec.

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
    var n = len(input)
    if n == 0:
        return
    # Pre-size the output buffer with the same upper bound the
    # scalar codec uses (one output byte costs >=5 input bits).
    output.reserve(len(output) + ((n * 8) + 4) // 5)
    var bits = UInt64(0)
    var nbits = 0
    var i = 0
    while i < n:
        bits = (bits << UInt64(8)) | UInt64(Int(input[i]))
        i += 1
        nbits += 8
        # Inner emit loop -- pull as many symbols as the
        # accumulator currently holds.
        while nbits >= 8:
            var top = Int((bits >> UInt64(nbits - 8)) & UInt64(0xFF))
            var entry = Int(_ROOT_TABLE[top])
            var clen = entry & 0xFF
            if clen > 0:
                var sym = entry >> 8
                output.append(UInt8(sym))
                nbits -= clen
                if nbits > 0:
                    bits = bits & ((UInt64(1) << UInt64(nbits)) - UInt64(1))
                else:
                    bits = UInt64(0)
                continue
            # Long-code path: bit-walker covers codes >= 9 bits.
            var matched = False
            for clen2 in range(9, 31):
                if nbits < clen2:
                    break
                var code = Int(
                    (bits >> UInt64(nbits - clen2)) & UInt64((1 << clen2) - 1)
                )
                var sym = _build_decode_lookup(code, clen2)
                if sym >= 0:
                    if sym == 256:
                        raise HuffmanError(HuffmanError.EOS_IN_INPUT)
                    output.append(UInt8(sym))
                    nbits -= clen2
                    if nbits > 0:
                        bits = bits & ((UInt64(1) << UInt64(nbits)) - UInt64(1))
                    else:
                        bits = UInt64(0)
                    matched = True
                    break
            if not matched:
                # Need more input bytes to disambiguate.
                break
    # Tail bit-walker: drain any trailing short codes that the
    # fast-table inner loop couldn't see because it required
    # ``nbits >= 8``. The HPACK Huffman table has codes as short
    # as 5 bits, so up to 7 trailing bits after the final byte
    # load can still encode a valid symbol that the scalar codec
    # would emit. We walk in the same MSB-first order, trying
    # successively longer codes -- ``_build_decode_lookup``
    # returns the unique canonical-prefix match per (code, clen).
    while True:
        var matched = False
        for clen in range(5, 31):
            if nbits < clen:
                break
            var code = Int(
                (bits >> UInt64(nbits - clen)) & UInt64((1 << clen) - 1)
            )
            var sym = _build_decode_lookup(code, clen)
            if sym >= 0:
                if sym == 256:
                    raise HuffmanError(HuffmanError.EOS_IN_INPUT)
                output.append(UInt8(sym))
                nbits -= clen
                if nbits > 0:
                    bits = bits & ((UInt64(1) << UInt64(nbits)) - UInt64(1))
                else:
                    bits = UInt64(0)
                matched = True
                break
        if not matched:
            break
    # Padding rules -- identical to scalar codec.
    if nbits > 7:
        raise HuffmanError(HuffmanError.PADDING_TOO_LONG)
    if nbits > 0:
        var expected = UInt64((1 << nbits) - 1)
        if bits != expected:
            raise HuffmanError(HuffmanError.INVALID_PADDING)


def huffman_decode_dispatch(
    input: Span[UInt8, _],
    mut output: List[UInt8],
    use_table: Bool = False,
) raises HuffmanError:
    """Pick fast-table vs scalar based on ``use_table`` and input length.

    The "fast table" path is :func:`huffman_decode_simd`, a 256-entry
    lookup-table decoder; despite the historical module name, the
    implementation is scalar (no SIMD intrinsics). The flag selects
    table-driven dispatch above ``SIMD_HUFFMAN_THRESHOLD_BYTES``.

    Args:
        input: The Huffman-encoded byte stream.
        output: The byte list to append the decoded form to.
        use_table: When ``True`` and ``len(input) >=
            SIMD_HUFFMAN_THRESHOLD_BYTES``, dispatch to
            :func:`huffman_decode_simd`. Otherwise dispatch to
            the scalar codec.

    Raises:
        HuffmanError: Forwarded from the underlying decoder.
    """
    if use_table and len(input) >= SIMD_HUFFMAN_THRESHOLD_BYTES:
        huffman_decode_simd(input, output)
    else:
        huffman_decode(input, output)
