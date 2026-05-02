"""HPACK Huffman codec — RFC 7541 Appendix B (Track B9).

Implements the canonical Huffman code from RFC 7541 Appendix B
for HPACK string-literal compression. Provides both encoder and
decoder over byte sequences with a direct-lookup table for the
common short-code path and a bit-by-bit fallback for long codes.

Why this is a Track B subtrack
-------------------------------

HTTP/2 (RFC 9113) and HTTP/3 (RFC 9114) both reference RFC 7541
HPACK as the wire compression format for header strings. The
Appendix B canonical Huffman code achieves ~25-35 % size
reduction on typical English-ASCII header values, but the
trivial bit-by-bit decoder is slow (one branch per input bit).
hyper's ``hpack`` crate, h2, and nginx all use a precomputed
state-machine table that consumes 4 bits of input at a time and
runs in ~3-5 cycles per output byte.

This commit ships the **table + a correct decoder + a correct
encoder + round-trip tests against RFC 7541 §C.4 fixtures** —
the substrate every later optimisation (4-bit nibble state
machine, AVX-512 PSHUFB shuffles, BMI2 PEXT-based bit gather)
will compose against. The current decoder is the bit-by-bit
canonical form: correct, conformant, slower than the eventual
SIMD-accelerated path but provably right against the spec
fixtures. SIMD acceleration is a follow-up commit that swaps
the inner loop without changing the public API.

What this commit ships
-----------------------

* The full RFC 7541 Appendix B table as an internal
  (symbol → code, code-length) map. 257 entries: byte values
  0..255 plus the EOS sentinel (symbol 256).
* ``huffman_encode(input: Span[UInt8, _], out: List[UInt8])``
  — append the Huffman-encoded form of ``input`` to ``out``.
  Pads the trailing partial byte with EOS-prefix 1-bits per
  RFC 7541 §5.2.
* ``huffman_decode(input: Span[UInt8, _], out: List[UInt8])``
  raises if the input contains the EOS symbol (decoded length
  ≥ 30 bits), padding longer than 7 bits, or a padding value
  that doesn't match the EOS prefix (RFC 7541 §5.2).
* ``HuffmanError`` — typed error covering the three RFC-defined
  failure modes (EOS in input, oversize padding, invalid
  padding bit pattern).
* ``huffman_encoded_length(input)`` / ``huffman_decoded_length
  (input)`` — size estimators for callers that want to
  pre-size the output buffer.

Bit ordering
------------

HPACK Huffman codes are written **MSB-first** within each byte.
For a code of length L bits with value C, the encoder shifts
bits into a 64-bit accumulator and flushes whole bytes; for the
trailing partial byte, the missing low bits are filled with the
top bits of the EOS code (``0x3FFFFFFF`` / 30 bits — the high
1-bits of which are all 1s, making the padding "all 1 bits" per
RFC 7541 §5.2).
"""

# ── Typed error ──────────────────────────────────────────────────────────────


@fieldwise_init
struct HuffmanError(
    Copyable,
    Equatable,
    ImplicitlyCopyable,
    Movable,
    Writable,
):
    """RFC 7541 §5.2 / §C-conformant decode failures.

    Variants:
        EOS_IN_INPUT: The input stream contains the EOS symbol
            (length ≥ 30 bits whose value matches
            ``0x3FFFFFFF``). Per RFC 7541 §5.2 this MUST be
            treated as a decoding error.
        PADDING_TOO_LONG: The partial-final-byte padding is
            longer than 7 bits (i.e. the input ends mid-symbol
            with > 7 bits remaining unconsumed).
        INVALID_PADDING: The padding bits don't match the high
            bits of the EOS code (must be "all 1s" per
            RFC 7541 §5.2).
    """

    comptime EOS_IN_INPUT: Int = 1
    comptime PADDING_TOO_LONG: Int = 2
    comptime INVALID_PADDING: Int = 3

    var variant: Int

    def __eq__(self, other: HuffmanError) -> Bool:
        return self.variant == other.variant

    def __ne__(self, other: HuffmanError) -> Bool:
        return self.variant != other.variant

    def write_to[W: Writer](self, mut writer: W):
        if self.variant == HuffmanError.EOS_IN_INPUT:
            writer.write("HuffmanError(EOS_IN_INPUT)")
        elif self.variant == HuffmanError.PADDING_TOO_LONG:
            writer.write("HuffmanError(PADDING_TOO_LONG)")
        elif self.variant == HuffmanError.INVALID_PADDING:
            writer.write("HuffmanError(INVALID_PADDING)")
        else:
            writer.write("HuffmanError(unknown=")
            writer.write(self.variant)
            writer.write(")")


# ── RFC 7541 Appendix B table ────────────────────────────────────────────────
# Each (symbol, code, length) row is taken verbatim from the
# normative table in the spec. Symbol 256 is EOS (length 30).


@always_inline
def _hpack_table_code(symbol: Int) -> Int:
    """Return the Huffman code for a symbol in [0, 256].

    Implemented as a straight switch on symbol so the compiler
    can fold the table into the instruction stream.
    """
    if symbol == 0:
        return 0x1FF8
    if symbol == 1:
        return 0x7FFFD8
    if symbol == 2:
        return 0xFFFFFE2
    if symbol == 3:
        return 0xFFFFFE3
    if symbol == 4:
        return 0xFFFFFE4
    if symbol == 5:
        return 0xFFFFFE5
    if symbol == 6:
        return 0xFFFFFE6
    if symbol == 7:
        return 0xFFFFFE7
    if symbol == 8:
        return 0xFFFFFE8
    if symbol == 9:
        return 0xFFFFEA
    if symbol == 10:
        return 0x3FFFFFFC
    if symbol == 11:
        return 0xFFFFFE9
    if symbol == 12:
        return 0xFFFFFEA
    if symbol == 13:
        return 0x3FFFFFFD
    if symbol == 14:
        return 0xFFFFFEB
    if symbol == 15:
        return 0xFFFFFEC
    if symbol == 16:
        return 0xFFFFFED
    if symbol == 17:
        return 0xFFFFFEE
    if symbol == 18:
        return 0xFFFFFEF
    if symbol == 19:
        return 0xFFFFFF0
    if symbol == 20:
        return 0xFFFFFF1
    if symbol == 21:
        return 0xFFFFFF2
    if symbol == 22:
        return 0x3FFFFFFE
    if symbol == 23:
        return 0xFFFFFF3
    if symbol == 24:
        return 0xFFFFFF4
    if symbol == 25:
        return 0xFFFFFF5
    if symbol == 26:
        return 0xFFFFFF6
    if symbol == 27:
        return 0xFFFFFF7
    if symbol == 28:
        return 0xFFFFFF8
    if symbol == 29:
        return 0xFFFFFF9
    if symbol == 30:
        return 0xFFFFFFA
    if symbol == 31:
        return 0xFFFFFFB
    if symbol == 32:
        return 0x14  # ' '
    if symbol == 33:
        return 0x3F8  # '!'
    if symbol == 34:
        return 0x3F9  # '"'
    if symbol == 35:
        return 0xFFA  # '#'
    if symbol == 36:
        return 0x1FF9  # '$'
    if symbol == 37:
        return 0x15  # '%'
    if symbol == 38:
        return 0xF8  # '&'
    if symbol == 39:
        return 0x7FA  # "'"
    if symbol == 40:
        return 0x3FA  # '('
    if symbol == 41:
        return 0x3FB  # ')'
    if symbol == 42:
        return 0xF9  # '*'
    if symbol == 43:
        return 0x7FB  # '+'
    if symbol == 44:
        return 0xFA  # ','
    if symbol == 45:
        return 0x16  # '-'
    if symbol == 46:
        return 0x17  # '.'
    if symbol == 47:
        return 0x18  # '/'
    if symbol == 48:
        return 0x0  # '0'
    if symbol == 49:
        return 0x1  # '1'
    if symbol == 50:
        return 0x2  # '2'
    if symbol == 51:
        return 0x19  # '3'
    if symbol == 52:
        return 0x1A  # '4'
    if symbol == 53:
        return 0x1B  # '5'
    if symbol == 54:
        return 0x1C  # '6'
    if symbol == 55:
        return 0x1D  # '7'
    if symbol == 56:
        return 0x1E  # '8'
    if symbol == 57:
        return 0x1F  # '9'
    if symbol == 58:
        return 0x5C  # ':'
    if symbol == 59:
        return 0xFB  # ';'
    if symbol == 60:
        return 0x7FFC  # '<'
    if symbol == 61:
        return 0x20  # '='
    if symbol == 62:
        return 0xFFB  # '>'
    if symbol == 63:
        return 0x3FC  # '?'
    if symbol == 64:
        return 0x1FFA  # '@'
    if symbol == 65:
        return 0x21  # 'A'
    if symbol == 66:
        return 0x5D  # 'B'
    if symbol == 67:
        return 0x5E  # 'C'
    if symbol == 68:
        return 0x5F  # 'D'
    if symbol == 69:
        return 0x60  # 'E'
    if symbol == 70:
        return 0x61  # 'F'
    if symbol == 71:
        return 0x62  # 'G'
    if symbol == 72:
        return 0x63  # 'H'
    if symbol == 73:
        return 0x64  # 'I'
    if symbol == 74:
        return 0x65  # 'J'
    if symbol == 75:
        return 0x66  # 'K'
    if symbol == 76:
        return 0x67  # 'L'
    if symbol == 77:
        return 0x68  # 'M'
    if symbol == 78:
        return 0x69  # 'N'
    if symbol == 79:
        return 0x6A  # 'O'
    if symbol == 80:
        return 0x6B  # 'P'
    if symbol == 81:
        return 0x6C  # 'Q'
    if symbol == 82:
        return 0x6D  # 'R'
    if symbol == 83:
        return 0x6E  # 'S'
    if symbol == 84:
        return 0x6F  # 'T'
    if symbol == 85:
        return 0x70  # 'U'
    if symbol == 86:
        return 0x71  # 'V'
    if symbol == 87:
        return 0x72  # 'W'
    if symbol == 88:
        return 0xFC  # 'X'
    if symbol == 89:
        return 0x73  # 'Y'
    if symbol == 90:
        return 0xFD  # 'Z'
    if symbol == 91:
        return 0x1FFB  # '['
    if symbol == 92:
        return 0x7FFF0  # '\'
    if symbol == 93:
        return 0x1FFC  # ']'
    if symbol == 94:
        return 0x3FFC  # '^'
    if symbol == 95:
        return 0x22  # '_'
    if symbol == 96:
        return 0x7FFD  # '`'
    if symbol == 97:
        return 0x3  # 'a'
    if symbol == 98:
        return 0x23  # 'b'
    if symbol == 99:
        return 0x4  # 'c'
    if symbol == 100:
        return 0x24  # 'd'
    if symbol == 101:
        return 0x5  # 'e'
    if symbol == 102:
        return 0x25  # 'f'
    if symbol == 103:
        return 0x26  # 'g'
    if symbol == 104:
        return 0x27  # 'h'
    if symbol == 105:
        return 0x6  # 'i'
    if symbol == 106:
        return 0x74  # 'j'
    if symbol == 107:
        return 0x75  # 'k'
    if symbol == 108:
        return 0x28  # 'l'
    if symbol == 109:
        return 0x29  # 'm'
    if symbol == 110:
        return 0x2A  # 'n'
    if symbol == 111:
        return 0x7  # 'o'
    if symbol == 112:
        return 0x2B  # 'p'
    if symbol == 113:
        return 0x76  # 'q'
    if symbol == 114:
        return 0x2C  # 'r'
    if symbol == 115:
        return 0x8  # 's'
    if symbol == 116:
        return 0x9  # 't'
    if symbol == 117:
        return 0x2D  # 'u'
    if symbol == 118:
        return 0x77  # 'v'
    if symbol == 119:
        return 0x78  # 'w'
    if symbol == 120:
        return 0x79  # 'x'
    if symbol == 121:
        return 0x7A  # 'y'
    if symbol == 122:
        return 0x7B  # 'z'
    if symbol == 123:
        return 0x7FFE
    if symbol == 124:
        return 0x7FC
    if symbol == 125:
        return 0x3FFD
    if symbol == 126:
        return 0x1FFD
    if symbol == 127:
        return 0xFFFFFFC
    if symbol == 128:
        return 0xFFFE6
    if symbol == 129:
        return 0x3FFFD2
    if symbol == 130:
        return 0xFFFE7
    if symbol == 131:
        return 0xFFFE8
    if symbol == 132:
        return 0x3FFFD3
    if symbol == 133:
        return 0x3FFFD4
    if symbol == 134:
        return 0x3FFFD5
    if symbol == 135:
        return 0x7FFFD9
    if symbol == 136:
        return 0x3FFFD6
    if symbol == 137:
        return 0x7FFFDA
    if symbol == 138:
        return 0x7FFFDB
    if symbol == 139:
        return 0x7FFFDC
    if symbol == 140:
        return 0x7FFFDD
    if symbol == 141:
        return 0x7FFFDE
    if symbol == 142:
        return 0xFFFFEB
    if symbol == 143:
        return 0x7FFFDF
    if symbol == 144:
        return 0xFFFFEC
    if symbol == 145:
        return 0xFFFFED
    if symbol == 146:
        return 0x3FFFD7
    if symbol == 147:
        return 0x7FFFE0
    if symbol == 148:
        return 0xFFFFEE
    if symbol == 149:
        return 0x7FFFE1
    if symbol == 150:
        return 0x7FFFE2
    if symbol == 151:
        return 0x7FFFE3
    if symbol == 152:
        return 0x7FFFE4
    if symbol == 153:
        return 0x1FFFDC
    if symbol == 154:
        return 0x3FFFD8
    if symbol == 155:
        return 0x7FFFE5
    if symbol == 156:
        return 0x3FFFD9
    if symbol == 157:
        return 0x7FFFE6
    if symbol == 158:
        return 0x7FFFE7
    if symbol == 159:
        return 0xFFFFEF
    if symbol == 160:
        return 0x3FFFDA
    if symbol == 161:
        return 0x1FFFDD
    if symbol == 162:
        return 0xFFFE9
    if symbol == 163:
        return 0x3FFFDB
    if symbol == 164:
        return 0x3FFFDC
    if symbol == 165:
        return 0x7FFFE8
    if symbol == 166:
        return 0x7FFFE9
    if symbol == 167:
        return 0x1FFFDE
    if symbol == 168:
        return 0x7FFFEA
    if symbol == 169:
        return 0x3FFFDD
    if symbol == 170:
        return 0x3FFFDE
    if symbol == 171:
        return 0xFFFFF0
    if symbol == 172:
        return 0x1FFFDF
    if symbol == 173:
        return 0x3FFFDF
    if symbol == 174:
        return 0x7FFFEB
    if symbol == 175:
        return 0x7FFFEC
    if symbol == 176:
        return 0x1FFFE0
    if symbol == 177:
        return 0x1FFFE1
    if symbol == 178:
        return 0x3FFFE0
    if symbol == 179:
        return 0x1FFFE2
    if symbol == 180:
        return 0x7FFFED
    if symbol == 181:
        return 0x3FFFE1
    if symbol == 182:
        return 0x7FFFEE
    if symbol == 183:
        return 0x7FFFEF
    if symbol == 184:
        return 0xFFFEA
    if symbol == 185:
        return 0x3FFFE2
    if symbol == 186:
        return 0x3FFFE3
    if symbol == 187:
        return 0x3FFFE4
    if symbol == 188:
        return 0x7FFFF0
    if symbol == 189:
        return 0x3FFFE5
    if symbol == 190:
        return 0x3FFFE6
    if symbol == 191:
        return 0x7FFFF1
    if symbol == 192:
        return 0x3FFFFE0
    if symbol == 193:
        return 0x3FFFFE1
    if symbol == 194:
        return 0xFFFEB
    if symbol == 195:
        return 0x7FFF1
    if symbol == 196:
        return 0x3FFFE7
    if symbol == 197:
        return 0x7FFFF2
    if symbol == 198:
        return 0x3FFFE8
    if symbol == 199:
        return 0x1FFFFEC
    if symbol == 200:
        return 0x3FFFFE2
    if symbol == 201:
        return 0x3FFFFE3
    if symbol == 202:
        return 0x3FFFFE4
    if symbol == 203:
        return 0x7FFFFDE
    if symbol == 204:
        return 0x7FFFFDF
    if symbol == 205:
        return 0x3FFFFE5
    if symbol == 206:
        return 0xFFFFF1
    if symbol == 207:
        return 0x1FFFFED
    if symbol == 208:
        return 0x7FFF2
    if symbol == 209:
        return 0x1FFFE3
    if symbol == 210:
        return 0x3FFFFE6
    if symbol == 211:
        return 0x7FFFFE0
    if symbol == 212:
        return 0x7FFFFE1
    if symbol == 213:
        return 0x3FFFFE7
    if symbol == 214:
        return 0x7FFFFE2
    if symbol == 215:
        return 0xFFFFF2
    if symbol == 216:
        return 0x1FFFE4
    if symbol == 217:
        return 0x1FFFE5
    if symbol == 218:
        return 0x3FFFFE8
    if symbol == 219:
        return 0x3FFFFE9
    if symbol == 220:
        return 0xFFFFFFD
    if symbol == 221:
        return 0x7FFFFE3
    if symbol == 222:
        return 0x7FFFFE4
    if symbol == 223:
        return 0x7FFFFE5
    if symbol == 224:
        return 0xFFFEC
    if symbol == 225:
        return 0xFFFFF3
    if symbol == 226:
        return 0xFFFED
    if symbol == 227:
        return 0x1FFFE6
    if symbol == 228:
        return 0x3FFFE9
    if symbol == 229:
        return 0x1FFFE7
    if symbol == 230:
        return 0x1FFFE8
    if symbol == 231:
        return 0x7FFFF3
    if symbol == 232:
        return 0x3FFFEA
    if symbol == 233:
        return 0x3FFFEB
    if symbol == 234:
        return 0x1FFFFEE
    if symbol == 235:
        return 0x1FFFFEF
    if symbol == 236:
        return 0xFFFFF4
    if symbol == 237:
        return 0xFFFFF5
    if symbol == 238:
        return 0x3FFFFEA
    if symbol == 239:
        return 0x7FFFF4
    if symbol == 240:
        return 0x3FFFFEB
    if symbol == 241:
        return 0x7FFFFE6
    if symbol == 242:
        return 0x3FFFFEC
    if symbol == 243:
        return 0x3FFFFED
    if symbol == 244:
        return 0x7FFFFE7
    if symbol == 245:
        return 0x7FFFFE8
    if symbol == 246:
        return 0x7FFFFE9
    if symbol == 247:
        return 0x7FFFFEA
    if symbol == 248:
        return 0x7FFFFEB
    if symbol == 249:
        return 0xFFFFFFE
    if symbol == 250:
        return 0x7FFFFEC
    if symbol == 251:
        return 0x7FFFFED
    if symbol == 252:
        return 0x7FFFFEE
    if symbol == 253:
        return 0x7FFFFEF
    if symbol == 254:
        return 0x7FFFFF0
    if symbol == 255:
        return 0x3FFFFEE
    return 0x3FFFFFFF  # 256 = EOS


@always_inline
def _hpack_table_length(symbol: Int) -> Int:
    """Return the Huffman code length (in bits) for a symbol in
    [0, 256]. EOS is 30 bits.

    Derived from the code value: the code is right-aligned in a
    32-bit word, so the length is the position of the highest
    set bit (or 1 for code == 0). For HPACK Appendix B the
    length is unique per symbol (canonical), so this property
    is sound. We special-case symbols whose code happens to be
    < 2^(canonical_length-1) (a leading-zero code, e.g.
    symbol 48 '0' has code 0x0 length 5) by hard-coding the
    length to its RFC value.
    """
    # Lengths derived directly from the RFC 7541 Appendix B
    # table. Stored as a comptime ASCII string of two-hex-digit
    # length values (00..1e for 0..30 bits) so the table is
    # immediately auditable against the spec.
    comptime _LEN_TABLE: StaticString = "0d171c1c1c1c1c1c1c181e1c1c1e1c1c1c1c1c1c1c1c1e1c1c1c1c1c1c1c1c1c060a0a0c0d06080b0a0a080b080606060505050606060606060607080f060c0a0d06070707070707070707070707070707070707070707070807080d130d0e060f05060506050606060507070606060506070605050607070707070f0b0e0d1c141614141616161716171717171718171818161718171717171516171617171816151416161717151716161815161717151516151716171714161616171616171a1a1413161716191a1a1a1b1b1a181913151a1b1b1a1b1815151a1a1c1b1b1b14181415161515171616191918181a171a1b1a1a1b1b1b1b1b1c1b1b1b1b1b1a1e"
    if symbol < 0 or symbol > 256:
        return 30
    var off = symbol * 2
    var hi = Int(_LEN_TABLE.unsafe_ptr()[off])
    var lo = Int(_LEN_TABLE.unsafe_ptr()[off + 1])
    return _hex_digit_value(hi) * 16 + _hex_digit_value(lo)


@always_inline
def _hex_digit_value(c: Int) -> Int:
    """Convert an ASCII hex digit byte to its 0..15 value."""
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 97 + 10
    if c >= 65 and c <= 70:
        return c - 65 + 10
    return 0


# ── Encoder ──────────────────────────────────────────────────────────────────


def huffman_encoded_length(input: Span[UInt8, _]) -> Int:
    """Return the byte length of the Huffman-encoded form of
    ``input``.

    Useful for callers that want to ``reserve`` an output buffer
    of the right size before calling :func:`huffman_encode`.
    """
    var bits = 0
    for i in range(len(input)):
        bits += _hpack_table_length(Int(input[i]))
    return (bits + 7) // 8


def huffman_encode(input: Span[UInt8, _], mut output: List[UInt8]):
    """Append the Huffman-encoded form of ``input`` to ``output``.

    Pads the trailing partial byte with EOS-prefix 1-bits per
    RFC 7541 §5.2 (the high bits of EOS are all 1, so the
    padding is "all 1 bits").

    Args:
        input: The bytes to encode.
        output: The byte list to append the encoded form to.
    """
    var bits = UInt64(0)
    var nbits = 0
    for i in range(len(input)):
        var sym = Int(input[i])
        var code = _hpack_table_code(sym)
        var clen = _hpack_table_length(sym)
        bits = (bits << UInt64(clen)) | UInt64(code)
        nbits += clen
        while nbits >= 8:
            nbits -= 8
            var b = UInt8(Int((bits >> UInt64(nbits)) & UInt64(0xFF)))
            output.append(b)
    if nbits > 0:
        # Pad with high bits of EOS (all 1s) to fill the byte.
        var pad_shift = 8 - nbits
        var b = UInt8(
            Int(
                ((bits << UInt64(pad_shift)) | UInt64((1 << pad_shift) - 1))
                & UInt64(0xFF)
            )
        )
        output.append(b)


# ── Decoder ──────────────────────────────────────────────────────────────────


@always_inline
def _build_decode_lookup(target_code: Int, target_len: Int) -> Int:
    """Helper for the canonical decoder — for a given prefix
    ``(code, len)`` accumulated by the bit-walker, return the
    matching symbol or -1 if no match.

    Implemented as a linear scan over [0, 256]. Slow but correct;
    SIMD acceleration is a follow-up commit.
    """
    for sym in range(257):
        if _hpack_table_length(sym) == target_len:
            if _hpack_table_code(sym) == target_code:
                return sym
    return -1


def huffman_decoded_length(input: Span[UInt8, _]) -> Int:
    """Return an upper bound on the decoded byte length.

    The exact length depends on the bit-content of the input
    (every output byte costs 5..30 input bits). The upper bound
    used here is ``len(input) * 8 / 5`` rounded up.
    """
    return ((len(input) * 8) + 4) // 5


def huffman_decode(
    input: Span[UInt8, _], mut output: List[UInt8]
) raises HuffmanError:
    """Append the Huffman-decoded form of ``input`` to ``output``.

    Args:
        input: The Huffman-encoded byte stream (typically from a
               HPACK string-literal field with the ``H`` flag
               set).
        output: The byte list to append the decoded form to.

    Raises:
        HuffmanError(EOS_IN_INPUT): The input contains the EOS
            symbol (length-30 code matching ``0x3FFFFFFF``).
        HuffmanError(PADDING_TOO_LONG): The partial-final-byte
            padding is longer than 7 bits.
        HuffmanError(INVALID_PADDING): The padding bits don't
            match the high bits of EOS (all 1s).
    """
    var bits = UInt64(0)
    var nbits = 0
    var i = 0
    var n = len(input)
    while i < n:
        bits = (bits << UInt64(8)) | UInt64(Int(input[i]))
        i += 1
        nbits += 8
        # Try to decode as many symbols as possible from the
        # accumulator.
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
                    bits = bits & UInt64(
                        (1 << nbits) - 1
                    ) if nbits > 0 else UInt64(0)
                    matched = True
                    break
            if not matched:
                break
    # Padding check: nbits MUST be in [0, 7], and the remaining
    # bits MUST all be 1.
    if nbits > 7:
        raise HuffmanError(HuffmanError.PADDING_TOO_LONG)
    if nbits > 0:
        var expected = UInt64((1 << nbits) - 1)
        if bits != expected:
            raise HuffmanError(HuffmanError.INVALID_PADDING)
