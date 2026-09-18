"""Variable-length integer codec for QUIC (RFC 9000 §16).

QUIC encodes integers in a self-describing format where the two
most-significant bits of the first byte select the encoding length:

| 2 MSB | Length | Usable bits | Range                  |
|------:|-------:|------------:|------------------------|
| 0b00  | 1      | 6           | 0 .. 63                |
| 0b01  | 2      | 14          | 0 .. 16,383            |
| 0b10  | 4      | 30          | 0 .. 1,073,741,823     |
| 0b11  | 8      | 62          | 0 .. 4,611,686,018,427,387,903 |

All multi-byte forms are big-endian. The two-bit length tag lives
in the highest two bits of the first byte; the remaining bits of
that byte are part of the value.

This module is intentionally sans-I/O: every function takes either
a buffer slice or a value and returns the other, with no socket
state. The codec is the load-bearing primitive for every other
QUIC frame: STREAM frame offsets, packet numbers, frame types,
ACK ranges -- everything is varint-encoded.

References:
- RFC 9000 §16 "Variable-Length Integer Encoding".
- aioquic ``buffer.pull_uint_var`` / ``buffer.push_uint_var``
  (the Python reference implementation we cross-validate against).
"""

from std.collections import List
from std.collections.span import Span


comptime VARINT_MAX: Int = (1 << 62) - 1
"""Largest representable varint value (``2 ** 62 - 1`` per RFC 9000
§16). Values above this cannot be encoded and must be rejected at
the codec boundary."""


@fieldwise_init
struct Varint(Copyable):
    """A decoded QUIC varint together with the number of wire bytes
    that produced it.

    ``value`` is the integer payload; ``consumed`` is the number of
    bytes the encoded form occupied (1, 2, 4, or 8). Callers use
    ``consumed`` to advance their cursor over the input buffer.
    """

    var value: UInt64
    var consumed: Int


def varint_encoded_length(value: UInt64) raises -> Int:
    """Return the wire length (1, 2, 4, or 8 bytes) required to
    encode ``value``.

    Raises ``Error`` if ``value`` exceeds :data:`VARINT_MAX`.
    """
    if value > UInt64(VARINT_MAX):
        raise Error("quic varint: value exceeds 2^62 - 1")
    if value < UInt64(64):
        return 1
    if value < UInt64(1 << 14):
        return 2
    if value < UInt64(1 << 30):
        return 4
    return 8


def encode_varint(value: UInt64) raises -> List[UInt8]:
    """Encode ``value`` into a fresh byte buffer.

    The encoding picks the shortest length that fits per RFC 9000
    §16. Raises ``Error`` for values above :data:`VARINT_MAX`. The
    "shortest form" rule is enforced on the encoder side; the
    decoder accepts any valid encoding (a producer may legitimately
    pad to a longer form for byte-alignment reasons -- aioquic does
    this for packet-number space).
    """
    var out = List[UInt8]()
    var n = varint_encoded_length(value)
    if n == 1:
        # 1-byte: 00xxxxxx
        out.append(UInt8(value & UInt64(0x3F)))
    elif n == 2:
        # 2-byte: 01xxxxxx xxxxxxxx
        out.append(UInt8(((value >> 8) & UInt64(0x3F)) | UInt64(0x40)))
        out.append(UInt8(value & UInt64(0xFF)))
    elif n == 4:
        # 4-byte: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        out.append(UInt8(((value >> 24) & UInt64(0x3F)) | UInt64(0x80)))
        out.append(UInt8((value >> 16) & UInt64(0xFF)))
        out.append(UInt8((value >> 8) & UInt64(0xFF)))
        out.append(UInt8(value & UInt64(0xFF)))
    else:
        # 8-byte: 11xxxxxx <7 more bytes big-endian>
        out.append(UInt8(((value >> 56) & UInt64(0x3F)) | UInt64(0xC0)))
        out.append(UInt8((value >> 48) & UInt64(0xFF)))
        out.append(UInt8((value >> 40) & UInt64(0xFF)))
        out.append(UInt8((value >> 32) & UInt64(0xFF)))
        out.append(UInt8((value >> 24) & UInt64(0xFF)))
        out.append(UInt8((value >> 16) & UInt64(0xFF)))
        out.append(UInt8((value >> 8) & UInt64(0xFF)))
        out.append(UInt8(value & UInt64(0xFF)))
    return out^


def decode_varint(buf: Span[UInt8, _]) raises -> Varint:
    """Decode the varint at the start of ``buf``.

    Returns a :class:`Varint` carrying the decoded value plus the
    number of bytes consumed. Raises ``Error`` if ``buf`` is too
    short to contain a complete encoding (truncated input is the
    most common varint-level failure mode).
    """
    var n = len(buf)
    if n == 0:
        raise Error("quic varint: empty buffer")
    var first = buf[0]
    # The top two bits of the first byte determine the length.
    var tag = Int(first >> 6) & 0x3
    var length: Int
    if tag == 0:
        length = 1
    elif tag == 1:
        length = 2
    elif tag == 2:
        length = 4
    else:
        length = 8
    if n < length:
        raise Error("quic varint: truncated; need " + String(length) + " bytes")
    # The remaining 6 bits of the first byte are the high bits of
    # the value. Subsequent bytes contribute 8 bits each, big-endian.
    var value = UInt64(first) & UInt64(0x3F)
    for i in range(1, length):
        value = (value << 8) | UInt64(buf[i])
    return Varint(value=value, consumed=length)
