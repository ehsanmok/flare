"""The Capsule Protocol (RFC 9297 sec 3).

A capsule is ``type (varint) || length (varint) || value`` on the data
stream of a tunnel such as an extended CONNECT. Sans-I/O: the encoder
appends to a caller-owned buffer and the parser reads from the front of
one, returning ``None`` until a whole capsule is there.
"""

from flare.quic.varint import decode_varint, encode_varint


comptime CAPSULE_TYPE_DATAGRAM: UInt64 = 0x00
"""RFC 9297 sec 3.5: an HTTP Datagram carried on the stream."""


@fieldwise_init
struct Capsule(Copyable):
    var capsule_type: UInt64
    var value: List[UInt8]


def encode_capsule(
    capsule_type: UInt64, value: Span[UInt8, _], mut out: List[UInt8]
) raises:
    """Append one capsule to ``out``."""
    out.extend(Span[UInt8, _](encode_varint(capsule_type)))
    out.extend(Span[UInt8, _](encode_varint(UInt64(len(value)))))
    out.extend(value)


def _varint_len(first: UInt8) -> Int:
    return 1 << Int(first >> 6)


def parse_capsule(
    buf: Span[UInt8, _], max_value: Int
) raises -> Optional[Tuple[Capsule, Int]]:
    """The capsule at the front of ``buf`` and the bytes it spans, or
    ``None`` while it is incomplete. A value longer than ``max_value``
    raises before any of it is buffered, so a peer cannot make the
    receiver hold an arbitrarily large capsule."""
    if len(buf) == 0 or len(buf) < _varint_len(buf[0]):
        return None
    var t = decode_varint(buf)
    var rest = buf[t.consumed :]
    if len(rest) == 0 or len(rest) < _varint_len(rest[0]):
        return None
    var n = decode_varint(rest)
    if n.value > UInt64(max_value):
        raise Error("capsule: value of " + String(n.value) + " bytes over cap")
    var start = t.consumed + n.consumed
    var end = start + Int(n.value)
    if end > len(buf):
        return None
    var value = List[UInt8](capacity=end - start)
    value.extend(buf[start:end])
    return (Capsule(t.value, value^), end)
