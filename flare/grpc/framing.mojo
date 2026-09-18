"""``gRPC`` length-prefix-message (LPM) framing codec.

Every gRPC message on the wire is a 5-byte header followed by an
opaque payload:

```
+--------+----------------+---------------+
| Flag   | Length (BE32)  | Payload bytes |
| (1B)   |   (4 bytes)    |  (Length B)   |
+--------+----------------+---------------+
```

- **Flag** (1 byte): bit 0 is the "compressed" flag (1 = the
  payload is compressed with the message-level codec negotiated
  via ``grpc-encoding``; 0 = uncompressed). All other bits are
  reserved and must be zero.
- **Length** (4 bytes, big-endian): the byte count of the
  payload that follows. The wire-level maximum is 2^32 - 1; a
  per-channel ``max-receive-message-length`` policy lives at a
  higher layer.
- **Payload**: opaque serialized protobuf (or other codec)
  bytes.

This is the wire format used by both unary RPCs (one frame in
each direction) and streaming RPCs (multiple frames per stream).
HTTP/2 DATA frames may carry a partial LPM frame or several
back-to-back; the decoder must therefore handle "need more data"
gracefully without throwing on a clean truncation at the
buffer boundary.

References:
- https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
- https://grpc.io/docs/what-is-grpc/core-concepts/ (call shapes)
"""

from std.collections import List
from std.collections.span import Span


comptime GRPC_COMPRESSION_NONE: UInt8 = 0x00
comptime GRPC_COMPRESSION_COMPRESSED: UInt8 = 0x01
"""LPM flag-byte values. Other bits are reserved (RFC for HTTP/2-
based gRPC framing) and must be zero on the wire."""


@fieldwise_init
struct GrpcCompressionFlag(Copyable):
    """Typed wrapper around the LPM flag byte. ``is_compressed()``
    returns True when bit 0 is set; ``raw`` exposes the byte for
    callers that need to forward greased / extension bits without
    interpretation."""

    var raw: UInt8

    def is_compressed(self) -> Bool:
        return (Int(self.raw) & 0x01) == 0x01

    def has_reserved_bits(self) -> Bool:
        """Return True if any reserved bit (bits 1..7) is set.
        Callers may treat this as a protocol violation; the codec
        itself accepts the bits to remain forward-compatible
        with future spec extensions."""
        return (Int(self.raw) & 0xFE) != 0


@fieldwise_init
struct GrpcMessage(Copyable):
    """A decoded LPM frame: flag + opaque payload bytes."""

    var flag: GrpcCompressionFlag
    var payload: List[UInt8]


@fieldwise_init
struct GrpcDecodeResult(Copyable):
    """Outcome of an LPM decode attempt.

    The decoder operates on a streaming buffer where the message
    boundary may not yet be visible. ``needs_more`` is True when
    the buffer is too short to contain a complete frame; callers
    should accumulate more bytes and try again. ``message`` is
    populated only when ``needs_more`` is False.
    """

    var message: GrpcMessage
    var consumed: Int
    var needs_more: Bool


def encode_grpc_message(
    payload: Span[UInt8, _],
    mut out: List[UInt8],
    compressed: Bool = False,
) raises:
    """Append a length-prefix-message (LPM) frame to ``out``.

    The frame is a single byte compression flag plus a 4-byte
    big-endian length plus the payload bytes. The caller is
    responsible for compressing the payload before calling this
    function if ``compressed=True``; the framer just sets the
    flag byte and prefixes the length.

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across calls so the underlying allocation
    amortises across the stream. The encoder appends only; it
    never reads from or truncates the existing contents.
    """
    var n = len(payload)
    if n > 0xFFFFFFFF:
        raise Error("grpc framing: payload exceeds 2^32 - 1 bytes")
    out.reserve(len(out) + 5 + n)
    out.append(UInt8(0x01) if compressed else UInt8(0x00))
    # Length: 4 bytes, big-endian.
    out.append(UInt8((n >> 24) & 0xFF))
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    for i in range(n):
        out.append(payload[i])


def decode_grpc_message(buf: Span[UInt8, _]) raises -> GrpcDecodeResult:
    """Decode the first complete LPM frame at the start of ``buf``.

    Returns ``needs_more=True`` (and an empty placeholder
    message) when the buffer is shorter than the declared frame.
    Raises only on hard errors -- in this version the only hard
    error is a payload length that would overflow Mojo's ``Int``
    when the framer eventually accumulates ``consumed`` bytes
    (which would require a length declaration > 2^31; the wire
    format allows up to 2^32 - 1 but Mojo's ``Int`` is 64-bit so
    this is purely defensive).
    """
    if len(buf) < 5:
        # Header not yet on the wire; ask the caller to wait.
        return GrpcDecodeResult(
            message=_empty_message(),
            consumed=0,
            needs_more=True,
        )
    var flag = GrpcCompressionFlag(raw=buf[0])
    # Length is unsigned 32-bit big-endian; assemble through Int64
    # to keep the math overflow-free.
    var length64 = (
        (Int64(buf[1]) << 24)
        | (Int64(buf[2]) << 16)
        | (Int64(buf[3]) << 8)
        | Int64(buf[4])
    )
    var length = Int(length64)
    var total = 5 + length
    if total > len(buf):
        return GrpcDecodeResult(
            message=_empty_message(),
            consumed=0,
            needs_more=True,
        )
    var payload = List[UInt8](capacity=length)
    for i in range(5, total):
        payload.append(buf[i])
    return GrpcDecodeResult(
        message=GrpcMessage(flag=flag^, payload=payload^),
        consumed=total,
        needs_more=False,
    )


def _empty_message() -> GrpcMessage:
    return GrpcMessage(
        flag=GrpcCompressionFlag(raw=UInt8(0)),
        payload=List[UInt8](),
    )
