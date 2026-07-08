"""HTTP/3 frame codec (RFC 9114 §7).

Every HTTP/3 frame on a request stream has the same shape:

```
Frame {
  Type   (varint),
  Length (varint),
  Frame Payload (..),
}
```

The frame *type* selects the payload schema. RFC 9114 §7.2 lists
the seven core types (DATA, HEADERS, CANCEL_PUSH, SETTINGS,
PUSH_PROMISE, GOAWAY, MAX_PUSH_ID); receivers are required to
*ignore* (not error on) unknown types so the wire format can be
extended without protocol negotiation.

This module is intentionally sans-I/O: the codec works on byte
spans + buffers and never touches a socket or a QUIC stream
adapter. The codec layer is the load-bearing primitive the
future reactor + QUIC stream multiplexer will compose on top of.

References:
- RFC 9114 §7 "HTTP/3 Frames".
- RFC 9000 §16 (varint format; reused via :mod:`flare.quic.varint`).
"""

from std.collections import List
from std.memory import Span

from flare.quic.varint import decode_varint, encode_varint


# ── Frame type constants (RFC 9114 §7.2) ─────────────────────────

comptime H3_FRAME_TYPE_DATA: UInt64 = 0x00
comptime H3_FRAME_TYPE_HEADERS: UInt64 = 0x01
comptime H3_FRAME_TYPE_CANCEL_PUSH: UInt64 = 0x03
comptime H3_FRAME_TYPE_SETTINGS: UInt64 = 0x04
comptime H3_FRAME_TYPE_PUSH_PROMISE: UInt64 = 0x05
comptime H3_FRAME_TYPE_GOAWAY: UInt64 = 0x07
comptime H3_FRAME_TYPE_MAX_PUSH_ID: UInt64 = 0x0D


# ── Standard SETTINGS identifiers (RFC 9114 §7.2.4.1 + RFC 9220) ─

comptime H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY: UInt64 = 0x01
comptime H3_SETTINGS_MAX_FIELD_SECTION_SIZE: UInt64 = 0x06
comptime H3_SETTINGS_QPACK_BLOCKED_STREAMS: UInt64 = 0x07
comptime H3_SETTINGS_ENABLE_CONNECT_PROTOCOL: UInt64 = 0x08
"""RFC 9220 — Bootstrapping WebSockets with HTTP/3."""


@fieldwise_init
struct Http3FrameType(Copyable, Movable):
    """Wraps a varint-encoded frame type. ``raw`` is the wire
    value; ``is_known()`` checks whether the type is one of the
    seven core types defined by RFC 9114. Receivers must ignore
    unknown types rather than erroring; the wrapper exists so
    callers can switch on the value cleanly."""

    var raw: UInt64

    def is_known(self) -> Bool:
        return (
            self.raw == H3_FRAME_TYPE_DATA
            or self.raw == H3_FRAME_TYPE_HEADERS
            or self.raw == H3_FRAME_TYPE_CANCEL_PUSH
            or self.raw == H3_FRAME_TYPE_SETTINGS
            or self.raw == H3_FRAME_TYPE_PUSH_PROMISE
            or self.raw == H3_FRAME_TYPE_GOAWAY
            or self.raw == H3_FRAME_TYPE_MAX_PUSH_ID
        )

    def is_reserved_grease(self) -> Bool:
        """RFC 9114 §7.2.8 reserves frame types of the form
        ``0x1f * N + 0x21`` as "grease" -- senders emit them to
        ensure receivers tolerate unknown types. The codec keeps
        the check inline so callers can audit grease tolerance."""
        if self.raw < UInt64(0x21):
            return False
        return (Int(self.raw) - 0x21) % 0x1F == 0


@fieldwise_init
struct Http3Frame(Copyable, Movable):
    """Parsed HTTP/3 frame: type + payload bytes.

    ``payload`` is a deep copy of the wire bytes that follow the
    type/length varints; callers own the buffer so the original
    receive buffer can be advanced/recycled.
    """

    var frame_type: Http3FrameType
    var payload: List[UInt8]


def encode_http3_frame(
    frame_type: UInt64,
    payload: Span[UInt8, _],
    mut out: List[UInt8],
) raises:
    """Append a complete RFC 9114 §7 frame (type varint, length
    varint, payload bytes) to ``out``.

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across frames so the underlying allocation
    amortises across the stream. The encoder appends only; it
    never reads from or truncates the existing contents.
    """
    var type_bytes = encode_varint(frame_type)
    var len_bytes = encode_varint(UInt64(len(payload)))
    out.reserve(len(out) + len(type_bytes) + len(len_bytes) + len(payload))
    for i in range(len(type_bytes)):
        out.append(type_bytes[i])
    for i in range(len(len_bytes)):
        out.append(len_bytes[i])
    for i in range(len(payload)):
        out.append(payload[i])


def decode_http3_frame(buf: Span[UInt8, _]) raises -> Http3Frame:
    """Decode the first complete frame at the start of ``buf``.

    Raises ``Error`` on a truncated input (a partial varint or a
    declared length that overruns ``buf``). The decoder does *not*
    advance past the frame on its own; the caller computes the
    consumed length as ``decode_varint(type).consumed +
    decode_varint(length).consumed + length``. This keeps the
    frame-level API focused on payload extraction; the
    framer-level API (stream cursor management) is the job of the
    HTTP/3 connection driver in a later cycle.
    """
    if len(buf) == 0:
        raise Error("h3 frame: empty buffer")
    var type_var = decode_varint(buf)
    var rest = buf[type_var.consumed :]
    if len(rest) == 0:
        raise Error("h3 frame: type without length")
    var len_var = decode_varint(rest)
    var payload_start = type_var.consumed + len_var.consumed
    var payload_end = payload_start + Int(len_var.value)
    if payload_end > len(buf):
        raise Error(
            "h3 frame: payload truncated (need "
            + String(payload_end)
            + " bytes, have "
            + String(len(buf))
            + ")"
        )
    var payload = List[UInt8](capacity=Int(len_var.value))
    for i in range(payload_start, payload_end):
        payload.append(buf[i])
    return Http3Frame(
        frame_type=Http3FrameType(raw=type_var.value),
        payload=payload^,
    )


# ── SETTINGS payload codec (RFC 9114 §7.2.4) ─────────────────────


@fieldwise_init
struct Http3Setting(Copyable, Movable):
    """A single ``identifier: value`` pair inside a SETTINGS
    frame's payload."""

    var identifier: UInt64
    var value: UInt64


def encode_http3_settings(
    settings: List[Http3Setting],
    mut out: List[UInt8],
) raises:
    """Append the body of an HTTP/3 SETTINGS frame to ``out``.

    Writes the ``identifier`` / ``value`` varint pairs in order;
    the result is the *payload* only. Wrap it in
    :func:`encode_http3_frame` with type
    :data:`H3_FRAME_TYPE_SETTINGS` to get a complete frame.

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across calls so the underlying allocation
    amortises across the stream. The encoder appends only; it
    never reads from or truncates the existing contents.
    """
    for i in range(len(settings)):
        var id_bytes = encode_varint(settings[i].identifier)
        var val_bytes = encode_varint(settings[i].value)
        for j in range(len(id_bytes)):
            out.append(id_bytes[j])
        for j in range(len(val_bytes)):
            out.append(val_bytes[j])


def decode_http3_settings(payload: Span[UInt8, _]) raises -> List[Http3Setting]:
    """Decode a SETTINGS-frame payload into a list of pairs.

    Raises if the payload is malformed (truncated varint, dangling
    identifier without a value). Duplicate identifiers are *not*
    rejected here -- RFC 9114 requires receivers to detect this
    and respond with H3_SETTINGS_ERROR, but that policy belongs
    to the connection driver, not the codec.
    """
    var out = List[Http3Setting]()
    var offset = 0
    var n = len(payload)
    while offset < n:
        var id_var = decode_varint(payload[offset:])
        offset += id_var.consumed
        if offset >= n:
            raise Error("h3 settings: identifier without value")
        var val_var = decode_varint(payload[offset:])
        offset += val_var.consumed
        out.append(Http3Setting(identifier=id_var.value, value=val_var.value))
    return out^
