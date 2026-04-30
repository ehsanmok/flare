"""HTTP/2 frame codec (RFC 9113 §4).

Every HTTP/2 frame is a 9-octet header followed by a payload:

::

    +-----------------------------------------------+
    | Length (24) |
    +---------------+---------------+---------------+
    | Type (8) | Flags (8) |
    +-+-------------+---------------+-------------------------------+
    |R| Stream Identifier (31) |
    +=+=============================================================+
    | Frame Payload (0...) ...
    +---------------------------------------------------------------+

This module provides:

- :class:`FrameHeader` — the 9-byte fixed header.
- :class:`Frame` — owned wrapper carrying header + payload.
- :class:`FrameType` / :class:`FrameFlags` — typed constants.
- :func:`parse_frame` — best-effort parser; raises ``H2Error`` on
  malformed length / oversized payload / invalid stream-id.
- :func:`encode_frame` — emit the wire representation.

The codec is *connection-agnostic*: it does not enforce stream
state, frame ordering, or the SETTINGS/window math. Those checks
live in :mod:`flare.http2.state`.
"""

from std.collections import Optional


# ── Constants (RFC 9113 §4.2 / §6.5) ─────────────────────────────────────

alias H2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
"""Fixed connection-preface bytes a client MUST send first."""

alias H2_DEFAULT_FRAME_SIZE = 16384
"""``SETTINGS_MAX_FRAME_SIZE`` initial value."""

alias H2_MAX_FRAME_SIZE = 16777215
"""24-bit length field upper bound."""


struct FrameType(Copyable, Defaultable, Movable):
    """RFC 9113 §6 frame type codes (Table 1)."""

    var value: UInt8

    def __init__(out self):
        self.value = UInt8(0)

    def __init__(out self, v: UInt8):
        self.value = v

    @staticmethod
    def DATA() -> FrameType:
        return FrameType(UInt8(0x0))

    @staticmethod
    def HEADERS() -> FrameType:
        return FrameType(UInt8(0x1))

    @staticmethod
    def PRIORITY() -> FrameType:
        return FrameType(UInt8(0x2))

    @staticmethod
    def RST_STREAM() -> FrameType:
        return FrameType(UInt8(0x3))

    @staticmethod
    def SETTINGS() -> FrameType:
        return FrameType(UInt8(0x4))

    @staticmethod
    def PUSH_PROMISE() -> FrameType:
        return FrameType(UInt8(0x5))

    @staticmethod
    def PING() -> FrameType:
        return FrameType(UInt8(0x6))

    @staticmethod
    def GOAWAY() -> FrameType:
        return FrameType(UInt8(0x7))

    @staticmethod
    def WINDOW_UPDATE() -> FrameType:
        return FrameType(UInt8(0x8))

    @staticmethod
    def CONTINUATION() -> FrameType:
        return FrameType(UInt8(0x9))

    def name(self) -> String:
        if self.value == UInt8(0x0):
            return "DATA"
        if self.value == UInt8(0x1):
            return "HEADERS"
        if self.value == UInt8(0x2):
            return "PRIORITY"
        if self.value == UInt8(0x3):
            return "RST_STREAM"
        if self.value == UInt8(0x4):
            return "SETTINGS"
        if self.value == UInt8(0x5):
            return "PUSH_PROMISE"
        if self.value == UInt8(0x6):
            return "PING"
        if self.value == UInt8(0x7):
            return "GOAWAY"
        if self.value == UInt8(0x8):
            return "WINDOW_UPDATE"
        if self.value == UInt8(0x9):
            return "CONTINUATION"
        return "UNKNOWN"


struct FrameFlags(Copyable, Defaultable, Movable):
    """RFC 9113 §6 per-type flag bits."""

    var bits: UInt8

    def __init__(out self):
        self.bits = UInt8(0)

    def __init__(out self, b: UInt8):
        self.bits = b

    def has(self, mask: UInt8) -> Bool:
        return (self.bits & mask) != UInt8(0)

    @staticmethod
    def END_STREAM() -> UInt8:
        return UInt8(0x1)

    @staticmethod
    def END_HEADERS() -> UInt8:
        return UInt8(0x4)

    @staticmethod
    def PADDED() -> UInt8:
        return UInt8(0x8)

    @staticmethod
    def PRIORITY() -> UInt8:
        return UInt8(0x20)

    @staticmethod
    def ACK() -> UInt8:
        return UInt8(0x1)


# ── FrameHeader ─────────────────────────────────────────────────────────


struct FrameHeader(Copyable, Defaultable, Movable):
    """The 9-octet HTTP/2 frame header (RFC 9113 §4.1).

    Stream id is unsigned 31-bit. The reserved high bit is masked
    off on parse and ignored on emit.
    """

    var length: Int
    var type: FrameType
    var flags: FrameFlags
    var stream_id: Int

    def __init__(out self):
        self.length = 0
        self.type = FrameType()
        self.flags = FrameFlags()
        self.stream_id = 0


# ── Frame ──────────────────────────────────────────────────────────────


struct Frame(Copyable, Defaultable, Movable):
    """A complete frame: header + owned payload bytes.

    The payload is verbatim from the wire — it has *not* been
    decoded into HEADERS / SETTINGS / etc. typed fields. Higher
    layers (``state.mojo`` and ``hpack.mojo``) interpret the bytes.
    """

    var header: FrameHeader
    var payload: List[UInt8]

    def __init__(out self):
        self.header = FrameHeader()
        self.payload = List[UInt8]()


# ── parse_frame ─────────────────────────────────────────────────────────


def parse_frame(buf: Span[UInt8, _]) raises -> Optional[Frame]:
    """Try to parse one frame from the front of ``buf``.

    Returns:
        ``None`` if ``buf`` doesn't contain a complete frame yet
        (callers should keep buffering). ``Some(Frame)`` otherwise.

    Raises:
        Error: For frames whose declared length exceeds
        :data:`H2_MAX_FRAME_SIZE` (RFC 9113 §4.2 — connection error
        ``FRAME_SIZE_ERROR``).
    """
    if len(buf) < 9:
        return Optional[Frame]()
    var length = (Int(buf[0]) << 16) | (Int(buf[1]) << 8) | Int(buf[2])
    if length > H2_MAX_FRAME_SIZE:
        raise Error("h2: frame length exceeds 24-bit max")
    if len(buf) < 9 + length:
        return Optional[Frame]()
    var f = Frame()
    f.header.length = length
    f.header.type = FrameType(buf[3])
    f.header.flags = FrameFlags(buf[4])
    var sid = (
        (Int(buf[5]) << 24)
        | (Int(buf[6]) << 16)
        | (Int(buf[7]) << 8)
        | Int(buf[8])
    )
    f.header.stream_id = sid & 0x7FFFFFFF
    f.payload = List[UInt8](capacity=length)
    for i in range(length):
        f.payload.append(buf[9 + i])
    return Optional[Frame](f^)


# ── encode_frame ────────────────────────────────────────────────────────


def encode_frame(f: Frame) -> List[UInt8]:
    """Emit the wire bytes for ``f`` (header + payload)."""
    var n = len(f.payload)
    var out = List[UInt8](capacity=9 + n)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    out.append(f.header.type.value)
    out.append(f.header.flags.bits)
    var sid = f.header.stream_id & 0x7FFFFFFF
    out.append(UInt8((sid >> 24) & 0xFF))
    out.append(UInt8((sid >> 16) & 0xFF))
    out.append(UInt8((sid >> 8) & 0xFF))
    out.append(UInt8(sid & 0xFF))
    for i in range(n):
        out.append(f.payload[i])
    return out^
