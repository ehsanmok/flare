"""QUIC v1 packet header codec (RFC 9000 §17).

QUIC packets come in two flavours:

- **Long header** (§17.2) — used during the handshake (Initial,
  0-RTT, Handshake, Retry). Carries the QUIC version and both
  Destination + Source Connection IDs explicitly.
- **Short header** (§17.3) — used after the handshake (1-RTT).
  Carries only the Destination Connection ID; the receiver
  already knows the SCID by virtue of the prior handshake.

This module parses the *public* (unprotected) parts of these
headers: the first byte's flag bits, the version, and the
connection IDs. The packet number and the length-prefixed
payload live inside header-protection-protected bytes that
require key material to access; that decryption layer is the
job of a later cycle's TLS adapter.

Connection IDs are 0..20 octet identifiers (§5.1.1). The long
header explicitly carries a length byte for each CID; the short
header relies on the receiver knowing the DCID length out of
band (typically pinned at handshake time).

References:
- RFC 9000 §17 "Packet Formats".
- RFC 9000 §5.1 "Connection IDs".
- aioquic ``packet.PullQuicHeader`` / ``packet.encode_quic_header``.
"""

from std.collections import List
from std.memory import Span

from .varint import decode_varint


comptime QUIC_VERSION_1: UInt32 = 0x00000001
"""RFC 9000's "version 1" wire constant. Returned by the parser
when the long header carries the standard QUIC v1 version."""

comptime QUIC_VERSION_NEGOTIATION: UInt32 = 0x00000000
"""Version negotiation packets (RFC 9000 §17.2.1) carry version=0
in the long header. The parser exposes this constant so callers
can detect VN packets cleanly without magic numbers."""

comptime PACKET_TYPE_INITIAL: Int = 0
comptime PACKET_TYPE_ZERO_RTT: Int = 1
comptime PACKET_TYPE_HANDSHAKE: Int = 2
comptime PACKET_TYPE_RETRY: Int = 3
"""Long-header packet types (§17.2). The two-bit ``T T`` field in
bits 4-5 of the first byte selects one of these four values."""

comptime MAX_CID_LENGTH: Int = 20
"""Maximum Connection ID length (§5.1.1). Receivers that observe
a CID length greater than 20 octets must reject the packet at the
codec boundary."""


@fieldwise_init
struct ConnectionId(Copyable, Movable):
    """A QUIC connection identifier (0..20 octets per §5.1.1)."""

    var bytes: List[UInt8]

    def length(self) -> Int:
        return len(self.bytes)

    def copy(self) -> Self:
        """Return a deep copy of this CID (so callers can move
        the original into a parent struct without invalidating
        downstream references)."""
        return Self(bytes=self.bytes.copy())


@fieldwise_init
struct _CidRead(Copyable, Movable):
    """Internal pair: CID plus the number of wire bytes it
    occupied (length prefix + payload). Wraps the values in a
    struct so callers can transfer-move the CID out cleanly."""

    var cid: ConnectionId
    var consumed: Int


def _read_cid(buf: Span[UInt8, _], offset: Int) raises -> _CidRead:
    """Read a length-prefixed CID at ``offset``. Returns the CID
    plus the number of bytes consumed (length byte + payload).
    Raises if the length exceeds :data:`MAX_CID_LENGTH` or the
    buffer is too short."""
    if offset >= len(buf):
        raise Error("quic packet: CID length byte beyond buffer")
    var n = Int(buf[offset])
    if n > MAX_CID_LENGTH:
        raise Error(
            "quic packet: CID length "
            + String(n)
            + " exceeds RFC 9000 §5.1.1 limit of 20"
        )
    var end = offset + 1 + n
    if end > len(buf):
        raise Error("quic packet: CID payload truncated")
    var bytes = List[UInt8]()
    for i in range(offset + 1, end):
        bytes.append(buf[i])
    return _CidRead(cid=ConnectionId(bytes=bytes^), consumed=1 + n)


@fieldwise_init
struct LongHeader(Copyable, Movable):
    """Parsed long-header fields.

    The ``payload_offset`` is the byte index inside the original
    buffer where the (still encrypted) packet payload begins.
    Callers that decrypt header protection use this offset as the
    starting point. For version negotiation packets the
    ``packet_type`` field is irrelevant and the payload is the
    list of supported versions; the parser leaves it on the caller
    to inspect ``version == QUIC_VERSION_NEGOTIATION``.
    """

    var packet_type: Int
    var version: UInt32
    var dcid: ConnectionId
    var scid: ConnectionId
    var payload_offset: Int


def parse_long_header(buf: Span[UInt8, _]) raises -> LongHeader:
    """Parse a long-header packet's public fields.

    The first byte's high two bits must be 0b11 (long header
    indicator). The next two bits carry the packet type. Bits
    0-3 are version-specific (reserved + packet-number length in
    QUIC v1, but those are header-protected and not parsed here).

    Then a 32-bit version, length-prefixed DCID, length-prefixed
    SCID. Initial-specific token + length parsing is split into
    :func:`parse_initial_extras` because Retry/Handshake/0-RTT
    packets share the same prefix but diverge from here.
    """
    if len(buf) < 7:
        raise Error("quic packet: long header truncated (< 7 bytes)")
    var first = buf[0]
    if (Int(first) & 0x80) == 0:
        raise Error("quic packet: long-header bit not set")
    if (Int(first) & 0x40) == 0:
        raise Error("quic packet: fixed bit (0x40) not set")
    var packet_type = (Int(first) >> 4) & 0x3
    # Version is a fixed 32-bit big-endian field at offset 1.
    var version = (
        (UInt32(buf[1]) << 24)
        | (UInt32(buf[2]) << 16)
        | (UInt32(buf[3]) << 8)
        | UInt32(buf[4])
    )
    var offset = 5
    var dcid_pair = _read_cid(buf, offset)
    offset += dcid_pair.consumed
    var scid_pair = _read_cid(buf, offset)
    offset += scid_pair.consumed
    # Copy the CIDs out of the pair wrappers; transferring out
    # of an inner field would leave the wrapper undeinit-able.
    return LongHeader(
        packet_type=packet_type,
        version=version,
        dcid=dcid_pair.cid.copy(),
        scid=scid_pair.cid.copy(),
        payload_offset=offset,
    )


@fieldwise_init
struct InitialExtras(Copyable, Movable):
    """Initial-specific extras that follow the long-header common
    prefix (§17.2.2): a length-prefixed token, then a varint
    declaring the protected payload length."""

    var token: List[UInt8]
    var payload_length: UInt64
    var consumed: Int


def parse_initial_extras(
    buf: Span[UInt8, _], offset: Int
) raises -> InitialExtras:
    """Parse the Initial-specific token + length fields starting
    at ``offset`` (typically the ``payload_offset`` returned by
    :func:`parse_long_header` for a packet whose type is
    Initial).
    """
    if offset >= len(buf):
        raise Error("quic initial: token-length offset beyond buffer")
    # Token length is varint-encoded.
    var tok_len_var = decode_varint(buf[offset:])
    var token_start = offset + tok_len_var.consumed
    var token_end = token_start + Int(tok_len_var.value)
    if token_end > len(buf):
        raise Error("quic initial: token payload truncated")
    var token = List[UInt8]()
    for i in range(token_start, token_end):
        token.append(buf[i])
    # Payload length is also varint-encoded.
    if token_end >= len(buf):
        raise Error("quic initial: payload-length varint missing")
    var len_var = decode_varint(buf[token_end:])
    var consumed = (token_end + len_var.consumed) - offset
    return InitialExtras(
        token=token^,
        payload_length=len_var.value,
        consumed=consumed,
    )


@fieldwise_init
struct ShortHeader(Copyable, Movable):
    """Parsed short-header (1-RTT) public fields.

    The DCID length is *not* on the wire; the caller passes it
    in (typically pinned at handshake time). The ``key_phase``
    bit is exposed because callers track key updates per
    connection.
    """

    var spin_bit: Bool
    var key_phase: Bool
    var dcid: ConnectionId
    var payload_offset: Int


def parse_short_header(
    buf: Span[UInt8, _], dcid_length: Int
) raises -> ShortHeader:
    """Parse a short-header (1-RTT) packet's public fields.

    The first byte's high two bits must be 0b01 (short header
    indicator + fixed bit). Bit 5 is the spin bit (§17.4); bits
    3-4 are reserved + key-phase, but the key-phase bit (bit 2)
    is header-protected, so callers that need it must apply
    header protection first. The parser exposes ``key_phase`` as
    a raw bit read for callers that have already deprotected.
    """
    if dcid_length < 0 or dcid_length > MAX_CID_LENGTH:
        raise Error(
            "quic packet: dcid_length "
            + String(dcid_length)
            + " out of [0, 20]"
        )
    if len(buf) < 1 + dcid_length:
        raise Error("quic packet: short header truncated")
    var first = buf[0]
    if (Int(first) & 0x80) != 0:
        raise Error("quic packet: long-header bit set, not short")
    if (Int(first) & 0x40) == 0:
        raise Error("quic packet: fixed bit (0x40) not set")
    var spin = (Int(first) & 0x20) != 0
    var kp = (Int(first) & 0x04) != 0
    var bytes = List[UInt8]()
    for i in range(1, 1 + dcid_length):
        bytes.append(buf[i])
    return ShortHeader(
        spin_bit=spin,
        key_phase=kp,
        dcid=ConnectionId(bytes=bytes^),
        payload_offset=1 + dcid_length,
    )


def encode_long_header(
    packet_type: Int,
    version: UInt32,
    dcid: ConnectionId,
    scid: ConnectionId,
    type_specific_bits: Int = 0,
) raises -> List[UInt8]:
    """Encode the long-header public prefix.

    ``type_specific_bits`` populates the low 4 bits of the first
    byte. For QUIC v1 those bits are reserved bits 2-3 + the
    encoded packet-number length in bits 0-1 (a 2-bit value, one
    less than the actual length). The caller computes these bits;
    the encoder just writes them.
    """
    if packet_type < 0 or packet_type > 3:
        raise Error("quic packet: packet_type out of [0, 3]")
    if dcid.length() > MAX_CID_LENGTH or scid.length() > MAX_CID_LENGTH:
        raise Error("quic packet: CID length exceeds 20")
    if type_specific_bits < 0 or type_specific_bits > 0xF:
        raise Error("quic packet: type_specific_bits out of 4 bits")
    var first = 0xC0 | (packet_type << 4) | type_specific_bits
    var out = List[UInt8]()
    out.append(UInt8(first))
    out.append(UInt8((Int(version) >> 24) & 0xFF))
    out.append(UInt8((Int(version) >> 16) & 0xFF))
    out.append(UInt8((Int(version) >> 8) & 0xFF))
    out.append(UInt8(Int(version) & 0xFF))
    out.append(UInt8(dcid.length()))
    for i in range(dcid.length()):
        out.append(dcid.bytes[i])
    out.append(UInt8(scid.length()))
    for i in range(scid.length()):
        out.append(scid.bytes[i])
    return out^


def encode_short_header(
    dcid: ConnectionId,
    spin_bit: Bool,
    key_phase: Bool,
    pn_length: Int = 1,
) raises -> List[UInt8]:
    """Encode the short-header public prefix.

    ``pn_length`` is the encoded packet-number length (1..4);
    this is the value the receiver would observe *after* header
    protection is removed. The encoder writes it into bits 0-1
    (value minus one). Header protection itself is the caller's
    job after this prefix is emitted.
    """
    if dcid.length() > MAX_CID_LENGTH:
        raise Error("quic packet: dcid length exceeds 20")
    if pn_length < 1 or pn_length > 4:
        raise Error("quic packet: pn_length out of [1, 4]")
    var first = 0x40
    if spin_bit:
        first |= 0x20
    if key_phase:
        first |= 0x04
    first |= (pn_length - 1) & 0x3
    var out = List[UInt8]()
    out.append(UInt8(first))
    for i in range(dcid.length()):
        out.append(dcid.bytes[i])
    return out^
