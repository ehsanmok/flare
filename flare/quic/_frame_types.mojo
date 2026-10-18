"""QUIC frame type codepoints and frame payload structs (RFC 9000 §19).

Re-exported by :mod:`flare.quic.frame`.
"""

from std.collections import List


# ── Frame type constants (RFC 9000 §19 master table) ──────────────────────────


comptime FRAME_TYPE_PADDING: Int = 0x00
comptime FRAME_TYPE_PING: Int = 0x01
comptime FRAME_TYPE_ACK: Int = 0x02
comptime FRAME_TYPE_ACK_ECN: Int = 0x03
comptime FRAME_TYPE_RESET_STREAM: Int = 0x04
comptime FRAME_TYPE_STOP_SENDING: Int = 0x05
comptime FRAME_TYPE_CRYPTO: Int = 0x06
comptime FRAME_TYPE_NEW_TOKEN: Int = 0x07
# STREAM frame range (§19.8): 0x08..0x0f, low 3 bits encode
# OFF (0x04), LEN (0x02), FIN (0x01).
comptime FRAME_TYPE_STREAM_BASE: Int = 0x08
comptime FRAME_TYPE_STREAM_MAX: Int = 0x0F
comptime STREAM_OFF_BIT: Int = 0x04
comptime STREAM_LEN_BIT: Int = 0x02
comptime STREAM_FIN_BIT: Int = 0x01
comptime FRAME_TYPE_MAX_DATA: Int = 0x10
comptime FRAME_TYPE_MAX_STREAM_DATA: Int = 0x11
comptime FRAME_TYPE_MAX_STREAMS_BIDI: Int = 0x12
comptime FRAME_TYPE_MAX_STREAMS_UNI: Int = 0x13
comptime FRAME_TYPE_DATA_BLOCKED: Int = 0x14
comptime FRAME_TYPE_STREAM_DATA_BLOCKED: Int = 0x15
comptime FRAME_TYPE_STREAMS_BLOCKED_BIDI: Int = 0x16
comptime FRAME_TYPE_STREAMS_BLOCKED_UNI: Int = 0x17
comptime FRAME_TYPE_NEW_CONNECTION_ID: Int = 0x18
comptime FRAME_TYPE_RETIRE_CONNECTION_ID: Int = 0x19
comptime FRAME_TYPE_PATH_CHALLENGE: Int = 0x1A
comptime FRAME_TYPE_PATH_RESPONSE: Int = 0x1B
comptime FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT: Int = 0x1C
comptime FRAME_TYPE_CONNECTION_CLOSE_APPLICATION: Int = 0x1D
comptime FRAME_TYPE_HANDSHAKE_DONE: Int = 0x1E

# RFC 9221 unreliable DATAGRAM frames. The low bit is the LEN flag:
# 0x30 carries the payload to the end of the QUIC packet, 0x31 prefixes
# the payload with an explicit length varint so it can be followed by
# more frames in the same packet.
comptime FRAME_TYPE_DATAGRAM_NOLEN: Int = 0x30
comptime FRAME_TYPE_DATAGRAM_LEN: Int = 0x31

# draft-ietf-quic-ack-frequency: how often the peer acknowledges.
comptime FRAME_TYPE_ACK_FREQUENCY: Int = 0xAF
comptime FRAME_TYPE_IMMEDIATE_ACK: Int = 0x1F


# ── Typed frame payload structs ──────────────────────────────────────────────


@fieldwise_init
struct AckFrequencyFrame(Copyable):
    """ACK_FREQUENCY (draft-ietf-quic-ack-frequency sec 4): acknowledge
    after more than ``ack_eliciting_threshold`` ack-eliciting packets or
    ``request_max_ack_delay`` microseconds, whichever comes first."""

    var sequence_number: UInt64
    var ack_eliciting_threshold: UInt64
    var request_max_ack_delay: UInt64
    var reordering_threshold: UInt64


@fieldwise_init
struct DatagramFrame(Copyable):
    """DATAGRAM (RFC 9221 §4) -- unreliable application datagram.

    ``has_length`` carries the wire-type distinction: ``True`` for type
    0x31 (an explicit length varint precedes the payload, so the frame
    may be followed by more frames), ``False`` for type 0x30 (the
    payload runs to the end of the QUIC packet -- it must be the last
    frame). The encoder picks the type from this flag.
    """

    var data: List[UInt8]
    var has_length: Bool


@fieldwise_init
struct AckRange(Copyable, ImplicitlyCopyable):
    """One ACK range (RFC 9000 §19.3.1): ``gap`` + ``length``.

    The first range in an ACK frame is implicit and uses
    ``first_ack_range``; subsequent ranges carry an explicit
    ``gap`` (number of unacked packets between the previous range
    and this one, minus one) and ``length`` (count of acked
    packets in this range, minus one).
    """

    var gap: UInt64
    var length: UInt64


@fieldwise_init
struct EcnCounts(Copyable, ImplicitlyCopyable):
    """ECN counts (§19.3.2): per-codepoint cumulative counts. Only
    present in ACK_ECN frames (type 0x03)."""

    var ect0: UInt64
    var ect1: UInt64
    var ce: UInt64


@fieldwise_init
struct AckFrame(Copyable):
    """ACK / ACK-ECN frame payload (§19.3).

    ``ecn`` is populated only when the wire type is ``0x03``
    (ACK_ECN). The largest acknowledged packet number is the
    explicit field; the implicit first range covers
    ``[largest - first_ack_range, largest]``.
    """

    var largest_acknowledged: UInt64
    var ack_delay: UInt64
    var first_ack_range: UInt64
    var ranges: List[AckRange]
    var ecn: List[EcnCounts]


@fieldwise_init
struct ResetStreamFrame(Copyable, ImplicitlyCopyable):
    """RESET_STREAM (§19.4)."""

    var stream_id: UInt64
    var application_error_code: UInt64
    var final_size: UInt64


@fieldwise_init
struct StopSendingFrame(Copyable, ImplicitlyCopyable):
    """STOP_SENDING (§19.5)."""

    var stream_id: UInt64
    var application_error_code: UInt64


@fieldwise_init
struct CryptoFrame(Copyable):
    """CRYPTO (§19.6) -- TLS handshake bytes carried in-band on the
    Initial / Handshake / 1-RTT crypto streams."""

    var offset: UInt64
    var data: List[UInt8]


@fieldwise_init
struct NewTokenFrame(Copyable):
    """NEW_TOKEN (§19.7) -- server-issued address-validation token
    delivered to the client for use on a future 0-RTT handshake."""

    var token: List[UInt8]


@fieldwise_init
struct StreamFrame(Copyable):
    """STREAM (§19.8) -- payload bytes carried on a logical stream.

    The wire type (0x08..0x0f) encodes three flag bits:
    OFF (0x04) presence of the offset field, LEN (0x02) presence
    of the length field, FIN (0x01) end-of-stream marker. The
    parser populates ``offset`` (defaulting to 0 when OFF is
    unset) and reads the trailing data based on LEN -- absent LEN,
    the frame extends to the end of the packet payload.
    """

    var stream_id: UInt64
    var offset: UInt64
    var data: List[UInt8]
    var fin: Bool


@fieldwise_init
struct MaxDataFrame(Copyable, ImplicitlyCopyable):
    """MAX_DATA (§19.9)."""

    var maximum_data: UInt64


@fieldwise_init
struct MaxStreamDataFrame(Copyable, ImplicitlyCopyable):
    """MAX_STREAM_DATA (§19.10)."""

    var stream_id: UInt64
    var maximum_stream_data: UInt64


@fieldwise_init
struct MaxStreamsFrame(Copyable, ImplicitlyCopyable):
    """MAX_STREAMS (§19.11). ``unidirectional`` carries the wire-type
    distinction (0x12 = bidi, 0x13 = uni)."""

    var unidirectional: Bool
    var maximum_streams: UInt64


@fieldwise_init
struct DataBlockedFrame(Copyable, ImplicitlyCopyable):
    """DATA_BLOCKED (§19.12)."""

    var maximum_data: UInt64


@fieldwise_init
struct StreamDataBlockedFrame(Copyable, ImplicitlyCopyable):
    """STREAM_DATA_BLOCKED (§19.13)."""

    var stream_id: UInt64
    var maximum_stream_data: UInt64


@fieldwise_init
struct StreamsBlockedFrame(Copyable, ImplicitlyCopyable):
    """STREAMS_BLOCKED (§19.14). ``unidirectional`` carries the wire
    distinction (0x16 = bidi, 0x17 = uni)."""

    var unidirectional: Bool
    var maximum_streams: UInt64


@fieldwise_init
struct NewConnectionIdFrame(Copyable):
    """NEW_CONNECTION_ID (§19.15)."""

    var sequence_number: UInt64
    var retire_prior_to: UInt64
    var connection_id: List[UInt8]
    var stateless_reset_token: List[UInt8]


@fieldwise_init
struct RetireConnectionIdFrame(Copyable, ImplicitlyCopyable):
    """RETIRE_CONNECTION_ID (§19.16)."""

    var sequence_number: UInt64


@fieldwise_init
struct PathChallengeFrame(Copyable):
    """PATH_CHALLENGE (§19.17) -- 8 bytes of unpredictable data."""

    var data: List[UInt8]


@fieldwise_init
struct PathResponseFrame(Copyable):
    """PATH_RESPONSE (§19.18) -- echoes a prior PATH_CHALLENGE
    payload to confirm reachability on the new path."""

    var data: List[UInt8]


@fieldwise_init
struct ConnectionCloseFrame(Copyable):
    """CONNECTION_CLOSE (§19.19).

    ``application`` distinguishes the wire type: ``False`` is the
    transport-level 0x1c (carries ``frame_type`` of the offending
    frame); ``True`` is the application-level 0x1d (no
    ``frame_type`` field).
    """

    var application: Bool
    var error_code: UInt64
    var frame_type: UInt64
    var reason_phrase: List[UInt8]


@fieldwise_init
struct HandshakeDoneFrame(Copyable, ImplicitlyCopyable):
    """HANDSHAKE_DONE (§19.20) -- one-byte type with no payload."""

    pass
