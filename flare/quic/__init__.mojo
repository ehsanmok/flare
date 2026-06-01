"""``flare.quic`` — sans-I/O QUIC v1 codec primitives (RFC 9000).

This package ships the *codec* layer of QUIC: pure byte-in /
byte-out parsers and emitters for the wire format. It contains
no socket I/O, no TLS handshake, no congestion controller, and
no reactor integration. Every public type's contract is "give me
bytes, get back a typed value (and optionally error context); give
me a typed value, get back bytes".

The codec layer is the load-bearing foundation that downstream
modules (the QUIC reactor + connection state machine, the TLS
handshake adapter, the congestion controllers) will build on top
of. Shipping the codec layer first lets us cross-validate against
reference implementations (aioquic, quiche) before committing to
a particular reactor / TLS / CC design.

Public re-exports:

- :class:`Varint` — variable-length integer codec (RFC 9000 §16).
- :func:`encode_varint`, :func:`decode_varint` — byte-level
  helpers around the ``Varint`` struct.
- :data:`VARINT_MAX` — largest representable varint value
  (``2 ** 62 - 1``).
"""

from .varint import (
    VARINT_MAX,
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)
from .packet import (
    QUIC_VERSION_1,
    QUIC_VERSION_NEGOTIATION,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_RETRY,
    MAX_CID_LENGTH,
    ConnectionId,
    LongHeader,
    InitialExtras,
    ShortHeader,
    encode_long_header,
    encode_short_header,
    parse_long_header,
    parse_initial_extras,
    parse_short_header,
)
from .frame import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    CryptoFrame,
    DataBlockedFrame,
    EcnCounts,
    Frame,
    FRAME_TYPE_ACK,
    FRAME_TYPE_ACK_ECN,
    FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_DATA_BLOCKED,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_MAX_STREAM_DATA,
    FRAME_TYPE_MAX_STREAMS_BIDI,
    FRAME_TYPE_MAX_STREAMS_UNI,
    FRAME_TYPE_NEW_CONNECTION_ID,
    FRAME_TYPE_NEW_TOKEN,
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PATH_CHALLENGE,
    FRAME_TYPE_PATH_RESPONSE,
    FRAME_TYPE_PING,
    FRAME_TYPE_RESET_STREAM,
    FRAME_TYPE_RETIRE_CONNECTION_ID,
    FRAME_TYPE_STOP_SENDING,
    FRAME_TYPE_STREAM_BASE,
    FRAME_TYPE_STREAM_DATA_BLOCKED,
    FRAME_TYPE_STREAMS_BLOCKED_BIDI,
    FRAME_TYPE_STREAMS_BLOCKED_UNI,
    HandshakeDoneFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    NewTokenFrame,
    ParsedFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ResetStreamFrame,
    RetireConnectionIdFrame,
    StopSendingFrame,
    StreamFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    encode_frame,
    parse_frame,
)
from .transport_params import (
    DEFAULT_ACK_DELAY_EXPONENT,
    DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
    DEFAULT_MAX_ACK_DELAY,
    DEFAULT_MAX_UDP_PAYLOAD_SIZE,
    TP_ID_ACK_DELAY_EXPONENT,
    TP_ID_ACTIVE_CONNECTION_ID_LIMIT,
    TP_ID_DISABLE_ACTIVE_MIGRATION,
    TP_ID_INITIAL_MAX_DATA,
    TP_ID_INITIAL_MAX_STREAMS_BIDI,
    TP_ID_INITIAL_MAX_STREAMS_UNI,
    TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
    TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
    TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
    TP_ID_INITIAL_SCID,
    TP_ID_MAX_ACK_DELAY,
    TP_ID_MAX_IDLE_TIMEOUT,
    TP_ID_MAX_UDP_PAYLOAD_SIZE,
    TP_ID_ORIGINAL_DCID,
    TP_ID_PREFERRED_ADDRESS,
    TP_ID_RETRY_SCID,
    TP_ID_STATELESS_RESET_TOKEN,
    TransportParameters,
    decode_transport_parameters,
    empty_transport_parameters,
    encode_transport_parameters,
)
