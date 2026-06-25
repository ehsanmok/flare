"""``flare.quic`` — sans-I/O QUIC v1 codec primitives (RFC 9000).

This package ships the *codec* layer of QUIC: pure byte-in /
byte-out parsers and emitters for the wire format, plus pure
state machines and congestion-controller helpers that operate
on owned value-typed state. It contains no socket I/O and no
TLS handshake. Every public type's contract is "give me bytes,
get back a typed value (and optionally error context); give me
a typed value, get back bytes".

The codec layer is the load-bearing foundation that downstream
modules (the QUIC reactor + datagram pump, the TLS handshake
adapter that drives the CRYPTO frames) will build on top of.
Shipping the codec layer first lets us cross-validate against
reference fixtures before committing to a particular reactor /
TLS design.

Public re-exports:

- :mod:`.varint` — variable-length integer codec
  (RFC 9000 §16): :class:`Varint`, :func:`encode_varint`,
  :func:`decode_varint`, :func:`varint_encoded_length`,
  :data:`VARINT_MAX`.
- :mod:`.packet` — long / short header codec
  (RFC 9000 §17): :class:`ConnectionId`, :class:`LongHeader`,
  :class:`ShortHeader`, :class:`InitialExtras`, the
  ``PACKET_TYPE_*`` constants, and their byte-level helpers.
- :mod:`.frame` — all 22 RFC 9000 §19 transport frames as typed
  payload structs plus :trait:`FrameHandler` +
  :func:`parse_frame_into[H]` for zero-carrier dispatch, and
  per-type ``encode_*`` writers that append to a caller-owned
  ``mut out: List[UInt8]``.
- :mod:`.transport_params` — RFC 9000 §18 transport-parameter
  codec: :class:`TransportParameters`,
  :func:`encode_transport_parameters`,
  :func:`decode_transport_parameters`, and the ``TP_ID_*``
  constants for every parameter the codec carries.
- :mod:`.state` — RFC 9000 §3 / §13 sans-I/O connection +
  stream state machines: :class:`Connection`, :class:`Stream`,
  :func:`handle_frame_buf`, :func:`mark_handshake_complete`,
  :func:`is_idle_timeout_expired`, :func:`connection_close`,
  the per-typed-payload ``apply_*`` helpers, and the
  ``CONN_STATE_*`` / ``STREAM_STATE_*`` constants.
- :mod:`.crypto` — sans-I/O QUIC v1 crypto math
  (RFC 9001 §5 + RFC 5869 + RFC 8446 §7.1): HKDF-Extract,
  HKDF-Expand, HKDF-Expand-Label, RFC 9001 §5.2 initial-
  secret derivation, plus the :trait:`QuicCrypto` AEAD
  trait surface that the QUIC server reactor binds against.
  The OpenSSL AEAD backend lands in a focused follow-up
  commit; this module exposes :class:`StubQuicCrypto` as a
  typed sentinel so the reactor wiring tests can pin the
  trait boundary today.
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
    FrameHandler,
    HandshakeDoneFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    NewTokenFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ResetStreamFrame,
    RetireConnectionIdFrame,
    StopSendingFrame,
    StreamFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    encode_ack,
    encode_connection_close,
    encode_crypto,
    encode_data_blocked,
    encode_handshake_done,
    encode_max_data,
    encode_max_stream_data,
    encode_max_streams,
    encode_new_connection_id,
    encode_new_token,
    encode_padding,
    encode_path_challenge,
    encode_path_response,
    encode_ping,
    encode_reset_stream,
    encode_retire_connection_id,
    encode_stop_sending,
    encode_stream,
    encode_stream_data_blocked,
    encode_streams_blocked,
    parse_frame_into,
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
from .crypto import (
    InitialSecrets,
    OpenSslQuicCrypto,
    PacketKeys,
    QUIC_V1_INITIAL_SALT,
    QuicAead,
    QuicCrypto,
    SHA256_OUTPUT_BYTES,
    StubQuicCrypto,
    aead_key_length,
    derive_initial_secrets,
    derive_packet_keys,
    hkdf_expand,
    hkdf_expand_label,
    hkdf_expand_label_empty_context,
    hkdf_extract,
)
from .protection import (
    UnprotectedPacket,
    decode_packet_number,
    protect_initial_packet,
    unprotect_initial_packet,
)
from .timers import (
    DecodedTimerToken,
    TIMER_KIND_ACK_DELAY,
    TIMER_KIND_IDLE,
    TIMER_KIND_PTO,
    decode_timer_token,
    encode_timer_token,
    timer_kind_name,
)
from .client import QuicClientConnection
from .server import (
    ConnectionIdTable,
    QuicConnection,
    QuicListener,
    QuicServerConfig,
    cid_to_hex,
)
from .state import (
    CONN_STATE_CLOSED,
    CONN_STATE_CLOSING,
    CONN_STATE_DRAINING,
    CONN_STATE_ESTABLISHED,
    CONN_STATE_HANDSHAKE,
    Connection,
    ConnectionEvents,
    STREAM_STATE_CLOSED,
    STREAM_STATE_HALF_CLOSED_LOCAL,
    STREAM_STATE_HALF_CLOSED_REMOTE,
    STREAM_STATE_IDLE,
    STREAM_STATE_OPEN,
    STREAM_STATE_RESET_RECVD,
    STREAM_STATE_RESET_SENT,
    Stream,
    apply_ack,
    apply_connection_close,
    apply_handshake_done,
    apply_max_data,
    apply_max_stream_data,
    apply_new_connection_id,
    apply_path_challenge,
    apply_path_response,
    apply_reset_stream,
    apply_retire_connection_id,
    apply_stop_sending,
    expand_ack_ranges,
    apply_stream,
    connection_close,
    empty_events,
    handle_frame_buf,
    is_idle_timeout_expired,
    mark_handshake_complete,
    new_connection,
    new_stream,
)
