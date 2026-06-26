"""QUIC transport-parameter codec (RFC 9000 §18 + §19.1.1).

QUIC peers exchange transport parameters during the TLS handshake
(carried in the TLS extension ``quic_transport_parameters``,
codepoint 0x39). Each parameter is encoded as
``varint(id) || varint(length) || bytes[length]``; the codec is
fully self-describing so unknown parameters are silently ignored
(RFC 9000 §7.4.2 -- forward compatibility).

Public surface:

* :class:`TransportParameters` -- typed carrier for the v1
  parameter set with sensible defaults from §18.2.
* :func:`encode_transport_parameters` -- serialise a populated
  :class:`TransportParameters` into a byte list. Unset parameters
  whose default is the wire absence are not emitted; explicitly
  set parameters always are.
* :func:`decode_transport_parameters` -- parse a byte buffer into
  a :class:`TransportParameters`; unknown ids are dropped on the
  floor per RFC.

Parameter ids covered (RFC 9000 §18.2 + RFC 9221 §3 for datagram):

  - 0x00 original_destination_connection_id (server only)
  - 0x01 max_idle_timeout (ms; 0 means no timeout)
  - 0x02 stateless_reset_token (server only; 16 bytes)
  - 0x03 max_udp_payload_size (default 65527)
  - 0x04 initial_max_data
  - 0x05 initial_max_stream_data_bidi_local
  - 0x06 initial_max_stream_data_bidi_remote
  - 0x07 initial_max_stream_data_uni
  - 0x08 initial_max_streams_bidi
  - 0x09 initial_max_streams_uni
  - 0x0a ack_delay_exponent (default 3)
  - 0x0b max_ack_delay (default 25 ms)
  - 0x0c disable_active_migration (flag, zero-length value)
  - 0x0e active_connection_id_limit (default 2; minimum 2)
  - 0x0f initial_source_connection_id
  - 0x10 retry_source_connection_id (server only)
  - 0x20 max_datagram_frame_size (RFC 9221 §3; enables DATAGRAM)

The 0x0d preferred_address parameter is structurally more
complex (carries a peer's preferred IP/port for migration); it is
not currently handled and is skipped on decode like any other
unknown id. Adding it is a strict superset change.

Sans-I/O contract: zero I/O imports; registered in
``tools/check_sans_io.sh`` so the contract is lint-enforced.

References:
- RFC 9000 §18 "Transport Parameter Encoding".
- RFC 9000 §7.4.2 "New Transport Parameters" (forward-compat).
- aioquic ``packet.PullQuicTransportParameters`` (Python ref).
"""

from std.collections import List, Optional
from std.memory import Span

from .varint import (
    Varint,
    decode_varint,
    encode_varint,
    varint_encoded_length,
)


# ── Parameter id constants (RFC 9000 §18.2 master table) ──────────────────


comptime TP_ID_ORIGINAL_DCID: Int = 0x00
comptime TP_ID_MAX_IDLE_TIMEOUT: Int = 0x01
comptime TP_ID_STATELESS_RESET_TOKEN: Int = 0x02
comptime TP_ID_MAX_UDP_PAYLOAD_SIZE: Int = 0x03
comptime TP_ID_INITIAL_MAX_DATA: Int = 0x04
comptime TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: Int = 0x05
comptime TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: Int = 0x06
comptime TP_ID_INITIAL_MAX_STREAM_DATA_UNI: Int = 0x07
comptime TP_ID_INITIAL_MAX_STREAMS_BIDI: Int = 0x08
comptime TP_ID_INITIAL_MAX_STREAMS_UNI: Int = 0x09
comptime TP_ID_ACK_DELAY_EXPONENT: Int = 0x0A
comptime TP_ID_MAX_ACK_DELAY: Int = 0x0B
comptime TP_ID_DISABLE_ACTIVE_MIGRATION: Int = 0x0C
comptime TP_ID_PREFERRED_ADDRESS: Int = 0x0D
comptime TP_ID_ACTIVE_CONNECTION_ID_LIMIT: Int = 0x0E
comptime TP_ID_INITIAL_SCID: Int = 0x0F
comptime TP_ID_RETRY_SCID: Int = 0x10
comptime TP_ID_MAX_DATAGRAM_FRAME_SIZE: Int = 0x20
"""RFC 9221 §3: max DATAGRAM frame size the endpoint will accept.
Absent or 0 means the peer MUST NOT send DATAGRAM frames."""

# Default values from RFC 9000 §18.2 (used when a parameter is
# absent on the wire). Encoders should NOT emit a parameter whose
# value equals the default; the receiver assumes the default for
# any absent id.
comptime DEFAULT_MAX_UDP_PAYLOAD_SIZE: UInt64 = UInt64(65527)
comptime DEFAULT_ACK_DELAY_EXPONENT: UInt64 = UInt64(3)
comptime DEFAULT_MAX_ACK_DELAY: UInt64 = UInt64(25)
comptime DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: UInt64 = UInt64(2)


# ── Typed parameter carrier ────────────────────────────────────────────────


@fieldwise_init
struct TransportParameters(Copyable, Movable):
    """Decoded QUIC transport parameters (RFC 9000 §18).

    Optional fields default to ``None`` to distinguish "absent on
    the wire" from "explicit zero". The caller treats ``None`` as
    the RFC default per parameter (encoded inline above each
    field's docstring); the codec only emits a parameter when its
    Optional is populated.

    Connection-id fields and the stateless reset token are stored
    as ``List[UInt8]`` so the caller can move them out into the
    connection-state-machine layer without a copy.
    """

    var original_destination_connection_id: List[UInt8]
    var max_idle_timeout: Optional[UInt64]
    var stateless_reset_token: List[UInt8]
    var max_udp_payload_size: Optional[UInt64]
    var initial_max_data: Optional[UInt64]
    var initial_max_stream_data_bidi_local: Optional[UInt64]
    var initial_max_stream_data_bidi_remote: Optional[UInt64]
    var initial_max_stream_data_uni: Optional[UInt64]
    var initial_max_streams_bidi: Optional[UInt64]
    var initial_max_streams_uni: Optional[UInt64]
    var ack_delay_exponent: Optional[UInt64]
    var max_ack_delay: Optional[UInt64]
    var disable_active_migration: Bool
    var active_connection_id_limit: Optional[UInt64]
    var initial_source_connection_id: List[UInt8]
    var retry_source_connection_id: List[UInt8]
    var max_datagram_frame_size: Optional[UInt64]
    """RFC 9221 §3 max_datagram_frame_size (id 0x20). When populated
    and non-zero, the peer may send DATAGRAM frames up to this size;
    absent / 0 disables datagrams for this connection."""


def empty_transport_parameters() -> TransportParameters:
    """Return a :class:`TransportParameters` with every field
    cleared (every Optional is ``None`` and every byte buffer is
    empty). Build up the carrier by populating the fields the
    caller wants on the wire, then pass to
    :func:`encode_transport_parameters`."""
    return TransportParameters(
        original_destination_connection_id=List[UInt8](),
        max_idle_timeout=None,
        stateless_reset_token=List[UInt8](),
        max_udp_payload_size=None,
        initial_max_data=None,
        initial_max_stream_data_bidi_local=None,
        initial_max_stream_data_bidi_remote=None,
        initial_max_stream_data_uni=None,
        initial_max_streams_bidi=None,
        initial_max_streams_uni=None,
        ack_delay_exponent=None,
        max_ack_delay=None,
        disable_active_migration=False,
        active_connection_id_limit=None,
        initial_source_connection_id=List[UInt8](),
        retry_source_connection_id=List[UInt8](),
        max_datagram_frame_size=None,
    )


# ── Encoder helpers ────────────────────────────────────────────────────────


def _emit_varint_param(mut out: List[UInt8], id: Int, value: UInt64) raises:
    """Emit one varint-valued parameter
    (``varint(id) || varint(len) || varint(value)``)."""
    var value_bytes = encode_varint(value)
    var id_bytes = encode_varint(UInt64(id))
    var len_bytes = encode_varint(UInt64(len(value_bytes)))
    for i in range(len(id_bytes)):
        out.append(id_bytes[i])
    for i in range(len(len_bytes)):
        out.append(len_bytes[i])
    for i in range(len(value_bytes)):
        out.append(value_bytes[i])


def _emit_bytes_param(mut out: List[UInt8], id: Int, value: List[UInt8]) raises:
    """Emit one byte-string parameter
    (``varint(id) || varint(len) || bytes``)."""
    var id_bytes = encode_varint(UInt64(id))
    var len_bytes = encode_varint(UInt64(len(value)))
    for i in range(len(id_bytes)):
        out.append(id_bytes[i])
    for i in range(len(len_bytes)):
        out.append(len_bytes[i])
    for i in range(len(value)):
        out.append(value[i])


def _emit_flag_param(mut out: List[UInt8], id: Int) raises:
    """Emit one zero-length flag parameter
    (``varint(id) || varint(0)``)."""
    var id_bytes = encode_varint(UInt64(id))
    for i in range(len(id_bytes)):
        out.append(id_bytes[i])
    out.append(UInt8(0x00))


# ── Top-level encoder ──────────────────────────────────────────────────────


def encode_transport_parameters(
    params: TransportParameters,
) raises -> List[UInt8]:
    """Serialise ``params`` to bytes.

    Only fields that have been populated (Optional is ``Some`` or
    a byte list is non-empty) are emitted; absent parameters are
    silently dropped so the receiver picks up the RFC default. The
    one exception is :data:`disable_active_migration`, which is
    emitted as a zero-length parameter whenever ``params.disable_
    active_migration`` is ``True``.
    """
    var out = List[UInt8]()
    if len(params.original_destination_connection_id) > 0:
        _emit_bytes_param(
            out,
            TP_ID_ORIGINAL_DCID,
            params.original_destination_connection_id,
        )
    if Bool(params.max_idle_timeout):
        _emit_varint_param(
            out, TP_ID_MAX_IDLE_TIMEOUT, params.max_idle_timeout.value()
        )
    if len(params.stateless_reset_token) > 0:
        if len(params.stateless_reset_token) != 16:
            raise Error(
                "quic transport_params: stateless_reset_token must be 16 bytes"
            )
        _emit_bytes_param(
            out,
            TP_ID_STATELESS_RESET_TOKEN,
            params.stateless_reset_token,
        )
    if Bool(params.max_udp_payload_size):
        _emit_varint_param(
            out,
            TP_ID_MAX_UDP_PAYLOAD_SIZE,
            params.max_udp_payload_size.value(),
        )
    if Bool(params.initial_max_data):
        _emit_varint_param(
            out, TP_ID_INITIAL_MAX_DATA, params.initial_max_data.value()
        )
    if Bool(params.initial_max_stream_data_bidi_local):
        _emit_varint_param(
            out,
            TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            params.initial_max_stream_data_bidi_local.value(),
        )
    if Bool(params.initial_max_stream_data_bidi_remote):
        _emit_varint_param(
            out,
            TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            params.initial_max_stream_data_bidi_remote.value(),
        )
    if Bool(params.initial_max_stream_data_uni):
        _emit_varint_param(
            out,
            TP_ID_INITIAL_MAX_STREAM_DATA_UNI,
            params.initial_max_stream_data_uni.value(),
        )
    if Bool(params.initial_max_streams_bidi):
        _emit_varint_param(
            out,
            TP_ID_INITIAL_MAX_STREAMS_BIDI,
            params.initial_max_streams_bidi.value(),
        )
    if Bool(params.initial_max_streams_uni):
        _emit_varint_param(
            out,
            TP_ID_INITIAL_MAX_STREAMS_UNI,
            params.initial_max_streams_uni.value(),
        )
    if Bool(params.ack_delay_exponent):
        var v = params.ack_delay_exponent.value()
        if v > UInt64(20):
            raise Error(
                "quic transport_params: ack_delay_exponent > 20"
                " (RFC 9000 §18.2)"
            )
        _emit_varint_param(out, TP_ID_ACK_DELAY_EXPONENT, v)
    if Bool(params.max_ack_delay):
        var v = params.max_ack_delay.value()
        if v >= UInt64(1 << 14):
            raise Error(
                "quic transport_params: max_ack_delay >= 2^14 ms"
                " (RFC 9000 §18.2)"
            )
        _emit_varint_param(out, TP_ID_MAX_ACK_DELAY, v)
    if params.disable_active_migration:
        _emit_flag_param(out, TP_ID_DISABLE_ACTIVE_MIGRATION)
    if Bool(params.active_connection_id_limit):
        var v = params.active_connection_id_limit.value()
        if v < UInt64(2):
            raise Error(
                "quic transport_params: active_connection_id_limit < 2"
                " (RFC 9000 §18.2)"
            )
        _emit_varint_param(out, TP_ID_ACTIVE_CONNECTION_ID_LIMIT, v)
    if len(params.initial_source_connection_id) > 0:
        _emit_bytes_param(
            out,
            TP_ID_INITIAL_SCID,
            params.initial_source_connection_id,
        )
    if len(params.retry_source_connection_id) > 0:
        _emit_bytes_param(
            out,
            TP_ID_RETRY_SCID,
            params.retry_source_connection_id,
        )
    if Bool(params.max_datagram_frame_size):
        _emit_varint_param(
            out,
            TP_ID_MAX_DATAGRAM_FRAME_SIZE,
            params.max_datagram_frame_size.value(),
        )
    return out^


# ── Decoder ────────────────────────────────────────────────────────────────


def _read_param_varint(data: Span[UInt8, _]) raises -> UInt64:
    """Decode a varint-shaped parameter value; rejects trailing
    bytes inside the parameter slice."""
    var v = decode_varint(data)
    if v.consumed != len(data):
        raise Error("quic transport_params: varint param has trailing bytes")
    return v.value


def decode_transport_parameters(
    buf: Span[UInt8, _]
) raises -> TransportParameters:
    """Parse a transport-parameters extension payload.

    Loops ``varint(id) || varint(length) || bytes[length]`` until
    the buffer is drained. Unknown ids are silently dropped per
    RFC 9000 §7.4.2. Duplicate parameter ids are rejected (the RFC
    requires each parameter to appear at most once).
    """
    var out = empty_transport_parameters()
    var seen = List[Int]()
    var pos = 0
    var n = len(buf)
    while pos < n:
        var id_var = decode_varint(buf[pos:])
        pos += id_var.consumed
        if pos >= n:
            raise Error(
                "quic transport_params: truncated; missing length varint"
            )
        var len_var = decode_varint(buf[pos:])
        pos += len_var.consumed
        var value_len = Int(len_var.value)
        if pos + value_len > n:
            raise Error("quic transport_params: value truncated")
        var id = Int(id_var.value)
        # Reject duplicates (§18 -- "If an endpoint receives
        # transport parameters from its peer that contain
        # duplicates ... it MUST treat receipt as a connection
        # error of type TRANSPORT_PARAMETER_ERROR").
        for i in range(len(seen)):
            if seen[i] == id:
                raise Error("quic transport_params: duplicate id " + String(id))
        seen.append(id)
        var value = buf[pos : pos + value_len]
        pos += value_len
        if id == TP_ID_ORIGINAL_DCID:
            for i in range(value_len):
                out.original_destination_connection_id.append(value[i])
        elif id == TP_ID_MAX_IDLE_TIMEOUT:
            out.max_idle_timeout = Optional[UInt64](_read_param_varint(value))
        elif id == TP_ID_STATELESS_RESET_TOKEN:
            if value_len != 16:
                raise Error(
                    "quic transport_params: stateless_reset_token must"
                    " be 16 bytes"
                )
            for i in range(value_len):
                out.stateless_reset_token.append(value[i])
        elif id == TP_ID_MAX_UDP_PAYLOAD_SIZE:
            var v = _read_param_varint(value)
            if v < UInt64(1200):
                raise Error(
                    "quic transport_params: max_udp_payload_size < 1200"
                    " (RFC 9000 §18.2)"
                )
            out.max_udp_payload_size = Optional[UInt64](v)
        elif id == TP_ID_INITIAL_MAX_DATA:
            out.initial_max_data = Optional[UInt64](_read_param_varint(value))
        elif id == TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
            out.initial_max_stream_data_bidi_local = Optional[UInt64](
                _read_param_varint(value)
            )
        elif id == TP_ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
            out.initial_max_stream_data_bidi_remote = Optional[UInt64](
                _read_param_varint(value)
            )
        elif id == TP_ID_INITIAL_MAX_STREAM_DATA_UNI:
            out.initial_max_stream_data_uni = Optional[UInt64](
                _read_param_varint(value)
            )
        elif id == TP_ID_INITIAL_MAX_STREAMS_BIDI:
            out.initial_max_streams_bidi = Optional[UInt64](
                _read_param_varint(value)
            )
        elif id == TP_ID_INITIAL_MAX_STREAMS_UNI:
            out.initial_max_streams_uni = Optional[UInt64](
                _read_param_varint(value)
            )
        elif id == TP_ID_ACK_DELAY_EXPONENT:
            var v = _read_param_varint(value)
            if v > UInt64(20):
                raise Error("quic transport_params: ack_delay_exponent > 20")
            out.ack_delay_exponent = Optional[UInt64](v)
        elif id == TP_ID_MAX_ACK_DELAY:
            var v = _read_param_varint(value)
            if v >= UInt64(1 << 14):
                raise Error("quic transport_params: max_ack_delay >= 2^14 ms")
            out.max_ack_delay = Optional[UInt64](v)
        elif id == TP_ID_DISABLE_ACTIVE_MIGRATION:
            if value_len != 0:
                raise Error(
                    "quic transport_params: disable_active_migration"
                    " must be zero-length"
                )
            out.disable_active_migration = True
        elif id == TP_ID_ACTIVE_CONNECTION_ID_LIMIT:
            var v = _read_param_varint(value)
            if v < UInt64(2):
                raise Error(
                    "quic transport_params: active_connection_id_limit < 2"
                )
            out.active_connection_id_limit = Optional[UInt64](v)
        elif id == TP_ID_INITIAL_SCID:
            for i in range(value_len):
                out.initial_source_connection_id.append(value[i])
        elif id == TP_ID_RETRY_SCID:
            for i in range(value_len):
                out.retry_source_connection_id.append(value[i])
        elif id == TP_ID_MAX_DATAGRAM_FRAME_SIZE:
            out.max_datagram_frame_size = Optional[UInt64](
                _read_param_varint(value)
            )
        # Any other id is silently dropped (RFC 9000 §7.4.2).
    return out^
