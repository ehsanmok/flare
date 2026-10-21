"""QUIC v1 transport-frame codec (RFC 9000 §19).

This module is the canonical sans-I/O codec for the 22 transport
frame types QUIC v1 carries inside (deprotected) packet payloads.
The parser walks one frame at a time and dispatches each decoded
payload through a typed callback on a caller-supplied
:trait:`FrameHandler`; the QUIC connection state machine implements
the handler and advances per-frame state without ever materialising
an intermediate carrier value.

Frame types covered (RFC 9000 §19, all 22):

* §19.1 PADDING (0x00)
* §19.2 PING (0x01)
* §19.3 ACK (0x02), ACK with ECN (0x03)
* §19.4 RESET_STREAM (0x04)
* §19.5 STOP_SENDING (0x05)
* §19.6 CRYPTO (0x06)
* §19.7 NEW_TOKEN (0x07)
* §19.8 STREAM (0x08..0x0f -- 8 sub-shapes via OFF/LEN/FIN bits)
* §19.9 MAX_DATA (0x10)
* §19.10 MAX_STREAM_DATA (0x11)
* §19.11 MAX_STREAMS (bidirectional 0x12, unidirectional 0x13)
* §19.12 DATA_BLOCKED (0x14)
* §19.13 STREAM_DATA_BLOCKED (0x15)
* §19.14 STREAMS_BLOCKED (bidirectional 0x16, unidirectional 0x17)
* §19.15 NEW_CONNECTION_ID (0x18)
* §19.16 RETIRE_CONNECTION_ID (0x19)
* §19.17 PATH_CHALLENGE (0x1a)
* §19.18 PATH_RESPONSE (0x1b)
* §19.19 CONNECTION_CLOSE (transport 0x1c, application 0x1d)
* §19.20 HANDSHAKE_DONE (0x1e)

Dispatch contract
-----------------

:func:`parse_frame_into` reads exactly one frame at the start of
the supplied :class:`Span[UInt8, _]`, fires the matching typed
callback on the caller's handler, and returns the number of wire
bytes consumed. The caller advances its cursor and re-invokes the
dispatcher on the remainder until the buffer drains or a parse
error fires.

Every typed payload struct is ``Copyable`` (which implies ``Movable``)
so the handler can stash the dispatched value (or move it into a
queue) without lifetime gymnastics.

Sans-I/O contract
-----------------

This file holds zero I/O imports. It is registered in
``tests/tools/check_sans_io.sh`` so the contract is lint-enforced.

References
----------

* RFC 9000 §19 "Frame Types and Formats".
* RFC 9000 §16 "Variable-Length Integer Encoding" (varint).
"""

from std.collections import List
from std.collections.span import Span

from .varint import (
    Varint,
    VARINT_MAX,
    decode_varint,
    encode_varint_into,
    varint_encoded_length,
)


comptime _MAX_STREAM_COUNT: UInt64 = UInt64(1) << 60
"""RFC 9000 sec 4.6: the largest valid MAX_STREAMS / STREAMS_BLOCKED value."""


from ._frame_types import (
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PING,
    FRAME_TYPE_ACK,
    FRAME_TYPE_ACK_ECN,
    FRAME_TYPE_RESET_STREAM,
    FRAME_TYPE_STOP_SENDING,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_NEW_TOKEN,
    FRAME_TYPE_STREAM_BASE,
    FRAME_TYPE_STREAM_MAX,
    STREAM_OFF_BIT,
    STREAM_LEN_BIT,
    STREAM_FIN_BIT,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_MAX_STREAM_DATA,
    FRAME_TYPE_MAX_STREAMS_BIDI,
    FRAME_TYPE_MAX_STREAMS_UNI,
    FRAME_TYPE_DATA_BLOCKED,
    FRAME_TYPE_STREAM_DATA_BLOCKED,
    FRAME_TYPE_STREAMS_BLOCKED_BIDI,
    FRAME_TYPE_STREAMS_BLOCKED_UNI,
    FRAME_TYPE_NEW_CONNECTION_ID,
    FRAME_TYPE_RETIRE_CONNECTION_ID,
    FRAME_TYPE_PATH_CHALLENGE,
    FRAME_TYPE_PATH_RESPONSE,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_DATAGRAM_NOLEN,
    FRAME_TYPE_DATAGRAM_LEN,
    FRAME_TYPE_ACK_FREQUENCY,
    FRAME_TYPE_IMMEDIATE_ACK,
    AckFrequencyFrame,
    DatagramFrame,
    AckRange,
    EcnCounts,
    AckFrame,
    ResetStreamFrame,
    StopSendingFrame,
    CryptoFrame,
    NewTokenFrame,
    StreamFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    DataBlockedFrame,
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
    NewConnectionIdFrame,
    RetireConnectionIdFrame,
    PathChallengeFrame,
    PathResponseFrame,
    ConnectionCloseFrame,
    HandshakeDoneFrame,
)


# ── Frame dispatch trait ─────────────────────────────────────────────────────


trait FrameHandler(Deinitable, Movable):
    """Per-type callback contract :func:`parse_frame_into` fires.

    The dispatcher reads one wire frame at the start of the input
    buffer and invokes the matching callback. Implementors carry
    out the per-frame state-machine work (or stash the dispatched
    payload for later use) without an intermediate carrier
    allocation: each callback receives the already-typed payload
    by value.

    The 20 callbacks below cover every RFC 9000 §19 frame type.
    The ACK / ACK-ECN split is collapsed into :meth:`on_ack` (the
    handler reads ``len(ack.ecn)`` to discriminate); the
    MAX_STREAMS / STREAMS_BLOCKED bidi/uni splits are collapsed
    via the ``unidirectional`` flag on the typed payload; the
    CONNECTION_CLOSE transport/application split is collapsed via
    the ``application`` flag.

    A frame type outside the v1 master table never reaches a
    callback: :func:`parse_frame_into` raises a
    ``FRAME_ENCODING_ERROR`` for it (RFC 9000 §12.4).
    """

    def on_padding(mut self, count: Int) raises:
        """PADDING run consumed (§19.1).

        ``count`` is the number of consecutive 0x00 bytes the
        parser collapsed into one callback (≥ 1).
        """
        ...

    def on_ping(mut self) raises:
        """PING frame (§19.2)."""
        ...

    def on_ack(mut self, ack: AckFrame) raises:
        """ACK / ACK-ECN frame (§19.3). When ``len(ack.ecn) == 1``
        the wire type was 0x03 (ACK with ECN counts); otherwise
        0x02."""
        ...

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        """RESET_STREAM (§19.4)."""
        ...

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        """STOP_SENDING (§19.5)."""
        ...

    def on_crypto(mut self, c: CryptoFrame) raises:
        """CRYPTO (§19.6)."""
        ...

    def on_new_token(mut self, t: NewTokenFrame) raises:
        """NEW_TOKEN (§19.7)."""
        ...

    def on_stream(mut self, sf: StreamFrame) raises:
        """STREAM (§19.8). The wire-type flag bits are surfaced via
        ``sf.offset`` (set / zero), the explicit data length (read
        when LEN was set) and ``sf.fin``."""
        ...

    def on_max_data(mut self, m: MaxDataFrame) raises:
        """MAX_DATA (§19.9)."""
        ...

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        """MAX_STREAM_DATA (§19.10)."""
        ...

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        """MAX_STREAMS (§19.11). The bidi (0x12) vs uni (0x13) wire
        split is surfaced via ``m.unidirectional``."""
        ...

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        """DATA_BLOCKED (§19.12)."""
        ...

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        """STREAM_DATA_BLOCKED (§19.13)."""
        ...

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        """STREAMS_BLOCKED (§19.14). The bidi (0x16) vs uni (0x17)
        wire split is surfaced via ``sb.unidirectional``."""
        ...

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        """NEW_CONNECTION_ID (§19.15)."""
        ...

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        """RETIRE_CONNECTION_ID (§19.16)."""
        ...

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        """PATH_CHALLENGE (§19.17)."""
        ...

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        """PATH_RESPONSE (§19.18)."""
        ...

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        """CONNECTION_CLOSE (§19.19). The transport (0x1c) vs
        application (0x1d) wire split is surfaced via
        ``cc.application``."""
        ...

    def on_handshake_done(mut self) raises:
        """HANDSHAKE_DONE (§19.20)."""
        ...

    def on_datagram(mut self, dg: DatagramFrame) raises:
        """DATAGRAM (RFC 9221 §4) -- an unreliable application
        datagram. ``dg.has_length`` records whether the wire type
        carried an explicit length (0x31) or ran to the end of the
        packet (0x30)."""
        ...

    def on_ack_frequency(mut self, f: AckFrequencyFrame) raises:
        """ACK_FREQUENCY (draft-ietf-quic-ack-frequency)."""
        ...

    def on_immediate_ack(mut self) raises:
        """IMMEDIATE_ACK (draft-ietf-quic-ack-frequency): acknowledge
        now."""
        ...


# ── Encoding helpers (varint append) ─────────────────────────────────────────


def _push_varint(mut out: List[UInt8], value: UInt64) raises:
    encode_varint_into(value, out)


def _push_bytes(mut out: List[UInt8], data: List[UInt8]):
    out.extend(Span(data))


# ── Per-type encoders ────────────────────────────────────────────────────────


def encode_datagram(frame: DatagramFrame, mut out: List[UInt8]) raises:
    """Encode a DATAGRAM frame (RFC 9221 §4).

    When ``frame.has_length`` is set, emit type 0x31 with an explicit
    length varint so the frame may be followed by others in the packet;
    otherwise emit type 0x30, which the caller MUST place last in the
    packet (its payload runs to the end of the QUIC payload).
    """
    if frame.has_length:
        out.append(UInt8(FRAME_TYPE_DATAGRAM_LEN))
        _push_varint(out, UInt64(len(frame.data)))
    else:
        out.append(UInt8(FRAME_TYPE_DATAGRAM_NOLEN))
    _push_bytes(out, frame.data)


def encode_padding(length: Int, mut out: List[UInt8]) raises:
    """Encode ``length`` PADDING frames (§19.1) as repeated 0x00s."""
    if length < 0:
        raise Error("quic frame: padding length negative")
    for _ in range(length):
        out.append(UInt8(FRAME_TYPE_PADDING))


def encode_ping(mut out: List[UInt8]):
    """Encode a PING frame (§19.2): single 0x01 byte."""
    out.append(UInt8(FRAME_TYPE_PING))


def encode_ack(frame: AckFrame, mut out: List[UInt8]) raises:
    """Encode an ACK / ACK-ECN frame (§19.3).

    Picks the type byte based on whether ``frame.ecn`` is empty
    (0x02) or carries a single :class:`EcnCounts` entry (0x03).
    """
    var ecn_count = len(frame.ecn)
    if ecn_count > 1:
        raise Error("quic ack: ecn list must hold 0 or 1 entries")
    if ecn_count == 1:
        out.append(UInt8(FRAME_TYPE_ACK_ECN))
    else:
        out.append(UInt8(FRAME_TYPE_ACK))
    _push_varint(out, frame.largest_acknowledged)
    _push_varint(out, frame.ack_delay)
    _push_varint(out, UInt64(len(frame.ranges)))
    _push_varint(out, frame.first_ack_range)
    for i in range(len(frame.ranges)):
        var r = frame.ranges[i]
        _push_varint(out, r.gap)
        _push_varint(out, r.length)
    if ecn_count == 1:
        var counts = frame.ecn[0]
        _push_varint(out, counts.ect0)
        _push_varint(out, counts.ect1)
        _push_varint(out, counts.ce)


def encode_reset_stream(frame: ResetStreamFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_RESET_STREAM))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.application_error_code)
    _push_varint(out, frame.final_size)


def encode_stop_sending(frame: StopSendingFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_STOP_SENDING))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.application_error_code)


def encode_crypto(frame: CryptoFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_CRYPTO))
    _push_varint(out, frame.offset)
    _push_varint(out, UInt64(len(frame.data)))
    _push_bytes(out, frame.data)


def encode_new_token(frame: NewTokenFrame, mut out: List[UInt8]) raises:
    if len(frame.token) == 0:
        raise Error("quic new_token: token must be non-empty (RFC 9000 §19.7)")
    out.append(UInt8(FRAME_TYPE_NEW_TOKEN))
    _push_varint(out, UInt64(len(frame.token)))
    _push_bytes(out, frame.token)


def encode_stream(
    frame: StreamFrame, mut out: List[UInt8], emit_length: Bool = True
) raises:
    """Encode a STREAM frame (§19.8).

    ``emit_length`` controls whether the LEN bit is set: producers
    that emit a STREAM frame as the *last* frame of a packet may
    omit the explicit length and let the frame extend to the
    packet boundary. Most callers pass ``emit_length=True`` for
    safe self-describing framing.
    """
    var type_byte = FRAME_TYPE_STREAM_BASE
    if frame.offset > UInt64(0):
        type_byte |= STREAM_OFF_BIT
    if emit_length:
        type_byte |= STREAM_LEN_BIT
    if frame.fin:
        type_byte |= STREAM_FIN_BIT
    out.append(UInt8(type_byte))
    _push_varint(out, frame.stream_id)
    if frame.offset > UInt64(0):
        _push_varint(out, frame.offset)
    if emit_length:
        _push_varint(out, UInt64(len(frame.data)))
    _push_bytes(out, frame.data)


def encode_max_data(frame: MaxDataFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_MAX_DATA))
    _push_varint(out, frame.maximum_data)


def encode_max_stream_data(
    frame: MaxStreamDataFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_MAX_STREAM_DATA))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.maximum_stream_data)


def encode_max_streams(frame: MaxStreamsFrame, mut out: List[UInt8]) raises:
    var t = (
        FRAME_TYPE_MAX_STREAMS_UNI if frame.unidirectional else FRAME_TYPE_MAX_STREAMS_BIDI
    )
    out.append(UInt8(t))
    _push_varint(out, frame.maximum_streams)


def encode_data_blocked(frame: DataBlockedFrame, mut out: List[UInt8]) raises:
    out.append(UInt8(FRAME_TYPE_DATA_BLOCKED))
    _push_varint(out, frame.maximum_data)


def encode_stream_data_blocked(
    frame: StreamDataBlockedFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_STREAM_DATA_BLOCKED))
    _push_varint(out, frame.stream_id)
    _push_varint(out, frame.maximum_stream_data)


def encode_streams_blocked(
    frame: StreamsBlockedFrame, mut out: List[UInt8]
) raises:
    var t = (
        FRAME_TYPE_STREAMS_BLOCKED_UNI if frame.unidirectional else FRAME_TYPE_STREAMS_BLOCKED_BIDI
    )
    out.append(UInt8(t))
    _push_varint(out, frame.maximum_streams)


def encode_new_connection_id(
    frame: NewConnectionIdFrame, mut out: List[UInt8]
) raises:
    var cid_len = len(frame.connection_id)
    if cid_len < 1 or cid_len > 20:
        raise Error("quic new_connection_id: cid length must be in [1, 20]")
    if len(frame.stateless_reset_token) != 16:
        raise Error(
            "quic new_connection_id: stateless reset token must be 16 bytes"
        )
    if frame.retire_prior_to > frame.sequence_number:
        raise Error("quic new_connection_id: retire_prior_to > sequence_number")
    out.append(UInt8(FRAME_TYPE_NEW_CONNECTION_ID))
    _push_varint(out, frame.sequence_number)
    _push_varint(out, frame.retire_prior_to)
    out.append(UInt8(cid_len))
    _push_bytes(out, frame.connection_id)
    _push_bytes(out, frame.stateless_reset_token)


def encode_retire_connection_id(
    frame: RetireConnectionIdFrame, mut out: List[UInt8]
) raises:
    out.append(UInt8(FRAME_TYPE_RETIRE_CONNECTION_ID))
    _push_varint(out, frame.sequence_number)


def encode_path_challenge(
    frame: PathChallengeFrame, mut out: List[UInt8]
) raises:
    if len(frame.data) != 8:
        raise Error("quic path_challenge: data must be exactly 8 bytes")
    out.append(UInt8(FRAME_TYPE_PATH_CHALLENGE))
    _push_bytes(out, frame.data)


def encode_path_response(frame: PathResponseFrame, mut out: List[UInt8]) raises:
    if len(frame.data) != 8:
        raise Error("quic path_response: data must be exactly 8 bytes")
    out.append(UInt8(FRAME_TYPE_PATH_RESPONSE))
    _push_bytes(out, frame.data)


def encode_connection_close(
    frame: ConnectionCloseFrame, mut out: List[UInt8]
) raises:
    var t = (
        FRAME_TYPE_CONNECTION_CLOSE_APPLICATION if frame.application else FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
    )
    out.append(UInt8(t))
    _push_varint(out, frame.error_code)
    if not frame.application:
        _push_varint(out, frame.frame_type)
    _push_varint(out, UInt64(len(frame.reason_phrase)))
    _push_bytes(out, frame.reason_phrase)


def encode_handshake_done(mut out: List[UInt8]):
    out.append(UInt8(FRAME_TYPE_HANDSHAKE_DONE))


def encode_ack_frequency(f: AckFrequencyFrame, mut out: List[UInt8]) raises:
    _push_varint(out, UInt64(FRAME_TYPE_ACK_FREQUENCY))
    _push_varint(out, f.sequence_number)
    _push_varint(out, f.ack_eliciting_threshold)
    _push_varint(out, f.request_max_ack_delay)
    _push_varint(out, f.reordering_threshold)


def encode_immediate_ack(mut out: List[UInt8]):
    out.append(UInt8(FRAME_TYPE_IMMEDIATE_ACK))


# ── Per-type parsers ─────────────────────────────────────────────────────────


def _read_varint(buf: Span[UInt8, _], mut pos: Int) raises -> UInt64:
    """Decode a varint starting at ``pos`` and advance the cursor."""
    var v = decode_varint(buf[pos:])
    pos += v.consumed
    return v.value


def _read_bytes(
    buf: Span[UInt8, _], mut pos: Int, n: Int
) raises -> List[UInt8]:
    """Copy ``n`` bytes starting at ``pos`` into a fresh list."""
    if n < 0:
        raise Error("quic frame: negative byte count")
    if pos + n > len(buf):
        raise Error("quic frame: truncated payload")
    var out = List[UInt8](capacity=n)
    out.extend(buf[pos : pos + n])
    pos += n
    return out^


# ── Top-level parse + dispatch ───────────────────────────────────────────────


def parse_frame_into[
    H: FrameHandler
](buf: Span[UInt8, _], mut handler: H) raises -> Int:
    """Parse a single transport frame at the start of ``buf`` and
    fire the matching :trait:`FrameHandler` callback.

    The QUIC frame type is itself varint-encoded (§19); for the
    22 codepoints defined in v1 the encoding is single-byte, but
    the dispatcher reads it as a varint to stay forward-compatible
    with extension types that may register higher-numbered
    codepoints. Codepoints outside the v1 master table are a
    connection error of type FRAME_ENCODING_ERROR (RFC 9000 §12.4):
    the dispatcher raises, so an unknown frame's body is never
    re-read as further frames.

    Returns the number of wire bytes consumed -- the caller
    advances its cursor and re-invokes the dispatcher on the
    remainder. The dispatcher never panics on malformed input;
    structural errors (truncated payload, malformed varint, range
    out of bounds) are reported via raised :class:`Error`.
    """
    if len(buf) == 0:
        raise Error("quic frame: empty buffer")
    var pos = 0
    var type_var = decode_varint(buf[pos:])
    pos += type_var.consumed
    var raw_type = type_var.value
    var t = Int(raw_type)
    if t == FRAME_TYPE_PADDING:
        # Per §19.1, PADDING is one byte. The caller can collapse
        # runs by repeatedly invoking the dispatcher; we surface a
        # single-frame view here so the caller attributes byte
        # counts cleanly. A small-batch optimisation could fuse
        # consecutive 0x00s but that lives in the connection
        # state-machine layer above.
        handler.on_padding(1)
        return pos
    if t == FRAME_TYPE_PING:
        handler.on_ping()
        return pos
    if t == FRAME_TYPE_ACK or t == FRAME_TYPE_ACK_ECN:
        var largest = _read_varint(buf, pos)
        var delay = _read_varint(buf, pos)
        var range_count = _read_varint(buf, pos)
        if range_count > UInt64(0x4000):
            raise Error("quic ack: range count exceeds RFC 9000 §19.3 cap")
        var first = _read_varint(buf, pos)
        var ranges = List[AckRange]()
        for _ in range(Int(range_count)):
            var gap = _read_varint(buf, pos)
            var length = _read_varint(buf, pos)
            ranges.append(AckRange(gap=gap, length=length))
        var ecn = List[EcnCounts]()
        if t == FRAME_TYPE_ACK_ECN:
            var ect0 = _read_varint(buf, pos)
            var ect1 = _read_varint(buf, pos)
            var ce = _read_varint(buf, pos)
            ecn.append(EcnCounts(ect0=ect0, ect1=ect1, ce=ce))
        # RFC 9000 sec 19.3.1: every computed packet number must be >= 0.
        # Varints are below 2^62, so the Int arithmetic cannot overflow.
        var smallest = Int(largest) - Int(first)
        if smallest < 0:
            raise Error("FRAME_ENCODING_ERROR: negative ack range")
        for i in range(len(ranges)):
            var next_largest = smallest - Int(ranges[i].gap) - 2
            smallest = next_largest - Int(ranges[i].length)
            if smallest < 0:
                raise Error("FRAME_ENCODING_ERROR: negative ack range")
        handler.on_ack(
            AckFrame(
                largest_acknowledged=largest,
                ack_delay=delay,
                first_ack_range=first,
                ranges=ranges^,
                ecn=ecn^,
            )
        )
        return pos
    if t == FRAME_TYPE_RESET_STREAM:
        var sid = _read_varint(buf, pos)
        var ec = _read_varint(buf, pos)
        var fs = _read_varint(buf, pos)
        handler.on_reset_stream(
            ResetStreamFrame(
                stream_id=sid, application_error_code=ec, final_size=fs
            )
        )
        return pos
    if t == FRAME_TYPE_STOP_SENDING:
        var sid = _read_varint(buf, pos)
        var ec = _read_varint(buf, pos)
        handler.on_stop_sending(
            StopSendingFrame(stream_id=sid, application_error_code=ec)
        )
        return pos
    if t == FRAME_TYPE_CRYPTO:
        var off = _read_varint(buf, pos)
        var n = _read_varint(buf, pos)
        var data = _read_bytes(buf, pos, Int(n))
        handler.on_crypto(CryptoFrame(offset=off, data=data^))
        return pos
    if t == FRAME_TYPE_NEW_TOKEN:
        var n = _read_varint(buf, pos)
        if n == UInt64(0):
            raise Error("quic new_token: empty token (RFC 9000 §19.7)")
        var token = _read_bytes(buf, pos, Int(n))
        handler.on_new_token(NewTokenFrame(token=token^))
        return pos
    if t >= FRAME_TYPE_STREAM_BASE and t <= FRAME_TYPE_STREAM_MAX:
        var has_off = (t & STREAM_OFF_BIT) != 0
        var has_len = (t & STREAM_LEN_BIT) != 0
        var fin = (t & STREAM_FIN_BIT) != 0
        var sid = _read_varint(buf, pos)
        var off = UInt64(0)
        if has_off:
            off = _read_varint(buf, pos)
        var data: List[UInt8]
        if has_len:
            var n = _read_varint(buf, pos)
            data = _read_bytes(buf, pos, Int(n))
        else:
            # No explicit length -- payload extends to end of buffer.
            data = _read_bytes(buf, pos, len(buf) - pos)
        handler.on_stream(
            StreamFrame(stream_id=sid, offset=off, data=data^, fin=fin)
        )
        return pos
    if t == FRAME_TYPE_MAX_DATA:
        var v = _read_varint(buf, pos)
        handler.on_max_data(MaxDataFrame(maximum_data=v))
        return pos
    if t == FRAME_TYPE_MAX_STREAM_DATA:
        var sid = _read_varint(buf, pos)
        var v = _read_varint(buf, pos)
        handler.on_max_stream_data(
            MaxStreamDataFrame(stream_id=sid, maximum_stream_data=v)
        )
        return pos
    if t == FRAME_TYPE_MAX_STREAMS_BIDI or t == FRAME_TYPE_MAX_STREAMS_UNI:
        var v = _read_varint(buf, pos)
        # RFC 9000 sec 4.6 / 19.11: a count above 2^60 cannot be a stream
        # count (stream ids are below 2^62).
        if v > _MAX_STREAM_COUNT:
            raise Error("FRAME_ENCODING_ERROR: MAX_STREAMS > 2^60")
        handler.on_max_streams(
            MaxStreamsFrame(
                unidirectional=t == FRAME_TYPE_MAX_STREAMS_UNI,
                maximum_streams=v,
            )
        )
        return pos
    if t == FRAME_TYPE_DATA_BLOCKED:
        var v = _read_varint(buf, pos)
        handler.on_data_blocked(DataBlockedFrame(maximum_data=v))
        return pos
    if t == FRAME_TYPE_STREAM_DATA_BLOCKED:
        var sid = _read_varint(buf, pos)
        var v = _read_varint(buf, pos)
        handler.on_stream_data_blocked(
            StreamDataBlockedFrame(stream_id=sid, maximum_stream_data=v)
        )
        return pos
    if (
        t == FRAME_TYPE_STREAMS_BLOCKED_BIDI
        or t == FRAME_TYPE_STREAMS_BLOCKED_UNI
    ):
        var v = _read_varint(buf, pos)
        # RFC 9000 sec 19.14: the same bound as MAX_STREAMS.
        if v > _MAX_STREAM_COUNT:
            raise Error("FRAME_ENCODING_ERROR: STREAMS_BLOCKED > 2^60")
        handler.on_streams_blocked(
            StreamsBlockedFrame(
                unidirectional=t == FRAME_TYPE_STREAMS_BLOCKED_UNI,
                maximum_streams=v,
            )
        )
        return pos
    if t == FRAME_TYPE_NEW_CONNECTION_ID:
        var seq = _read_varint(buf, pos)
        var retire = _read_varint(buf, pos)
        if pos >= len(buf):
            raise Error("quic new_connection_id: truncated cid length")
        var cid_len = Int(buf[pos])
        pos += 1
        if cid_len < 1 or cid_len > 20:
            raise Error("quic new_connection_id: cid length out of [1, 20]")
        var cid = _read_bytes(buf, pos, cid_len)
        var token = _read_bytes(buf, pos, 16)
        if retire > seq:
            raise Error(
                "quic new_connection_id: retire_prior_to > sequence_number"
            )
        handler.on_new_connection_id(
            NewConnectionIdFrame(
                sequence_number=seq,
                retire_prior_to=retire,
                connection_id=cid^,
                stateless_reset_token=token^,
            )
        )
        return pos
    if t == FRAME_TYPE_RETIRE_CONNECTION_ID:
        var seq = _read_varint(buf, pos)
        handler.on_retire_connection_id(
            RetireConnectionIdFrame(sequence_number=seq)
        )
        return pos
    if t == FRAME_TYPE_PATH_CHALLENGE:
        var data = _read_bytes(buf, pos, 8)
        handler.on_path_challenge(PathChallengeFrame(data=data^))
        return pos
    if t == FRAME_TYPE_PATH_RESPONSE:
        var data = _read_bytes(buf, pos, 8)
        handler.on_path_response(PathResponseFrame(data=data^))
        return pos
    if (
        t == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
        or t == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
    ):
        var ec = _read_varint(buf, pos)
        var ft = UInt64(0)
        if t == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT:
            ft = _read_varint(buf, pos)
        var rn = _read_varint(buf, pos)
        var reason = _read_bytes(buf, pos, Int(rn))
        handler.on_connection_close(
            ConnectionCloseFrame(
                application=t == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
                error_code=ec,
                frame_type=ft,
                reason_phrase=reason^,
            )
        )
        return pos
    if t == FRAME_TYPE_HANDSHAKE_DONE:
        handler.on_handshake_done()
        return pos
    if t == FRAME_TYPE_DATAGRAM_NOLEN or t == FRAME_TYPE_DATAGRAM_LEN:
        # RFC 9221 §4: 0x30 runs to the end of the packet; 0x31 has an
        # explicit length varint and may be followed by more frames.
        var has_len = t == FRAME_TYPE_DATAGRAM_LEN
        var dlen: Int
        if has_len:
            dlen = Int(_read_varint(buf, pos))
        else:
            dlen = len(buf) - pos
        var data = _read_bytes(buf, pos, dlen)
        handler.on_datagram(DatagramFrame(data=data^, has_length=has_len))
        return pos
    if t == FRAME_TYPE_ACK_FREQUENCY:
        var seq = _read_varint(buf, pos)
        var threshold = _read_varint(buf, pos)
        var delay = _read_varint(buf, pos)
        var reorder = _read_varint(buf, pos)
        handler.on_ack_frequency(
            AckFrequencyFrame(seq, threshold, delay, reorder)
        )
        return pos
    if t == FRAME_TYPE_IMMEDIATE_ACK:
        handler.on_immediate_ack()
        return pos
    raise Error("FRAME_ENCODING_ERROR: unknown frame type " + String(raw_type))
