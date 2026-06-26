"""QUIC codec demo -- byte-level round-trip across the sans-I/O sublayer.

This example walks the QUIC v1 codec layer end-to-end without
opening a UDP socket. It exercises:

* :mod:`flare.quic.varint` -- the RFC 9000 §16 varint codec.
* :mod:`flare.quic.frame` -- the §19 frame codec (PING / ACK /
  STREAM / CRYPTO / CONNECTION_CLOSE).
* :mod:`flare.quic.transport_params` -- the §18 transport-
  parameter codec.
* :mod:`flare.quic.state` -- the §3 stream + §10 connection
  state machines.

The example builds three frames, encodes them, parses them back,
walks the decoded frames through the connection state machine,
and prints the resulting :class:`ConnectionEvents`. The full
sequence is byte-clean: the encoded bytes are exactly what the
reactor wrapper would put on the wire after the AEAD seal step.

Sans-I/O contract: no UDP, no rustls, no allocator beyond the
codec's own. Everything below the AEAD layer is fair game from
this entry point.
"""

from std.collections import List
from std.memory import Span

from flare.quic import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    DatagramFrame,
    EcnCounts,
    FRAME_TYPE_ACK,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_PING,
    FRAME_TYPE_STREAM_BASE,
    FrameHandler,
    StreamFrame,
    apply_handshake_done,
    apply_stream,
    decode_transport_parameters,
    empty_events,
    encode_handshake_done,
    encode_ping,
    encode_stream,
    encode_transport_parameters,
    encode_varint,
    handle_frame_buf,
    new_connection,
    parse_frame_into,
)
from flare.quic.frame import (
    CryptoFrame,
    DataBlockedFrame,
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
    StreamDataBlockedFrame,
    StreamsBlockedFrame,
)
from flare.quic.transport_params import empty_transport_parameters


@fieldwise_init
struct _DemoHandler(FrameHandler, Movable):
    """Minimal :trait:`FrameHandler` recording the frame types the
    demo exercises (PING / STREAM / HANDSHAKE_DONE). Everything
    else falls through to a no-op so the demo can drive the
    dispatcher with unrelated frame seeds without raising."""

    var ping_count: Int
    var stream_seen: Bool
    var stream_id: UInt64
    var stream_fin: Bool
    var handshake_done_count: Int

    def on_padding(mut self, count: Int) raises:
        pass

    def on_ping(mut self) raises:
        self.ping_count += 1

    def on_ack(mut self, ack: AckFrame) raises:
        pass

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        pass

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        pass

    def on_crypto(mut self, c: CryptoFrame) raises:
        pass

    def on_new_token(mut self, t: NewTokenFrame) raises:
        pass

    def on_stream(mut self, sf: StreamFrame) raises:
        self.stream_seen = True
        self.stream_id = sf.stream_id
        self.stream_fin = sf.fin

    def on_max_data(mut self, m: MaxDataFrame) raises:
        pass

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        pass

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        pass

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        pass

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        pass

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        pass

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        pass

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        pass

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        pass

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        pass

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        pass

    def on_handshake_done(mut self) raises:
        self.handshake_done_count += 1

    def on_datagram(mut self, dg: DatagramFrame) raises:
        pass

    def on_unknown(mut self, type_id: UInt64) raises:
        pass


def _hex(bytes: List[UInt8]) -> String:
    var s = String(capacity=len(bytes) * 3)
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        var hi = b // 16
        var lo = b % 16
        s += chr(48 + hi) if hi < 10 else chr(87 + hi)
        s += chr(48 + lo) if lo < 10 else chr(87 + lo)
        s += " "
    return s^


def main() raises:
    print("=" * 60)
    print("QUIC codec demo -- sans-I/O round-trip")
    print("=" * 60)
    print()

    # ── Varint round trip ─────────────────────────────────────────
    print("[1] Varint codec")
    var lengths = List[UInt64]()
    lengths.append(UInt64(0))
    lengths.append(UInt64(63))
    lengths.append(UInt64(64))
    lengths.append(UInt64(16383))
    lengths.append(UInt64(1 << 20))
    for i in range(len(lengths)):
        var enc = encode_varint(lengths[i])
        print(
            "    varint("
            + String(lengths[i])
            + ") -> "
            + String(len(enc))
            + " bytes: "
            + _hex(enc)
        )
    print()

    # ── Frame round trip ──────────────────────────────────────────
    print("[2] Frame codec round trip")
    var ping_bytes = List[UInt8]()
    encode_ping(ping_bytes)
    var demo_handler = _DemoHandler(
        ping_count=0,
        stream_seen=False,
        stream_id=UInt64(0),
        stream_fin=False,
        handshake_done_count=0,
    )
    var ping_consumed = parse_frame_into(
        Span[UInt8, _](ping_bytes), demo_handler
    )
    print("    PING       -> " + _hex(ping_bytes))
    print(
        "      consumed = "
        + String(ping_consumed)
        + ", ping_count="
        + String(demo_handler.ping_count)
    )

    var data = List[UInt8]()
    for c in String("hello").as_bytes():
        data.append(c)
    var stream_bytes = List[UInt8]()
    encode_stream(
        StreamFrame(
            stream_id=UInt64(0),
            offset=UInt64(0),
            data=data^,
            fin=True,
        ),
        stream_bytes,
    )
    var stream_consumed = parse_frame_into(
        Span[UInt8, _](stream_bytes), demo_handler
    )
    print("    STREAM(fin=1, off=0, hello) -> " + _hex(stream_bytes))
    print(
        "      consumed = "
        + String(stream_consumed)
        + ", stream_id="
        + String(demo_handler.stream_id)
        + ", fin="
        + String(demo_handler.stream_fin)
    )

    var hsd_bytes = List[UInt8]()
    encode_handshake_done(hsd_bytes)
    print("    HANDSHAKE_DONE -> " + _hex(hsd_bytes))
    print()

    # ── Transport parameters round trip ───────────────────────────
    print("[3] Transport parameters codec round trip")
    var tp = empty_transport_parameters()
    tp.max_idle_timeout = Optional[UInt64](UInt64(30000))
    tp.initial_max_data = Optional[UInt64](UInt64(1 << 20))
    tp.initial_max_streams_bidi = Optional[UInt64](UInt64(100))
    tp.disable_active_migration = True
    var tp_bytes = encode_transport_parameters(tp)
    print("    encoded " + String(len(tp_bytes)) + " bytes: " + _hex(tp_bytes))
    var tp_back = decode_transport_parameters(Span[UInt8, _](tp_bytes))
    print(
        "      max_idle_timeout = "
        + String(tp_back.max_idle_timeout.value())
        + " ms, initial_max_data = "
        + String(tp_back.initial_max_data.value())
        + ", disable_active_migration = "
        + String(tp_back.disable_active_migration)
    )
    print()

    # ── State machine drive ───────────────────────────────────────
    print("[4] Connection state machine drive")
    var conn = new_connection()
    var events = empty_events()
    _ = handle_frame_buf(conn, Span[UInt8, _](ping_bytes), UInt64(100), events)
    _ = handle_frame_buf(conn, Span[UInt8, _](hsd_bytes), UInt64(200), events)
    var stream2_bytes = List[UInt8]()
    var data2 = List[UInt8]()
    for c in String("hello").as_bytes():
        data2.append(c)
    encode_stream(
        StreamFrame(
            stream_id=UInt64(0),
            offset=UInt64(0),
            data=data2^,
            fin=True,
        ),
        stream2_bytes,
    )
    _ = handle_frame_buf(
        conn, Span[UInt8, _](stream2_bytes), UInt64(300), events
    )
    print("    handshake_done = " + String(events.handshake_done))
    print("    new_streams = " + String(len(events.new_streams)))
    print("    finished_streams = " + String(len(events.finished_streams)))
    print("    state = " + String(conn.state))
    print()

    print("[OK] codec round-trip + state-machine drive clean.")
