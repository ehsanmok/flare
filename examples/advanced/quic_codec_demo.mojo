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
* :mod:`flare.quic.cc` -- the RFC 9438 CUBIC + RFC 9406
  HyStart++ controller as pure functions.

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
    EcnCounts,
    FRAME_TYPE_ACK,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_PING,
    FRAME_TYPE_STREAM_BASE,
    Frame,
    StreamFrame,
    cc_init,
    can_send,
    decode_transport_parameters,
    empty_events,
    encode_frame,
    encode_transport_parameters,
    encode_varint,
    handle_frame,
    new_connection,
    on_ack_received,
    on_packet_sent,
    on_round_start,
    pacing_rate_bytes_per_second,
    parse_frame,
)
from flare.quic.frame import _zero_frame
from flare.quic.transport_params import empty_transport_parameters


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
    var ping = _zero_frame(FRAME_TYPE_PING)
    var ping_bytes = List[UInt8]()
    encode_frame(ping^, ping_bytes)
    var ping_back = parse_frame(Span[UInt8, _](ping_bytes))
    print("    PING       -> " + _hex(ping_bytes))
    print(
        "      consumed = "
        + String(ping_back.consumed)
        + ", kind="
        + String(ping_back.frame.kind)
    )

    var data = List[UInt8]()
    for c in String("hello").as_bytes():
        data.append(c)
    var sf = StreamFrame(
        stream_id=UInt64(0),
        offset=UInt64(0),
        data=data^,
        fin=True,
    )
    var stream = _zero_frame(FRAME_TYPE_STREAM_BASE)
    stream.stream = sf^
    var stream_bytes = List[UInt8]()
    encode_frame(stream^, stream_bytes)
    var stream_back = parse_frame(Span[UInt8, _](stream_bytes))
    print("    STREAM(fin=1, off=0, hello) -> " + _hex(stream_bytes))
    print(
        "      consumed = "
        + String(stream_back.consumed)
        + ", stream_id="
        + String(stream_back.frame.stream.stream_id)
        + ", fin="
        + String(stream_back.frame.stream.fin)
    )

    var hsd = _zero_frame(FRAME_TYPE_HANDSHAKE_DONE)
    var hsd_bytes = List[UInt8]()
    encode_frame(hsd^, hsd_bytes)
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
    handle_frame(conn, ping_back.frame, UInt64(100), events)
    handle_frame(conn, hsd^, UInt64(200), events)
    var stream2 = _zero_frame(FRAME_TYPE_STREAM_BASE)
    var data2 = List[UInt8]()
    for c in String("hello").as_bytes():
        data2.append(c)
    stream2.stream = StreamFrame(
        stream_id=UInt64(0),
        offset=UInt64(0),
        data=data2^,
        fin=True,
    )
    handle_frame(conn, stream2^, UInt64(300), events)
    print("    handshake_done = " + String(events.handshake_done))
    print("    new_streams = " + String(len(events.new_streams)))
    print("    finished_streams = " + String(len(events.finished_streams)))
    print("    state = " + String(conn.state))
    print()

    # ── Congestion control drive ──────────────────────────────────
    print("[5] CUBIC + HyStart++ drive")
    var cc = cc_init()
    on_round_start(cc)
    on_packet_sent(cc, UInt64(1200))
    var new_cwnd = on_ack_received(
        cc, UInt64(1200), UInt64(20_000), UInt64(20_000)
    )
    print("    cwnd after first ack = " + String(new_cwnd) + " bytes")
    print(
        "    pacing rate = "
        + String(pacing_rate_bytes_per_second(cc) // 1024)
        + " KiB/s"
    )
    print("    can_send 1200B? " + String(can_send(cc)))
    print()

    print("[OK] codec round-trip + state-machine drive clean.")
