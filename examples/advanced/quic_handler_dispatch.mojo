"""RFC 9000 §19 transport-frame dispatch demo.

This example wires an in-line :trait:`FrameHandler` into
:func:`parse_frame_into` and walks a buffer that already holds
the byte form of several QUIC frame types (PADDING, PING,
STREAM, MAX_DATA, HANDSHAKE_DONE, CONNECTION_CLOSE). The
handler prints the frame type the dispatcher delivered and
records a small per-type tally; the driver loop advances by
the consumed byte count returned from each call and asserts
the total walked exactly the length of the buffer.

The shape is the same one a future reactor would use: the
caller owns the byte buffer (typically the deprotected packet
payload from RFC 9000 §17), threads a single handler value
through repeated dispatches, and never materialises an
intermediate frame carrier. The handler stays free to advance
its own state machine, queue work for later, or fold the
typed payload into a connection-level event log.

Sans-I/O contract: no UDP, no rustls, no allocator beyond the
codec's own. The dispatcher entry point is the same one the
QUIC connection state machine wraps inside
:func:`flare.quic.handle_frame_buf`.
"""

from std.collections import List
from std.memory import Span

from flare.quic import (
    AckFrame,
    ConnectionCloseFrame,
    FrameHandler,
    StreamFrame,
    encode_connection_close,
    encode_handshake_done,
    encode_max_data,
    encode_padding,
    encode_ping,
    encode_stream,
    parse_frame_into,
)
from flare.quic.frame import (
    CryptoFrame,
    DataBlockedFrame,
    DatagramFrame,
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


@fieldwise_init
struct _PrintingHandler(FrameHandler, Movable):
    """Demo handler -- prints the dispatched frame type and bumps
    a per-category counter. Production code would advance the
    connection state machine in place of the print + tally.
    """

    var padding: Int
    var ping: Int
    var stream: Int
    var max_data: Int
    var handshake_done: Int
    var connection_close: Int
    var other: Int

    def on_padding(mut self, count: Int) raises:
        print("  PADDING        count=" + String(count))
        self.padding += count

    def on_ping(mut self) raises:
        print("  PING")
        self.ping += 1

    def on_ack(mut self, ack: AckFrame) raises:
        self.other += 1

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        self.other += 1

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        self.other += 1

    def on_crypto(mut self, c: CryptoFrame) raises:
        self.other += 1

    def on_new_token(mut self, t: NewTokenFrame) raises:
        self.other += 1

    def on_stream(mut self, sf: StreamFrame) raises:
        print(
            "  STREAM         id="
            + String(sf.stream_id)
            + " off="
            + String(sf.offset)
            + " len="
            + String(len(sf.data))
            + " fin="
            + String(sf.fin)
        )
        self.stream += 1

    def on_max_data(mut self, m: MaxDataFrame) raises:
        print("  MAX_DATA       max=" + String(m.maximum_data))
        self.max_data += 1

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        self.other += 1

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        self.other += 1

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        self.other += 1

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        self.other += 1

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        self.other += 1

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        self.other += 1

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        self.other += 1

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        self.other += 1

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        self.other += 1

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        var reason = String()
        for i in range(len(cc.reason_phrase)):
            reason += chr(Int(cc.reason_phrase[i]))
        print(
            "  CONNECTION_CLOSE app="
            + String(cc.application)
            + " err="
            + String(cc.error_code)
            + ' reason="'
            + reason
            + '"'
        )
        self.connection_close += 1

    def on_handshake_done(mut self) raises:
        print("  HANDSHAKE_DONE")
        self.handshake_done += 1

    def on_datagram(mut self, dg: DatagramFrame) raises:
        print("  DATAGRAM       len=" + String(len(dg.data)))
        self.other += 1

    def on_unknown(mut self, type_id: UInt64) raises:
        print("  UNKNOWN        type_id=" + String(type_id))
        self.other += 1


def main() raises:
    print("=" * 60)
    print("QUIC §19 frame dispatch -- sans-I/O")
    print("=" * 60)
    print()

    # Build a single wire buffer that splices several frames
    # back-to-back. The dispatcher walks it one frame at a time;
    # each pass returns the consumed byte count so the driver can
    # advance the cursor and re-invoke.
    var wire = List[UInt8]()
    encode_padding(4, wire)
    encode_ping(wire)
    var hello = List[UInt8]()
    for c in String("hello").as_bytes():
        hello.append(c)
    encode_stream(
        StreamFrame(
            stream_id=UInt64(4),
            offset=UInt64(0),
            data=hello^,
            fin=True,
        ),
        wire,
    )
    encode_max_data(MaxDataFrame(maximum_data=UInt64(1 << 20)), wire)
    encode_handshake_done(wire)
    var reason = List[UInt8]()
    for c in String("bye").as_bytes():
        reason.append(c)
    encode_connection_close(
        ConnectionCloseFrame(
            application=False,
            error_code=UInt64(0),
            frame_type=UInt64(0),
            reason_phrase=reason^,
        ),
        wire,
    )

    print("[1] composed wire buffer = " + String(len(wire)) + " bytes")
    print()

    var handler = _PrintingHandler(
        padding=0,
        ping=0,
        stream=0,
        max_data=0,
        handshake_done=0,
        connection_close=0,
        other=0,
    )

    print("[2] dispatch loop")
    var pos = 0
    while pos < len(wire):
        var rest = Span[UInt8, _](wire)[pos:]
        var n = parse_frame_into(rest, handler)
        if n == 0:
            raise Error("dispatch made no progress")
        pos += n

    if pos != len(wire):
        raise Error(
            "dispatcher consumed "
            + String(pos)
            + " bytes; buffer length "
            + String(len(wire))
        )
    print()

    print("[3] per-type tally")
    print("    PADDING runs    = " + String(handler.padding))
    print("    PING            = " + String(handler.ping))
    print("    STREAM          = " + String(handler.stream))
    print("    MAX_DATA        = " + String(handler.max_data))
    print("    HANDSHAKE_DONE  = " + String(handler.handshake_done))
    print("    CONNECTION_CLOSE= " + String(handler.connection_close))
    print()

    print("[OK] one buffer, one handler, no carrier allocation.")
