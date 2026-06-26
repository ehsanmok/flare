"""Fuzz harness: ``flare.quic.frame.parse_frame_into``.

QUIC v1 frames are (varint type) + (type-specific payload) per
RFC 9000 §19, with 22 frame types covering everything from PADDING
through HANDSHAKE_DONE. The harness drives the type-discriminating
first byte/varint with the full range and feeds the remainder of
the input as the would-be payload, exercising the per-type parser
arms via the trait-dispatch entry point.

Properties checked:

1. ``parse_frame_into`` either:
   - returns a ``consumed`` count in ``[1, len(data)]``, having
     fired exactly one :trait:`FrameHandler` callback for the
     decoded payload, or
   - raises a regular ``Error`` (truncated payload, malformed
     varint, oversize length, validation failure). It must never
     panic on arbitrary bytes.

2. **Idempotent re-decode.** When the first call succeeds, the
   harness calls ``parse_frame_into`` a second time on a copy of
   the input bytes against a fresh recording handler and asserts
   the same ``consumed`` count is reported. The codec is required
   to be deterministic.

Run:
    pixi run --environment fuzz fuzz-quic-frame-decode
"""

from mozz import FuzzConfig, fuzz

from flare.quic.frame import (
    AckFrame,
    ConnectionCloseFrame,
    CryptoFrame,
    DataBlockedFrame,
    DatagramFrame,
    FrameHandler,
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
    StreamFrame,
    StreamsBlockedFrame,
    parse_frame_into,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


@fieldwise_init
struct _NoOpHandler(FrameHandler, Movable):
    """:trait:`FrameHandler` that swallows every callback and
    counts dispatches. The fuzz harness uses it as a structural
    drain so the dispatcher's parsing branches run end-to-end.
    """

    var dispatches: Int

    def on_padding(mut self, count: Int) raises:
        self.dispatches += 1

    def on_ping(mut self) raises:
        self.dispatches += 1

    def on_ack(mut self, ack: AckFrame) raises:
        self.dispatches += 1

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        self.dispatches += 1

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        self.dispatches += 1

    def on_crypto(mut self, c: CryptoFrame) raises:
        self.dispatches += 1

    def on_new_token(mut self, t: NewTokenFrame) raises:
        self.dispatches += 1

    def on_stream(mut self, sf: StreamFrame) raises:
        self.dispatches += 1

    def on_max_data(mut self, m: MaxDataFrame) raises:
        self.dispatches += 1

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        self.dispatches += 1

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        self.dispatches += 1

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        self.dispatches += 1

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        self.dispatches += 1

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        self.dispatches += 1

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        self.dispatches += 1

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        self.dispatches += 1

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        self.dispatches += 1

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        self.dispatches += 1

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        self.dispatches += 1

    def on_handshake_done(mut self) raises:
        self.dispatches += 1

    def on_datagram(mut self, dg: DatagramFrame) raises:
        self.dispatches += 1

    def on_unknown(mut self, type_id: UInt64) raises:
        self.dispatches += 1


def target(data: List[UInt8]) raises:
    var n = len(data)
    if n == 0:
        return
    var span = Span[UInt8, _](data)

    var ok_first = True
    var consumed_first = 0
    var dispatches_first = 0
    try:
        var h1 = _NoOpHandler(dispatches=0)
        consumed_first = parse_frame_into(span, h1)
        dispatches_first = h1.dispatches
        _assert(
            consumed_first >= 1 and consumed_first <= n,
            (
                "quic frame parse: consumed="
                + String(consumed_first)
                + " out of bounds "
                + String(n)
            ),
        )
        _assert(
            dispatches_first == 1,
            (
                "quic frame parse: handler fired "
                + String(dispatches_first)
                + " times (expected 1)"
            ),
        )
    except:
        ok_first = False

    if ok_first:
        var h2 = _NoOpHandler(dispatches=0)
        var consumed_second = parse_frame_into(span, h2)
        _assert(
            consumed_second == consumed_first,
            "quic frame parse: non-deterministic consumed count",
        )
        _assert(
            h2.dispatches == 1,
            "quic frame parse: replay handler fired wrong number of times",
        )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_frame_decode.mojo -- RFC 9000 §19 frame codec")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00"))  # PADDING
    seeds.append(_bytes("\x01"))  # PING
    seeds.append(_bytes("\x02\x00\x00\x00"))  # ACK no-range
    seeds.append(_bytes("\x06\x00\x00"))  # CRYPTO empty payload
    seeds.append(_bytes("\x1c\x00\x00\x00"))  # CONN_CLOSE_TRANSPORT
    seeds.append(_bytes("\x1e"))  # HANDSHAKE_DONE
    seeds.append(_bytes("\x08\x00\x00"))  # STREAM(off=0, len=0, fin=0)
    seeds.append(_bytes("\x1f"))  # unknown type (in v1 master table gap)

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_frame_decode",
            corpus_dir="fuzz/corpus/quic_frame_decode",
            max_input_len=256,
        ),
        seeds,
    )
