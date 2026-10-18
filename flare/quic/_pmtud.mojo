"""Datagram Packetization Layer PMTU Discovery (RFC 8899, RFC 9000 sec 14.3).

Sans-I/O. A path starts at :data:`PMTU_BASE`, the size every QUIC path
must carry (RFC 9000 sec 14). Probes (PING + PADDING) test larger sizes
up to the ceiling, the smaller of the local limit and the peer's
``max_udp_payload_size``: the ceiling first, as most paths carry it,
then a binary search. A size is validated when its probe is
acknowledged; three unanswered probes rule it out. Probes are kept out
of loss recovery, so their loss is never taken for congestion (RFC 9002
sec 14.4). Two consecutive PTOs above the base are a black hole (RFC
8899 sec 4.3): the size falls back to the base, lost frames are re-split
to fit it (:func:`split_frames`), and probing resumes a minute later.
"""

from .frame import (
    AckFrame,
    AckFrequencyFrame,
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
    encode_stream,
    parse_frame_into,
)

comptime PMTU_BASE: Int = 1200
comptime _MAX_PROBES: Int = 3
comptime _SEARCH_DONE: Int = 20
"""Stop once the untested range is narrower than this many bytes."""
comptime _RETRY_MS: UInt64 = 60_000
"""Wait after a black hole before probing again."""


struct PmtuDiscovery(Copyable, Defaultable):
    var current: Int
    """The largest validated datagram size; what egress fills to."""
    var ceiling: Int
    var hi: Int
    """Largest size not yet ruled out."""
    var probe_size: Int
    """Size of the probe in flight, 0 when none."""
    var probe_pn: UInt64
    var probe_sent_ms: UInt64
    var fails: Int
    var next_ms: UInt64

    def __init__(out self):
        self.current = PMTU_BASE
        self.ceiling = PMTU_BASE
        self.hi = PMTU_BASE
        self.probe_size = 0
        self.probe_pn = 0
        self.probe_sent_ms = 0
        self.fails = 0
        self.next_ms = 0

    def set_ceiling(mut self, ceiling: Int):
        """The most the path may carry, once the peer's limit is known."""
        self.ceiling = max(ceiling, PMTU_BASE)
        self.hi = self.ceiling

    def want_probe(self, now_ms: UInt64) -> Int:
        """The size to probe now, or 0."""
        if self.probe_size != 0 or now_ms < self.next_ms:
            return 0
        if self.hi - self.current < _SEARCH_DONE:
            return 0
        if self.hi == self.ceiling:
            return self.hi
        return (self.current + self.hi + 1) // 2

    def on_probe_sent(mut self, pn: UInt64, size: Int, now_ms: UInt64):
        self.probe_pn = pn
        self.probe_size = size
        self.probe_sent_ms = now_ms

    def on_acked(mut self, ranges: List[UInt64]):
        """Feed the ``[lo, hi]`` pairs of an ACK; validates the probe if
        it is among them."""
        if self.probe_size == 0:
            return
        for i in range(0, len(ranges) - 1, 2):
            if ranges[i] <= self.probe_pn and self.probe_pn <= ranges[i + 1]:
                self.current = max(self.current, self.probe_size)
                self.probe_size = 0
                self.fails = 0
                return

    def check_lost(mut self, now_ms: UInt64, pto_ms: UInt64):
        """A probe unanswered for three PTOs is lost; three losses at one
        size rule it, and everything above it, out."""
        if self.probe_size == 0 or now_ms < self.probe_sent_ms + 3 * pto_ms:
            return
        self.fails += 1
        if self.fails >= _MAX_PROBES:
            self.hi = self.probe_size - 1
            self.fails = 0
        self.probe_size = 0

    def on_black_hole(mut self, now_ms: UInt64):
        """Packets above the base are not getting through: fall back to
        it and search again later."""
        if self.current == PMTU_BASE:
            return
        self.current = PMTU_BASE
        self.hi = self.ceiling
        self.probe_size = 0
        self.fails = 0
        self.next_ms = now_ms + _RETRY_MS


struct _Split(FrameHandler):
    var stream: Optional[StreamFrame]
    var padding: Bool

    def __init__(out self):
        self.stream = None
        self.padding = False

    def on_padding(mut self, count: Int) raises:
        self.padding = True

    def on_stream(mut self, sf: StreamFrame) raises:
        self.stream = sf.copy()

    def on_ping(mut self) raises:
        pass

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
        pass

    def on_datagram(mut self, dg: DatagramFrame) raises:
        pass

    def on_ack_frequency(mut self, f: AckFrequencyFrame) raises:
        pass

    def on_immediate_ack(mut self) raises:
        pass


def split_frames(
    frames: Span[UInt8, _], budget: Int
) raises -> List[List[UInt8]]:
    """Repack a lost packet's frames into payloads of at most ``budget``
    bytes: a STREAM frame too long for one is split by offset (FIN on
    the last piece), PADDING is dropped (a payload under 16 bytes is padded
    back to 16), other frames are kept whole."""
    var out = List[List[UInt8]]()
    var cur = List[UInt8]()
    var pos = 0
    while pos < len(frames):
        var h = _Split()
        var n = parse_frame_into(frames[pos:], h)
        if h.padding:
            pos += n
            continue
        var pieces = List[List[UInt8]]()
        if h.stream and n > budget:
            ref sf = h.stream.value()
            var chunk = budget - 24
            var off = 0
            while True:
                var take = min(chunk, len(sf.data) - off)
                var last = off + take == len(sf.data)
                var piece = List[UInt8]()
                encode_stream(
                    StreamFrame(
                        stream_id=sf.stream_id,
                        offset=sf.offset + UInt64(off),
                        data=List[UInt8](
                            Span[UInt8, _](sf.data)[off : off + take]
                        ),
                        fin=sf.fin and last,
                    ),
                    piece,
                )
                pieces.append(piece^)
                off += take
                if last:
                    break
        else:
            pieces.append(List[UInt8](frames[pos : pos + n]))
        for i in range(len(pieces)):
            if len(cur) > 0 and len(cur) + len(pieces[i]) > budget:
                out.append(cur^)
                cur = List[UInt8]()
            cur.extend(Span[UInt8, _](pieces[i]))
        pos += n
    if len(cur) > 0:
        out.append(cur^)
    for i in range(len(out)):
        if len(out[i]) < 16:  # header-protection sample floor (RFC 9001 5.4.2)
            out[i].resize(16, UInt8(0))
    return out^
