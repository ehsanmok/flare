"""QUIC connection + stream state machines (RFC 9000 §3 + §13).

Pure sans-I/O state model for a QUIC connection. The reactor
wrapping wraps this in UDP I/O + crypto; the codec layer here
just walks the state machines as packets / frames / timer ticks
arrive.

Public surface:

* :class:`StreamState` -- the 7-state RFC 9000 §3.1 / §3.2 stream
  state machine (IDLE / OPEN / HALF_CLOSED_LOCAL / HALF_CLOSED_
  REMOTE / RESET_SENT / RESET_RECVD / CLOSED).
* :class:`Stream` -- one bidi or uni stream's state, including
  send/recv high-water-marks for flow control.
* :class:`ConnectionState` -- the connection-level state
  (HANDSHAKE / ESTABLISHED / CLOSING / DRAINING / CLOSED) per
  RFC 9000 §10.
* :class:`Connection` -- top-level container holding
  - per-side keying state (handshake_complete flag),
  - flow-control limits,
  - per-stream :class:`Stream` instances keyed by stream-id,
  - the timer-driven idle / pto / loss-detection deadlines.
* :func:`handle_frame_buf` -- per-buffer ingestion entry point.
  Reads one wire frame from the start of ``buf``, dispatches the
  matching :trait:`FrameHandler` callback into the connection
  state machines, and returns the number of bytes consumed. The
  caller drains a packet payload by advancing its cursor and
  re-invoking the dispatcher.
* :class:`ConnectionEvents` -- the value the driver returns from
  one tick: bytes the caller should send, the next deadline at
  which to call back, plus connection-level events (handshake
  done, stream finished, connection closed).
* :func:`apply_stream` / :func:`apply_ack` / etc. -- per-typed
  payload helpers the dispatcher calls; exposed so the reactor
  layer (and tests) can drive transitions directly when they
  already have a typed payload in hand.

The state-machine layer is intentionally sans-I/O: there are no
sockets, no TLS handshake, no time source. The caller passes
``now_us`` into every entry point and receives
:class:`ConnectionEvents` carrying the next deadline; the timer
shape lives in the reactor wrapper.

References:
- RFC 9000 §3 "Stream States" + §10 "Connection Termination".
- RFC 9000 §13 "Packetization and Reliability".
"""

from std.collections import List, Optional, Dict
from std.memory import Span, UnsafePointer
from .frame import (
    AckFrame,
    AckRange,
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


# ── Stream state machine (RFC 9000 §3) ─────────────────────────────────────


comptime STREAM_STATE_IDLE: Int = 0
comptime STREAM_STATE_OPEN: Int = 1
comptime STREAM_STATE_HALF_CLOSED_LOCAL: Int = 2
comptime STREAM_STATE_HALF_CLOSED_REMOTE: Int = 3
comptime STREAM_STATE_RESET_SENT: Int = 4
comptime STREAM_STATE_RESET_RECVD: Int = 5
comptime STREAM_STATE_CLOSED: Int = 6


@fieldwise_init
struct Stream(Copyable, ImplicitlyCopyable, Movable):
    """Per-stream state for one bidi or uni QUIC stream.

    The state field uses the seven STREAM_STATE_* constants;
    transitions are driven by frames (STREAM with FIN, RESET_STREAM,
    STOP_SENDING) routed through :func:`handle_frame_buf`. Send
    and receive high-water-marks are tracked separately so flow
    control can advance independently per direction.
    """

    var id: UInt64
    var state: Int
    var send_offset: UInt64
    var recv_offset: UInt64
    var max_send_data: UInt64
    var max_recv_data: UInt64
    var fin_sent: Bool
    var fin_received: Bool


def new_stream(id: UInt64, max_data: UInt64) -> Stream:
    """Build a fresh :class:`Stream` in the OPEN state."""
    return Stream(
        id=id,
        state=STREAM_STATE_OPEN,
        send_offset=UInt64(0),
        recv_offset=UInt64(0),
        max_send_data=max_data,
        max_recv_data=max_data,
        fin_sent=False,
        fin_received=False,
    )


# ── Connection state machine (RFC 9000 §10) ────────────────────────────────


comptime CONN_STATE_HANDSHAKE: Int = 0
comptime CONN_STATE_ESTABLISHED: Int = 1
comptime CONN_STATE_CLOSING: Int = 2
comptime CONN_STATE_DRAINING: Int = 3
comptime CONN_STATE_CLOSED: Int = 4


# ── Connection migration limits (RFC 9000 §19.15-§19.18) ──────────────────
comptime _CID_MIN_LEN: Int = 1
comptime _CID_MAX_LEN: Int = 20
comptime _RESET_TOKEN_LEN: Int = 16
comptime _PATH_DATA_LEN: Int = 8


@fieldwise_init
struct _PeerConnId(Copyable, Movable):
    """One entry in the peer's connection-ID table (RFC 9000
    §5.1.1): a Source CID the peer issued via NEW_CONNECTION_ID
    plus its stateless-reset token. Keyed by sequence number in
    :attr:`Connection.peer_cids`; the client picks one of these as
    the active Destination CID when it migrates paths."""

    var cid: List[UInt8]
    var reset_token: List[UInt8]


@fieldwise_init
struct ConnectionEvents(Copyable, Movable):
    """Per-tick output of the connection state machine.

    The driver calls :func:`handle_frame_buf` (one or more times)
    with parsed frames, then reads :class:`ConnectionEvents` to
    discover what state has changed:

    * ``handshake_done`` -- TLS handshake completed this tick.
    * ``connection_closed`` -- the peer closed the connection or
      we did; ``error_code`` carries the reason.
    * ``finished_streams`` -- streams whose recv side reached FIN
      this tick (the caller delivers them up to the application).
    * ``new_streams`` -- streams created by an inbound STREAM
      frame that the local side hadn't seen before.
    * ``crypto_frames`` -- CRYPTO frames (RFC 9000 §19.6) parsed
      this tick. The sans-I/O state machine cannot drive the TLS
      handshake adapter directly without breaking the no-I/O
      contract; instead the parser appends every CRYPTO payload
      here and the reactor wrapper drains the list
      after :func:`handle_frame_buf` returns and forwards each
      payload to its :class:`flare.tls.rustls_quic.RustlsQuicSession`
      at the matching encryption level.
    * ``stream_chunks`` -- STREAM frames (RFC 9000 §19.8) parsed
      this tick. Same shape as ``crypto_frames``: the sans-I/O
      state machine updates per-stream offsets + FIN bookkeeping
      and appends the full :class:`StreamFrame` (stream id +
      offset + payload + fin) here so the H3 reactor wrapper
      can route per-stream bytes to
      :class:`flare.h3.H3Connection.feed_stream_chunk` /
      :meth:`feed_uni_stream_chunk` after
      :func:`handle_frame_buf` returns.
    * ``next_deadline_us`` -- earliest absolute time the driver
      should call back (for idle / PTO / loss detection); ``0``
      means "no scheduled timer".
    """

    var handshake_done: Bool
    var connection_closed: Bool
    var error_code: UInt64
    var finished_streams: List[UInt64]
    var new_streams: List[UInt64]
    var crypto_frames: List[CryptoFrame]
    var stream_chunks: List[StreamFrame]
    var next_deadline_us: UInt64
    var path_responses: List[List[UInt8]]
    """PATH_RESPONSE payloads (§19.18) the driver must echo back on
    the path a PATH_CHALLENGE arrived on, to prove reachability."""
    var retire_connection_ids: List[UInt64]
    """Peer-CID sequence numbers the driver must RETIRE_CONNECTION_ID
    (§19.16), queued when a NEW_CONNECTION_ID's ``retire_prior_to``
    obsoletes a stored CID."""
    var path_validated: Bool
    """Set when an inbound PATH_RESPONSE matched our outstanding
    PATH_CHALLENGE: the new path is confirmed reachable (§8.2)."""
    var acked_packets: List[UInt64]
    """Packet numbers an inbound ACK frame acknowledged this tick
    (§19.3, expanded from the ACK ranges). The client loss-recovery
    path retires its in-flight sent packets against this list."""
    var datagrams: List[List[UInt8]]
    """RFC 9221 DATAGRAM payloads received this tick. The reactor /
    application drains these after :func:`handle_frame_buf` returns;
    unreliable, unordered, and not retransmitted on loss."""


def empty_events() -> ConnectionEvents:
    return ConnectionEvents(
        handshake_done=False,
        connection_closed=False,
        error_code=UInt64(0),
        finished_streams=List[UInt64](),
        new_streams=List[UInt64](),
        crypto_frames=List[CryptoFrame](),
        stream_chunks=List[StreamFrame](),
        next_deadline_us=UInt64(0),
        path_responses=List[List[UInt8]](),
        retire_connection_ids=List[UInt64](),
        path_validated=False,
        acked_packets=List[UInt64](),
        datagrams=List[List[UInt8]](),
    )


@fieldwise_init
struct Connection(Copyable, Movable):
    """Top-level connection state.

    Holds the connection-level state, the per-stream map, and the
    timer-shape fields the driver uses to schedule the next tick.
    The connection here only tracks the data-plane state machines.

    Uses :class:`Dict` for the stream map so the driver can look
    up by stream id in O(1); RFC 9000 caps stream ids at 2**62-1
    so the key space is wide enough that stream-id overflow is a
    non-concern.
    """

    var state: Int
    var handshake_complete: Bool
    var idle_timeout_us: UInt64
    var last_activity_us: UInt64
    var max_data_send: UInt64
    var max_data_recv: UInt64
    var bytes_in_flight: UInt64
    var streams: Dict[UInt64, Stream]
    var ack_pending: Bool
    var largest_received_packet: UInt64
    var largest_acked_by_peer: UInt64
    var close_error_code: UInt64
    var close_reason: List[UInt8]
    var peer_cids: Dict[UInt64, _PeerConnId]
    """Peer-issued Source CIDs (RFC 9000 §5.1.1) keyed by sequence
    number, learned from NEW_CONNECTION_ID. The migration path
    picks a spare entry as the next active Destination CID."""
    var active_dcid_seq: UInt64
    """Sequence number of the peer CID currently used as the active
    Destination CID. ``0`` is the handshake CID (§5.1.1)."""
    var outgoing_path_challenge: List[UInt8]
    """The 8-byte PATH_CHALLENGE payload we last sent while probing
    a new path; an inbound PATH_RESPONSE must echo it to validate
    the path (§8.2). Empty when no probe is outstanding."""
    var path_validated: Bool
    """True once the outstanding path probe was confirmed by a
    matching PATH_RESPONSE."""


def new_connection(
    idle_timeout_us: UInt64 = UInt64(30_000_000),
    initial_max_data: UInt64 = UInt64(1 << 20),
) -> Connection:
    """Build a fresh :class:`Connection` in the HANDSHAKE state."""
    return Connection(
        state=CONN_STATE_HANDSHAKE,
        handshake_complete=False,
        idle_timeout_us=idle_timeout_us,
        last_activity_us=UInt64(0),
        max_data_send=initial_max_data,
        max_data_recv=initial_max_data,
        bytes_in_flight=UInt64(0),
        streams=Dict[UInt64, Stream](),
        ack_pending=False,
        largest_received_packet=UInt64(0),
        largest_acked_by_peer=UInt64(0),
        close_error_code=UInt64(0),
        close_reason=List[UInt8](),
        peer_cids=Dict[UInt64, _PeerConnId](),
        active_dcid_seq=UInt64(0),
        outgoing_path_challenge=List[UInt8](),
        path_validated=False,
    )


# ── Per-typed-payload state transitions ────────────────────────────────────


@always_inline
def _arrive(mut conn: Connection, now_us: UInt64, ack_eliciting: Bool):
    """Per-frame bookkeeping: update activity time + ack-pending.

    Every frame ingestion calls this first. ACK / PADDING /
    CONNECTION_CLOSE pass ``ack_eliciting=False`` per RFC 9002 §2;
    everything else is ack-eliciting.
    """
    conn.last_activity_us = now_us
    if ack_eliciting:
        conn.ack_pending = True


def apply_stream(
    mut conn: Connection,
    sf: StreamFrame,
    mut events: ConnectionEvents,
) raises:
    """Apply a STREAM frame (§19.8) to the connection.

    Creates the stream on first sight, advances the recv offset
    high-water-mark, enforces the flow-control limit, and emits a
    ``finished_streams`` entry when the FIN bit closes the recv
    side. Raises on flow-control violation. The full
    :class:`StreamFrame` is also appended to
    :attr:`ConnectionEvents.stream_chunks` so the H3 reactor
    wrapper can route the payload bytes to its
    per-connection :class:`flare.h3.H3Connection` without
    re-parsing the QUIC packet.
    """
    var sid = sf.stream_id
    var existing = conn.streams.get(sid)
    var s: Stream
    if Bool(existing):
        s = existing.value()
    else:
        s = new_stream(sid, conn.max_data_recv)
        events.new_streams.append(sid)
    var end = sf.offset + UInt64(len(sf.data))
    if end > s.max_recv_data:
        raise Error(
            "quic state: stream " + String(sid) + " flow-control violation"
        )
    if end > s.recv_offset:
        s.recv_offset = end
    if sf.fin and not s.fin_received:
        s.fin_received = True
        events.finished_streams.append(sid)
        if s.state == STREAM_STATE_OPEN:
            s.state = STREAM_STATE_HALF_CLOSED_REMOTE
        elif s.state == STREAM_STATE_HALF_CLOSED_LOCAL:
            s.state = STREAM_STATE_CLOSED
    conn.streams[sid] = s
    events.stream_chunks.append(sf.copy())


def apply_ack(mut conn: Connection, ack: AckFrame):
    """Apply an ACK frame to the connection-level bookkeeping.

    ``largest_acknowledged`` names the largest packet WE sent that
    the peer received; it lives in its own packet-number space and
    must NOT touch ``largest_received_packet`` (the largest packet
    WE received, which seeds inbound pn reconstruction).
    """
    if ack.largest_acknowledged > conn.largest_acked_by_peer:
        conn.largest_acked_by_peer = ack.largest_acknowledged


comptime _ACK_EXPAND_CAP: Int = 256
"""Cap how many individual packet numbers one ACK is expanded into.
Bounds the work an adversarial ACK with huge ranges can cause; our
own flows ack a handful of packets per frame. A peer that
genuinely acks more than 256 packets in one frame just gets the
newest 256 retired here -- the rest retire on the next ACK."""


def expand_ack_ranges(ack: AckFrame) -> List[UInt64]:
    """Expand an ACK frame's ranges (RFC 9000 §19.3.1) into the
    explicit list of acknowledged packet numbers, newest first,
    capped at :data:`_ACK_EXPAND_CAP`.

    The first range covers ``[largest - first_ack_range, largest]``;
    each subsequent range starts ``gap + 2`` below the previous
    range's smallest and spans ``length + 1`` packets.
    """
    var out = List[UInt64]()
    var largest = ack.largest_acknowledged
    # Implicit first range.
    var first_len = ack.first_ack_range
    var lo = largest - first_len if largest >= first_len else UInt64(0)
    var pn = largest
    while pn >= lo:
        out.append(pn)
        if len(out) >= _ACK_EXPAND_CAP or pn == UInt64(0):
            return out^
        pn -= UInt64(1)
    var cur_lo = lo
    for i in range(len(ack.ranges)):
        var gap = ack.ranges[i].gap
        var length = ack.ranges[i].length
        # Next range's largest = cur_lo - gap - 2 (RFC 9000 §19.3.1).
        var step = gap + UInt64(2)
        if cur_lo < step:
            break
        var next_largest = cur_lo - step
        var next_lo = (
            next_largest - length if next_largest >= length else UInt64(0)
        )
        var p = next_largest
        while p >= next_lo:
            out.append(p)
            if len(out) >= _ACK_EXPAND_CAP or p == UInt64(0):
                return out^
            p -= UInt64(1)
        cur_lo = next_lo
    return out^


def apply_connection_close(
    mut conn: Connection,
    cc: ConnectionCloseFrame,
    mut events: ConnectionEvents,
):
    """Apply a CONNECTION_CLOSE frame to the connection. Marks the
    connection as DRAINING and stores the close reason."""
    conn.state = CONN_STATE_DRAINING
    conn.close_error_code = cc.error_code
    var reason = List[UInt8]()
    for i in range(len(cc.reason_phrase)):
        reason.append(cc.reason_phrase[i])
    conn.close_reason = reason^
    events.connection_closed = True
    events.error_code = cc.error_code


def apply_max_data(mut conn: Connection, m: MaxDataFrame):
    """Apply a MAX_DATA frame: monotonically advance the
    connection's send-side flow-control limit."""
    if m.maximum_data > conn.max_data_send:
        conn.max_data_send = m.maximum_data


def apply_max_stream_data(mut conn: Connection, m: MaxStreamDataFrame):
    """Apply a MAX_STREAM_DATA frame: advance the per-stream send
    high-water-mark for the addressed stream (no-op if the stream
    has not been seen yet)."""
    var sid = m.stream_id
    var s_opt = conn.streams.get(sid)
    if Bool(s_opt):
        var s = s_opt.value()
        if m.maximum_stream_data > s.max_send_data:
            s.max_send_data = m.maximum_stream_data
        conn.streams[sid] = s


def apply_reset_stream(mut conn: Connection, rs: ResetStreamFrame):
    """Apply a RESET_STREAM frame: transition the stream to
    RESET_RECVD (no-op if the stream is unknown)."""
    var sid = rs.stream_id
    var s_opt = conn.streams.get(sid)
    if Bool(s_opt):
        var s = s_opt.value()
        s.state = STREAM_STATE_RESET_RECVD
        conn.streams[sid] = s


def apply_stop_sending(mut conn: Connection, ss: StopSendingFrame):
    """Apply a STOP_SENDING frame: transition the stream to
    RESET_SENT (no-op if the stream is unknown)."""
    var sid = ss.stream_id
    var s_opt = conn.streams.get(sid)
    if Bool(s_opt):
        var s = s_opt.value()
        s.state = STREAM_STATE_RESET_SENT
        conn.streams[sid] = s


def apply_handshake_done(mut conn: Connection, mut events: ConnectionEvents):
    """Apply a HANDSHAKE_DONE frame: flip the connection to
    ESTABLISHED and surface the event."""
    conn.handshake_complete = True
    conn.state = CONN_STATE_ESTABLISHED
    events.handshake_done = True


def apply_new_connection_id(
    mut conn: Connection,
    ncid: NewConnectionIdFrame,
    mut events: ConnectionEvents,
) raises:
    """Apply a NEW_CONNECTION_ID frame (RFC 9000 §19.15).

    Records the peer's spare Source CID + stateless-reset token in
    :attr:`Connection.peer_cids`, then honors ``retire_prior_to``:
    every stored CID with a lower sequence number is dropped and a
    RETIRE_CONNECTION_ID is queued in
    :attr:`ConnectionEvents.retire_connection_ids` (§5.1.2). If the
    active DCID is among those retired, the active sequence advances
    to this freshly issued CID.

    Validates the wire fields at this trust boundary: CID length in
    [1, 20], a 16-byte reset token, and ``retire_prior_to`` no
    greater than ``sequence_number`` (a PROTOCOL_VIOLATION per
    §19.15 otherwise).
    """
    if (
        len(ncid.connection_id) < _CID_MIN_LEN
        or len(ncid.connection_id) > _CID_MAX_LEN
    ):
        raise Error("quic state: NEW_CONNECTION_ID length out of [1, 20]")
    if len(ncid.stateless_reset_token) != _RESET_TOKEN_LEN:
        raise Error(
            "quic state: NEW_CONNECTION_ID reset token must be 16 bytes"
        )
    if ncid.retire_prior_to > ncid.sequence_number:
        raise Error(
            "quic state: NEW_CONNECTION_ID retire_prior_to > sequence_number"
        )
    conn.peer_cids[ncid.sequence_number] = _PeerConnId(
        cid=ncid.connection_id.copy(),
        reset_token=ncid.stateless_reset_token.copy(),
    )
    if ncid.retire_prior_to > UInt64(0):
        var to_retire = List[UInt64]()
        for entry in conn.peer_cids.items():
            if entry.key < ncid.retire_prior_to:
                to_retire.append(entry.key)
        for i in range(len(to_retire)):
            _ = conn.peer_cids.pop(to_retire[i])
            events.retire_connection_ids.append(to_retire[i])
        if conn.active_dcid_seq < ncid.retire_prior_to:
            conn.active_dcid_seq = ncid.sequence_number


def apply_retire_connection_id(
    mut conn: Connection, rcid: RetireConnectionIdFrame
):
    """Apply a RETIRE_CONNECTION_ID frame (RFC 9000 §19.16): the
    peer is retiring one of the CIDs WE issued. The state-machine
    layer has no local-CID table to prune (the driver owns SCID
    issuance), so this is bookkeeping-only: activity + ack-pending
    are recorded by the caller. Kept as a named helper for symmetry
    and so the driver can hook CID-pool accounting later."""
    pass


def apply_path_challenge(
    mut conn: Connection,
    pc: PathChallengeFrame,
    mut events: ConnectionEvents,
) raises:
    """Apply a PATH_CHALLENGE frame (RFC 9000 §19.17): queue a
    PATH_RESPONSE echoing the exact 8-byte payload so the peer can
    validate the path (§8.2). Validates the fixed 8-byte length at
    this trust boundary."""
    if len(pc.data) != _PATH_DATA_LEN:
        raise Error("quic state: PATH_CHALLENGE data must be 8 bytes")
    events.path_responses.append(pc.data.copy())


def apply_path_response(
    mut conn: Connection,
    pr: PathResponseFrame,
    mut events: ConnectionEvents,
) raises:
    """Apply a PATH_RESPONSE frame (RFC 9000 §19.18): if it echoes
    our outstanding PATH_CHALLENGE byte-for-byte, the probed path is
    validated -- clear the probe and surface ``path_validated`` so
    the driver can promote the new path (§8.2). A non-matching
    response is ignored (a stale or spoofed echo). Validates the
    fixed 8-byte length at this trust boundary."""
    if len(pr.data) != _PATH_DATA_LEN:
        raise Error("quic state: PATH_RESPONSE data must be 8 bytes")
    if len(conn.outgoing_path_challenge) != _PATH_DATA_LEN:
        return
    for i in range(_PATH_DATA_LEN):
        if pr.data[i] != conn.outgoing_path_challenge[i]:
            return
    conn.path_validated = True
    conn.outgoing_path_challenge = List[UInt8]()
    events.path_validated = True


# ── Frame-dispatch adapter ────────────────────────────────────────────────


@fieldwise_init
struct _ConnFrameHandler(FrameHandler):
    """:trait:`FrameHandler` impl bridging the parser into the
    connection state machines.

    Holds raw addresses for the caller's :class:`Connection` and
    :class:`ConnectionEvents` so the dispatcher can mutate them
    in place without owning them. The handler is built once per
    :func:`handle_frame_buf` call and discarded immediately; the
    pointer lifetimes are bounded by the calling stack frame.
    """

    var conn_addr: Int
    var events_addr: Int
    var now_us: UInt64

    @always_inline
    def _conn(self) -> UnsafePointer[Connection, MutUntrackedOrigin]:
        return UnsafePointer[Connection, MutUntrackedOrigin](
            unsafe_from_address=self.conn_addr
        )

    @always_inline
    def _events(
        self,
    ) -> UnsafePointer[ConnectionEvents, MutUntrackedOrigin]:
        return UnsafePointer[ConnectionEvents, MutUntrackedOrigin](
            unsafe_from_address=self.events_addr
        )

    def on_padding(mut self, count: Int) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=False)

    def on_ping(mut self) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_ack(mut self, ack: AckFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=False)
        apply_ack(self._conn()[], ack)
        var acked = expand_ack_ranges(ack)
        for i in range(len(acked)):
            self._events()[].acked_packets.append(acked[i])

    def on_reset_stream(mut self, rs: ResetStreamFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_reset_stream(self._conn()[], rs)

    def on_stop_sending(mut self, ss: StopSendingFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_stop_sending(self._conn()[], ss)

    def on_crypto(mut self, c: CryptoFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        # CRYPTO frames carry TLS-handshake bytes that the sans-I/O
        # state machine deliberately does not interpret. Surface the
        # raw frame on :class:`ConnectionEvents` so the reactor
        # can forward the bytes to the rustls QUIC
        # session at the matching encryption level after this
        # :func:`handle_frame_buf` call returns. Handshake completion
        # is still signalled separately via
        # :func:`mark_handshake_complete`.
        self._events()[].crypto_frames.append(c.copy())

    def on_new_token(mut self, t: NewTokenFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_stream(mut self, sf: StreamFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_stream(self._conn()[], sf, self._events()[])

    def on_max_data(mut self, m: MaxDataFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_max_data(self._conn()[], m)

    def on_max_stream_data(mut self, m: MaxStreamDataFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_max_stream_data(self._conn()[], m)

    def on_max_streams(mut self, m: MaxStreamsFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_data_blocked(mut self, db: DataBlockedFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_stream_data_blocked(mut self, sdb: StreamDataBlockedFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_streams_blocked(mut self, sb: StreamsBlockedFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)

    def on_new_connection_id(mut self, ncid: NewConnectionIdFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_new_connection_id(self._conn()[], ncid, self._events()[])

    def on_retire_connection_id(mut self, rcid: RetireConnectionIdFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_retire_connection_id(self._conn()[], rcid)

    def on_path_challenge(mut self, pc: PathChallengeFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_path_challenge(self._conn()[], pc, self._events()[])

    def on_path_response(mut self, pr: PathResponseFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_path_response(self._conn()[], pr, self._events()[])

    def on_connection_close(mut self, cc: ConnectionCloseFrame) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=False)
        apply_connection_close(self._conn()[], cc, self._events()[])

    def on_handshake_done(mut self) raises:
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        apply_handshake_done(self._conn()[], self._events()[])

    def on_datagram(mut self, dg: DatagramFrame) raises:
        # RFC 9221 §5: DATAGRAM frames are ack-eliciting; the payload
        # is surfaced for the reactor/application to drain. The
        # sans-I/O layer keeps no per-datagram ordering or retransmit
        # state -- they are unreliable by contract.
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)
        self._events()[].datagrams.append(dg.data.copy())

    def on_unknown(mut self, type_id: UInt64) raises:
        # Forward-compatibility: extension codepoints are ignored
        # at the state-machine layer; the reactor wrapper may
        # still log them if it cares.
        _arrive(self._conn()[], self.now_us, ack_eliciting=True)


# ── Top-level frame ingestion ─────────────────────────────────────────────


def handle_frame_buf(
    mut conn: Connection,
    buf: Span[UInt8, _],
    now_us: UInt64,
    mut events: ConnectionEvents,
) raises -> Int:
    """Apply one wire frame from the start of ``buf`` to the
    connection state machines.

    Returns the number of bytes the dispatcher consumed; the
    caller drains the rest of a packet payload by advancing its
    cursor and re-invoking the dispatcher on the remainder.
    Internally builds a small adapter implementing
    :trait:`flare.quic.frame.FrameHandler` and delegates to
    :func:`flare.quic.frame.parse_frame_into`.
    """
    if conn.state == CONN_STATE_CLOSED:
        # Drop bytes silently — caller will advance past closed
        # connections in its packet drain.
        return len(buf)
    var conn_addr = Int(UnsafePointer[Connection, _](to=conn))
    var events_addr = Int(UnsafePointer[ConnectionEvents, _](to=events))
    var h = _ConnFrameHandler(
        conn_addr=conn_addr, events_addr=events_addr, now_us=now_us
    )
    return parse_frame_into(buf, h)


def mark_handshake_complete(
    mut conn: Connection, now_us: UInt64, mut events: ConnectionEvents
):
    """Explicit hook the TLS handshake adapter calls when its key
    schedule reaches HANDSHAKE_DONE. Mirrors the
    :data:`FRAME_TYPE_HANDSHAKE_DONE` path so the connection state
    advances regardless of which side the signal came from.
    """
    if conn.state == CONN_STATE_HANDSHAKE:
        conn.handshake_complete = True
        conn.state = CONN_STATE_ESTABLISHED
        events.handshake_done = True
        conn.last_activity_us = now_us


def is_idle_timeout_expired(conn: Connection, now_us: UInt64) -> Bool:
    """Whether the idle timeout has elapsed since ``last_activity_us``.

    Returns ``False`` if no traffic has been observed yet (the
    handshake hasn't started); the reactor uses this to retire
    stalled connections per RFC 9000 §10.1.
    """
    if conn.last_activity_us == UInt64(0):
        return False
    if conn.idle_timeout_us == UInt64(0):
        return False
    return (now_us - conn.last_activity_us) >= conn.idle_timeout_us


def connection_close(
    mut conn: Connection,
    error_code: UInt64,
    reason: String,
    application: Bool = False,
):
    """Mark the connection as closing with the given error code +
    reason. The driver later emits a CONNECTION_CLOSE frame and
    transitions to DRAINING.
    """
    if (
        conn.state == CONN_STATE_CLOSING
        or conn.state == CONN_STATE_DRAINING
        or conn.state == CONN_STATE_CLOSED
    ):
        return
    conn.state = CONN_STATE_CLOSING
    conn.close_error_code = error_code
    var bytes = List[UInt8]()
    for c in reason.as_bytes():
        bytes.append(c)
    conn.close_reason = bytes^
