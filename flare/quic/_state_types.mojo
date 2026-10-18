"""QUIC stream state, the per-stream record, and the events a frame
batch produces. Re-exported by :mod:`flare.quic.state`.
"""

from std.collections import List, Optional

from ._frame_types import (
    EcnCounts,
    CryptoFrame,
    StopSendingFrame,
    StreamFrame,
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
struct Stream(Copyable, ImplicitlyCopyable):
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
    # The two halves of a bidirectional stream reset independently
    # (RFC 9000 sec 3.1, 3.2), which the single ``state`` cannot show:
    # RESET_STREAM and STOP_SENDING / our own reset overwrote each other.
    # ``peer_reset``: the peer reset its send half (RESET_STREAM received).
    # ``send_reset``: our send half is reset (STOP_SENDING received, or we
    # reset it); no STREAM frames may follow.
    var peer_reset: Bool
    var send_reset: Bool


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
        peer_reset=False,
        send_reset=False,
    )


@fieldwise_init
struct ConnectionEvents(Copyable):
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
      :class:`flare.http3.Http3Connection.feed_stream_chunk` /
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
    var retired_local_cids: List[UInt64]
    """Sequence numbers of connection IDs we issued that the peer
    retired with RETIRE_CONNECTION_ID (§19.16); the driver stops routing
    them and issues replacements."""
    var path_validated: Bool
    """Set when an inbound PATH_RESPONSE matched our outstanding
    PATH_CHALLENGE: the new path is confirmed reachable (§8.2)."""
    var acked_ranges: List[UInt64]
    """Packet-number ranges inbound ACK frames acknowledged this tick
    (§19.3.1), as flat ``[lo, hi]`` pairs in descending order. Loss
    recovery retires its in-flight packets against them. It used to get
    the ranges expanded into at most 256 packet numbers, so with more
    than that in flight older acknowledged packets were later declared
    lost and re-sent."""
    var datagrams: List[List[UInt8]]
    """RFC 9221 DATAGRAM payloads received this tick. The reactor /
    application drains these after :func:`handle_frame_buf` returns;
    unreliable, unordered, and not retransmitted on loss."""
    var stop_sending_resets: List[StopSendingFrame]
    """STOP_SENDING frames (§19.5) received for a stream whose send half
    was not yet reset. RFC 9000 §3.5: the endpoint MUST answer each with a
    RESET_STREAM (the driver knows the final size); a stream already in
    ``Reset Sent`` is not listed, so the reply goes out once."""
    var ack_ecn: List[EcnCounts]
    """ECN counts (sec 19.3.2) of the ACK_ECN frames received this tick,
    in order; an ACK without counts adds nothing."""


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
        retired_local_cids=List[UInt64](),
        path_validated=False,
        acked_ranges=List[UInt64](),
        datagrams=List[List[UInt8]](),
        stop_sending_resets=List[StopSendingFrame](),
        ack_ecn=List[EcnCounts](),
    )
