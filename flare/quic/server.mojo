"""``flare.quic.server`` -- QUIC server reactor.

Wraps the sans-I/O QUIC connection state machine
(:class:`flare.quic.state.Connection`) in a UDP listener +
per-connection dispatcher. The per-datagram dispatch loop
threads bytes through :class:`OpenSslQuicCrypto` packet
protection, the transport-frame parser, and
:meth:`Connection.handle_frame` to produce
:class:`ConnectionEvents` for the H3 driver above; idle
timers sit on the shared TimerWheel.

## What ships here

- :class:`QuicServerConfig` -- bind configuration: host, port,
  rustls config carrier, idle timeout, max packet size.
- :class:`QuicListener` -- factory that owns a bound UDP
  socket plus the per-connection dispatch table. The :meth:`bind`
  factory opens the socket, :meth:`tick` drains one datagram
  (unit-testable), :meth:`run` is the blocking event loop, and
  :meth:`shutdown` requests a clean exit.
- :class:`QuicConnection` -- per-connection driver that
  composes the existing :class:`flare.quic.state.Connection`
  state machine with the rustls QUIC session.
- :class:`ConnectionIdTable` -- per-listener routing table from
  Connection ID to connection slot, used by the dispatch loop
  to route inbound datagrams via the Destination Connection ID
  in the packet header (RFC 9000 §5.1).

References:
- RFC 9000 §5 "Connections" -- Connection ID routing.
- RFC 9000 §10 "Connection Termination" -- idle / draining.
- RFC 9000 §17 "Packet Formats" -- long / short header parse
  for the dispatch path.
"""

# TODO(2026-08-31, track-quic-listener): this module is dominated by the
# single ``QuicListener`` struct (bind / tick / run / shutdown + the
# per-datagram dispatch loop). Mojo cannot split one struct's methods
# across files, so the file stays over the 1000-line bar; the value
# types (QuicServerConfig / QuicConnection / ConnectionIdTable) and pure
# helpers already moved to ``_server_types`` / ``_server_support``.
# Further shrinking needs the cold dispatch methods reworked into free
# functions. Allowlisted in tests/tools/check_reactor_size.sh until then.

from std.collections import Dict, List
from std.collections.span import Span
from std.os import getenv

from ..net.address import IpAddr, SocketAddr
from ..udp import UdpSocket
from ..udp.batch import (
    BatchReceiver,
    UdpBatchUnsupported,
    send_segmented,
    udp_batch_supported,
)
from flare.crypto.hmac import hmac_sha256

from .crypto import QuicAead
from .frame import (
    ConnectionCloseFrame,
    CryptoFrame,
    DataBlockedFrame,
    MaxDataFrame,
    MaxStreamDataFrame,
    MaxStreamsFrame,
    NewConnectionIdFrame,
    NewTokenFrame,
    PathResponseFrame,
    ResetStreamFrame,
    StreamDataBlockedFrame,
    StreamFrame,
    DatagramFrame,
    EcnCounts,
    encode_ack,
    encode_datagram,
    encode_connection_close,
    encode_crypto,
    encode_data_blocked,
    encode_handshake_done,
    encode_max_data,
    encode_max_stream_data,
    encode_max_streams,
    encode_new_connection_id,
    encode_new_token,
    encode_path_response,
    encode_ping,
    encode_reset_stream,
    encode_stream_data_blocked,
)
from .packet import (
    ConnectionId,
    InitialExtras,
    LongHeader,
    MAX_CID_LENGTH,
    PACKET_TYPE_INITIAL,
    QUIC_VERSION_1,
    PACKET_TYPE_HANDSHAKE,
    encode_long_header,
    parse_initial_extras,
    parse_long_header,
    parse_short_header,
)
from .protection import (
    decode_packet_number,
    protect_initial_packet,
)
from .varint import decode_varint, encode_varint
from .transport_params import (
    check_client_transport_params,
    decode_transport_parameters,
)
from .state import (
    CONN_STATE_CLOSING,
    CONN_STATE_DRAINING,
    MAX_QUEUED_DATAGRAM_BYTES,
    QUIC_FLOW_CONTROL_ERROR,
    QUIC_PROTOCOL_VIOLATION,
    QUIC_STREAM_LIMIT_ERROR,
    QUIC_STREAM_STATE_ERROR,
    Connection,
    ConnectionEvents,
    connection_close,
    empty_events,
    mark_handshake_complete,
    mark_local_stream_opened,
)
from ..http3.server import (
    H3_DATAGRAM_ERROR,
    H3_SERVER_CONTROL_STREAM_ID,
    Http3Connection,
    h3_error_code,
)
from ..http3.response_writer import (
    encode_response_data,
    encode_response_trailers,
)
from ..http.request import Request
from ..http.response import Response
from ..http.response_stream import ChunkSourceBox
from ..http.cancel import Cancel
from ..qpack import QpackHeader
from ..runtime import Pool
from .timers import (
    TIMER_KIND_ACK_DELAY,
    TIMER_KIND_IDLE,
    TIMER_KIND_PTO,
    decode_timer_token,
    encode_timer_token,
)
from ..runtime.timer_wheel import TimerWheel
from ..tls.rustls_quic import (
    QuicEncryptionLevel,
    RustlsQuicAcceptor,
    RustlsQuicConfig,
)
from ..tls._rustls_quic_ffi import (
    _do_accept,
    _do_feed_crypto,
    _do_have_keys,
    _do_header_decrypt,
    _do_header_encrypt,
    _do_install_early_keys,
    _do_is_handshake_complete,
    _do_key_update,
    _do_packet_decrypt,
    _do_packet_decrypt_1rtt,
    _do_packet_encrypt,
    _do_peer_transport_params,
    _do_session_free,
    _do_take_crypto,
)
from .packet import encode_short_header, packet_number_length
from .retry import (
    NEW_TOKEN_VERSION,
    encode_retry_packet,
    encode_version_negotiation,
    mint_new_token,
    mint_retry_token,
    validate_new_token,
    validate_retry_token,
)
from ._server_0rtt import (
    EarlyDataReplayGuard,
    EarlyDataStrikeSet,
    early_data_packet_len,
)
from ._server_migration import MigrationProbe, new_path_challenge
from ._server_support import (
    QUIC_CRYPTO_BUFFER_EXCEEDED,
    QUIC_TRANSPORT_PARAMETER_ERROR,
    _ACK_MAX_RANGES,
    _ack_contains,
    _CryptoReasm,
    _CryptoStream,
    _SessionSlot,
    _ack_from_ranges,
    _ack_record,
    _bufsize_from_env,
    _effective_idle_ms,
    _encode_h3_stream_frame,
    _inbound_level_for_datagram,
    _monotonic_ms,
    _random_bytes,
    _ready_sentinel,
)
from ._loss_recovery import LossRecovery
from ._worker_route import DatagramInbox, cid_owner, inbox_at
from ._server_types import (
    ConnectionIdTable,
    Http3Tunnel,
    QuicConnection,
    QuicServerConfig,
    _StreamTx,
    _encode_server_transport_params,
    cid_to_hex,
)


comptime _NEW_TOKEN_MAX_AGE_MS: UInt64 = 24 * 3600 * 1000
"""How long a NEW_TOKEN token is honoured."""


def _ip_bytes(peer: SocketAddr) -> List[UInt8]:
    """The client IP a NEW_TOKEN token is bound to (not the port)."""
    return List[UInt8](String(peer.ip).as_bytes())


comptime _MAX_CLOSING_MS: UInt64 = 10_000
"""Upper bound on the closing period (RFC 9000 sec 10.2: three PTOs).
Bounds how long a closed slot is retained when the PTO has backed off."""
comptime _MIN_INITIAL_DATAGRAM: Int = 1200
"""RFC 9000 sec 14.1: a server discards an Initial carried in a datagram
smaller than this. The floor is what keeps the 3x anti-amplification
budget worth something."""
comptime _HANDSHAKE_CHUNK: Int = 1100
"""Most CRYPTO bytes per Initial / Handshake packet, so every packet
fits a 1200-byte datagram with its header and AEAD tag."""
comptime _LONG_PACKET_OVERHEAD: Int = 80
"""Upper bound on a long-header packet's bytes beyond its CRYPTO data:
header with two 20-byte CIDs, length and packet-number fields, frame
header, AEAD tag."""

# Flow-control grant windows kept ahead of consumption so the peer
# never blocks mid-run (RFC 9000 sec 19.9 / 19.11). 64 MiB of
# connection credit and 4096 extra bidi streams comfortably cover a
# 30 s h2load run at the documented HTTP/3 rate.
comptime _MAX_DATA_WINDOW: UInt64 = 64 * 1024 * 1024
comptime _MAX_STREAMS_BIDI_WINDOW: UInt64 = 4096
comptime _MAX_STREAM_WINDOW: UInt64 = 16 * 1024 * 1024
"""Cap on the auto-tuned per-stream receive window."""
comptime _STREAM_PULL_HIGH_WATER: Int = 64 * 1024
"""A streaming response's source is not pulled while this many bytes
are still queued unsent on its stream: flow control or the congestion
window is holding them, and pulling more would only grow the queue."""
comptime _MAX_ISSUED_CIDS: UInt64 = 4
"""Connection IDs the server keeps issued at once, whatever larger
``active_connection_id_limit`` the peer allows: enough for migration
and rotation without a routing entry per CID the peer would buffer."""
comptime _H3_REQUEST_CANCELLED: UInt64 = 0x10C
"""RFC 9114 sec 8.1: the RESET_STREAM code for an abandoned response."""
comptime _GSO_MIN_DATAGRAMS: Int = 8
"""Stream bytes a drain must have queued, in datagrams, before it batches
its egress for GSO (see :attr:`QuicListener._gso_active`)."""
comptime _GSO_MAX_SEGMENTS: Int = 16
"""Most datagrams handed to the kernel in one GSO ``sendmsg``: enough to
cut the per-datagram syscall cost, small enough to keep each burst short
(quinn-udp sends at most 10 by default; the kernel limit is 64)."""
comptime _H3_NO_ERROR: UInt64 = 0x100
"""RFC 9114 sec 8.1: the code for a graceful close."""

# Max datagrams drained per reactor tick. Bounds the time spent in one
# tick so a single hot connection cannot starve the serve loop's H3
# pump / timer / egress pass, while amortizing that per-tick work over
# a burst of inbound datagrams. Measured sweet spot for the -m100 h3
# workload: draining too aggressively (e.g. 1024) delays egress within
# a tick and lowers throughput; 64 keeps RX and egress interleaved.
comptime _RX_BATCH: Int = 64

# Kernel UDP buffer sizes. Default 0 == leave the kernel default in
# place. Counter-intuitively, raising SO_RCVBUF on the single-reactor
# loopback h3 bench HURT both throughput and the p99.9 tail: a deeper
# kernel queue lets the reactor fall further behind during a burst, so
# queued datagrams age (bufferbloat) and median dropped ~3% while
# p99.9 doubled. The default-small buffer applies backpressure earlier
# and keeps the reactor closer to real time. The knob is still exposed
# for real-network deployments where the default rmem causes genuine
# drops -- set FLARE_QUIC_RCVBUF / FLARE_QUIC_SNDBUF (bytes) to raise
# it. The kernel doubles the request and clamps to
# net.core.{rmem,wmem}_max, so the effective size may be smaller.
comptime _DEFAULT_QUIC_RCVBUF: Int = 0
comptime _DEFAULT_QUIC_SNDBUF: Int = 0


# -- Listener -----------------------------------------------------------


struct QuicListener(Movable):
    """UDP listener + per-connection dispatcher.

    Long-lived. One instance per QUIC server bind. Construct via
    :meth:`bind`; the constructor opens the UDP socket and binds
    it. The reactor drives the listener via :meth:`run` (blocks
    until :meth:`shutdown`) or :meth:`tick` (single iteration --
    used by tests + by callers that want to multiplex the event
    loop with other work).
    """

    var config: QuicServerConfig
    var cid_table: ConnectionIdTable
    var connections: List[QuicConnection]
    """Connection slab. Per-connection state lives here; the
    :class:`ConnectionIdTable` maps each Connection ID to the
    slot index. Slots are append-only; the closed-slot sweeper
    runs at the end of every :meth:`advance_timers` call so
    idle-timed-out connections get reaped against the same
    monotonic clock the wheel uses."""
    var _next_serial: UInt64
    var tls_acceptor: RustlsQuicAcceptor
    """Long-lived rustls QUIC acceptor built once at
    :meth:`bind` from :attr:`QuicServerConfig.rustls_config`.
    Owns the rustls ``ServerConfig`` (cert + key + ALPN list)
    that every per-connection session derives keys from. When
    the caller passes the default (empty PEM)
    :class:`RustlsQuicConfig`, the FFI returns a NULL handle and
    the dispatch path routes all CRYPTO frames through the
    silent-drop branch -- existing tests that bind a listener
    purely to exercise the UDP / routing / timer surfaces
    continue to work without supplying real PEM material."""
    var free_slots: List[Int]
    """Reclaimed slots ready for the next accepted connection; see
    :meth:`_reclaim_slot`."""
    var slot_free: List[Bool]
    """Per-slot: on :attr:`free_slots`, so never reclaimed twice."""
    var tls_sessions: List[_SessionSlot]
    """Parallel slab to :attr:`connections`: one rustls QUIC
    session carrier per :class:`QuicConnection` slot. Each
    :class:`_SessionSlot` holds the raw rustls
    ``Box<Session>*`` (or 0 for the NULL-PEM sentinel) plus the
    current outbound encryption level. The slab owns the
    handles; :meth:`__deinit__` walks every non-zero handle through
    :func:`flare.tls._rustls_quic_ffi._do_session_free` exactly
    once at listener teardown. The shared FFI library handle for
    every per-slot call is borrowed from
    :attr:`tls_acceptor._lib` so the .so stays mapped across
    every feed-crypto / take-crypto roundtrip."""
    var tls_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the INITIAL level.
    Each successful :meth:`feed_crypto` is followed by
    :meth:`take_crypto` and the resulting bytes append here;
    :meth:`_drain_and_send` wraps them in a CRYPTO frame inside an
    Initial-level packet, AEAD-protects with
    :func:`protect_initial_packet`, and emits via :meth:`send_to`.
    Cleared after every successful drain."""
    var tls_handshake_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the HANDSHAKE
    level. Populated by :meth:`_dispatch_crypto_frames` after
    rustls emits ``KeyChange::Handshake``. Drained by the egress
    builder which wraps each batch in a CRYPTO frame inside a
    Handshake-level packet, AEAD-protects via
    :class:`RustlsQuicSession.packet_encrypt` at level 2, and
    emits via :meth:`send_to`."""
    var crypto_reasm: List[_CryptoReasm]
    """Per-slot inbound CRYPTO reassembly state (one per
    encryption level). Parallel slab to :attr:`connections`;
    reorders + coalesces inbound CRYPTO fragments so rustls's
    in-order ``read_hs`` sees a contiguous handshake stream."""
    var tls_1rtt_egress_queues: List[List[UInt8]]
    """Per-slot outbound CRYPTO byte queue at the 1-RTT
    (APPLICATION) level. Populated by
    :meth:`_dispatch_crypto_frames` after rustls emits
    ``KeyChange::OneRtt``. Drained by the egress builder which
    encodes each batch into a 1-RTT short-header packet,
    AEAD-protects via :class:`RustlsQuicSession.packet_encrypt`
    at level 3, and emits via :meth:`send_to`."""
    var peer_addrs: List[SocketAddr]
    """Per-slot peer UDP address. Parallel slab to
    :attr:`connections` -- captured in :meth:`_accept_initial`
    from the inbound datagram's sender. The egress path reads
    this to call :meth:`send_to(slot, ...)` without re-parsing
    the inbound datagram."""
    var migration_probe: List[MigrationProbe]
    """Per-slot connection-migration path-validation state (RFC 9000
    sec 8 / sec 9): the candidate address under validation plus the
    anti-amplification byte counters. Default (no migration) is an
    idle probe that costs nothing."""
    var loss: List[LossRecovery]
    """Per-slot RFC 9002 loss-recovery state. Parallel slab to
    :attr:`connections`, grown in :meth:`_accept_initial` alongside the
    others. ``LossRecovery`` is Movable but not Copyable, so this slab
    is read through ``self.loss[slot].method()`` or a ``ref`` binding --
    never the ``.copy()`` idiom the Copyable slabs use."""
    var loss_init: List[LossRecovery]
    """Per-slot loss recovery for the CRYPTO packets sent in the
    Initial space (RFC 9002 sec 6, separate packet-number space). A
    lost server flight used to be recovered only by the idle timeout;
    these and :attr:`loss_hs` re-send it on loss or PTO."""
    var loss_hs: List[LossRecovery]
    """The same for the Handshake space."""
    var rx_1rtt_ranges: List[List[UInt64]]
    """Per-slot received 1-RTT packet numbers, stored as disjoint
    ranges (flat [low, high] pairs, descending by high). The ACK
    frame is built from these so we acknowledge only packets we
    actually received: the peer skips packet numbers to detect
    optimistic-ACK attacks (RFC 9000 sec 21.4), so acking a
    contiguous span would acknowledge a never-sent number and the
    peer would close with PROTOCOL_VIOLATION (sec 13.1)."""
    var rx_1rtt_ack_pending: List[Bool]
    """Per-slot flag: an ack-eliciting 1-RTT packet arrived and
    has not yet been acknowledged. Cleared once the egress path
    emits the ACK frame."""
    var handshake_done_sent: List[Bool]
    """Per-slot flag: the server has emitted HANDSHAKE_DONE
    (RFC 9000 sec 19.20) once the 1-RTT keys installed. Confirms
    the handshake so the peer stops retransmitting its Finished
    and discards Handshake keys."""
    var next_local_cid_seq: List[UInt64]
    """Per-slot next NEW_CONNECTION_ID sequence number to issue
    (RFC 9000 sec 19.15). The handshake CID is sequence 0; the
    server issues sequence 1 with the first 1-RTT flight so a
    migrating client has a spare Destination CID to switch to
    (sec 9.5 requires a fresh CID per path)."""
    var pending_migration_tx: List[List[UInt8]]
    """Per-slot buffer of already-encoded 1-RTT migration frames
    (PATH_RESPONSE echoes for inbound PATH_CHALLENGEs) awaiting
    egress. Stashed in :meth:`_process_one_packet` from the
    surfaced :class:`ConnectionEvents` and flushed by the 1-RTT
    coalesced drain."""
    var rx_stream_bytes: List[UInt64]
    """Per-slot cumulative count of inbound stream payload bytes.
    Feeds the connection-level MAX_DATA the egress path advertises
    so the peer's flow-control window never closes (RFC 9000 sec
    19.9)."""
    var rx_bidi_stream_count: List[UInt64]
    """Per-slot count of client-initiated bidi streams observed
    (largest ``(stream_id >> 2) + 1``). Feeds the MAX_STREAMS_BIDI
    grant (RFC 9000 sec 19.11) so HTTP/3, which opens one bidi
    stream per request, can keep opening streams past the initial
    transport-parameter limit."""
    var http3_connections: List[Http3Connection]
    """Per-slot HTTP/3 connection driver. Parallel slab to
    :attr:`connections` -- one :class:`flare.http3.Http3Connection`
    instance per QUIC connection. Allocated in
    :meth:`_accept_initial` so every accepted connection has its
    H3 driver ready; STREAM frames from the post-handshake 1-RTT
    payload route through :meth:`_route_http3_stream_chunks` into
    the matching slot.

    The slab carries the H3 driver unconditionally rather than
    waiting for the ``h3`` ALPN to be negotiated. The QUIC
    layer cannot inspect ALPN without finishing the rustls
    handshake and we want the slab indices to stay in lockstep
    with :attr:`connections`. The H3 driver itself drops
    non-H3 traffic (the STREAM frames simply never reach
    :meth:`Http3Connection.feed_stream_chunk` until 1-RTT keys
    install, at which point the peer already negotiated H3 via
    ALPN by definition)."""
    var _drain_deadline_ms: UInt64
    """Monotonic ms by which a graceful drain closes every connection;
    0 when not draining (see :meth:`begin_drain`)."""
    var _open_sources: Int
    """Streaming responses whose chunk source is still open, across
    every slot; lets :meth:`pump_http3_streams` return at once when 0."""
    var early_strike: EarlyDataStrikeSet
    """Listener-level cross-connection 0-RTT replay defense (RFC 9001
    sec 9.2). Keyed on each accepted connection's original DCID with a
    time window from :attr:`QuicServerConfig.early_data_strike_window_ms`.
    Consulted once per connection on its first 0-RTT packet so a
    captured first flight replayed as a fresh accept is refused. Idle
    (never populated) unless 0-RTT is enabled."""
    var timer_wheel: TimerWheel
    """Per-listener :class:`flare.runtime.timer_wheel.TimerWheel`
    driving idle timeouts. Each scheduled timer's token is
    :func:`flare.quic.timers.encode_timer_token(kind, slot)`;
    :meth:`advance_timers` dispatches each fired token to the
    matching :class:`QuicConnection` callback."""
    var _reset_key: List[UInt8]
    """Listener-wide static key (32 bytes from urandom) for deriving
    stateless-reset tokens (RFC 9000 sec 10.3.1). The token for a CID is
    ``HMAC-SHA256(_reset_key, cid)[:16]``: deterministic so a peer that
    stored the token (issued via NEW_CONNECTION_ID) recognizes the reset,
    yet unguessable without the key. The same key signs every issued
    token and every emitted stateless reset, so they always match."""
    var _retry_key: List[UInt8]
    """Listener-wide static key (32 bytes from urandom) for HMAC Retry
    tokens (RFC 9000 sec 8.1 address validation). Only used when
    :attr:`QuicServerConfig.require_address_validation` is set; signs
    every minted token and validates every replayed one."""
    var _socket: UdpSocket
    var _local_addr: SocketAddr
    var _stopping: Bool
    """Set by :meth:`shutdown`. Read by :meth:`run` at the top of
    every loop iteration so the event loop exits cleanly after
    the next ``recv_from`` returns or times out."""
    var _rx_batch: BatchReceiver
    """Reusable ``recvmmsg`` vector that drains a burst of inbound
    datagrams in one syscall (RFC-agnostic kernel optimization).
    Sized to :data:`_RX_BATCH` x ``max_udp_payload_size``."""
    var _gso_ok: Bool
    """Latched: UDP GSO (``UDP_SEGMENT``) egress is usable. Flipped off
    for good the first time the kernel or NIC refuses a segmented send,
    after which every datagram goes out alone (the quinn-udp fallback).
    ``FLARE_QUIC_NO_GSO=1`` disables it."""
    var _gso_active: Bool
    """GSO batching is on for the drain in progress: set only when the
    drain has at least :data:`_GSO_MIN_DATAGRAMS` datagrams of stream
    data to send. Holding a few small responses back until the end of the
    drain delays the client more than the saved syscalls are worth."""
    var _gso_buf: List[UInt8]
    """Datagrams queued for one segmented send: equal-size segments,
    the last one possibly shorter."""
    var _gso_seg: Int
    var _gso_count: Int
    var _gso_peer: SocketAddr
    var _fwd_data: List[UInt8]
    var _fwd_lens: List[Int]
    var _fwd_peers: List[SocketAddr]
    """Scratch for the datagrams taken from this worker's inbox."""
    var _rcv_timeout_ms: Int
    """``SO_RCVTIMEO`` currently set on the socket (-1 before the first
    :meth:`tick`)."""
    var _rx_batch_ok: Bool
    """Latched capability flag: ``True`` while the batched
    ``recvmmsg`` drain is usable. Flipped to ``False`` permanently on
    the first ``ENOSYS`` (kernel without the syscall) so the reactor
    falls back to the per-datagram ``try_recv_from`` loop."""
    var _rx_ecn: Int
    """ECN codepoint of the datagram being dispatched (0 when unknown)."""
    var _ecn_marking: Bool
    """Sent datagrams are marked ECT(0) (``config.ecn``, until a
    connection fails ECN validation)."""

    def __init__(
        out self,
        config: QuicServerConfig,
        var sock: UdpSocket,
        addr: SocketAddr,
        var tls_acceptor: RustlsQuicAcceptor,
    ) raises:
        """Wrap an already-bound :class:`UdpSocket`. Internal --
        callers use :meth:`bind`."""
        self.config = config.copy()
        self.cid_table = ConnectionIdTable()
        self.connections = List[QuicConnection]()
        self._next_serial = 1
        self.tls_acceptor = tls_acceptor^
        self.tls_sessions = List[_SessionSlot]()
        self.tls_egress_queues = List[List[UInt8]]()
        self.tls_handshake_egress_queues = List[List[UInt8]]()
        self.crypto_reasm = List[_CryptoReasm]()
        self.tls_1rtt_egress_queues = List[List[UInt8]]()
        self.peer_addrs = List[SocketAddr]()
        self.migration_probe = List[MigrationProbe]()
        self.loss = List[LossRecovery]()
        self.loss_init = List[LossRecovery]()
        self.loss_hs = List[LossRecovery]()
        self.rx_1rtt_ranges = List[List[UInt64]]()
        self.rx_1rtt_ack_pending = List[Bool]()
        self.handshake_done_sent = List[Bool]()
        self.next_local_cid_seq = List[UInt64]()
        self.pending_migration_tx = List[List[UInt8]]()
        self.rx_stream_bytes = List[UInt64]()
        self.rx_bidi_stream_count = List[UInt64]()
        self.free_slots = List[Int]()
        self.slot_free = List[Bool]()
        self.http3_connections = List[Http3Connection]()
        self._open_sources = 0
        self._drain_deadline_ms = 0
        self.early_strike = EarlyDataStrikeSet(
            window_ms=config.early_data_strike_window_ms
        )
        # Anchored at the clock advance_timers is driven by. At 0, the
        # first advance walked every millisecond since boot (about 10^9
        # ticks at a day's uptime) and fired every armed timer at once.
        self.timer_wheel = TimerWheel(now_ms=_monotonic_ms())
        self._reset_key = _random_bytes(32)
        # Workers share the token key, so a NEW_TOKEN token one issued is
        # honoured by the worker a later connection lands on.
        self._retry_key = _random_bytes(32)
        if len(config.cid_route_key) > 0:
            self._retry_key = hmac_sha256(
                config.cid_route_key, List[UInt8]("flare token key".as_bytes())
            )
        self._socket = sock^
        self._local_addr = addr
        self._stopping = False
        self._rx_batch = BatchReceiver(
            capacity=_RX_BATCH,
            max_payload=Int(config.max_udp_payload_size),
        )
        # Batched recvmmsg drain is on by default on Linux. Operators
        # can force the per-datagram path (e.g. to A/B the syscall-
        # batching win, or work around an exotic kernel) by setting
        # FLARE_QUIC_NO_BATCH=1.
        self._gso_ok = udp_batch_supported() and (
            getenv("FLARE_QUIC_NO_GSO", "0") != "1"
        )
        self._gso_active = False
        self._gso_buf = List[UInt8]()
        self._gso_seg = 0
        self._gso_count = 0
        self._gso_peer = addr
        self._rcv_timeout_ms = -1
        self._fwd_data = List[UInt8]()
        self._fwd_lens = List[Int]()
        self._fwd_peers = List[SocketAddr]()
        self._rx_ecn = 0
        self._ecn_marking = config.ecn and udp_batch_supported()
        self._rx_batch_ok = udp_batch_supported() and (
            getenv("FLARE_QUIC_NO_BATCH", "0") != "1"
        )

    def __deinit__(deinit self):
        """Drop the listener: release every rustls session in
        the slab exactly once.

        Each :class:`_SessionSlot` is a non-owning carrier; the
        slab itself is the unique owner of the underlying
        ``Box<Session>*`` allocations rustls produced via
        :func:`_do_accept`. The free routes through
        :meth:`RustlsQuicAcceptor.free_session` so Mojo's
        ``deinit`` rule (no sub-field access during ``deinit``)
        is respected -- the acceptor borrows ``self`` (and its
        ``_lib``) by reference rather than via a sub-field of
        the listener.
        """
        for i in range(len(self.tls_sessions)):
            var h = self.tls_sessions[i].handle
            if h != 0:
                self.tls_acceptor.free_session(h)
        # Free any HTTP/3 streaming sources still open at teardown (a
        # connection dropped mid-stream). The ChunkSourceBox boxed in
        # the pool owns the concrete source; free it exactly once.
        for i in range(len(self.connections)):
            for entry in self.connections[i].h3_tx.items():
                if entry.value.src_addr != 0:
                    Pool[ChunkSourceBox].free(entry.value.src_addr)

    @staticmethod
    def bind(config: QuicServerConfig) raises -> QuicListener:
        """Open the UDP socket and bind it to ``config.host`` /
        ``config.port``. Returns a ready-to-run listener.

        If ``config.port == 0`` the kernel picks an ephemeral
        port; read it back via :meth:`local_addr`.

        Constructs the per-listener rustls QUIC acceptor from
        ``config.rustls_config`` at bind time so each accepted
        connection's TLS session is materialized against the
        same long-lived ``ServerConfig``. An empty / malformed
        PEM does not raise here; the acceptor
        surfaces a NULL handle and CRYPTO bytes route through
        the silent-drop branch.
        """
        if config.http3.h3_datagram and config.max_datagram_frame_size == 0:
            raise Error(
                "QuicListener.bind: http3.h3_datagram needs"
                " max_datagram_frame_size > 0 (RFC 9297 sec 2.1.1)"
            )
        var ip = IpAddr.parse(config.host)
        var addr = SocketAddr(ip, config.port)
        var sock = UdpSocket.bind(addr, reuse_port=config.num_workers > 1)
        # UDP buffer sizing is opt-in (default keeps the kernel
        # default; see _DEFAULT_QUIC_RCVBUF for why raising it hurt the
        # loopback bench). When the env knob requests a non-zero size we
        # apply it; the kernel clamps to net.core.{rmem,wmem}_max, so a
        # failure (or a smaller effective size) is non-fatal.
        var rcvbuf = _bufsize_from_env(
            "FLARE_QUIC_RCVBUF", _DEFAULT_QUIC_RCVBUF
        )
        if rcvbuf > 0:
            try:
                sock.set_recv_buffer(rcvbuf)
            except:
                pass
        var sndbuf = _bufsize_from_env(
            "FLARE_QUIC_SNDBUF", _DEFAULT_QUIC_SNDBUF
        )
        if sndbuf > 0:
            try:
                sock.set_send_buffer(sndbuf)
            except:
                pass
        var actual = sock.local_addr()
        # Read clients' ECN marks; mark ours ECT(0) when asked.
        sock.set_ecn(2 if config.ecn else 0)
        var acceptor = RustlsQuicAcceptor(config.rustls_config.copy())
        var cfg = config.copy()
        if cfg.num_workers > 1 and len(cfg.cid_route_key) == 0:
            cfg.cid_route_key = _random_bytes(32)
        return QuicListener(cfg, sock^, actual, acceptor^)

    def local_addr(self) -> SocketAddr:
        """Return the address the UDP socket is actually bound to.
        After :meth:`bind` with ``config.port == 0`` this reports
        the kernel-chosen ephemeral port."""
        return self._local_addr

    def bound(self) -> Bool:
        """Whether the UDP socket is bound. True for every
        listener returned by :meth:`bind`."""
        return True

    def connection_count(self) -> Int:
        """Number of connection slots currently allocated."""
        return len(self.connections)

    def dispatch_datagram(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Route a single UDP datagram to the right connection slot.

        Parses the first byte to pick long vs short header,
        extracts the Destination Connection ID, looks it up in
        :attr:`cid_table`, and either:

        * Routes the datagram to the existing slot via
          :meth:`_handle_inbound`. Decryption failures are caught
          and converted to silent drops so a single bad sender
          can't poison the listener.
        * Allocates a new slot for an Initial packet with an
          unknown DCID (the QUIC accept path -- RFC 9000 §7),
          then drives the same inbound path on the new connection
          so the first Initial advances the state machine.
        * Returns ``-1`` to drop short-header packets with
          unknown DCIDs (those datagrams are silently
          discarded).
        """
        if len(datagram) < 1:
            return -1
        var first = Int(datagram[0])
        var is_long = (first & 0x80) != 0
        var slot: Int
        if is_long:
            slot = self._dispatch_long(datagram, peer)
        else:
            slot = self._dispatch_short(datagram, peer)
            # Unknown-DCID short-header datagram (RFC 9000 sec 10.3): the
            # peer thinks a connection exists that we have no state for.
            # Instead of a silent drop, send a stateless reset so the peer
            # tears the dead connection down promptly rather than waiting
            # out its idle timeout. Bounded + loop-safe by
            # :meth:`_build_stateless_reset`.
            if slot < 0:
                if not self._forward_foreign(datagram, peer):
                    self._maybe_send_stateless_reset(datagram, peer)
                return -1
            # Connection migration (RFC 9000 sec 9): a short-header
            # (1-RTT) packet routed by a known DCID but arriving from
            # a new source address means the client moved paths (NAT
            # rebind or an explicit migrate()). Follow it so the
            # egress + PATH_RESPONSE go back to where the client now
            # is.
            # RFC 9000 sec 8 / sec 9 path validation: a 1-RTT packet
            # from a new source means the client moved paths. A strict
            # egress hold -- do NOT switch the egress address to the new
            # path yet (the prior "follow immediately" let large 1-RTT
            # responses reflect off the server to a spoofed source).
            # Instead start a server-initiated PATH_CHALLENGE probe to
            # the candidate, keep all non-probe egress on the validated
            # path (:attr:`peer_addrs`), and only promote the candidate
            # once the client echoes our challenge (see
            # :meth:`_process_one_packet`). Probe egress to the
            # unvalidated candidate is bounded at 3x received bytes
            # (sec 8.1 / sec 21.5.4) by :meth:`_drain_migration_probe`.
            #
            # Only once the datagram has authenticated. The probe
            # used to start on the header alone, before decryption, so
            # a spoofed short-header packet with a known DCID restarted
            # validation and aimed PATH_CHALLENGEs at any address.
            if slot >= 0 and slot < len(self.connections):
                var authed = self._handle_inbound(slot, datagram)
                if (
                    authed
                    and slot < len(self.peer_addrs)
                    and self.peer_addrs[slot] != peer
                ):
                    self._begin_path_validation(slot, peer, len(datagram))
            return slot
        if slot >= 0 and slot < len(self.connections):
            _ = self._handle_inbound(slot, datagram)
        return slot

    def _handle_inbound(
        mut self, slot: Int, datagram: Span[UInt8, _]
    ) raises -> Bool:
        """Decrypt + dispatch one inbound datagram by encryption
        level.

        Initial packets decrypt off the DCID-derived secret in
        the sans-I/O connection. Handshake + 1-RTT packets carry
        keys rustls keeps sealed, so they decrypt through the
        slot's rustls session here (the listener owns the FFI
        handle) and the plaintext drives the state machine via
        :meth:`QuicConnection.dispatch_plaintext`.

        Decrypt and frame-parse failures drop silently per
        RFC 9001 sec 5.2; the slot stays alive for retransmits.
        On success, inbound CRYPTO bytes feed rustls via
        :meth:`_dispatch_crypto_frames` and the idle timer re-arms.

        Returns whether a 1-RTT packet in the datagram decrypted, which
        is what lets the caller trust the datagram's source address.
        """
        # The real clock. This was 0, so last_activity_us never moved
        # and the 0-RTT strike set, keyed on now_us // 1000, never let
        # an entry age out: once it filled, 0-RTT was refused for the
        # life of the listener.
        var now_us = _monotonic_ms() * UInt64(1000)
        # Closing state (RFC 9000 sec 10.2.1): nothing in the packet is
        # processed; it is answered with CONNECTION_CLOSE instead.
        if (
            slot >= 0
            and slot < len(self.connections)
            and self.connections[slot].closing
        ):
            self._answer_closing(slot)
            return False
        if slot >= 0 and slot < len(self.connections):
            self.connections[slot].amp_rx += len(datagram)
        # A datagram may carry several coalesced QUIC packets
        # (RFC 9000 sec 12.2): e.g. an Initial-level ACK ahead of a
        # Handshake packet carrying the client Finished, or a
        # Handshake packet ahead of the first 1-RTT request. Each
        # long-header packet's length is self-describing, so walk
        # the datagram packet by packet; a short-header (1-RTT)
        # packet is always last and runs to the datagram end.
        var n = len(datagram)
        var offset = 0
        var processed_any = False
        var authed_1rtt = False
        while offset < n:
            var first = Int(datagram[offset])
            # A zero first byte is PADDING that trails the last real
            # packet; nothing further to parse.
            if first == 0:
                break
            var sub = datagram[offset:]
            var lvl = _inbound_level_for_datagram(sub)
            var is_long = (first & 0x80) != 0
            var packet_len: Int
            if is_long:
                try:
                    var lh = parse_long_header(sub)
                    if lvl == QuicEncryptionLevel.INITIAL:
                        var ie = parse_initial_extras(sub, lh.payload_offset)
                        packet_len = (
                            lh.payload_offset
                            + ie.consumed
                            + Int(ie.payload_length)
                        )
                    elif lvl == QuicEncryptionLevel.HANDSHAKE:
                        var lv = decode_varint(sub[lh.payload_offset :])
                        packet_len = (
                            lh.payload_offset + lv.consumed + Int(lv.value)
                        )
                    elif (
                        lvl == QuicEncryptionLevel.EARLY_DATA
                        and len(self.connections[slot].rx_early_secret) != 0
                    ):
                        # 0-RTT with early keys installed: a long-header
                        # packet with an explicit Length varint, framed
                        # like Handshake. Step into it so the inner
                        # 1-RTT packet (if coalesced after) is still
                        # reached.
                        packet_len = early_data_packet_len(sub)
                    else:
                        # 0-RTT without early keys, or Retry: stop the
                        # coalescing scan.
                        break
                except:
                    break
                if packet_len <= 0 or offset + packet_len > n:
                    break
            else:
                packet_len = n - offset
            var ok = self._process_one_packet(
                slot, datagram[offset : offset + packet_len], lvl, now_us
            )
            if ok and lvl == QuicEncryptionLevel.APPLICATION:
                authed_1rtt = True
            # RFC 9000 sec 10.1: only a packet that was received and
            # processed successfully restarts the idle timer. Every
            # packet used to, so anyone who knew the CID could keep a
            # dead connection's slot alive with garbage datagrams.
            if ok:
                processed_any = True
            offset += packet_len
        if processed_any:
            self.connections[slot].idle_sent_since_rx = False
            _ = self.schedule_idle_timeout(slot)
        return authed_1rtt

    def _process_one_packet(
        mut self,
        slot: Int,
        packet: Span[UInt8, _],
        inbound_lvl: Int,
        now_us: UInt64,
    ) raises -> Bool:
        """Decrypt + dispatch a single (already de-coalesced) QUIC
        packet at ``inbound_lvl``. Initial decrypts in the sans-I/O
        connection; Handshake + 1-RTT decrypt through the slot's
        rustls session. Failures drop silently per RFC 9001 sec 5.2.
        Returns whether the packet decrypted and was dispatched.
        """
        # Read the local CID length up front so the rustls decrypt
        # helper (which takes ``mut self``) doesn't have to alias a
        # held ref into the connection slab. Everything below mutates
        # ``self.connections[slot]`` in place -- no whole-connection
        # deep copy on the per-packet hot path.
        var local_cid_len = self.connections[slot].local_cid.length()
        var events = empty_events()
        var ok = True
        if inbound_lvl == QuicEncryptionLevel.INITIAL:
            if self.connections[slot].initial_keys_discarded:
                ok = False  # RFC 9001 sec 4.9.1
            else:
                try:
                    self.connections[slot].conn.ack_pending = False
                    events = self.connections[slot].handle_packet(
                        packet, now_us
                    )
                    if self.connections[slot].conn.ack_pending:
                        self.connections[slot].lh_ack_pending[0] = True
                except:
                    ok = False
                    self._close_after_state_error(slot)
        elif inbound_lvl == QuicEncryptionLevel.HANDSHAKE:
            if len(self.connections[slot].rx_handshake_secret) == 0:
                ok = False  # keys not installed yet; drop
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot, packet, inbound_lvl, local_cid_len
                    )
                    self.connections[slot].conn.ack_pending = False
                    events = self.connections[slot].dispatch_plaintext(
                        Span[UInt8, _](dec[0]), now_us, dec[1], True, 1
                    )
                    if self.connections[slot].conn.ack_pending:
                        self.connections[slot].lh_ack_pending[1] = True
                    # The first Handshake packet ends the Initial space
                    # (RFC 9001 sec 4.9.1): stop tracking its packets.
                    if not self.connections[slot].initial_keys_discarded:
                        self.loss_init[slot] = LossRecovery()
                        self.connections[slot].lh_ack_pending[0] = False
                    self.connections[slot].initial_keys_discarded = True
                    # A Handshake packet proves the peer holds the
                    # address (RFC 9000 sec 8.1).
                    self.connections[slot].addr_validated = True
                except:
                    ok = False
                    self._close_after_state_error(slot)
        elif inbound_lvl == QuicEncryptionLevel.APPLICATION:
            if len(self.connections[slot].rx_1rtt_secret) == 0:
                ok = False
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot, packet, inbound_lvl, local_cid_len
                    )
                    # A packet number already received is a duplicate
                    # (a retransmit that crossed our ACK, or a replay):
                    # drop it. It was dispatched again, so a request
                    # in it ran twice.
                    if _ack_contains(self.rx_1rtt_ranges[slot], dec[1]):
                        raise Error("duplicate packet")
                    # Clear the state-machine ack-eliciting marker so
                    # it reflects only THIS packet after dispatch.
                    self.connections[slot].conn.ack_pending = False
                    events = self.connections[slot].dispatch_plaintext(
                        Span[UInt8, _](dec[0]), now_us, dec[1]
                    )
                    # Record the received pn into the ACK ranges so
                    # the egress ACK reflects exactly what arrived,
                    # gaps and all (RFC 9000 sec 13.2 / 21.4).
                    _ack_record(self.rx_1rtt_ranges[slot], dec[1])
                    self._count_ecn(slot)
                    # Only owe an ACK for ack-eliciting packets (a
                    # request's STREAM/CRYPTO frames). Acking the
                    # peer's pure-ACK packets would, since our ACK
                    # also carries MAX_DATA/MAX_STREAMS (ack-
                    # eliciting), provoke an endless ack-of-ack storm
                    # (RFC 9000 sec 13.2.1).
                    if self.connections[slot].conn.ack_pending:
                        self.rx_1rtt_ack_pending[slot] = True
                except:
                    ok = False
                    self._close_after_state_error(slot)
        elif inbound_lvl == QuicEncryptionLevel.EARLY_DATA:
            if len(self.connections[slot].rx_early_secret) == 0:
                ok = False  # 0-RTT keys not installed: drop
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot, packet, inbound_lvl, local_cid_len
                    )
                    # Cross-connection replay defense (RFC 9001 sec
                    # 9.2): on this connection's *first* 0-RTT packet,
                    # strike its original DCID against the listener-wide
                    # set. A captured first flight replayed as a fresh
                    # accept reuses the same ODCID, so a live strike
                    # means refuse 0-RTT (fall back to 1-RTT). The
                    # intra-connection guard below then handles replays
                    # within this same connection.
                    var admit_ok = True
                    if not self.connections[slot].early_guard.any_seen:
                        var now_ms = now_us // UInt64(1000)
                        var odcid = cid_to_hex(
                            self.connections[slot].initial_dcid
                        )
                        if not self.early_strike.strike(odcid, now_ms):
                            admit_ok = False
                    # Anti-replay + byte-budget admission (RFC 9001
                    # sec 9.2): a replayed / stale 0-RTT packet number
                    # or an over-budget flight is dropped before it can
                    # touch the state machine.
                    if admit_ok and self.connections[slot].early_guard.admit(
                        dec[1], len(dec[0])
                    ):
                        events = self.connections[slot].dispatch_plaintext(
                            Span[UInt8, _](dec[0]), now_us, dec[1]
                        )
                        self._count_ecn(slot)
                    else:
                        ok = False
                except:
                    ok = False
                    self._close_after_state_error(slot)
        else:
            ok = False  # Retry not handled here
        if not ok:
            return False
        if len(events.datagrams) > 0 and not self._queue_datagrams(
            slot, events
        ):
            return True
        self._dispatch_crypto_frames(slot, events, inbound_lvl)
        # LossRecovery tracks the 1-RTT packets we send, so only
        # application-space ACKs name its packet numbers. An Initial or
        # Handshake ACK counts in its own space and was misread as
        # acknowledging 1-RTT packets with those numbers.
        if inbound_lvl == QuicEncryptionLevel.APPLICATION:
            self._consume_acks(slot, events)
            self._retire_local_cids(slot, events)
        elif inbound_lvl == QuicEncryptionLevel.INITIAL or (
            inbound_lvl == QuicEncryptionLevel.HANDSHAKE
        ):
            self._consume_lh_acks(slot, events, inbound_lvl)
        # Requests only from 1-RTT, or 0-RTT the early guard admitted.
        # Dispatch used to happen at every level, so a request in an
        # Initial reached the handler before any handshake.
        if (
            inbound_lvl == QuicEncryptionLevel.APPLICATION
            or inbound_lvl == QuicEncryptionLevel.EARLY_DATA
        ):
            self._route_http3_stream_chunks(slot, events)
        self._stash_migration_egress(slot, events)
        # The client echoed our server-initiated PATH_CHALLENGE: the
        # candidate path is validated (RFC 9000 sec 8.2). Promote it to
        # the connection's egress address -- this is the strict-hold
        # release point, the first moment non-probe 1-RTT egress is
        # allowed to follow the client to the new path -- and lift the
        # anti-amplification cap.
        if events.path_validated and slot < len(self.migration_probe):
            if self.migration_probe[slot].probing and slot < len(
                self.peer_addrs
            ):
                self.peer_addrs[slot] = self.migration_probe[slot].candidate
            self.migration_probe[slot].on_validated()
        return True

    def _count_ecn(mut self, slot: Int):
        """Count the codepoint of the application-space packet just
        processed (RFC 9000 sec 13.4.1): ECT(0) = 2, ECT(1) = 1, CE = 3."""
        if self._rx_ecn == 0:
            return
        ref e = self.connections[slot].ecn_rx
        e[0 if self._rx_ecn == 2 else (1 if self._rx_ecn == 1 else 2)] += 1

    def _begin_path_validation(
        mut self, slot: Int, peer: SocketAddr, datagram_len: Int
    ) raises:
        """Start (or refresh) server-initiated validation of a new
        peer address (RFC 9000 sec 8.2). Stashes a PATH_CHALLENGE for
        the candidate and arms the connection to match the client's
        PATH_RESPONSE. When the candidate is already being probed this
        only grows its received-byte budget (no re-issue per packet).

        The actual probe egress -- and its 3x anti-amplification
        accounting -- happens at drain time in
        :meth:`_drain_migration_probe`, which charges the protected
        datagram (not just the frame) against the candidate's budget
        and holds it back when the budget is exhausted."""
        if slot < 0 or slot >= len(self.migration_probe):
            return
        if not self.migration_probe[slot].should_start(peer):
            self.migration_probe[slot].note_rx(peer, UInt64(datagram_len))
            return
        self.migration_probe[slot].start(peer, UInt64(datagram_len))
        var data = _random_bytes(8)
        self.connections[slot].conn.outgoing_path_challenge = data.copy()
        var frame = new_path_challenge(data)
        var buf = self.pending_migration_tx[slot].copy()
        for i in range(len(frame)):
            buf.append(frame[i])
        self.pending_migration_tx[slot] = buf^

    def _stash_migration_egress(
        mut self, slot: Int, events: ConnectionEvents
    ) raises:
        """Encode the migration frames surfaced this packet
        (PATH_RESPONSE echoes for inbound PATH_CHALLENGEs, RFC 9000
        sec 8.2 / 19.18) into the slot's pending-migration buffer.
        The 1-RTT coalesced drain flushes them on the next egress
        pass, back to the (possibly migrated) peer address."""
        if slot < 0 or slot >= len(self.pending_migration_tx):
            return
        if len(events.path_responses) == 0:
            return
        var buf = self.pending_migration_tx[slot].copy()
        for i in range(len(events.path_responses)):
            encode_path_response(
                PathResponseFrame(data=events.path_responses[i].copy()), buf
            )
        self.pending_migration_tx[slot] = buf^

    def _issue_new_connection_id(
        mut self, slot: Int, mut plaintext: List[UInt8]
    ) raises:
        """Encode a NEW_CONNECTION_ID frame (RFC 9000 sec 19.15)
        into ``plaintext`` granting the peer a fresh server Source
        CID, and register it in :attr:`cid_table` so a migrating
        client that switches its Destination CID to this value still
        routes to ``slot`` (sec 9.5 requires a new CID per path).

        The CID length matches the listener's pinned
        ``local_cid_length`` so the short-header parser
        (:meth:`_dispatch_short`) reads it correctly. The CID + the
        16-byte stateless-reset token are drawn from urandom so
        neither is guessable (sec 5.1.1 / 10.3).
        """
        if slot < 0 or slot >= len(self.next_local_cid_seq):
            return
        var cid_len = self.config.local_cid_length
        if cid_len <= 0 or cid_len > MAX_CID_LENGTH:
            return
        var seq = self.next_local_cid_seq[slot]
        var new_cid = self._new_local_cid()
        var cid_bytes = new_cid.bytes.copy()
        # Derive the reset token from the CID so a later stateless reset
        # for this CID (RFC 9000 sec 10.3) reproduces the same 16 bytes
        # the peer stored here.
        var token = self._stateless_reset_token(new_cid)
        encode_new_connection_id(
            NewConnectionIdFrame(
                sequence_number=seq,
                retire_prior_to=UInt64(0),
                connection_id=cid_bytes^,
                stateless_reset_token=token^,
            ),
            plaintext,
        )
        var key = cid_to_hex(new_cid)
        self.cid_table.register(key, slot)
        self.connections[slot].issued_cids[seq] = key^
        self.next_local_cid_seq[slot] = seq + UInt64(1)

    def _retire_local_cids(mut self, slot: Int, events: ConnectionEvents):
        """Unroute the CIDs the peer retired and queue replacements
        (RFC 9000 sec 5.1.2). Retiring a sequence number never issued is
        a PROTOCOL_VIOLATION (sec 19.16)."""
        for i in range(len(events.retired_local_cids)):
            var seq = events.retired_local_cids[i]
            if seq >= self.next_local_cid_seq[slot]:
                self._close_for(
                    slot,
                    QUIC_PROTOCOL_VIOLATION,
                    "RETIRE_CONNECTION_ID for a CID never issued",
                )
                return
            var key = self.connections[slot].issued_cids.get(seq)
            if key:
                _ = self.connections[slot].issued_cids.pop(seq, String(""))
                try:
                    self.cid_table.retire(key.value())
                except:
                    pass
                self.connections[slot].cid_replenish += 1

    def _new_local_cid(self) raises -> ConnectionId:
        """A fresh random CID of the pinned length. On a multi-worker
        listener it is redrawn until its owner (see
        :func:`flare.quic._worker_route.cid_owner`) is this worker, which
        takes ``num_workers`` draws on average."""
        while True:
            var b = _random_bytes(self.config.local_cid_length)
            if (
                cid_owner(self.config.cid_route_key, b, self.config.num_workers)
                == self.config.worker_id
            ):
                return ConnectionId(bytes=b^)

    def _forward_foreign(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Bool:
        """Hand a short-header packet for an unknown CID to the worker
        that owns the CID, if that is another worker of this listener (a
        migrated or rebound client whose new 4-tuple hashed elsewhere).
        Returns whether it was forwarded; a datagram the inbox cannot take
        is dropped and counts as forwarded, never answered with a reset."""
        if self.config.num_workers <= 1 or self.config.inbox_table == 0:
            return False
        var n = self.config.local_cid_length
        if len(datagram) < 1 + n:
            return False
        var cid = List[UInt8](capacity=n)
        cid.extend(datagram[1 : 1 + n])
        var owner = cid_owner(
            self.config.cid_route_key, cid, self.config.num_workers
        )
        if owner == self.config.worker_id:
            return False
        _ = inbox_at(self.config.inbox_table, owner)[].push(datagram, peer)
        return True

    def _take_forwarded(mut self, mut dirty: List[Int]) raises:
        """Dispatch the datagrams other workers forwarded to this one."""
        if self.config.inbox_table == 0:
            return
        inbox_at(self.config.inbox_table, self.config.worker_id)[].take(
            self._fwd_data, self._fwd_lens, self._fwd_peers
        )
        var pos = 0
        for i in range(len(self._fwd_lens)):
            var n = self._fwd_lens[i]
            var data = List[UInt8](capacity=n)
            data.extend(Span[UInt8, _](self._fwd_data)[pos : pos + n])
            pos += n
            var peer = self._fwd_peers[i]
            var slot = self.dispatch_datagram(Span[UInt8, _](data), peer)
            if slot >= 0 and slot not in dirty:
                dirty.append(slot)

    def _stateless_reset_token(self, cid: ConnectionId) raises -> List[UInt8]:
        """Derive the 16-byte stateless-reset token for ``cid``
        (RFC 9000 sec 10.3.1): the first 16 bytes of
        ``HMAC-SHA256(_reset_key, cid_bytes)``. Deterministic in the CID,
        so the token issued via NEW_CONNECTION_ID and the token on a
        later stateless reset for the same CID are identical."""
        var mac = hmac_sha256(self._reset_key, cid.bytes.copy())
        var token = List[UInt8](capacity=16)
        for i in range(16):
            token.append(mac[i])
        return token^

    def _build_stateless_reset(
        self, dcid: ConnectionId, triggering_len: Int
    ) raises -> List[UInt8]:
        """Build a stateless-reset datagram for an unknown short-header
        ``dcid`` (RFC 9000 sec 10.3).

        Layout: a short-header-shaped packet of unpredictable bytes
        ending in the 16-byte stateless-reset token derived from
        ``dcid``. The first byte has the high bit clear + the fixed bit
        set (``0x40``) so it reads as a valid short header; the leading
        bytes are random so the datagram is indistinguishable from a
        regular 1-RTT packet on the wire.

        Returns an empty list (caller drops) when the triggering packet
        is too small to safely reset: the reset MUST be shorter than the
        packet that triggered it (to avoid an infinite reset loop, sec
        10.3) yet at least 21 bytes (5 random + 16 token). When the
        triggering packet can't accommodate both bounds we stay silent.
        """
        comptime MIN_RESET_LEN = 21
        if triggering_len <= MIN_RESET_LEN:
            return List[UInt8]()
        # Largest reset still strictly shorter than the trigger, capped
        # so we don't echo arbitrarily large datagrams.
        var total = triggering_len - 1
        if total > 64:
            total = 64
        var rand_len = total - 16
        var out = _random_bytes(rand_len)
        out[0] = (out[0] & 0x3F) | 0x40  # clear long-header + key-phase noise
        var token = self._stateless_reset_token(dcid)
        for i in range(16):
            out.append(token[i])
        return out^

    def _decrypt_post_initial(
        mut self,
        slot: Int,
        datagram: Span[UInt8, _],
        level: Int,
        dcid_length: Int,
    ) raises -> Tuple[List[UInt8], UInt64]:
        """Strip header protection + AEAD-decrypt a Handshake or
        1-RTT datagram through the slot's rustls session, which
        owns the real per-level keys.

        Returns ``(plaintext, packet_number)``. Raises on any
        bounds, FFI, or AEAD failure so the caller drops the
        packet (RFC 9001 sec 5.2).

        Header protection: rustls's ``decrypt_in_place`` unmasks
        the first byte, derives the packet-number length from it,
        then XORs only that many bytes of the supplied slice. A
        4-byte scratch copy of the pn region is therefore safe --
        only ``pn_length`` bytes are touched, the rest discarded,
        and the datagram bytes are never mutated.
        """
        if slot < 0 or slot >= len(self.tls_sessions):
            raise Error("_decrypt_post_initial: slot out of range")
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            raise Error("_decrypt_post_initial: NULL session handle")
        # pn_offset and packet_end depend on the header form. A
        # long-header Handshake packet carries a Length varint
        # after the SCID that bounds the protected payload (so the
        # AEAD ciphertext stops at packet_end, not end-of-datagram,
        # which matters when packets are coalesced or padded). A
        # short-header 1-RTT packet has no Length field and is
        # always last in its datagram (RFC 9000 sec 12.2), so it runs
        # to the datagram end.
        var pn_offset: Int
        var packet_end: Int
        if (
            level == QuicEncryptionLevel.HANDSHAKE
            or level == QuicEncryptionLevel.EARLY_DATA
        ):
            # Both are long-header packets carrying a Length varint
            # after the SCID that bounds the protected payload.
            var lh = parse_long_header(datagram)
            var len_var = decode_varint(datagram[lh.payload_offset :])
            pn_offset = lh.payload_offset + len_var.consumed
            packet_end = pn_offset + Int(len_var.value)
            if packet_end > len(datagram):
                raise Error(
                    "_decrypt_post_initial: handshake length exceeds datagram"
                )
        else:
            pn_offset = parse_short_header(datagram, dcid_length).payload_offset
            packet_end = len(datagram)
        # The HP sample sits 4 bytes past the pn field start
        # (RFC 9001 sec 5.4.2); that window must fit the datagram.
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(datagram):
            raise Error(
                "_decrypt_post_initial: HP sample window exceeds packet"
            )
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(datagram[sample_offset + i])
        # Scratch the first byte + 4 candidate pn bytes; rustls
        # unmasks first, reads pn_length, XORs only that many.
        var first_local: UInt8 = datagram[0]
        var pn_local = List[UInt8]()
        for i in range(4):
            pn_local.append(datagram[pn_offset + i])
        var first_addr = Int(Pointer(to=first_local))
        _do_header_decrypt(
            self.tls_acceptor._fns,
            handle,
            level,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            4,
        )
        var pn_length = (Int(first_local) & 0x03) + 1
        var truncated_pn = UInt64(0)
        for i in range(pn_length):
            truncated_pn = (truncated_pn << 8) | UInt64(pn_local[i])
        var space = 1 if level == QuicEncryptionLevel.HANDSHAKE else 2
        var packet_number = decode_packet_number(
            truncated_pn,
            pn_length,
            self.connections[slot].rx_largest[space],
        )
        # AAD is the unprotected header: first byte + bytes up to
        # the pn field + the pn_length real pn bytes.
        var header = List[UInt8](capacity=pn_offset + pn_length)
        header.append(first_local)
        header.extend(datagram[1:pn_offset])
        header.extend(Span[UInt8, _](pn_local)[:pn_length])
        var ciphertext_start = pn_offset + pn_length
        if ciphertext_start > packet_end:
            raise Error("_decrypt_post_initial: pn length exceeds packet end")
        var payload = List[UInt8](capacity=packet_end - ciphertext_start)
        payload.extend(datagram[ciphertext_start:packet_end])
        # decrypt_in_place verifies + strips the 16-byte AEAD tag,
        # writing plaintext over the ciphertext prefix of ``payload``.
        # The FFI also reports the plaintext length, but the QUIC
        # AEAD suites (AES-GCM / ChaCha20-Poly1305) always use a
        # 16-byte tag (RFC 9001 sec 5.3), so the plaintext is exactly
        # the leading ``len(payload) - 16`` bytes; we slice that
        # directly rather than depend on the out-parameter readback.
        if level == QuicEncryptionLevel.APPLICATION:
            # The key phase bit picks the key (RFC 9001 sec 6.3). A
            # packet that opens under the next generation is the peer's
            # key update: rustls has rotated, and we answer in the new
            # phase from the next packet on.
            var phase = (Int(first_local) >> 2) & 1
            if (
                _do_packet_decrypt_1rtt(
                    self.tls_acceptor._fns,
                    handle,
                    phase,
                    packet_number,
                    header,
                    payload,
                )
                == 1
            ):
                ref c = self.connections[slot]
                c.key_phase = not c.key_phase
                c.phase_first_pn = c.tx_1rtt_pn
        else:
            _ = _do_packet_decrypt(
                self.tls_acceptor._fns,
                handle,
                level,
                packet_number,
                header,
                payload,
            )
        comptime QUIC_AEAD_TAG_LEN = 16
        var plaintext_len = len(payload) - QUIC_AEAD_TAG_LEN
        if plaintext_len < 0:
            raise Error("_decrypt_post_initial: payload shorter than AEAD tag")
        payload.resize(plaintext_len, 0)
        return (payload^, packet_number)

    def _dispatch_crypto_frames(
        mut self, slot: Int, events: ConnectionEvents, inbound_lvl: Int
    ) raises:
        """Forward inbound CRYPTO frame bytes to the slot's
        rustls QUIC session, drain outbound CRYPTO bytes at
        EVERY encryption level into the per-slot egress queue,
        and -- after each drain -- check whether rustls's
        `KeyChange` pump has just installed Handshake or 1-RTT
        keys on the slot's session.  When the keys at a level
        flip from None to Some(_) we stamp a sentinel onto the
        connection's per-level secret carrier so the
        post-Initial decrypt path flips from "drop silently" to
        "dispatch via rustls".

        The Mojo side does NOT carry raw traffic secrets --
        rustls's `quic::Secrets` is `pub(crate)`-sealed. The
        carriers :attr:`QuicConnection.rx_handshake_secret` /
        `.tx_handshake_secret` / `.rx_1rtt_secret` /
        `.tx_1rtt_secret` are reused as boolean readiness
        markers: empty list == not installed; non-empty list
        (length 1, contents `0xff`) == installed and the rustls
        session has the keys.

        Both the feed-crypto and take-crypto FFI calls route
        through :attr:`tls_acceptor._lib` so the .so stays
        mapped across the call (Mojo's ASAP destructor cannot
        unmap the library between symbol resolution and the
        thunk).
        """
        if slot < 0 or slot >= len(self.tls_sessions):
            return
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return

        # Reassemble inbound CRYPTO into a contiguous, in-order
        # byte stream before feeding rustls. A peer may fragment +
        # reorder CRYPTO frames within a packet (RFC 9000 sec 19.6);
        # rustls's read_hs consumes the handshake stream strictly
        # in order, so out-of-order fragments are buffered until
        # the gap ahead of them fills. All frames in one batch
        # share the parent packet's encryption level (RFC 9001
        # sec 4.1.3), so the caller supplies that level.
        var fed_crypto = False
        if (
            len(events.crypto_frames) > 0
            and inbound_lvl >= 0
            and inbound_lvl < 4
        ):
            ref reasm = self.crypto_reasm[slot]
            try:
                for i in range(len(events.crypto_frames)):
                    reasm.levels[inbound_lvl].insert(
                        events.crypto_frames[i].offset,
                        events.crypto_frames[i].data,
                    )
            except:
                self._close_for(
                    slot,
                    QUIC_CRYPTO_BUFFER_EXCEEDED,
                    "CRYPTO data too far ahead of the handshake",
                )
                return
            var ordered = reasm.levels[inbound_lvl].drain_contiguous()
            if len(ordered) > 0:
                _ = _do_feed_crypto(
                    self.tls_acceptor._lib, handle, inbound_lvl, ordered
                )
                fed_crypto = True

        # Steady-state fast path: once 1-RTT keys are installed and
        # this packet fed no new CRYPTO, rustls has nothing to drain
        # or re-key, so skip the five per-packet FFI crossings below.
        # The handshake-completing packet always feeds CRYPTO, so the
        # post-handshake outbound drain (session tickets) still runs
        # on that turn.
        if not fed_crypto and len(self.connections[slot].rx_1rtt_secret) != 0:
            return

        # Drain rustls's outbound CRYPTO bytes at every level
        # rustls might have buffered for us. The KeyChange-driven
        # pump in `flare_rustls_quic_drain_outbound` routes bytes
        # onto the correct per-level pending queue inside the Rust
        # shim; we just call take_crypto once per level and append.
        try:
            var out_initial = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.INITIAL,
            )
            for k in range(len(out_initial)):
                self.tls_egress_queues[slot].append(out_initial[k])
        except:
            pass
        try:
            var out_hs = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.HANDSHAKE,
            )
            for k in range(len(out_hs)):
                self.tls_handshake_egress_queues[slot].append(out_hs[k])
        except:
            pass
        try:
            var out_1rtt = _do_take_crypto(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.APPLICATION,
            )
            for k in range(len(out_1rtt)):
                self.tls_1rtt_egress_queues[slot].append(out_1rtt[k])
        except:
            pass

        # After every CRYPTO pump, ask rustls whether the
        # KeyChange-driven pump just installed Handshake or
        # 1-RTT keys on this session. The conditional install
        # below is idempotent (stamping the sentinel twice is a
        # no-op): once the level flips, every subsequent call
        # sees `have_keys == True` and we install once.
        var have_hs = (
            _do_have_keys(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.HANDSHAKE,
            )
            == 1
        )
        var have_1rtt = (
            _do_have_keys(
                self.tls_acceptor._lib,
                handle,
                QuicEncryptionLevel.APPLICATION,
            )
            == 1
        )
        # Install once per direction, in place. The guard conditions
        # stay false after the first install, so post-handshake
        # packets (where have_1rtt is always true) don't pay a
        # whole-connection deep copy here.
        if have_hs and len(self.connections[slot].rx_handshake_secret) == 0:
            self.connections[slot].install_handshake_keys(
                _ready_sentinel(), _ready_sentinel()
            )
        if have_1rtt and len(self.connections[slot].rx_1rtt_secret) == 0:
            self.connections[slot].install_1rtt_keys(
                _ready_sentinel(), _ready_sentinel()
            )
            # The client's transport parameters are in the ClientHello
            # rustls has just processed (RFC 9000 sec 7.4, 18.2).
            if not self._client_params_ok(slot, handle):
                return
        # The client's Finished completes the handshake (RFC 9001 sec
        # 4.1.1); HANDSHAKE_DONE then goes out on the next drain, not on
        # the client's first ack-eliciting 1-RTT packet.
        if (
            inbound_lvl == QuicEncryptionLevel.HANDSHAKE
            and not self.connections[slot].conn.handshake_complete
            and _do_is_handshake_complete(self.tls_acceptor._lib, handle)
        ):
            var hs_events = empty_events()
            mark_handshake_complete(
                self.connections[slot].conn, UInt64(0), hs_events
            )

        # 0-RTT (EarlyData) keys: only when the listener is configured
        # for early data (budget > 0) and we have not already installed
        # them. Gated this way, the default (0-RTT off) hot path pays
        # nothing -- no FFI call, no branch beyond the budget compare.
        # rustls exposes the resumed-ClientHello early keys after the
        # Initial CRYPTO feed; install_early_keys returns 1 once they
        # exist and 0-RTT was accepted (RFC 9001 sec 4.1).
        var early_budget = self.config.rustls_config.max_early_data_size
        if (
            early_budget > UInt32(0)
            and len(self.connections[slot].rx_early_secret) == 0
        ):
            if _do_install_early_keys(self.tls_acceptor._lib, handle) == 1:
                self.connections[slot].install_early_data_keys(
                    _ready_sentinel()
                )
                self.connections[slot].early_guard = EarlyDataReplayGuard(
                    max_bytes=UInt64(Int(early_budget))
                )

    def _client_params_ok(mut self, slot: Int, handle: Int) -> Bool:
        """Validate the client's ``quic_transport_parameters`` once the
        1-RTT keys exist (RFC 9000 sec 7.3, 7.4, 18.2): they must decode,
        carry no server-only parameter, and name the Source Connection ID
        of the client's Initial as ``initial_source_connection_id``.
        Closes the slot with TRANSPORT_PARAMETER_ERROR and returns
        ``False`` otherwise."""
        var raw = List[UInt8]()
        try:
            raw = _do_peer_transport_params(self.tls_acceptor._lib, handle)
        except:
            pass
        try:
            check_client_transport_params(
                Span[UInt8, _](raw), self.connections[slot].peer_cid.bytes
            )
        except e:
            self._close_for(slot, QUIC_TRANSPORT_PARAMETER_ERROR, String(e))
            return False
        # The idle timeout is the minimum of the two advertised values
        # (RFC 9000 sec 10.1): remember the client's and re-arm with it.
        try:
            var tp = decode_transport_parameters(Span[UInt8, _](raw))
            if Bool(tp.max_idle_timeout):
                self.connections[
                    slot
                ].peer_idle_ms = tp.max_idle_timeout.value()
            _ = self.schedule_idle_timeout(slot)
            # The client's flow-control limits on what we send (RFC 9000
            # sec 18.2): its connection limit, and the limit of each
            # stream it opens. Raised, never lowered, in case a 0-RTT
            # MAX_DATA / MAX_STREAM_DATA already arrived.
            ref c = self.connections[slot].conn
            var md = tp.initial_max_data.or_else(UInt64(0))
            if md > c.max_data_send:
                c.max_data_send = md
            self.connections[
                slot
            ].peer_cid_limit = tp.active_connection_id_limit.or_else(UInt64(2))
            self.connections[
                slot
            ].peer_max_datagram = tp.max_datagram_frame_size.or_else(0)
            self.http3_connections[slot].peer_quic_datagram = (
                self.connections[slot].peer_max_datagram > 0
            )
            self.connections[slot].pmtu.set_ceiling(
                min(
                    Int(self.config.max_udp_payload_size),
                    Int(tp.max_udp_payload_size.or_else(65527)),
                )
            )
            var msd = tp.initial_max_stream_data_bidi_local.or_else(UInt64(0))
            c.peer_initial_max_stream_data = msd
            var open_sids = List[UInt64]()
            for entry in c.streams.items():
                open_sids.append(entry.key)
            for i in range(len(open_sids)):
                ref st = c.streams[open_sids[i]]
                if st.max_send_data < msd:
                    st.max_send_data = msd
        except:
            pass
        return True

    # -- H3 dispatch surface ----------------------------------------------

    def _route_http3_stream_chunks(
        mut self, slot: Int, events: ConnectionEvents
    ) raises:
        """Route every STREAM frame surfaced on ``events`` to the
        slot's :class:`flare.http3.Http3Connection`.

        RFC 9114 §6 puts H3 traffic on QUIC bidirectional + uni
        streams; the stream id parity bits classify which kind a
        frame belongs to (RFC 9000 §2.1: even = client-initiated
        bidi / uni based on the low two bits). The H3 driver
        accepts both flavors through different entry points;
        this method picks the right one and also signals FIN
        when the QUIC layer observed end-of-stream.

        No-op if the slot is out of range or no STREAM frames
        were surfaced this tick. Empty payload chunks with FIN
        still drive :meth:`flare.http3.Http3Connection.signal_end_of_stream`
        so the H3 driver can advance request state.
        """
        if slot < 0 or slot >= len(self.http3_connections):
            return
        if len(events.stream_chunks) == 0:
            return
        # Pass 1: connection + stream flow-control accounting (RFC
        # 9000 sec 4). Track total inbound stream bytes for MAX_DATA
        # and the client bidi-stream high-water mark (id & 3 == 0)
        # for MAX_STREAMS_BIDI; both are advertised on the next ACK
        # so the peer never blocks over a long run. Done first so the
        # in-place H3 feed below can hold one mutable ref into the
        # slab without aliasing these rx_* counters.
        #
        # Limits are enforced here too (RFC 9000 sec 4). Any stream id
        # was accepted, any number of streams, and any amount of data:
        # the grants below were computed from what the peer had sent,
        # so its credit grew with its own sending.
        for i in range(len(events.stream_chunks)):
            var sid = Int(events.stream_chunks[i].stream_id)
            var is_uni = (sid & 0x2) != 0
            var plen = len(events.stream_chunks[i].data)
            if (sid & 0x1) != 0:
                # Server-initiated: we open no bidi streams, and our uni
                # streams are send-only (sec 19.8).
                self._close_for(slot, QUIC_STREAM_STATE_ERROR, "stream id")
                return
            if slot < len(self.rx_stream_bytes):
                self.rx_stream_bytes[slot] += UInt64(plen)
            ref qc = self.connections[slot]
            if not is_uni:
                var count = UInt64((sid >> 2) + 1)
                if count > qc.fc_adv_max_bidi:
                    self._close_for(
                        slot, QUIC_STREAM_LIMIT_ERROR, "too many streams"
                    )
                    return
                if (
                    slot < len(self.rx_bidi_stream_count)
                    and count > self.rx_bidi_stream_count[slot]
                ):
                    self.rx_bidi_stream_count[slot] = count
            elif UInt64((sid >> 2) + 1) > qc.conn.adv_max_streams_uni:
                # RFC 9000 sec 4.6: the unidirectional limit we sent is
                # enforced like the bidirectional one.
                self._close_for(
                    slot,
                    QUIC_STREAM_LIMIT_ERROR,
                    "too many unidirectional streams",
                )
                return
            var end = events.stream_chunks[i].offset + UInt64(plen)
            var prev = qc.fc_stream_end.get(sid, UInt64(0))
            if end > prev:
                qc.fc_stream_end[sid] = end
                qc.fc_received += end - prev
                if is_uni:
                    qc.fc_consumed += end - prev
            if qc.fc_received > qc.fc_adv_max_data:
                self._close_for(
                    slot, QUIC_FLOW_CONTROL_ERROR, "stream data past MAX_DATA"
                )
                return
        # Pass 2: feed H3 in place. Mutating the slot through a ref
        # avoids deep-copying the whole Http3Connection (its per-stream
        # state Dict) on every inbound datagram -- the dominant
        # per-request CPU cost under stream concurrency.
        ref h3 = self.http3_connections[slot]
        var h3_code = UInt64(0)
        var h3_reason = String("")
        for i in range(len(events.stream_chunks)):
            # By offset: the reassembler orders, dedupes and holds back
            # FIN until the stream is whole, and drops frames for a
            # request stream already answered (a retransmit crossing
            # our ACK used to run the request again).
            try:
                h3.feed_stream_frame(
                    Int(events.stream_chunks[i].stream_id),
                    events.stream_chunks[i].offset,
                    Span[UInt8, _](events.stream_chunks[i].data),
                    events.stream_chunks[i].fin,
                )
            except e:
                # An H3 / QPACK connection error from the driver. It
                # used to propagate out of ``tick`` and stop the serve
                # loop; it closes this connection instead.
                h3_reason = String(e)
                h3_code = h3_error_code(h3_reason)
                break
        # A field section the driver could not decode (QPACK-05): the
        # request stream is dead and the peer must be told, not left
        # waiting on a connection that otherwise stays up.
        if h3_code == 0 and h3.connection_error_code != 0:
            h3_code = h3.connection_error_code
            h3_reason = h3.connection_error_reason
        if h3_code != 0:
            self._close_for(slot, h3_code, h3_reason, application=True)
            return
        # Pass 3: stream credit, from the bytes delivered in order. The
        # highest offset seen was used, so data past a gap earned more
        # credit, and the peer could pile up more out-of-order bytes than
        # the reassembly holds.
        for i in range(len(events.stream_chunks)):
            var sid = Int(events.stream_chunks[i].stream_id)
            var delivered = self.http3_connections[slot].delivered_offset(sid)
            self._grant_stream_credit(slot, sid, delivered)

    def _grant_stream_credit(mut self, slot: Int, sid: Int, end: UInt64):
        """Keep a client stream's receive limit a window ahead of the
        bytes delivered in order, ``end`` (RFC 9000 sec 4.2): once less
        than half the window is left, raise the limit to ``end +
        window`` and queue a MAX_STREAM_DATA. Without it an upload larger than the initial
        window stalled. Memory stays bounded by MAX_DATA, which is
        granted only as requests are answered. The window doubles, up to
        :data:`_MAX_STREAM_WINDOW`, when grants come faster than twice
        the smoothed RTT, so a fast path is not held to one window per
        round trip."""
        ref qc = self.connections[slot]
        var usid = UInt64(sid)
        if usid not in qc.conn.streams:
            return
        try:
            ref st = qc.conn.streams[usid]
            if st.fin_received:
                return
            var window = qc.fc_stream_window
            if st.max_recv_data - end >= window // 2:
                return
            var now = _monotonic_ms()
            var srtt = self.loss[slot].smoothed_rtt if slot < len(
                self.loss
            ) else UInt64(0)
            if (
                qc.fc_last_grant_ms != 0
                and now - qc.fc_last_grant_ms < 2 * max(srtt, UInt64(1))
                and window < _MAX_STREAM_WINDOW
            ):
                window = min(window * 2, _MAX_STREAM_WINDOW)
                qc.fc_stream_window = window
            qc.fc_last_grant_ms = now
            st.max_recv_data = end + window
            qc.fc_grants.append(sid)
        except:
            pass

    def take_http3_completed_streams(self, slot: Int) raises -> List[Int]:
        """Return the stream ids ready for handler dispatch on
        ``slot``. Delegates to
        :meth:`flare.http3.Http3Connection.take_completed_streams`.
        Empty list if the slot is out of range or has no H3
        driver attached."""
        if slot < 0 or slot >= len(self.http3_connections):
            return List[Int]()
        return self.http3_connections[slot].take_completed_streams()

    def take_http3_request(
        mut self, slot: Int, stream_id: Int
    ) raises -> Request:
        """Materialize the :class:`flare.http.Request` for
        ``(slot, stream_id)``. The dispatch caller invokes a
        Handler with this Request, then feeds the Response back
        through :meth:`emit_http3_response`.

        Raises if the slot is out of range or the H3 driver
        does not track the stream (see
        :meth:`flare.http3.Http3Connection.take_request` for the
        underlying gating)."""
        if slot < 0 or slot >= len(self.http3_connections):
            raise Error(
                "take_http3_request: slot " + String(slot) + " out of range"
            )
        ref h3 = self.http3_connections[slot]
        return h3.take_request(stream_id)

    def _append_http3_egress(
        mut self, slot: Int, stream_id: Int, var frames: List[UInt8]
    ) raises:
        """Queue ``frames`` on ``stream_id``'s response egress, creating
        the record on first use (the bytes are moved in, not copied).
        Shared by the buffered emit path and the streaming DATA pump."""
        ref txs = self.connections[slot].h3_tx
        if stream_id not in txs:
            var st = _StreamTx()
            st.buf = frames^
            txs[stream_id] = st^
            return
        txs[stream_id].buf.extend(Span[UInt8, _](frames))

    def emit_http3_response(
        mut self, slot: Int, stream_id: Int, var response: Response
    ) raises:
        """Encode ``response`` and queue it on the stream's egress for
        the 1-RTT drain (:meth:`_drain_1rtt_coalesced`), which frames it
        as far as flow control and the congestion window allow once the
        slot's 1-RTT keys are installed.

        A streaming response (one carrying a ``body_stream`` chunk
        source) is handled incrementally: its HEADERS (and any inline
        ``body`` prefix) are queued now, the source is boxed on the
        stream's record, and :meth:`pump_http3_streams` pulls its body
        one chunk per tick. The FIN waits until the source is exhausted.
        """
        if slot < 0 or slot >= len(self.http3_connections):
            raise Error(
                "emit_http3_response: slot " + String(slot) + " out of range"
            )
        # Detect streaming before the response is moved into the driver.
        if response.body_stream:
            # Take the source out; pre-encode trailers (emitted after the
            # final DATA frame, right before FIN). With body_stream gone
            # the driver's emit_response frames HEADERS + any inline body
            # prefix only -- no buffered stream body.
            var src = response.body_stream.take()
            var trailer_bytes = List[UInt8]()
            if len(response.trailers._keys) > 0:
                var tr = List[QpackHeader]()
                for i in range(len(response.trailers._keys)):
                    tr.append(
                        QpackHeader(
                            String(response.trailers._keys[i]),
                            String(response.trailers._values[i]),
                        )
                    )
                encode_response_trailers(tr, trailer_bytes)
            ref h3 = self.http3_connections[slot]
            h3.emit_response(stream_id, response^)
            var frames = h3.take_response_frames(stream_id)
            self._append_http3_egress(slot, stream_id, frames^)
            ref st = self.connections[slot].h3_tx[stream_id]
            st.src_addr = Pool[ChunkSourceBox].alloc_move(src^)
            st.trailer_bytes = trailer_bytes^
            self._open_sources += 1
            return
        ref h3 = self.http3_connections[slot]
        h3.emit_response(stream_id, response^)
        var frames = h3.take_response_frames(stream_id)
        self._append_http3_egress(slot, stream_id, frames^)
        self.connections[slot].h3_tx[stream_id].done = True

    def take_http3_response_egress(
        mut self, slot: Int, stream_id: Int
    ) raises -> List[UInt8]:
        """Take the response bytes queued on ``stream_id`` and not yet
        framed, bypassing the 1-RTT drain. Returns an empty list when
        nothing is queued. A finished buffered response's record is
        dropped; a streaming one keeps its source."""
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        ref txs = self.connections[slot].h3_tx
        if stream_id not in txs:
            return List[UInt8]()
        ref st = txs[stream_id]
        var out = List[UInt8](Span[UInt8, _](st.buf)[st.pos :])
        st.consume(st.pending())
        if st.done and st.src_addr == 0:
            _ = txs.pop(stream_id)
        return out^

    # -- Extended CONNECT tunnels (RFC 9220) -------------------------------

    def open_http3_tunnel(
        mut self, slot: Int, stream_id: Int
    ) raises -> Http3Tunnel:
        """Accept the extended CONNECT request on ``stream_id`` (taken
        with :meth:`take_http3_request`): queue a 200 HEADERS and keep the
        stream open both ways."""
        ref h3 = self.http3_connections[slot]
        h3.emit_response(stream_id, Response(status=200))
        self._append_http3_egress(
            slot, stream_id, h3.take_response_frames(stream_id)
        )
        return Http3Tunnel(slot, stream_id, self.connections[slot].serial)

    def is_http3_tunnel_request(self, slot: Int, stream_id: Int) -> Bool:
        """Whether the request on ``stream_id`` is an extended CONNECT
        (RFC 9220), ready before the client ends the stream."""
        if slot < 0 or slot >= len(self.http3_connections):
            return False
        return self.http3_connections[slot].is_tunnel(stream_id)

    def _tunnel_live(self, t: Http3Tunnel) -> Bool:
        return (
            t.slot >= 0
            and t.slot < len(self.connections)
            and self.connections[t.slot].serial == t.serial
            and self.connections[t.slot].alive
            and t.stream_id in self.connections[t.slot].h3_tx
        )

    def http3_tunnel_open(self, t: Http3Tunnel) -> Bool:
        """Whether ``t`` still carries bytes both ways: neither side has
        ended or reset it and its connection is up."""
        if not self._tunnel_live(t):
            return False
        var s = self.connections[t.slot].conn.streams.get(UInt64(t.stream_id))
        if not s or s.value().peer_reset or s.value().send_reset:
            return False
        var done = True
        try:
            done = self.connections[t.slot].h3_tx[t.stream_id].done
        except:
            pass
        if done:
            return False
        try:
            return not self.http3_connections[t.slot].stream_fin_received(
                t.stream_id
            )
        except:
            return False

    def send_http3_tunnel(
        mut self, t: Http3Tunnel, data: Span[UInt8, _]
    ) raises -> Bool:
        """Queue ``data`` as one DATA frame on ``t``; False when the
        tunnel is closed. The drain sends it as flow control allows."""
        if not self.http3_tunnel_open(t):
            return False
        encode_response_data(
            data, self.connections[t.slot].h3_tx[t.stream_id].buf
        )
        return True

    def take_http3_tunnel(mut self, t: Http3Tunnel) -> List[UInt8]:
        """The bytes the peer sent on ``t`` since the last call. They
        count as consumed, so connection credit keeps up with a
        long-lived tunnel (RFC 9000 sec 4.2)."""
        if not self._tunnel_live(t):
            return List[UInt8]()
        ref h3 = self.http3_connections[t.slot]
        var data = h3.take_stream_body(t.stream_id)
        var delivered = h3.delivered_offset(t.stream_id)
        ref qc = self.connections[t.slot]
        var prev = qc.fc_tunnel_credited.get(t.stream_id, UInt64(0))
        if delivered > prev:
            qc.fc_consumed += delivered - prev
            qc.fc_tunnel_credited[t.stream_id] = delivered
        return data^

    def close_http3_tunnel(mut self, t: Http3Tunnel):
        """End our side of ``t``: FIN after the queued bytes, then the
        stream is reclaimed."""
        if self._tunnel_live(t):
            try:
                self.connections[t.slot].h3_tx[t.stream_id].done = True
            except:
                pass

    def pump_http3_streams(mut self, cancel: Cancel) raises -> Int:
        """Advance every active HTTP/3 streaming response by one chunk.

        For each stream whose source is still open, pulls a single chunk
        (mirroring the H1/H2 one-chunk-per-edge yield) and queues it as a
        DATA frame on the stream's egress. On end-of-stream the source is
        freed, the trailers are queued, and the record is marked ``done``
        so the drain sends the FIN after the last byte. Returns the
        number of streams advanced (produced a chunk or reached EOS).

        Backpressure: a stream with :data:`_STREAM_PULL_HIGH_WATER` bytes
        still unsent is skipped. The drain only frames what the peer's
        MAX_STREAM_DATA / MAX_DATA and the congestion window allow, so a
        fast source cannot outrun a slow reader.
        """
        if self._open_sources == 0:
            return 0
        var advanced = 0
        for slot in range(len(self.connections)):
            if len(self.connections[slot].h3_tx) == 0:
                continue
            var sids = List[Int]()
            for entry in self.connections[slot].h3_tx.items():
                if (
                    entry.value.src_addr != 0
                    and entry.value.pending() < _STREAM_PULL_HIGH_WATER
                ):
                    sids.append(entry.key)
            for i in range(len(sids)):
                var sid = sids[i]
                var src_addr = self.connections[slot].h3_tx[sid].src_addr
                var chunk = (
                    Pool[ChunkSourceBox].get_ptr(src_addr)[].next(cancel)
                )
                ref st = self.connections[slot].h3_tx[sid]
                if chunk:
                    if len(chunk.value()) > 0:
                        encode_response_data(
                            Span[UInt8, _](chunk.value()), st.buf
                        )
                else:
                    # End-of-stream: free the boxed source exactly once;
                    # the trailers ride right before the FIN.
                    Pool[ChunkSourceBox].free(src_addr)
                    st.src_addr = 0
                    st.buf.extend(Span[UInt8, _](st.trailer_bytes))
                    st.trailer_bytes = List[UInt8]()
                    st.done = True
                    self._open_sources -= 1
                advanced += 1
        return advanced

    def _dispatch_long(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Long-header path: parse the full header, route by DCID,
        and accept an Initial packet against an unknown DCID."""
        if len(datagram) >= 7 and not _is_quic_v1(datagram):
            self._maybe_negotiate_version(datagram, peer)
            return -1
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return -1
        if (
            lh.packet_type == PACKET_TYPE_INITIAL
            and len(datagram) < _MIN_INITIAL_DATAGRAM
        ):
            return -1  # RFC 9000 sec 14.1
        var dcid_hex = cid_to_hex(lh.dcid)
        var slot = self.cid_table.lookup(dcid_hex)
        if slot >= 0:
            return slot
        if lh.packet_type == PACKET_TYPE_INITIAL:
            var retry_odcid = Optional[ConnectionId]()
            if self.config.require_address_validation:
                if self._new_token_ok(lh, datagram, peer):
                    # Skips the Retry round trip only: the address stays
                    # unvalidated (3x limit) until the handshake proves
                    # it, so a replayed token amplifies nothing.
                    return self._accept_initial(lh, peer)
                retry_odcid = self._retry_gate(lh, datagram, peer)
                if not retry_odcid:
                    # A Retry was issued, or the token was absent/invalid:
                    # do not commit handshake state for this datagram.
                    return -1
            return self._accept_initial(lh, peer, retry_odcid)
        return -1

    def _maybe_negotiate_version(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ):
        """Answer a long-header packet of a version we do not speak with
        Version Negotiation (RFC 9000 sec 6.1), listing QUIC v1 and a
        reserved grease version (sec 6.3). Only the version-independent
        fields are read (RFC 8999 sec 5.1). A Version Negotiation packet
        (version 0) is never answered, and neither is a datagram under
        1200 bytes, so the reply cannot amplify (sec 5.2.2, 14.1)."""
        if len(datagram) < _MIN_INITIAL_DATAGRAM:
            return
        if (
            datagram[1] == 0
            and datagram[2] == 0
            and datagram[3] == 0
            and datagram[4] == 0
        ):
            return
        var dlen = Int(datagram[5])
        if dlen > MAX_CID_LENGTH or 7 + dlen > len(datagram):
            return
        var slen = Int(datagram[6 + dlen])
        if slen > MAX_CID_LENGTH or 7 + dlen + slen > len(datagram):
            return
        var dcid = ConnectionId(
            bytes=List[UInt8](Span[UInt8, _](datagram)[6 : 6 + dlen])
        )
        var scid = ConnectionId(
            bytes=List[UInt8](
                Span[UInt8, _](datagram)[7 + dlen : 7 + dlen + slen]
            )
        )
        var versions = List[UInt32]()
        versions.append(QUIC_VERSION_1)
        versions.append(UInt32(0x1A2A3A4A))
        try:
            var vn = encode_version_negotiation(scid, dcid, versions)
            _ = self.send_to(Span[UInt8, _](vn), peer)
        except:
            pass

    def _new_token_ok(
        self, lh: LongHeader, datagram: Span[UInt8, _], peer: SocketAddr
    ) -> Bool:
        """Whether the Initial carries a NEW_TOKEN token this listener
        issued to the client's IP address (RFC 9000 sec 8.1.3)."""
        try:
            var extras = parse_initial_extras(datagram, lh.payload_offset)
            return validate_new_token(
                self._retry_key,
                extras.token,
                _ip_bytes(peer),
                _monotonic_ms(),
                _NEW_TOKEN_MAX_AGE_MS,
            )
        except:
            return False

    def _retry_gate(
        mut self, lh: LongHeader, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Optional[ConnectionId]:
        """RFC 9000 sec 8.1 address-validation gate for an unknown-DCID
        Initial. Returns the client's original DCID, recovered from a
        valid token, when the client may be accepted; ``None`` when the
        caller must NOT accept (a Retry was sent, or the token was
        missing / invalid). The ODCID used to be thrown away here, so
        the transport parameters named the wrong one.

        Token-less Initial -> mint an HMAC token bound to the peer address
        + original DCID and answer with a Retry (the client re-sends its
        Initial carrying the token + the server's new DCID). Tokened
        Initial -> validate; a good token accepts, a bad / expired one is
        dropped. The Retry datagram is tiny relative to the >=1200-byte
        Initial that triggered it, so it is inherently within the RFC 9000
        sec 8.1 3x anti-amplification limit.
        """
        var addr_bytes = List[UInt8](String(peer).as_bytes())
        var now = _monotonic_ms()
        var extras: InitialExtras
        try:
            extras = parse_initial_extras(datagram, lh.payload_offset)
        except:
            return None  # malformed Initial -> drop
        # No token, or a NEW_TOKEN one that did not validate: answer with
        # a Retry (sec 8.1.3).
        if len(extras.token) == 0 or extras.token[0] == NEW_TOKEN_VERSION:
            try:
                var token = mint_retry_token(
                    self._retry_key, addr_bytes, lh.dcid, now
                )
                var scid = ConnectionId(
                    bytes=_random_bytes(self.config.local_cid_length)
                )
                var retry = encode_retry_packet(
                    lh.version, lh.scid, scid, token, lh.dcid
                )
                _ = self.send_to(Span[UInt8, _](retry), peer)
            except:
                pass  # best-effort; a failed Retry just drops the Initial
            return None
        var odcid = validate_retry_token(
            self._retry_key,
            extras.token,
            addr_bytes,
            now,
            self.config.retry_token_max_age_ms,
        )
        return odcid^  # the recovered ODCID, or None to drop

    def _dispatch_short(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Short-header path: parse with the listener's pinned
        DCID length, route by DCID."""
        var sh_dcid_len = self.config.local_cid_length
        if sh_dcid_len <= 0 or sh_dcid_len > MAX_CID_LENGTH:
            return -1
        var sh = parse_short_header(datagram, sh_dcid_len)
        var dcid_hex = cid_to_hex(sh.dcid)
        return self.cid_table.lookup(dcid_hex)

    def _maybe_send_stateless_reset(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises:
        """Emit a stateless reset for an unknown-DCID short-header
        datagram (RFC 9000 sec 10.3), best-effort.

        Parses the DCID with the listener's pinned length, derives the
        reset token from it, and sends a loop-safe reset to ``peer``.
        Any parse / build / send failure is swallowed (the reset is an
        optimization over a silent drop, never a correctness
        requirement)."""
        var sh_dcid_len = self.config.local_cid_length
        if sh_dcid_len <= 0 or sh_dcid_len > MAX_CID_LENGTH:
            return
        var dcid: ConnectionId
        try:
            dcid = parse_short_header(datagram, sh_dcid_len).dcid.copy()
        except:
            return
        var reset = self._build_stateless_reset(dcid, len(datagram))
        if len(reset) == 0:
            return
        try:
            _ = self.send_to(Span[UInt8, _](reset), peer)
        except:
            pass

    def _accept_initial(
        mut self,
        lh: LongHeader,
        peer: SocketAddr,
        retry_odcid: Optional[ConnectionId] = Optional[ConnectionId](),
    ) raises -> Int:
        """Allocate a new connection slot for an Initial packet
        with an unknown DCID.

        The server registers the client-chosen DCID in
        :attr:`cid_table` so subsequent Initials addressed to
        the same DCID route here. RFC 9000 §7.2 says the server
        SHOULD choose its own SCID and switch to it on the
        server-side response.

        Also materializes the per-slot rustls QUIC session, the
        empty CRYPTO egress queue, the peer UDP address (so the
        egress drain can :meth:`send_to` without re-parsing), and
        arms the per-connection idle timeout.
        """
        # Our own CID, of the length the short-header parser assumes
        # (RFC 9000 sec 7.2). The client's DCID stays registered too,
        # for its Initial retransmits and for Initial keys.
        var local_cid = self._new_local_cid()
        var peer_cid = lh.scid.copy()
        var qc = QuicConnection(
            local_cid,
            peer_cid,
            self.config.max_idle_timeout_ms * UInt64(1_000),
            self.config.initial_max_data,
        )
        qc.initial_dcid = lh.dcid.copy()
        qc.fc_adv_max_data = self.config.initial_max_data
        qc.fc_adv_max_bidi = self.config.initial_max_streams_bidi
        qc.conn.adv_max_streams_bidi = self.config.initial_max_streams_bidi
        qc.conn.adv_max_streams_uni = self.config.initial_max_streams_uni
        qc.conn.max_datagram_recv = self.config.max_datagram_frame_size
        qc.serial = self._next_serial
        self._next_serial += 1
        if retry_odcid:
            qc.addr_validated = True  # the Retry token proved it
        var live = len(self.connections) - len(self.free_slots)
        if live >= self.config.max_connections or self._drain_deadline_ms != 0:
            return -1
        var reuse = len(self.free_slots) > 0
        var slot: Int
        if reuse:
            slot = self.free_slots.pop()
            self.slot_free[slot] = False
            self.connections[slot] = qc^
        else:
            slot = len(self.connections)
            self.connections.append(qc^)
            self.slot_free.append(False)
        # After a Retry the client's current DCID is the Retry's SCID;
        # the original DCID came back in the token.
        var original_dcid = lh.dcid.copy()
        var retry_scid = List[UInt8]()
        if retry_odcid:
            original_dcid = retry_odcid.value().copy()
            retry_scid = lh.dcid.bytes.copy()
        var session = self._new_session_slot(
            local_cid, original_dcid, retry_scid
        )
        if reuse:
            self.tls_sessions[slot] = session^
            self.tls_egress_queues[slot] = List[UInt8]()
            self.tls_handshake_egress_queues[slot] = List[UInt8]()
            self.crypto_reasm[slot] = _CryptoReasm()
            self.tls_1rtt_egress_queues[slot] = List[UInt8]()
            self.peer_addrs[slot] = peer
            self.migration_probe[slot] = MigrationProbe()
            self.rx_1rtt_ranges[slot] = List[UInt64]()
            self.rx_1rtt_ack_pending[slot] = False
            self.handshake_done_sent[slot] = False
            self.next_local_cid_seq[slot] = UInt64(1)
            self.pending_migration_tx[slot] = List[UInt8]()
            self.rx_stream_bytes[slot] = UInt64(0)
            self.rx_bidi_stream_count[slot] = UInt64(0)
            self.http3_connections[slot] = Http3Connection.with_config(
                self.config.http3
            )
            self.loss[slot] = LossRecovery()
            self.loss_init[slot] = LossRecovery()
            self.loss_hs[slot] = LossRecovery()
        else:
            self.tls_sessions.append(session^)
            self.tls_egress_queues.append(List[UInt8]())
            self.tls_handshake_egress_queues.append(List[UInt8]())
            self.crypto_reasm.append(_CryptoReasm())
            self.tls_1rtt_egress_queues.append(List[UInt8]())
            self.peer_addrs.append(peer)
            self.migration_probe.append(MigrationProbe())
            self.rx_1rtt_ranges.append(List[UInt64]())
            self.rx_1rtt_ack_pending.append(False)
            self.handshake_done_sent.append(False)
            self.next_local_cid_seq.append(UInt64(1))
            self.pending_migration_tx.append(List[UInt8]())
            self.rx_stream_bytes.append(UInt64(0))
            self.rx_bidi_stream_count.append(UInt64(0))
            self.http3_connections.append(
                Http3Connection.with_config(self.config.http3)
            )
            self.loss.append(LossRecovery())
            self.loss_init.append(LossRecovery())
            self.loss_hs.append(LossRecovery())
        self.cid_table.register(cid_to_hex(local_cid), slot)
        self.connections[slot].issued_cids[UInt64(0)] = cid_to_hex(local_cid)
        self.cid_table.register(cid_to_hex(lh.dcid), slot)
        _ = self.schedule_idle_timeout(slot)
        return slot

    def _new_session_slot(
        mut self,
        local_cid: ConnectionId,
        original_dcid: ConnectionId,
        retry_scid: List[UInt8] = List[UInt8](),
    ) -> _SessionSlot:
        """Materialize a per-slot rustls QUIC session.

        Empty-PEM configurations (the default
        :class:`RustlsQuicConfig` shape that the existing test
        suite + fuzz harness rely on) leave the acceptor's
        opaque handle at 0; this method short-circuits to the
        NULL-handle sentinel slot. Production paths with a real
        PEM cert encode the server's QUIC transport parameters
        (RFC 9000 sec 18) and hand them to :func:`_do_accept` so
        rustls emits the mandatory ``quic_transport_parameters``
        TLS extension; any FFI rejection falls through to the
        NULL sentinel so the slab stays in lockstep with
        :attr:`connections`.
        """
        if self.tls_acceptor._opaque_handle == 0:
            return _SessionSlot(handle=0)
        var tp_blob: List[UInt8]
        try:
            tp_blob = _encode_server_transport_params(
                self.config, local_cid, original_dcid, retry_scid
            )
        except:
            return _SessionSlot(handle=0)
        try:
            var handle = _do_accept(
                self.tls_acceptor._lib,
                self.tls_acceptor._opaque_handle,
                tp_blob,
            )
            return _SessionSlot(handle=handle)
        except:
            return _SessionSlot(handle=0)

    def tick(mut self, timeout_ms: Int = 100) raises -> Bool:
        """Drain a burst of inbound datagrams and pump egress.

        Reactor I/O loop step:

        1. One ``recvmmsg`` blocks (``SO_RCVTIMEO``) until a datagram
           arrives or the wait times out cleanly, and takes the rest of
           the burst, up to :data:`_RX_BATCH` datagrams, with each
           one's ECN codepoint. Without ``recvmmsg``, a blocking
           ``recv_from`` wakes the tick and ``try_recv_from`` drains
           the rest. Either way the per-tick H3 pump / timer / egress
           bookkeeping in the serve loop is amortized over the whole
           burst instead of paid per datagram.
        3. Each datagram routes through :meth:`dispatch_datagram`
           by DCID; the matched slot's :meth:`_drain_and_send`
           flushes its ACK / response.

        Returns ``True`` if at least one datagram was dispatched,
        ``False`` if the initial ``recv_from`` timed out.
        """
        if timeout_ms != self._rcv_timeout_ms:
            # One setsockopt per change, not one per loop turn.
            self._socket.set_recv_timeout(timeout_ms)
            self._rcv_timeout_ms = timeout_ms
        # Drain each touched slot once, after the whole burst: draining
        # after every datagram sent one ACK packet per packet received
        # (RFC 9000 sec 13.2.1 asks for one per two ack-eliciting).
        var dirty = List[Int]()
        if self._rx_batch_ok:
            # One recvmmsg waits (up to SO_RCVTIMEO) for the first
            # datagram and takes the rest of the burst, with each one's
            # ECN codepoint; the blocking recv_from below saw neither.
            try:
                var n = self._rx_batch.recv(self._socket.fd(), wait=True)
                for i in range(n):
                    self._rx_ecn = self._rx_batch.ecn(i)
                    var nslot = self.dispatch_datagram(
                        self._rx_batch.message(i), self._rx_batch.sender(i)
                    )
                    if nslot >= 0 and nslot not in dirty:
                        dirty.append(nslot)
                self._rx_ecn = 0
                self._take_forwarded(dirty)
                if n == 0:
                    _ = self.drain_all_egress()
                    return False
                self._drain_slots(dirty)
                return True
            except e:
                self._rx_ecn = 0
                # ENOSYS: latch off and fall through to the per-datagram
                # path for the rest of the process lifetime.
                if String(e).startswith("UdpBatchUnsupported"):
                    self._rx_batch_ok = False
                else:
                    self._drain_slots(dirty)
                    raise e^
        var buf = List[UInt8]()
        buf.resize(Int(self.config.max_udp_payload_size), 0)
        var sender: SocketAddr
        var got: Int
        try:
            var pair = self._socket.recv_from(Span[UInt8, _](buf))
            got = pair[0]
            sender = pair[1]
        except e:
            # ``UdpSocket.recv_from`` raises :class:`Timeout` for
            # both ``EAGAIN`` and ``EWOULDBLOCK``; the dispatch
            # loop treats both as "no datagram this tick" but
            # still drains pending egress so an already-handshaking
            # session can flush its ServerHello fragments.
            var msg = String(e)
            if msg.startswith("Timeout") or msg.startswith("recvfrom"):
                var fwd = List[Int]()
                self._take_forwarded(fwd)
                _ = self.drain_all_egress()
                return False
            raise e^
        if got <= 0:
            var fwd = List[Int]()
            self._take_forwarded(fwd)
            _ = self.drain_all_egress()
            return False
        var slot = self.dispatch_datagram(Span[UInt8, _](buf[:got]), sender)
        if slot >= 0:
            dirty.append(slot)
        # Drain the rest of the socket queue without blocking so a
        # high-rate sender's burst is handled in one tick (the path
        # without recvmmsg).
        for _ in range(_RX_BATCH - 1):
            var nb_got: Int
            var nb_sender: SocketAddr
            try:
                var nb = self._socket.try_recv_from(Span[UInt8, _](buf))
                nb_got = nb[0]
                nb_sender = nb[1]
            except:
                break
            if nb_got <= 0:
                break
            var nslot = self.dispatch_datagram(
                Span[UInt8, _](buf[:nb_got]), nb_sender
            )
            if nslot >= 0 and nslot not in dirty:
                dirty.append(nslot)
        self._take_forwarded(dirty)
        self._drain_slots(dirty)
        return True

    def _drain_slots(mut self, slots: List[Int]) raises:
        """Flush the egress of every slot a receive burst touched."""
        for i in range(len(slots)):
            _ = self._drain_and_send(slots[i])

    def poll_timeout_ms(self, max_ms: Int = 100) -> Int:
        """How long :meth:`tick` may block: until the next timer (PTO,
        loss time, idle, closing) is due, at most ``max_ms`` and at least
        1 ms (``SO_RCVTIMEO`` 0 would block forever). A fixed 100 ms wait
        delayed every timer on a quiet connection by up to that long."""
        var now = _monotonic_ms()
        var next = self.timer_wheel.next_fire_ms()
        if next <= now:
            return 1
        return max(1, min(max_ms, Int(next - now)))

    def send_to(self, datagram: Span[UInt8, _], addr: SocketAddr) raises -> Int:
        """Emit a single fully-protected QUIC datagram on the
        listener's UDP socket. Thin wrapper over
        :meth:`flare.udp.socket.UdpSocket.send_to` so the
        egress path has the same surface the unit tests stub.
        Returns the byte count actually written (UDP either
        sends the whole datagram or raises)."""
        return self._socket.send_to(datagram, addr)

    def drain_all_egress(mut self) raises -> Int:
        """Drain every slot's :attr:`tls_egress_queues` onto the
        wire. Returns the number of datagrams emitted.

        Called from the reactor between recv ticks (and on the
        ``recv_from`` timeout path) so a slot with pending
        outbound CRYPTO bytes can flush even if no inbound
        datagram arrived. Pure no-op if no slot has pending
        bytes.
        """
        var emitted = 0
        for slot in range(len(self.connections)):
            if self._drain_and_send(slot):
                emitted += 1
        return emitted

    def _drain_and_send(mut self, slot: Int) raises -> Bool:
        """Drain every pending egress queue for ``slot`` onto
        the wire.

        Returns ``True`` if at least one datagram was emitted.
        Per-level queues drained (each is independent and any
        subset can be non-empty at a given tick):

        * ``tls_egress_queues[slot]`` -- Initial-level CRYPTO
          (rustls ServerHello + EncryptedExtensions before the
          KeyChange::Handshake fires).
          Encrypted via flare's :func:`protect_initial_packet`
          (DCID-derived OpenSSL secret per RFC 9001 §5.2).
        * ``tls_handshake_egress_queues[slot]`` -- Handshake-
          level CRYPTO (rustls Certificate + CertificateVerify
          + Finished, between KeyChange::Handshake and
          KeyChange::OneRtt).
          Encrypted via :meth:`_build_handshake_response`
          which routes through rustls's
          ``Keys.local.packet.encrypt_in_place``.
        * ``tls_1rtt_egress_queues[slot]`` -- 1-RTT CRYPTO
          (rustls post-handshake messages like
          NewSessionTicket).
          Encrypted via :meth:`_build_1rtt_handshake_crypto`.
        * ``QuicConnection.h3_tx`` -- 1-RTT STREAM frames carrying
          H3 response bytes (the live H3 reactor's actual
          payload). Encrypted via the coalescing 1-RTT drain
          (:meth:`_drain_1rtt_coalesced`).

        Each builder is a no-op (returns empty) when its
        respective queue is empty OR the matching per-level
        readiness sentinel hasn't been installed yet by the
        :meth:`_dispatch_crypto_frames` pump.  Slots whose
        connection is closed (`alive == False`) skip every
        level entirely.

        Errors during build/protect short-circuit to ``False``
        without raising; the silent-drop discipline mirrors the
        inbound side (RFC 9001 §5.2).
        """
        if slot < 0 or slot >= len(self.connections):
            return False
        if slot >= len(self.peer_addrs):
            return False
        if not self.connections[slot].alive:
            return False
        # RFC 9000 sec 10.2.2: a draining endpoint sends no packet.
        if self.connections[slot].conn.state == CONN_STATE_DRAINING:
            return False
        var emitted = False
        var peer = self.peer_addrs[slot]
        # The handshake flight goes out in packets of at most
        # _HANDSHAKE_CHUNK CRYPTO bytes (a whole certificate chain in
        # one packet overran any path MTU), and, until the peer's
        # address is validated, only as far as 3x the bytes received
        # from it (RFC 9000 sec 8.1). What does not fit stays queued
        # for the next drain, after the peer sends more.
        # Initial and Handshake CRYPTO, with the ACKs owed at those
        # levels, coalesced into one datagram (RFC 9000 sec 12.2): the
        # Handshake packet is built first so the Initial ahead of it can
        # be padded to make an ack-eliciting Initial datagram 1200 bytes
        # (sec 14.1).
        while True:
            ref qc = self.connections[slot]
            var init_q = len(self.tls_egress_queues[slot])
            var hs_ready = len(qc.tx_handshake_secret) > 0
            var hs_q = len(self.tls_handshake_egress_queues[slot])
            if not hs_ready:
                hs_q = 0
            # Nothing more is sent at a level once its keys are
            # discarded (RFC 9001 sec 4.9).
            var want_init = not qc.initial_keys_discarded and (
                init_q > 0 or qc.lh_ack_pending[0]
            )
            var want_hs = (
                hs_ready
                and not self.handshake_done_sent[slot]
                and (hs_q > 0 or qc.lh_ack_pending[1])
            )
            if not want_init and not want_hs:
                break
            var take_i = min(init_q, _HANDSHAKE_CHUNK) if want_init else 0
            var take_h = min(hs_q, _HANDSHAKE_CHUNK - take_i)
            var est = take_i + take_h + 2 * _LONG_PACKET_OVERHEAD
            if take_i > 0 and est < _MIN_INITIAL_DATAGRAM:
                est = _MIN_INITIAL_DATAGRAM
            if not self._amplification_allows(slot, est):
                break
            var hs_dg = List[UInt8]()
            if want_hs:
                hs_dg = self._build_handshake_response(
                    slot, max_bytes=take_h if take_h > 0 else -1
                )
                if len(hs_dg) > 0:
                    self.tls_handshake_egress_queues[slot] = _queue_rest(
                        self.tls_handshake_egress_queues[slot], take_h
                    )
            var datagram = List[UInt8]()
            if want_init:
                datagram = self._build_initial_response(
                    slot,
                    max_bytes=take_i if take_i > 0 else -1,
                    pad_to=_MIN_INITIAL_DATAGRAM - len(hs_dg),
                )
                if len(datagram) > 0:
                    self.tls_egress_queues[slot] = _queue_rest(
                        self.tls_egress_queues[slot], take_i
                    )
            datagram.extend(Span[UInt8, _](hs_dg))
            if len(datagram) == 0:
                break
            _ = self.send_to(Span[UInt8, _](datagram), peer)
            self.connections[slot].amp_tx += len(datagram)
            emitted = True
            self._rearm_pto_timer(slot)
        # 1-RTT-level CRYPTO (rustls post-handshake; gated on
        # the 1-RTT readiness sentinel).
        if (
            slot < len(self.tls_1rtt_egress_queues)
            and len(self.tls_1rtt_egress_queues[slot]) > 0
        ):
            var rtt_dg = self._build_1rtt_handshake_crypto(slot)
            if len(rtt_dg) > 0:
                _ = self.send_to(Span[UInt8, _](rtt_dg), peer)
                self.tls_1rtt_egress_queues[slot] = List[UInt8]()
                emitted = True
        # 1-RTT ACK (+ HANDSHAKE_DONE once). Only emit once a real
        # 1-RTT packet has arrived: acking a packet number the peer
        # never sent is a protocol violation (RFC 9000 sec 13.1).
        # Without the ACK the peer's loss detection stalls and it
        # retransmits forever (sec 13.2). HANDSHAKE_DONE (sec 19.20)
        # rides the first ACK to confirm the handshake so the peer
        # discards Handshake keys.
        # Coalesced 1-RTT egress: the pending ACK (+ HANDSHAKE_DONE
        # once + flow-control credit) and every ready H3 response
        # STREAM frame are packed into as few datagrams as the MTU
        # allows -- one AEAD encrypt + one sendto per datagram
        # instead of one per response plus a separate ACK packet.
        # Path-validation probe egress: routed to the candidate
        # under its own 3x budget, kept off the validated-path drain
        # below. No-op in steady state (nothing stashed, not probing).
        if self._drain_migration_probe(slot):
            emitted = True
        if self._drain_1rtt_coalesced(slot, peer):
            emitted = True
        return emitted

    def _drain_migration_probe(mut self, slot: Int) raises -> Bool:
        """Strict-hold egress for path-validation frames.

        PATH_CHALLENGE / PATH_RESPONSE frames stashed for ``slot`` are
        sent in their own 1-RTT datagram. While a candidate path is
        under validation they go ONLY to that candidate -- never the
        validated path -- and the protected datagram is charged against
        the candidate's 3x anti-amplification budget (RFC 9000 sec 8.1
        / sec 21.5.4); when the budget is exhausted the frames stay
        stashed and flush on a later drain once more bytes arrive on
        the path. With no migration in flight (the steady state) this
        is a pure no-op: nothing is stashed and ``probing`` is False.

        Returns ``True`` iff a datagram was emitted.
        """
        if slot < 0 or slot >= len(self.pending_migration_tx):
            return False
        if len(self.pending_migration_tx[slot]) == 0:
            return False
        if not self._has_1rtt_keys(slot):
            return False
        var probing = (
            slot < len(self.migration_probe)
            and self.migration_probe[slot].probing
        )
        var dest: SocketAddr
        if probing:
            dest = self.migration_probe[slot].candidate
        else:
            # A same-path client PATH_CHALLENGE (no migration): echo on
            # the validated path, no amplification cap.
            dest = self.peer_addrs[slot]
        var frames = self.pending_migration_tx[slot].copy()
        if probing:
            # Estimate the protected datagram size (frames + short
            # header + pn + AEAD tag) and refuse to exceed the
            # unvalidated path's 3x budget. Held frames stay stashed and
            # flush once inbound bytes grow the budget.
            var est = (
                len(frames)
                + self.connections[slot].peer_cid.length()
                + 1  # short-header flags byte
                + 2  # packet-number length
                + 16  # AEAD tag
            )
            if not self.migration_probe[slot].amplification_allows(est):
                return False
        # Not tracked for loss recovery: this goes to the *candidate*
        # address under an anti-amplification budget, and RFC 9002
        # keeps congestion and loss state per path. Folding probe
        # packets into the established path's LossRecovery would
        # conflate two paths' RTT samples.
        var dg = self._build_1rtt_response(slot, frames^)
        if len(dg) == 0:
            return False
        _ = self.send_to(Span[UInt8, _](dg), dest)
        self.pending_migration_tx[slot] = List[UInt8]()
        if probing:
            self.migration_probe[slot].note_tx(len(dg))
        return True

    def _close_after_state_error(mut self, slot: Int):
        """A frame the state machine rejected (PROTOCOL_VIOLATION,
        STREAM_STATE_ERROR, ...) has already put the connection into
        CLOSING; signal it like every other connection error: a
        CONNECTION_CLOSE and the closing period (RFC 9000 sec 10.2, 11.1)."""
        if (
            slot >= 0
            and slot < len(self.connections)
            and self.connections[slot].alive
            and self.connections[slot].conn.state == CONN_STATE_CLOSING
        ):
            self._close_for(
                slot,
                self.connections[slot].conn.close_error_code,
                "frame rejected",
            )

    def _close_for(
        mut self,
        slot: Int,
        code: UInt64,
        reason: String,
        application: Bool = False,
    ):
        """Close ``slot`` with error ``code``: the connection error is
        signalled with a 1-RTT CONNECTION_CLOSE (RFC 9000 sec 11.1) and
        the slot enters the closing state (sec 10.2) -- see
        :meth:`_enter_closing`. ``application`` selects the
        application-level frame (0x1d) that HTTP/3 and QPACK codes travel
        in (RFC 9114 sec 8); their values overlap the transport CRYPTO
        range, so they were sent as transport errors."""
        connection_close(self.connections[slot].conn, code, reason)
        self.connections[slot].alive = False
        self._enter_closing(slot, code, application)

    def _enter_closing(
        mut self, slot: Int, code: UInt64, application: Bool = False
    ):
        """Send CONNECTION_CLOSE(``code``) and keep ``slot`` routable for
        three PTOs (capped at :data:`_MAX_CLOSING_MS`), answering each
        packet it receives meanwhile (RFC 9000 sec 10.2, 10.2.1).

        The idle timer is replaced by one that ends the closing period,
        and the PTO timer is dropped. When no 1-RTT keys exist yet there
        is no packet to carry the frame: the slot then closes silently
        and the next timer of the slot reclaims it, as before.
        """
        if slot < 0 or slot >= len(self.peer_addrs):
            return
        try:
            var plaintext = List[UInt8]()
            encode_connection_close(
                ConnectionCloseFrame(
                    application, code, UInt64(0), List[UInt8]()
                ),
                plaintext,
            )
            # Enough ciphertext for the header-protection sample.
            while len(plaintext) < 16:
                plaintext.append(UInt8(0))
            var frame = plaintext.copy()
            var dg = self._build_1rtt_response(slot, plaintext^)
            if len(dg) == 0:
                return
            _ = self.send_to(Span[UInt8, _](dg), self.peer_addrs[slot])
            self.connections[slot].close_frame = frame^
        except:
            return
        var period = UInt64(3) * self.loss[
            slot
        ].pto_interval_ms() if slot < len(self.loss) else UInt64(0)
        if period > _MAX_CLOSING_MS:
            period = _MAX_CLOSING_MS
        if period < UInt64(1):
            period = UInt64(1)
        try:
            self._cancel_pto_timer(slot)
            var old_id = self.connections[slot].idle_timer_id
            if old_id != UInt64(0):
                _ = self.timer_wheel.cancel(old_id)
            self.connections[slot].idle_timer_id = self.timer_wheel.schedule(
                after_ms=Int(period),
                token=encode_timer_token(TIMER_KIND_IDLE, slot),
            )
            self.connections[slot].closing = True
            self.connections[slot].closing_rx = 0
        except:
            pass

    def _answer_closing(mut self, slot: Int):
        """A packet arrived for a closing slot: answer with CONNECTION_CLOSE
        (RFC 9000 sec 10.2.1), for the 1st, 2nd, 4th, 8th, ... packet so a
        flood cannot make the server a reflector."""
        if slot >= len(self.peer_addrs):
            return
        self.connections[slot].closing_rx += 1
        var n = self.connections[slot].closing_rx
        if (n & (n - 1)) != 0:
            return
        try:
            var dg = self._build_1rtt_response(
                slot, self.connections[slot].close_frame.copy()
            )
            if len(dg) > 0:
                _ = self.send_to(Span[UInt8, _](dg), self.peer_addrs[slot])
        except:
            pass

    def _note_stream_consumed(mut self, slot: Int, sid: Int):
        """A request stream was answered: its bytes and its stream slot
        count toward the next grant."""
        ref qc = self.connections[slot]
        if sid in qc.fc_stream_end:
            try:
                qc.fc_consumed += qc.fc_stream_end.pop(
                    sid
                ) - qc.fc_tunnel_credited.pop(sid, UInt64(0))
            except:
                pass
        if (sid & 0x3) == 0:
            qc.fc_closed_bidi += 1

    def _amplification_allows(self, slot: Int, crypto_bytes: Int) -> Bool:
        """Whether a long-header packet carrying ``crypto_bytes`` fits
        the slot's 3x anti-amplification budget (RFC 9000 sec 8.1)."""
        ref c = self.connections[slot]
        if c.addr_validated:
            return True
        return c.amp_tx + crypto_bytes + _LONG_PACKET_OVERHEAD <= 3 * c.amp_rx

    def _has_1rtt_keys(self, slot: Int) -> Bool:
        """True if the slot has installed 1-RTT traffic secrets
        (handshake complete). Gates the ACK / HANDSHAKE_DONE egress.
        """
        if slot < 0 or slot >= len(self.connections):
            return False
        return len(self.connections[slot].tx_1rtt_secret) > 0

    def _drain_1rtt_coalesced(
        mut self, slot: Int, peer: SocketAddr
    ) raises -> Bool:
        """Coalesced 1-RTT egress: pack the pending ACK frame and
        every ready H3 response STREAM frame for ``slot`` into as
        few short-header datagrams as the path MTU allows, one
        AEAD encrypt + one ``sendto`` per datagram.

        This replaces the prior one-datagram-per-response (plus a
        separate ACK datagram) scheme. Under stream concurrency the
        old scheme issued ~2 syscalls + 2 rustls crossings per
        request; coalescing collapses a whole batch of responses
        into a handful of full-size datagrams, which is the dominant
        win for matching the Rust h3 baselines (RFC 9000 sec 12.2
        permits any number of frames per packet).

        Returns True iff at least one datagram was sent.
        """
        if not self._has_1rtt_keys(slot):
            return False
        # Plaintext budget: leave headroom for the short header
        # (1 + dcid) + packet number + AEAD tag so the protected
        # datagram stays within the validated path size (RFC 9000
        # sec 14): it used to fill max_udp_payload_size from the first
        # packet, which a path with a smaller MTU black-holed.
        var budget = self.connections[slot].pmtu.current - 64
        if budget < 64:
            budget = 64
        var plaintext = List[UInt8](capacity=budget + 64)
        var emitted = False

        # ACK (+ HANDSHAKE_DONE once + flow-control credit) leads
        # the first datagram. These frames are small and always fit.
        var owe_ack = (
            self.rx_1rtt_ack_pending[slot]
            and len(self.rx_1rtt_ranges[slot]) >= 2
        )
        var first_flight = (
            not self.handshake_done_sent[slot]
            and self.connections[slot].conn.handshake_complete
        )
        if owe_ack or first_flight:
            if owe_ack:
                var ack = _ack_from_ranges(self.rx_1rtt_ranges[slot], UInt64(0))
                ref e = self.connections[slot].ecn_rx
                if e[0] + e[1] + e[2] > 0:
                    ack.ecn.append(EcnCounts(ect0=e[0], ect1=e[1], ce=e[2]))
                encode_ack(ack, plaintext)
            if not self.handshake_done_sent[slot]:
                encode_handshake_done(plaintext)
            # Credit from consumption: at most _MAX_DATA_WINDOW bytes
            # and _MAX_STREAMS_BIDI_WINDOW streams outstanding beyond
            # what has been answered. Never lowered (sec 4.1).
            ref qc = self.connections[slot]
            var want_data = qc.fc_consumed + _MAX_DATA_WINDOW
            if want_data > qc.fc_adv_max_data:
                qc.fc_adv_max_data = want_data
            var want_bidi = qc.fc_closed_bidi + _MAX_STREAMS_BIDI_WINDOW
            if want_bidi > qc.fc_adv_max_bidi:
                qc.fc_adv_max_bidi = want_bidi
                qc.conn.adv_max_streams_bidi = want_bidi
            var max_data = MaxDataFrame(maximum_data=qc.fc_adv_max_data)
            encode_max_data(max_data, plaintext)
            var max_streams = MaxStreamsFrame(
                unidirectional=False,
                maximum_streams=qc.fc_adv_max_bidi,
            )
            encode_max_streams(max_streams, plaintext)
            if not self.handshake_done_sent[slot]:
                # Spare CIDs up to the peer's limit (RFC 9000 sec 5.1.1),
                # so it can migrate or rotate (sec 9.5).
                var want = min(
                    self.connections[slot].peer_cid_limit, _MAX_ISSUED_CIDS
                )
                for _ in range(1, Int(want)):
                    self._issue_new_connection_id(slot, plaintext)
                # A token the client may present next time to skip the
                # Retry round trip (RFC 9000 sec 8.1.3).
                if self.config.require_address_validation:
                    encode_new_token(
                        NewTokenFrame(
                            mint_new_token(
                                self._retry_key,
                                _ip_bytes(self.peer_addrs[slot]),
                                _monotonic_ms(),
                            )
                        ),
                        plaintext,
                    )
                # RFC 9114 sec 6.2.1: each side MUST initiate its control
                # stream at the beginning of the connection and send
                # SETTINGS first. The server's is stream 3, the first
                # server-initiated unidirectional stream; it was never
                # opened (H3-07). The first 1-RTT flight carries it, once.
                var control = self.http3_connections[
                    slot
                ].take_control_stream_start()
                if len(control) > 0:
                    _encode_h3_stream_frame(
                        plaintext,
                        UInt64(H3_SERVER_CONTROL_STREAM_ID),
                        UInt64(0),
                        Span[UInt8, _](control),
                        fin=False,
                    )
                    self.connections[slot].ctrl_off = UInt64(len(control))
                    mark_local_stream_opened(
                        self.connections[slot].conn,
                        UInt64(H3_SERVER_CONTROL_STREAM_ID),
                    )
            self.rx_1rtt_ack_pending[slot] = False
            if not self.handshake_done_sent[slot] and slot < len(self.loss_hs):
                # Handshake confirmed: the Handshake space is done
                # (RFC 9001 sec 4.9.2).
                self.loss_hs[slot] = LossRecovery()
                self.connections[slot].lh_ack_pending[1] = False
            self.handshake_done_sent[slot] = True

        # Migration path-validation frames (PATH_CHALLENGE /
        # PATH_RESPONSE) are NOT coalesced here -- they are routed to the
        # candidate path under their own anti-amplification budget via
        # :meth:`_drain_migration_probe`, which runs separately in
        # :meth:`_drain_and_send`. This drain only ever targets the
        # validated egress address.

        # Control-stream frames (GOAWAY) after the stream's SETTINGS.
        if (
            len(self.connections[slot].ctrl_tx) > 0
            and self.handshake_done_sent[slot]
        ):
            var frames = List[UInt8]()
            swap(frames, self.connections[slot].ctrl_tx)
            if budget - len(plaintext) < len(frames) + 24:
                if self._flush_1rtt(slot, plaintext, peer, budget):
                    emitted = True
            _encode_h3_stream_frame(
                plaintext,
                UInt64(H3_SERVER_CONTROL_STREAM_ID),
                self.connections[slot].ctrl_off,
                Span[UInt8, _](frames),
                fin=False,
            )
            self.connections[slot].ctrl_off += UInt64(len(frames))

        # Replacements for CIDs the peer retired (RFC 9000 sec 5.1.2).
        while (
            self.connections[slot].cid_replenish > 0
            and self.handshake_done_sent[slot]
        ):
            if budget - len(plaintext) < 48:
                if self._flush_1rtt(slot, plaintext, peer, budget):
                    emitted = True
            self._issue_new_connection_id(slot, plaintext)
            self.connections[slot].cid_replenish -= 1

        # Receive credit raised since the last flight (RFC 9000 sec 4.2).
        if len(self.connections[slot].fc_grants) > 0:
            var grants = List[Int]()
            swap(grants, self.connections[slot].fc_grants)
            for i in range(len(grants)):
                var s_opt = self.connections[slot].conn.streams.get(
                    UInt64(grants[i])
                )
                if not s_opt:
                    continue
                if budget - len(plaintext) < 24:
                    if self._flush_1rtt(slot, plaintext, peer, budget):
                        emitted = True
                encode_max_stream_data(
                    MaxStreamDataFrame(
                        UInt64(grants[i]), s_opt.value().max_recv_data
                    ),
                    plaintext,
                )

        if len(self.connections[slot].dg_tx) > 0:
            if self._flush_1rtt(slot, plaintext, peer, budget):
                emitted = True
            if self._drain_datagrams(slot, peer, budget):
                emitted = True

        # Response bytes, as far as the peer's MAX_STREAM_DATA and
        # MAX_DATA (RFC 9000 sec 4.1) and the congestion window (RFC 9002
        # sec 7) allow. What does not fit stays queued on the stream and
        # goes out on a later drain, after the peer's ACKs and grants.
        comptime _STREAM_HDR_MAX = 24
        var sids = List[Int]()
        var queued = 0
        for entry in self.connections[slot].h3_tx.items():
            sids.append(entry.key)
            queued += entry.value.pending()
        self._gso_active = (
            self._gso_ok and queued >= _GSO_MIN_DATAGRAMS * budget
        )
        var cc_open = True
        # Whether the datagram being filled already passed the
        # congestion-window check; reset on every flush.
        var dg_admitted = False
        for i in range(len(sids)):
            var sid = sids[i]
            var st = self.connections[slot].h3_tx.pop(sid)
            var s_opt = self.connections[slot].conn.streams.get(UInt64(sid))
            if not s_opt or s_opt.value().send_reset:
                # The peer sent STOP_SENDING (or the stream is gone): the
                # response is abandoned, and STOP_SENDING is answered with
                # RESET_STREAM (RFC 9000 sec 3.5).
                if s_opt:
                    if budget - len(plaintext) < 32:
                        if self._flush_1rtt(slot, plaintext, peer, budget):
                            emitted = True
                        dg_admitted = False
                    encode_reset_stream(
                        ResetStreamFrame(
                            UInt64(sid), _H3_REQUEST_CANCELLED, st.off
                        ),
                        plaintext,
                    )
                if st.src_addr != 0:
                    Pool[ChunkSourceBox].free(st.src_addr)
                    self._open_sources -= 1
                self._reclaim_http3_stream(slot, sid)
                continue
            var stream_limit = s_opt.value().max_send_data
            var conn_limit = self.connections[slot].conn.max_data_send
            var conn_sent = self.connections[slot].fc_tx_sent
            var stream_room = (
                Int(stream_limit - st.off) if stream_limit > st.off else 0
            )
            var conn_room = (
                Int(conn_limit - conn_sent) if conn_limit > conn_sent else 0
            )
            var avail = min(st.pending(), min(stream_room, conn_room))
            var fin_now = st.done and avail == st.pending()
            var sent = 0
            var fin_sent = False
            while cc_open and (sent < avail or (fin_now and not fin_sent)):
                var room = budget - len(plaintext) - _STREAM_HDR_MAX
                if room <= 0:
                    if self._flush_1rtt(slot, plaintext, peer, budget):
                        emitted = True
                    dg_admitted = False
                    room = budget - _STREAM_HDR_MAX
                if not dg_admitted:
                    if not self.loss[slot].can_send(UInt64(budget)):
                        cc_open = False
                        break
                    var wait = self.loss[slot].pace_admit(
                        _monotonic_ms(), UInt64(budget)
                    )
                    if wait > 0:
                        # Paced: resume when the bucket refills.
                        cc_open = False
                        self._arm_send_timer(slot, Int(wait))
                        break
                    dg_admitted = True
                var take = min(room, avail - sent)
                var fin = fin_now and sent + take == avail
                _encode_h3_stream_frame(
                    plaintext,
                    UInt64(sid),
                    st.off + UInt64(sent),
                    Span[UInt8, _](st.buf)[
                        st.pos + sent : st.pos + sent + take
                    ],
                    fin=fin,
                )
                sent += take
                fin_sent = fin
            st.consume(sent)
            self.connections[slot].fc_tx_sent += UInt64(sent)
            if fin_sent:
                # The response is complete: reclaim the per-stream
                # carriers now, or completed streams pile up in the H3
                # driver's and the QUIC connection's stream Dicts.
                self._reclaim_http3_stream(slot, sid)
                continue
            if cc_open and st.pending() > 0:
                # Held by flow control: tell the peer, once per limit
                # (RFC 9000 sec 4.1, sec 19.12-19.13).
                if budget - len(plaintext) < 24:
                    if self._flush_1rtt(slot, plaintext, peer, budget):
                        emitted = True
                    dg_admitted = False
                if stream_room <= avail and st.blocked_at != stream_limit:
                    encode_stream_data_blocked(
                        StreamDataBlockedFrame(UInt64(sid), stream_limit),
                        plaintext,
                    )
                    st.blocked_at = stream_limit
                elif (
                    conn_room <= avail
                    and self.connections[slot].fc_blocked_at != conn_limit
                ):
                    encode_data_blocked(DataBlockedFrame(conn_limit), plaintext)
                    self.connections[slot].fc_blocked_at = conn_limit
            self.connections[slot].h3_tx[sid] = st^

        if len(plaintext) > 0:
            var dg = self._build_1rtt_response(
                slot, plaintext^, ack_eliciting=True
            )
            if len(dg) > 0:
                self._queue_datagram(dg, peer)
                emitted = True
        self._flush_gso()
        self._gso_active = False
        if self.handshake_done_sent[slot] and self._probe_pmtu(slot, peer):
            emitted = True
        return emitted

    def _probe_pmtu(mut self, slot: Int, peer: SocketAddr) raises -> Bool:
        """Send the next path-MTU probe, if one is due (RFC 9000 sec
        14.3): a PING padded to the size under test, outside loss
        recovery so its loss is not read as congestion (RFC 9002 sec
        14.4)."""
        ref pm = self.connections[slot].pmtu
        var now = _monotonic_ms()
        pm.check_lost(now, self.loss[slot].pto_interval_ms())
        var size = pm.want_probe()
        if size == 0:
            return False
        var frames = List[UInt8](capacity=size)
        encode_ping(frames)
        # Short header + 4-byte packet number + AEAD tag.
        var overhead = 1 + len(self.connections[slot].peer_cid.bytes) + 4 + 16
        frames.resize(size - overhead, UInt8(0))
        var pn = self.connections[slot].tx_1rtt_pn
        var dg = self._build_1rtt_response(slot, frames^, pn_length=4)
        if len(dg) == 0:
            return False
        self.connections[slot].pmtu.on_probe_sent(pn, len(dg), now)
        _ = self.send_to(Span[UInt8, _](dg), peer)
        return True

    def send_datagram(mut self, slot: Int, payload: Span[UInt8, _]) -> Bool:
        """Queue ``payload`` as an unreliable DATAGRAM (RFC 9221) for the
        next drain. False, and nothing queued, when the client takes no
        DATAGRAMs, the frame would exceed its ``max_datagram_frame_size``
        or one packet, or the queue is full."""
        if slot < 0 or slot >= len(self.connections):
            return False
        ref c = self.connections[slot]
        var n = len(payload)
        var frame = n + 9  # type + length varint, at most
        if (
            UInt64(frame) > c.peer_max_datagram
            or frame > c.pmtu.current - 64
            or c.dg_tx_bytes + n > MAX_QUEUED_DATAGRAM_BYTES
        ):
            return False
        c.dg_tx_bytes += n
        c.dg_tx.append(List[UInt8](payload))
        return True

    def _queue_datagrams(mut self, slot: Int, events: ConnectionEvents) -> Bool:
        """Queue the DATAGRAM payloads received in one packet, up to the
        queue cap. With HTTP Datagrams on (RFC 9297 sec 2.1), each must
        start with a Quarter Stream ID below 2^60 or the connection is
        closed with H3_DATAGRAM_ERROR (returns False); one for a stream
        that is not an open tunnel is dropped."""
        for i in range(len(events.datagrams)):
            ref d = events.datagrams[i]
            if self.config.http3.h3_datagram:
                var sid = -1
                try:
                    var q = decode_varint(Span[UInt8, _](d))
                    if q.value < UInt64(1) << 60:
                        sid = Int(q.value) * 4
                except:
                    pass
                if sid < 0:
                    self._close_for(
                        slot,
                        H3_DATAGRAM_ERROR,
                        "malformed HTTP Datagram",
                        application=True,
                    )
                    return False
                if not (
                    sid in self.connections[slot].h3_tx
                    and self.http3_connections[slot].is_tunnel(sid)
                ):
                    continue
            ref qd = self.connections[slot]
            if qd.dg_rx_bytes + len(d) <= MAX_QUEUED_DATAGRAM_BYTES:
                qd.dg_rx_bytes += len(d)
                qd.dg_rx.append(d.copy())
        return True

    def send_http3_datagram(
        mut self, t: Http3Tunnel, payload: Span[UInt8, _]
    ) raises -> Bool:
        """Send ``payload`` as an HTTP Datagram (RFC 9297) on tunnel
        ``t``. False, and nothing sent, unless both ends sent
        SETTINGS_H3_DATAGRAM, the tunnel is open, and
        :meth:`send_datagram` takes it."""
        if (
            not self.config.http3.h3_datagram
            or not self.http3_tunnel_open(t)
            or not self.http3_connections[t.slot].peer_settings_h3_datagram
        ):
            return False
        var dg = encode_varint(UInt64(t.stream_id // 4))
        dg.extend(payload)
        return self.send_datagram(t.slot, Span[UInt8, _](dg))

    def take_http3_datagrams(mut self, t: Http3Tunnel) -> List[List[UInt8]]:
        """The HTTP Datagram payloads received on tunnel ``t`` since the
        last call, Quarter Stream ID removed."""
        var out = List[List[UInt8]]()
        if not self._tunnel_live(t):
            return out^
        ref qd = self.connections[t.slot]
        var keep = List[List[UInt8]]()
        for i in range(len(qd.dg_rx)):
            ref d = qd.dg_rx[i]
            try:
                var q = decode_varint(Span[UInt8, _](d))
                if Int(q.value) * 4 == t.stream_id:
                    qd.dg_rx_bytes -= len(d)
                    out.append(List[UInt8](Span[UInt8, _](d)[q.consumed :]))
                    continue
            except:
                pass
            keep.append(d.copy())
        qd.dg_rx = keep^
        return out^

    def take_datagrams(mut self, slot: Int) -> List[List[UInt8]]:
        """The DATAGRAM payloads received on ``slot`` since the last call,
        in arrival order."""
        var out = List[List[UInt8]]()
        if slot >= 0 and slot < len(self.connections):
            swap(out, self.connections[slot].dg_rx)
            self.connections[slot].dg_rx_bytes = 0
        return out^

    def _drain_datagrams(
        mut self, slot: Int, peer: SocketAddr, budget: Int
    ) raises -> Bool:
        """Send the queued DATAGRAMs, packed into packets of their own:
        they count against the congestion window and the pacer, but are
        not kept for retransmission (RFC 9221 sec 5.2). What the window
        does not admit stays queued."""
        var dgs = List[List[UInt8]]()
        swap(dgs, self.connections[slot].dg_tx)
        self.connections[slot].dg_tx_bytes = 0
        var frames = List[UInt8](capacity=budget)
        var emitted = False
        var i = 0
        while i < len(dgs):
            if len(frames) + len(dgs[i]) + 9 > budget:
                emitted = self._send_untracked(slot, frames, peer) or emitted
                frames.clear()
            if len(frames) == 0:
                if not self.loss[slot].can_send(UInt64(budget)):
                    break
                var wait = self.loss[slot].pace_admit(
                    _monotonic_ms(), UInt64(budget)
                )
                if wait > 0:
                    self._arm_send_timer(slot, Int(wait))
                    break
            encode_datagram(DatagramFrame(dgs[i].copy(), True), frames)
            i += 1
        emitted = self._send_untracked(slot, frames, peer) or emitted
        ref c = self.connections[slot]
        while i < len(dgs):
            c.dg_tx_bytes += len(dgs[i])
            c.dg_tx.append(dgs[i].copy())
            i += 1
        return emitted

    def _send_untracked(
        mut self, slot: Int, frames: List[UInt8], peer: SocketAddr
    ) raises -> Bool:
        """Send ``frames`` as an ack-eliciting 1-RTT packet whose frames
        loss recovery does not keep."""
        if len(frames) == 0:
            return False
        var dg = self._build_1rtt_response(
            slot, frames.copy(), ack_eliciting=True, keep_frames=False
        )
        if len(dg) == 0:
            return False
        self._queue_datagram(dg, peer)
        return True

    def _reclaim_http3_stream(mut self, slot: Int, sid: Int) raises:
        """Drop the H3 driver's and the QUIC connection's state for a
        finished or abandoned response stream (its egress record is
        already gone), so the completed-stream scan stays linear."""
        self.http3_connections[slot].close_request_stream(sid)
        self._note_stream_consumed(slot, sid)
        if UInt64(sid) in self.connections[slot].conn.streams:
            _ = self.connections[slot].conn.streams.pop(UInt64(sid))

    def _arm_send_timer(mut self, slot: Int, after_ms: Int) raises:
        """Wake the slot's egress in ``after_ms`` (the pacer is holding
        data back), unless a wake-up is already armed."""
        if self.connections[slot].send_timer_id != UInt64(0):
            return
        self.connections[slot].send_timer_id = self.timer_wheel.schedule(
            after_ms=after_ms,
            token=encode_timer_token(TIMER_KIND_ACK_DELAY, slot),
        )

    def _flush_1rtt(
        mut self,
        slot: Int,
        mut plaintext: List[UInt8],
        peer: SocketAddr,
        budget: Int,
    ) raises -> Bool:
        """Send ``plaintext`` as one ack-eliciting 1-RTT datagram and
        leave it empty for the next. Returns whether a datagram went out.
        """
        if len(plaintext) == 0:
            return False
        var frames = plaintext^
        plaintext = List[UInt8](capacity=budget + 64)
        if self._gso_active:
            # PADDING to the full budget makes every mid-drain datagram
            # the same size, which a GSO send requires (RFC 9000 sec
            # 19.1: PADDING frames are zero bytes).
            frames.resize(budget, UInt8(0))
        var dg = self._build_1rtt_response(slot, frames^, ack_eliciting=True)
        if len(dg) == 0:
            return False
        self._queue_datagram(dg, peer)
        return True

    def _queue_datagram(mut self, dg: List[UInt8], peer: SocketAddr) raises:
        """Send ``dg`` now, or queue it for one GSO send with the
        datagrams around it (same peer, equal size, a shorter one only
        last). :meth:`_flush_gso` sends what is queued."""
        if not self._gso_active:
            _ = self.send_to(Span[UInt8, _](dg), peer)
            return
        if self._gso_count > 0 and (
            self._gso_peer != peer
            or len(dg) > self._gso_seg
            or len(self._gso_buf) % self._gso_seg != 0
            or self._gso_count >= _GSO_MAX_SEGMENTS
        ):
            self._flush_gso()
        if self._gso_count == 0:
            self._gso_seg = len(dg)
            self._gso_peer = peer
        self._gso_buf.extend(Span[UInt8, _](dg))
        self._gso_count += 1

    def _flush_gso(mut self) raises:
        """Send the queued datagrams: one ``sendmsg`` with a
        ``UDP_SEGMENT`` size when there are several. If the kernel or NIC
        refuses (EINVAL / EIO / ENOPROTOOPT), GSO is turned off for good
        and the batch goes out datagram by datagram."""
        if self._gso_count == 0:
            return
        var peer = self._gso_peer
        var buf = List[UInt8]()
        swap(buf, self._gso_buf)
        if self._gso_count == 1:
            _ = self.send_to(Span[UInt8, _](buf), peer)
        else:
            try:
                _ = send_segmented(
                    self._socket.fd(), peer, Span[UInt8, _](buf), self._gso_seg
                )
            except:
                self._gso_ok = False
                self._gso_active = False
                var pos = 0
                while pos < len(buf):
                    var end = min(pos + self._gso_seg, len(buf))
                    _ = self.send_to(Span[UInt8, _](buf)[pos:end], peer)
                    pos = end
        swap(buf, self._gso_buf)
        self._gso_buf.clear()
        self._gso_count = 0

    def _take_lh_ack(mut self, slot: Int, space: Int) raises -> List[UInt8]:
        """The ACK frame owed for long-header ``space`` (0 Initial,
        1 Handshake), or nothing; clears the debt."""
        var out = List[UInt8]()
        ref c = self.connections[slot]
        if c.lh_ack_pending[space] and len(c.rx_lh_ranges[space]) >= 2:
            encode_ack(_ack_from_ranges(c.rx_lh_ranges[space], 0), out)
        c.lh_ack_pending[space] = False
        return out^

    def _build_initial_response(
        mut self,
        slot: Int,
        pn_length: Int = 2,
        max_bytes: Int = 0,
        frames: List[UInt8] = List[UInt8](),
        pad_to: Int = 0,
    ) raises -> List[UInt8]:
        """Materialize a server-side Initial packet that carries
        the slot's pending egress CRYPTO bytes.

        Splits cleanly from :meth:`_drain_and_send` so unit tests
        can exercise the wire-format builder without binding a
        UDP socket. Returns the protected datagram bytes ready
        for :meth:`send_to`.

        ``pn_length`` defaults to 2 which is the comfortable
        ServerHello / EncryptedExtensions size for any
        reasonable cert chain (covers 0..65535 packet numbers
        per RFC 9001 §5.3). The caller may raise this to 3 / 4
        once long-running connections cross the 2-byte pn
        window.
        """
        # ``frames`` re-sends CRYPTO from a lost packet; otherwise take
        # the next ``max_bytes`` of the queue. An ACK for the Initial
        # space leads when one is owed (RFC 9000 sec 13.1).
        var qbytes = List[UInt8]()
        var payload = self._take_lh_ack(slot, 0)
        var ack_len = len(payload)
        if len(frames) > 0:
            payload.extend(Span[UInt8, _](frames))
        elif max_bytes >= 0:
            qbytes = _queue_prefix(self.tls_egress_queues[slot], max_bytes)
            if len(qbytes) > 0:
                encode_crypto(
                    CryptoFrame(
                        offset=self.connections[slot].tx_initial_offset,
                        data=qbytes.copy(),
                    ),
                    payload,
                )
        if len(payload) == 0:
            return List[UInt8]()
        var eliciting = len(payload) > ack_len
        var tracked = List[UInt8](Span[UInt8, _](payload)[ack_len:])
        # RFC 9000 sec 14.1: a datagram carrying an ack-eliciting Initial
        # is at least 1200 bytes. PADDING frames (zero bytes) fill the
        # packet to ``pad_to``. Beyond the payload a server Initial has
        # first byte, version, two CID lengths, an empty token, a 2-byte
        # Length (the payload is >= 64 bytes once padded), the packet
        # number and the 16-byte tag.
        if eliciting and pad_to > 0:
            var size = (
                len(payload)
                + 1
                + 4
                + 2
                + self.connections[slot].peer_cid.length()
                + self.connections[slot].local_cid.length()
                + 1
                + 2
                + pn_length
                + 16
            )
            if size < pad_to:
                payload.resize(len(payload) + pad_to - size, UInt8(0))
        var conn = self.connections[slot].copy()
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_INITIAL,
            QUIC_VERSION_1,
            conn.peer_cid,
            conn.local_cid,
            type_specific_bits=first_bits,
        )
        # Token-length varint (always 0 for server-side Initial
        # responses per RFC 9000 §17.2.2 -- only the client may
        # echo a NEW_TOKEN-issued token).
        var token_len_var = encode_varint(UInt64(0))
        for i in range(len(token_len_var)):
            prefix.append(token_len_var[i])
        # Payload length: CRYPTO frame body + pn_length + 16-byte
        # AEAD tag per RFC 9000 §17.2.5.
        var payload_total = UInt64(len(payload) + pn_length + 16)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        var pn = conn.tx_initial_pn
        var datagram = protect_initial_packet(
            Span[UInt8, _](prefix),
            packet_number=pn,
            pn_length=pn_length,
            plaintext=Span[UInt8, _](payload),
            dcid=conn.initial_dcid,
            is_server=True,
        )
        # Advance the connection's outbound Initial-level
        # counters so the next drain emits a fresh pn + offset.
        conn.tx_initial_pn = pn + UInt64(1)
        conn.tx_initial_offset = conn.tx_initial_offset + UInt64(len(qbytes))
        self.connections[slot] = conn^
        if eliciting and slot < len(self.loss_init):
            self.loss_init[slot].on_sent(
                pn, tracked^, _monotonic_ms(), size=UInt64(len(datagram))
            )
        return datagram^

    # -- Handshake + 1-RTT egress via rustls --------------------------------

    def _build_handshake_response(
        mut self,
        slot: Int,
        pn_length: Int = 2,
        max_bytes: Int = 0,
        frames: List[UInt8] = List[UInt8](),
    ) raises -> List[UInt8]:
        """Wrap the slot's pending Handshake-level CRYPTO bytes
        into a long-header Handshake packet, AEAD-protected via
        the slot's rustls session's
        ``Keys.local.packet.encrypt_in_place`` + header-
        protected via ``Keys.local.header.encrypt_in_place``
        (RFC 9001 §5.3 + §5.4).

        Splits cleanly from :meth:`_drain_and_send` so unit
        tests can exercise the wire-format builder without
        binding a UDP socket.  Returns the protected datagram
        bytes ready for :meth:`send_to`; empty list if the
        slot is out of range, the per-slot Handshake queue is
        empty, or rustls hasn't installed level-2 keys yet
        (the post-handshake-bridge sentinel gate).

        The flow mirrors :meth:`_build_initial_response` but:

        * The header omits the Initial-level token field
          (RFC 9000 §17.2.4 -- Handshake long headers carry
          only the payload-length varint after the SCID).
        * The AEAD + HP routes through
          :func:`_do_packet_encrypt` and
          :func:`_do_header_encrypt` at
          :data:`QuicEncryptionLevel.HANDSHAKE` instead of
          flare's :func:`protect_initial_packet` (the DCID-
          derived OpenSSL Initial path doesn't apply at
          Handshake -- the keys come from rustls's
          ``KeyChange::Handshake`` at the matching session
          slot).
        * The per-connection ``tx_handshake_pn`` +
          ``tx_handshake_offset`` counters advance on success.
        """
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        if slot >= len(self.tls_handshake_egress_queues):
            return List[UInt8]()
        if (
            len(self.tls_handshake_egress_queues[slot]) == 0
            and len(frames) == 0
            and not self.connections[slot].lh_ack_pending[1]
        ):
            return List[UInt8]()
        var conn = self.connections[slot].copy()
        # Per-direction sentinel gates the egress: if rustls
        # hasn't yet emitted KeyChange::Handshake then tx_handshake
        # keys aren't ready.  The pump in `_dispatch_crypto_frames`
        # stamps both rx + tx sentinels together; checking the tx
        # side here keeps the egress aligned with the inbound gate
        # on the same level.
        if len(conn.tx_handshake_secret) == 0:
            return List[UInt8]()
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return List[UInt8]()
        if pn_length < 1 or pn_length > 4:
            raise Error(
                "_build_handshake_response: pn_length out of [1, 4]: "
                + String(pn_length)
            )
        # 1. The ACK owed for the Handshake space, then CRYPTO: re-sent
        # ``frames`` from a lost packet, or the next ``max_bytes`` of the
        # rustls take_crypto output at Handshake level.
        var qbytes = List[UInt8]()
        var payload = self._take_lh_ack(slot, 1)
        var ack_len = len(payload)
        if len(frames) > 0:
            payload.extend(Span[UInt8, _](frames))
        elif max_bytes >= 0:
            qbytes = _queue_prefix(
                self.tls_handshake_egress_queues[slot], max_bytes
            )
            if len(qbytes) > 0:
                encode_crypto(
                    CryptoFrame(
                        offset=conn.tx_handshake_offset, data=qbytes.copy()
                    ),
                    payload,
                )
        if len(payload) == 0:
            return List[UInt8]()
        var tracked = List[UInt8](Span[UInt8, _](payload)[ack_len:])
        # 2. Build the long-header prefix (no token varint at
        # Handshake level per RFC 9000 §17.2.4).
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_HANDSHAKE,
            QUIC_VERSION_1,
            conn.peer_cid,
            conn.local_cid,
            type_specific_bits=first_bits,
        )
        var payload_total = UInt64(len(payload) + pn_length + 16)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        # 3. Build the unprotected header = prefix + pn bytes.
        var pn = conn.tx_handshake_pn
        var unprotected_header = List[UInt8]()
        for i in range(len(prefix)):
            unprotected_header.append(prefix[i])
        for i in range(pn_length):
            var shift = (pn_length - 1 - i) * 8
            unprotected_header.append(UInt8((Int(pn) >> shift) & 0xFF))
        # 4. AEAD-encrypt the payload via rustls at level 2.
        # The payload buffer is mutated in place; the returned
        # tag is appended afterward.  The FFI binding helpers
        # take `read lib: OwnedDLHandle`, which borrows without
        # moving, so we pass `self.tls_acceptor._lib` directly
        # at each callsite (the OwnedDLHandle itself is not
        # ImplicitlyCopyable and cannot be aliased into a local).
        var encrypted_payload = payload.copy()
        var tag = _do_packet_encrypt(
            self.tls_acceptor._fns,
            handle,
            QuicEncryptionLevel.HANDSHAKE,
            pn,
            unprotected_header,
            encrypted_payload,
        )
        # 5. Assemble the protected datagram = header + ciphertext + tag.
        var protected = List[UInt8]()
        for i in range(len(unprotected_header)):
            protected.append(unprotected_header[i])
        for i in range(len(encrypted_payload)):
            protected.append(encrypted_payload[i])
        for i in range(len(tag)):
            protected.append(tag[i])
        # 6. Apply header protection via rustls at level 2.
        var pn_offset = len(unprotected_header) - pn_length
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(protected):
            raise Error(
                "_build_handshake_response: ciphertext too short for HP sample"
            )
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(protected[sample_offset + i])
        # Stage the first byte + pn bytes on the stack so rustls
        # can XOR them in place; copy back afterward.
        var first_local: UInt8 = protected[0]
        var pn_local = List[UInt8]()
        for i in range(pn_length):
            pn_local.append(protected[pn_offset + i])
        var first_addr = Int(Pointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._fns,
            handle,
            QuicEncryptionLevel.HANDSHAKE,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            pn_length,
        )
        protected[0] = first_local
        for i in range(pn_length):
            protected[pn_offset + i] = pn_local[i]
        # 7. Advance the per-connection Handshake counters.
        conn.tx_handshake_pn = pn + UInt64(1)
        conn.tx_handshake_offset = conn.tx_handshake_offset + UInt64(
            len(qbytes)
        )
        # ``conn`` was copied before the owed ACK was taken above.
        conn.lh_ack_pending[1] = False
        self.connections[slot] = conn^
        if len(tracked) > 0 and slot < len(self.loss_hs):
            self.loss_hs[slot].on_sent(
                pn, tracked^, _monotonic_ms(), size=UInt64(len(protected))
            )
        return protected^

    def _build_1rtt_response(
        mut self,
        slot: Int,
        var plaintext: List[UInt8],
        var pn_length: Int = 2,
        ack_eliciting: Bool = False,
        keep_frames: Bool = True,
    ) raises -> List[UInt8]:
        """Wrap an arbitrary 1-RTT plaintext payload (CRYPTO
        bytes from rustls's post-handshake KeyChange::OneRtt
        path, OR STREAM-frame H3 response bytes) into a
        short-header 1-RTT packet, AEAD-protected via the
        slot's rustls session's
        ``Keys.local.packet.encrypt_in_place`` + header-
        protected via ``Keys.local.header.encrypt_in_place``
        at :data:`QuicEncryptionLevel.APPLICATION`.

        ``plaintext`` is the in-place buffer of plaintext
        bytes the caller has already encoded into QUIC frames
        (CRYPTO at level 3 for post-handshake NEW_TOKEN /
        HANDSHAKE_DONE / NEW_CONNECTION_ID, or STREAM for H3).
        The function consumes it.  Returns the protected
        datagram bytes ready for :meth:`send_to`; empty list
        if the slot is out of range, rustls hasn't installed
        1-RTT keys yet, or the session handle is NULL.
        """
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        # RFC 9000 sec 10.2.2: "An endpoint in the draining state MUST NOT
        # send any packets." Every 1-RTT egress path (ACKs, responses, PTO
        # retransmits, the delayed-ACK timer) goes through this builder.
        if self.connections[slot].conn.state == CONN_STATE_DRAINING:
            return List[UInt8]()
        # Read only the fields this builder needs and bump the pn
        # counter in place at the end -- deep-copying the whole
        # QuicConnection (its streams Dict) per outbound packet is
        # the dominant egress-side CPU cost under concurrency.
        if len(self.connections[slot].tx_1rtt_secret) == 0:
            return List[UInt8]()
        # Snapshot before the protection step consumes ``plaintext``.
        # Only ack-eliciting packets are tracked: RFC 9002 sec 2 defines
        # a packet as ack-eliciting iff it carries anything other than
        # ACK, PADDING and CONNECTION_CLOSE, and only those are
        # retransmittable.
        var tracked_frames = List[UInt8]()
        if ack_eliciting and keep_frames:
            tracked_frames = plaintext.copy()
        if slot >= len(self.tls_sessions):
            return List[UInt8]()
        var handle = self.tls_sessions[slot].handle
        if handle == 0:
            return List[UInt8]()
        if pn_length < 1 or pn_length > 4:
            raise Error(
                "_build_1rtt_response: pn_length out of [1, 4]: "
                + String(pn_length)
            )
        var pn = self.connections[slot].tx_1rtt_pn
        if slot < len(self.loss):
            pn_length = max(
                pn_length,
                packet_number_length(
                    pn,
                    self.loss[slot].largest_acked,
                    self.loss[slot].has_largest_acked,
                ),
            )
        # Start a key update once the current key has protected
        # ``key_update_interval`` packets and one of them was acked
        # (RFC 9001 sec 6.1, 6.6).
        ref kc = self.connections[slot]
        if (
            pn - kc.phase_first_pn >= self.config.key_update_interval
            and slot < len(self.loss)
            and self.loss[slot].has_largest_acked
            and self.loss[slot].largest_acked >= kc.phase_first_pn
        ):
            _ = _do_key_update(self.tls_acceptor._lib, handle)
            kc.key_phase = not kc.key_phase
            kc.phase_first_pn = pn
        var peer_cid = kc.peer_cid.copy()
        # 1. Build the unprotected short-header prefix (spin bit 0).
        var prefix = encode_short_header(
            peer_cid,
            spin_bit=False,
            key_phase=kc.key_phase,
            pn_length=pn_length,
        )
        # 2. Build unprotected header = prefix + pn bytes.
        var unprotected_header = List[UInt8](capacity=len(prefix) + pn_length)
        for i in range(len(prefix)):
            unprotected_header.append(prefix[i])
        for i in range(pn_length):
            var shift = (pn_length - 1 - i) * 8
            unprotected_header.append(UInt8((Int(pn) >> shift) & 0xFF))
        # 3. AEAD-encrypt via rustls at level 3.  See the
        # _build_handshake_response comment for why we pass
        # `self.tls_acceptor._lib` directly at each call.
        var encrypted_payload = plaintext^
        var tag = _do_packet_encrypt(
            self.tls_acceptor._fns,
            handle,
            QuicEncryptionLevel.APPLICATION,
            pn,
            unprotected_header,
            encrypted_payload,
        )
        # 4. Assemble the protected datagram. Move the header buffer in
        # as the base (it is no longer needed standalone) and reserve
        # the full datagram length so the payload + tag append in one
        # allocation -- the per-byte grow loop here was a top _realloc /
        # allocator-TLS cost under request concurrency.
        var header_len = len(unprotected_header)
        var protected = unprotected_header^
        protected.reserve(header_len + len(encrypted_payload) + len(tag))
        protected.extend(Span[UInt8, _](encrypted_payload))
        protected.extend(Span[UInt8, _](tag))
        # 5. Apply header protection via rustls at level 3.
        var pn_offset = header_len - pn_length
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(protected):
            raise Error(
                "_build_1rtt_response: ciphertext too short for HP sample"
            )
        var sample = List[UInt8](capacity=16)
        for i in range(16):
            sample.append(protected[sample_offset + i])
        var first_local: UInt8 = protected[0]
        var pn_local = List[UInt8](capacity=pn_length)
        for i in range(pn_length):
            pn_local.append(protected[pn_offset + i])
        var first_addr = Int(Pointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._fns,
            handle,
            QuicEncryptionLevel.APPLICATION,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            pn_length,
        )
        protected[0] = first_local
        for i in range(pn_length):
            protected[pn_offset + i] = pn_local[i]
        # 6. Advance the 1-RTT pn counter (no offset counter at
        # 1-RTT -- per-stream offsets live on each STREAM frame
        # encoded into the plaintext).
        self.connections[slot].tx_1rtt_pn = pn + UInt64(1)
        # RFC 9000 sec 10.1: the first ack-eliciting packet sent after a
        # received one restarts the idle timer; later sends do not.
        if ack_eliciting and not self.connections[slot].idle_sent_since_rx:
            self.connections[slot].idle_sent_since_rx = True
            _ = self.schedule_idle_timeout(slot)
        if ack_eliciting and slot < len(self.loss):
            # Account the true on-wire size, not len(plaintext): the
            # congestion window is a bound on bytes the path carries.
            self.loss[slot].on_sent(
                pn,
                tracked_frames^,
                _monotonic_ms(),
                size=UInt64(len(protected)),
            )
            # An ACK that retired everything left no PTO armed; without
            # one, a flight lost whole would hold the congestion window
            # shut for good (RFC 9002 sec 6.2.1: arm on every send).
            if self.connections[slot].pto_timer_id == UInt64(0):
                self._rearm_pto_timer(slot)
        return protected^

    def _build_1rtt_handshake_crypto(
        mut self, slot: Int, pn_length: Int = 2
    ) raises -> List[UInt8]:
        """Wrap the slot's pending 1-RTT-level CRYPTO bytes
        (rustls post-handshake messages: NewSessionTicket etc.)
        into a 1-RTT packet via :meth:`_build_1rtt_response`.

        Distinct from H3 STREAM-frame egress, which the
        coalescing drain (:meth:`_drain_1rtt_coalesced`) encodes
        via :func:`_encode_h3_stream_frame`; both end up calling
        :meth:`_build_1rtt_response` with the appropriate
        plaintext.
        """
        if slot >= len(self.tls_1rtt_egress_queues):
            return List[UInt8]()
        if len(self.tls_1rtt_egress_queues[slot]) == 0:
            return List[UInt8]()
        if slot < 0 or slot >= len(self.connections):
            return List[UInt8]()
        # Wrap the bytes in a CRYPTO frame -- the offset is
        # tracked per-stream-id at the 1-RTT level, but for the
        # CRYPTO frame stream the offset is just a monotonic
        # counter.  rustls's post-handshake messages are small
        # and infrequent so a fresh CryptoFrame(offset=0) per
        # drain is correct as long as the egress queue gets
        # cleared every flush (which it does in `_drain_and_send`).
        var qbytes = self.tls_1rtt_egress_queues[slot].copy()
        var crypto = CryptoFrame(offset=UInt64(0), data=qbytes^)
        var plaintext = List[UInt8]()
        encode_crypto(crypto, plaintext)
        return self._build_1rtt_response(
            slot, plaintext^, pn_length, ack_eliciting=True
        )

    def run(mut self) raises:
        """Run the listener's event loop. Blocks until
        :meth:`shutdown` flips the stop flag.

        The loop drives the full I/O cycle
        ``recv -> dispatch -> drain -> protect -> sendto ->
        advance_timers``:

        1. ``tick(100)`` blocks up to 100 ms in ``recv_from``;
           on a datagram it runs the dispatch + handle + drain
           chain.
        2. On a 100 ms timeout it still calls
           :meth:`drain_all_egress` so any session that started
           handshaking can flush its first response.
        3. :meth:`advance_timers` then runs the wheel against
           the current monotonic clock so the idle-timeout
           callbacks fire on time.

        The 100 ms recv timeout caps the worst-case timer slop
        and the shutdown-flag polling interval.
        """
        while not self._stopping:
            _ = self.tick(timeout_ms=100)
            var now_ms = _monotonic_ms()
            _ = self.advance_timers(now_ms)

    def begin_drain(mut self, timeout_ms: Int) raises:
        """Start a graceful shutdown (RFC 9114 sec 5.2): every live
        connection is sent GOAWAY naming the next request stream it may
        not open, new connections are refused, and :meth:`drain_step`
        closes each connection once its requests are answered or
        ``timeout_ms`` has passed."""
        var wait = UInt64(timeout_ms) if timeout_ms > 0 else UInt64(0)
        self._drain_deadline_ms = _monotonic_ms() + wait + 1
        for slot in range(len(self.connections)):
            if not self.connections[slot].alive:
                continue
            if self.http3_connections[slot].goaway_emitted:
                continue
            # Client request streams are 0, 4, 8, ...: the next unseen
            # one is 4 x the count seen so far.
            var next_id = UInt64(4) * self.rx_bidi_stream_count[slot]
            var goaway = self.http3_connections[slot].emit_goaway(next_id)
            self.connections[slot].ctrl_tx.extend(Span[UInt8, _](goaway))

    def drain_step(mut self) raises -> Bool:
        """Advance a drain started by :meth:`begin_drain`: close (H3_NO_ERROR,
        RFC 9114 sec 5.2) each connection with no request left in flight,
        and every connection once the deadline passes. Returns whether no
        live connection remains; False when no drain is running."""
        if self._drain_deadline_ms == 0:
            return False
        var expired = _monotonic_ms() >= self._drain_deadline_ms
        var live = 0
        for slot in range(len(self.connections)):
            if not self.connections[slot].alive:
                continue
            var busy = (
                self.http3_connections[slot].active_request_count() > 0
                or len(self.connections[slot].h3_tx) > 0
                or len(self.connections[slot].ctrl_tx) > 0
            )
            if busy and not expired:
                live += 1
                continue
            self._close_for(slot, _H3_NO_ERROR, "", application=True)
        return live == 0

    def shutdown(mut self):
        """Request the event loop to exit. Idempotent; safe to
        call from a signal handler (sets a single Bool flag)."""
        self._stopping = True

    # -- Timer scheduling -----------------------------------------------

    def schedule_idle_timeout(mut self, slot: Int) raises -> UInt64:
        """Arm the idle timer for ``slot`` from the current wheel tick.

        The delay is the effective idle timeout of RFC 9000 sec 10.1:
        the minimum of ``config.max_idle_timeout_ms`` and the client's
        ``max_idle_timeout`` (when non-zero), at least three PTOs. When
        both are 0 the timeout is disabled: nothing is armed and the
        returned id is 0. Cancels the slot's previous idle timer if any
        so every ``handle_packet`` only ever has one idle timer in
        flight per connection.

        Returns the new timer id (stored back into the slot's
        :attr:`QuicConnection.idle_timer_id`).
        """
        if slot < 0 or slot >= len(self.connections):
            raise Error(
                "schedule_idle_timeout: slot " + String(slot) + " out of range"
            )
        # Touch only the idle_timer_id field; this runs once per
        # inbound datagram, so a whole-connection deep copy here is
        # pure overhead.
        var old_id = self.connections[slot].idle_timer_id
        if old_id != UInt64(0):
            _ = self.timer_wheel.cancel(old_id)
        var pto_ms = UInt64(0)
        if slot < len(self.loss):
            pto_ms = self.loss[slot].pto_interval_ms()
        var effective = _effective_idle_ms(
            self.config.max_idle_timeout_ms,
            self.connections[slot].peer_idle_ms,
            pto_ms,
        )
        if effective == UInt64(0):
            self.connections[slot].idle_timer_id = UInt64(0)
            return UInt64(0)
        var token = encode_timer_token(TIMER_KIND_IDLE, slot)
        var id = self.timer_wheel.schedule(after_ms=Int(effective), token=token)
        self.connections[slot].idle_timer_id = id
        return id

    def advance_timers(mut self, now_ms: UInt64) raises -> Int:
        """Advance the wheel to ``now_ms`` and dispatch every fired
        timer token to the matching action (per
        :mod:`flare.quic.timers`). Returns the number of tokens
        dispatched.

        Handles all three registered kinds:

        * ``TIMER_KIND_IDLE`` -- RFC 9000 sec 10.1 idle timeout:
          flips the connection to closed via ``on_idle_expired``.
        * ``TIMER_KIND_ACK_DELAY`` -- RFC 9000 sec 13.2.1 deferred
          ACK: flushes any owed 1-RTT ACK through the coalesced
          egress path so a quiescent peer still learns what arrived
          even when no further inbound packet drives a drain.
        * ``TIMER_KIND_PTO`` -- RFC 9002 sec 6.2 probe timeout:
          dispatched to :meth:`_on_pto_expired`.

        Also sweeps the CID table for any connections whose
        ``alive`` flag flipped False during dispatch (idle
        timeout, draining); their CIDs are retired so a stray
        retransmit doesn't route to a dead slot.
        """
        var fired = List[UInt64]()
        self.timer_wheel.advance(now_ms, fired)
        for i in range(len(fired)):
            var decoded = decode_timer_token(fired[i])
            var slot = decoded.slot
            if slot < 0 or slot >= len(self.connections):
                continue
            # A closing slot (RFC 9000 sec 10.2) is ended by its closing
            # timer alone -- the TIMER_KIND_IDLE entry _enter_closing
            # armed. Any other timer of the slot must not cut the closing
            # period short.
            if (
                self.connections[slot].closing
                and decoded.kind != TIMER_KIND_IDLE
            ):
                continue
            if decoded.kind == TIMER_KIND_IDLE:
                self.connections[slot].on_idle_expired()
            elif decoded.kind == TIMER_KIND_ACK_DELAY:
                # Deferred ACK, or the pacer's resume.
                self.connections[slot].send_timer_id = UInt64(0)
                if slot < len(self.peer_addrs):
                    var peer = self.peer_addrs[slot]
                    _ = self._drain_1rtt_coalesced(slot, peer)
            elif decoded.kind == TIMER_KIND_PTO:
                self._on_pto_expired(slot)
            if not self.connections[slot].alive:
                self._reclaim_slot(slot)
        return len(fired)

    def _on_pto_expired(mut self, slot: Int) raises:
        """RFC 9002 sec 6.2 probe-timeout action for ``slot``.

        Re-sends the frames of the oldest unacked packet under a fresh
        packet number, then re-arms. When nothing is tracked -- a PTO
        armed before any ack-eliciting packet went out -- it falls back
        to re-flushing whatever 1-RTT egress is still pending, which is
        what this handler did before loss recovery was wired.

        Gives up once ``pto_count`` passes
        :attr:`QuicServerConfig.max_pto_count`: ``LossRecovery`` bounds
        the backoff at 64x the base interval, but nothing bounds how
        long the server keeps probing a peer that has gone dark.

        Send pacing (RFC 9002 sec 7.7) remains out of scope. The
        congestion window gates burst size without an inter-packet
        timer, which is also the budget QUIC GSO would need before
        ``send_segmented`` could be wired into egress.
        """
        if slot < 0 or slot >= len(self.peer_addrs):
            return
        if slot >= len(self.loss):
            return
        # A peer that has gone completely dark would otherwise be probed
        # forever: LossRecovery caps the backoff at 64x but nothing caps
        # the attempt count. Past the configured limit, close the slot
        # and let the normal retire path reclaim it.
        var probes = self.loss[slot].pto_count
        if slot < len(self.loss_hs):
            probes = max(
                probes,
                max(
                    self.loss_init[slot].pto_count, self.loss_hs[slot].pto_count
                ),
            )
        if probes > self.config.max_pto_count:
            self.connections[slot].alive = False
            self._cancel_pto_timer(slot)
            return
        var peer = self.peer_addrs[slot]
        # The loss-time timer (RFC 9002 sec 6.1.2) shares this one: a
        # packet past the time threshold is lost, not a probe's business.
        var lost = self.loss[slot].detect_lost(_monotonic_ms())
        if len(lost) > 0:
            for i in range(len(lost)):
                if len(lost[i]) == 0:
                    continue
                var dg = self._build_1rtt_response(
                    slot, lost[i].copy(), ack_eliciting=True
                )
                if len(dg) > 0:
                    _ = self.send_to(Span[UInt8, _](dg), peer)
            self._rearm_pto_timer(slot)
            return
        # A handshake still in flight probes its earliest space first
        # (RFC 9002 sec 6.2.1): re-send that space's oldest CRYPTO.
        if slot < len(self.loss_hs):
            var di = self.loss_init[slot].pto_deadline()
            var dh = self.loss_hs[slot].pto_deadline()
            if di != 0 or dh != 0:
                if di != 0 and (dh == 0 or di <= dh):
                    var lost = self.loss_init[slot].fire_pto()
                    self._resend_lh(slot, QuicEncryptionLevel.INITIAL, lost)
                else:
                    var lost = self.loss_hs[slot].fire_pto()
                    self._resend_lh(slot, QuicEncryptionLevel.HANDSHAKE, lost)
                self._rearm_pto_timer(slot)
                return
        var frames = self.loss[slot].fire_pto()
        if len(frames) > 0:
            var dg = self._build_1rtt_response(
                slot, frames^, ack_eliciting=True
            )
            if len(dg) > 0:
                _ = self.send_to(Span[UInt8, _](dg), peer)
        else:
            # Nothing tracked to probe with: fall back to re-flushing
            # whatever 1-RTT egress is still pending, which is what this
            # handler did before loss recovery was wired.
            _ = self._drain_1rtt_coalesced(slot, peer)
        self._rearm_pto_timer(slot)

    def _consume_acks(mut self, slot: Int, events: ConnectionEvents) raises:
        """Feed inbound ACK ranges to this slot's loss recovery.

        ``flare.quic.state.handle_frame_buf`` already decodes ACK frames
        into ``events.acked_ranges`` for both peers; the server simply
        never read the field, so a dropped response sat unretransmitted
        until the idle timeout killed the connection. Mirrors the
        client's per-poll order: ack, then detect-and-resend, then
        re-arm.
        """
        if slot < 0 or slot >= len(self.loss):
            return
        if len(events.acked_ranges) == 0:
            return
        # RFC 9000 sec 13.1: acknowledging a packet never sent is a
        # PROTOCOL_VIOLATION. Ranges are newest first, so [1] is the top.
        var next_pn = self.connections[slot].tx_1rtt_pn
        if events.acked_ranges[1] >= next_pn:
            self._close_for(
                slot,
                QUIC_PROTOCOL_VIOLATION,
                "ACK for a packet that was never sent",
            )
            return
        var prev_largest = self.loss[slot].largest_acked
        var had_largest = self.loss[slot].has_largest_acked
        var now = _monotonic_ms()
        _ = self.loss[slot].on_ack_ranges(events.acked_ranges, now, next_pn)
        self.connections[slot].pmtu.on_acked(events.acked_ranges)
        if self._ecn_marking:
            # Only an ACK that moves the largest acknowledged is checked
            # (RFC 9000 sec 13.4.2.1): reordered ones carry older counts.
            var advanced = (
                not had_largest or self.loss[slot].largest_acked > prev_largest
            )
            ref lr = self.loss[slot]
            if self.connections[slot].ecn_tx.on_ack(
                lr.last_newly_acked if advanced else 0, events.ack_ecn
            ):
                lr.cc.on_congestion_event(lr.last_acked_sent_ms, now)
            if not self.connections[slot].ecn_tx.ok:
                self._ecn_marking = False
                try:
                    self._socket.set_ecn(0)
                except:
                    pass
        self._retransmit_lost(slot)
        self._rearm_pto_timer(slot)

    def _consume_lh_acks(
        mut self, slot: Int, events: ConnectionEvents, level: Int
    ) raises:
        """Feed an Initial or Handshake ACK to that space's loss
        recovery and re-send the CRYPTO of any packet now lost (RFC 9002
        sec 6.1). An ACK naming a packet never sent in the space is a
        PROTOCOL_VIOLATION (RFC 9000 sec 13.1)."""
        if len(events.acked_ranges) == 0 or slot >= len(self.loss_hs):
            return
        var is_init = level == QuicEncryptionLevel.INITIAL
        var next_pn = self.connections[slot].tx_initial_pn if is_init else (
            self.connections[slot].tx_handshake_pn
        )
        if events.acked_ranges[1] >= next_pn:
            self._close_for(
                slot,
                QUIC_PROTOCOL_VIOLATION,
                "ACK for a packet that was never sent",
            )
            return
        var lost: List[List[UInt8]]
        if is_init:
            _ = self.loss_init[slot].on_ack_ranges(
                events.acked_ranges, _monotonic_ms(), next_pn
            )
            lost = self.loss_init[slot].detect_lost(_monotonic_ms())
        else:
            _ = self.loss_hs[slot].on_ack_ranges(
                events.acked_ranges, _monotonic_ms(), next_pn
            )
            lost = self.loss_hs[slot].detect_lost(_monotonic_ms())
        for i in range(len(lost)):
            self._resend_lh(slot, level, lost[i])
        self._rearm_pto_timer(slot)

    def _resend_lh(mut self, slot: Int, level: Int, frames: List[UInt8]) raises:
        """Re-send long-header CRYPTO ``frames`` in a fresh packet at
        ``level``, within the anti-amplification budget (RFC 9000 sec
        8.1). An Initial is padded to 1200 bytes (sec 14.1)."""
        if len(frames) == 0 or slot >= len(self.peer_addrs):
            return
        var is_init = level == QuicEncryptionLevel.INITIAL
        var est = len(frames) + _LONG_PACKET_OVERHEAD
        if is_init and est < _MIN_INITIAL_DATAGRAM:
            est = _MIN_INITIAL_DATAGRAM
        if not self._amplification_allows(slot, est):
            return
        var dg: List[UInt8]
        if is_init:
            dg = self._build_initial_response(
                slot, frames=frames, pad_to=_MIN_INITIAL_DATAGRAM
            )
        else:
            dg = self._build_handshake_response(slot, frames=frames)
        if len(dg) == 0:
            return
        _ = self.send_to(Span[UInt8, _](dg), self.peer_addrs[slot])
        self.connections[slot].amp_tx += len(dg)

    def _retransmit_lost(mut self, slot: Int) raises:
        """Re-send the frames of every packet now declared lost.

        RFC 9002: frames are retransmitted, packets are not -- each
        rides a fresh packet number via :meth:`_build_1rtt_response`.
        """
        if slot < 0 or slot >= len(self.loss):
            return
        if slot >= len(self.peer_addrs):
            return
        var peer = self.peer_addrs[slot]
        var lost = self.loss[slot].detect_lost(_monotonic_ms())
        for i in range(len(lost)):
            var frames = lost[i].copy()
            if len(frames) == 0:
                continue
            var dg = self._build_1rtt_response(
                slot, frames^, ack_eliciting=True
            )
            if len(dg) > 0:
                _ = self.send_to(Span[UInt8, _](dg), peer)

    def _cancel_pto_timer(mut self, slot: Int) raises:
        """Drop this slot's armed PTO entry, if any."""
        if slot < 0 or slot >= len(self.connections):
            return
        var old_id = self.connections[slot].pto_timer_id
        if old_id != UInt64(0):
            _ = self.timer_wheel.cancel(old_id)
            self.connections[slot].pto_timer_id = UInt64(0)

    def _rearm_pto_timer(mut self, slot: Int) raises:
        """Re-schedule this slot's PTO from the current deadline.

        Mirrors :meth:`schedule_idle_timeout`: cancel the old entry,
        then schedule a fresh one. Called once per dispatch tick rather
        than once per sent packet, matching the cadence at which the
        client calls ``_check_pto`` -- a cancel plus reschedule for
        every packet in a burst is pure overhead when the deadline only
        moves with the oldest in-flight packet.
        """
        if slot < 0 or slot >= len(self.connections):
            return
        if slot >= len(self.loss):
            return
        self._cancel_pto_timer(slot)
        var deadline = self.loss[slot].pto_deadline()
        var lt = self.loss[slot].loss_deadline()
        if lt != 0 and (deadline == 0 or lt < deadline):
            deadline = lt
        if slot < len(self.loss_hs):
            var di = self.loss_init[slot].pto_deadline()
            var dh = self.loss_hs[slot].pto_deadline()
            if di != 0 and (deadline == 0 or di < deadline):
                deadline = di
            if dh != 0 and (deadline == 0 or dh < deadline):
                deadline = dh
        if deadline == UInt64(0):
            return
        var now = _monotonic_ms()
        var after_ms = 1 if deadline <= now else Int(deadline - now)
        var token = encode_timer_token(TIMER_KIND_PTO, slot)
        self.connections[slot].pto_timer_id = self.timer_wheel.schedule(
            after_ms=after_ms, token=token
        )

    def _reclaim_slot(mut self, slot: Int) raises:
        """Retire a dead slot's CIDs, cancel its timers, free its
        rustls session and streaming sources, and put the slot on
        :attr:`free_slots` for the next accepted connection. A slot
        used to stay allocated for the life of the listener, so every
        per-slot table grew with every connection ever accepted, and
        each tick scanned all of them."""
        if slot < 0 or slot >= len(self.connections):
            return
        if slot < len(self.slot_free) and self.slot_free[slot]:
            return
        self._retire_slot_cids(slot)
        # A timer left armed would fire into the next connection given
        # this slot; the idle one would close it.
        if self.connections[slot].idle_timer_id != UInt64(0):
            _ = self.timer_wheel.cancel(self.connections[slot].idle_timer_id)
            self.connections[slot].idle_timer_id = UInt64(0)
        self._cancel_pto_timer(slot)
        if slot < len(self.tls_sessions):
            var h = self.tls_sessions[slot].handle
            if h != 0:
                self.tls_acceptor.free_session(h)
                self.tls_sessions[slot] = _SessionSlot(handle=0)
        # Free streaming sources exactly once; the connection record
        # itself is replaced when the slot is reused.
        for entry in self.connections[slot].h3_tx.items():
            if entry.value.src_addr != 0:
                Pool[ChunkSourceBox].free(entry.value.src_addr)
                self._open_sources -= 1
        self.connections[slot].h3_tx = Dict[Int, _StreamTx]()
        if slot < len(self.slot_free):
            self.slot_free[slot] = True
        self.free_slots.append(slot)

    def _retire_slot_cids(mut self, slot: Int) raises:
        """Drop every CID -> slot mapping that points at this
        slot. Called when the slot's connection has closed so
        late retransmits don't route to a dead slot."""
        if slot < 0 or slot >= len(self.connections):
            return
        for entry in self.connections[slot].issued_cids.items():
            self.cid_table.retire(entry.value)
        self.cid_table.retire(cid_to_hex(self.connections[slot].local_cid))
        self.cid_table.retire(cid_to_hex(self.connections[slot].initial_dcid))

    def close(mut self):
        """Close the underlying UDP socket. Idempotent. The
        :class:`UdpSocket` destructor also closes the fd, so
        explicit calls are only required when callers want to
        free the port before the listener goes out of scope."""
        self._socket.close()


def _queue_prefix(q: List[UInt8], max_bytes: Int) -> List[UInt8]:
    """The first ``max_bytes`` of ``q`` (all of it when ``max_bytes`` is
    0 or larger than ``q``)."""
    var n = len(q) if max_bytes <= 0 or max_bytes > len(q) else max_bytes
    return List[UInt8](Span[UInt8, _](q)[:n])


def _queue_rest(q: List[UInt8], sent: Int) -> List[UInt8]:
    """``q`` without its first ``sent`` bytes."""
    if sent >= len(q):
        return List[UInt8]()
    return List[UInt8](Span[UInt8, _](q)[sent:])


def _is_quic_v1(datagram: Span[UInt8, _]) -> Bool:
    """Whether a long-header datagram carries QUIC version 1 (the
    version field is bytes 1..4, RFC 8999 sec 5.1)."""
    return (
        datagram[1] == 0
        and datagram[2] == 0
        and datagram[3] == 0
        and datagram[4] == 1
    )
