"""``flare.quic._server_types`` -- QUIC server value types.

The per-connection driver and routing types peeled out of the
oversized ``flare.quic.server`` so the reactor module
(:class:`flare.quic.server.QuicListener`) stays focused on the
UDP event loop. Pure code motion -- ``flare.quic.server``
re-exports these names, so existing import paths
(``from flare.quic.server import QuicConnection`` /
``QuicServerConfig`` / ``ConnectionIdTable`` / ``cid_to_hex``)
keep resolving unchanged.

## What ships here

- :class:`QuicServerConfig` -- bind-time configuration carrier.
- :class:`QuicConnection` -- per-connection driver composing the
  sans-I/O :class:`flare.quic.state.Connection` with the rustls
  QUIC session.
- :class:`ConnectionIdTable` -- CID -> slot routing table.
- :func:`cid_to_hex` -- lowercase-hex CID key for the table.
"""

from std.hash import Hasher
from std.collections import Dict, List, Optional
from std.collections.span import Span

from ._server_0rtt import EarlyDataReplayGuard
from ._server_support import _ack_record
from .crypto import QuicAead
from .packet import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    parse_long_header,
)
from .protection import (
    unprotect_1rtt_packet,
    unprotect_handshake_packet,
    unprotect_initial_packet,
)
from ._ecn import EcnValidator
from ._pmtud import PmtuDiscovery
from .state import (
    MIN_ACK_DELAY_US,
    CONN_STATE_CLOSED,
    Connection,
    ConnectionEvents,
    dispatch_frames,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from .transport_params import (
    empty_transport_parameters,
    encode_transport_parameters,
)
from ..http3.server import Http3Config
from ..tls.rustls_quic import RustlsQuicConfig


# -- Per-stream response egress ---------------------------------------


struct _StreamTx(Copyable):
    """Response bytes queued on one request stream, and how far they
    have gone out.

    ``buf[pos:]`` is queued but not yet framed; its first byte sits at
    QUIC stream offset ``off``. The 1-RTT drain frames no further than
    the peer's MAX_STREAM_DATA / MAX_DATA and the congestion window
    allow, so the rest waits here for credit (RFC 9000 sec 4.1,
    RFC 9002 sec 7). ``done`` means nothing more will be queued: the
    FIN goes out with the last byte.

    A streaming response also keeps its chunk source, boxed in a
    ``Pool[ChunkSourceBox]`` at ``src_addr`` (0 once freed), and its
    pre-encoded trailers, queued after the last chunk.
    """

    var buf: List[UInt8]
    var pos: Int
    var off: UInt64
    var done: Bool
    var src_addr: Int
    var trailer_bytes: List[UInt8]
    var blocked_at: UInt64
    """Stream limit we last sent STREAM_DATA_BLOCKED for, so a stalled
    stream reports each limit once."""

    def __init__(out self):
        self.buf = List[UInt8]()
        self.pos = 0
        self.off = 0
        self.done = False
        self.src_addr = 0
        self.trailer_bytes = List[UInt8]()
        self.blocked_at = UInt64.MAX

    def pending(self) -> Int:
        """Queued bytes not yet framed."""
        return len(self.buf) - self.pos

    def consume(mut self, n: Int):
        """Mark ``n`` queued bytes framed. A buffer whose sent prefix is
        at least 64 KiB and half of it is compacted, so a long streaming
        response does not keep everything it ever sent, while a buffered
        body is not copied at all."""
        self.pos += n
        self.off += UInt64(n)
        if self.pos == len(self.buf):
            self.buf = List[UInt8]()
            self.pos = 0
        elif self.pos >= 65536 and self.pos * 2 >= len(self.buf):
            var rest = List[UInt8](capacity=len(self.buf) - self.pos)
            rest.extend(Span[UInt8, _](self.buf)[self.pos :])
            self.buf = rest^
            self.pos = 0


# -- Configuration carrier ----------------------------------------------


@fieldwise_init
struct Http3Tunnel(Copyable, ImplicitlyCopyable):
    """An accepted extended CONNECT stream (RFC 9220). It names the
    connection's serial as well as its slot, so a handle that outlives
    its connection never reaches the next connection given the slot."""

    var slot: Int
    var stream_id: Int
    var serial: UInt64


struct QuicServerConfig(Copyable, Defaultable):
    """Bind-time configuration for the QUIC server reactor.

    Most fields have sensible production defaults; the user
    supplies a :class:`RustlsQuicConfig` (certificate + key + ALPN
    list) and optionally overrides the timeouts + CC choice.
    """

    var host: String
    """IPv4/IPv6 address to bind the UDP listener to. Default is
    ``"0.0.0.0"`` for IPv4 wildcard binding."""

    var port: UInt16
    """UDP port. Default 0 means "let the kernel pick" -- caller
    reads the resolved port back via
    :meth:`QuicListener.local_addr` after :meth:`QuicListener.bind`."""

    var rustls_config: RustlsQuicConfig
    """The rustls QUIC server configuration carrier. Provides the
    certificate chain, private key, ALPN list, and 0-RTT toggle."""

    var aead_choice: Int
    """AEAD selector codepoint (:class:`flare.quic.crypto.QuicAead`).
    Default: AES-128-GCM (the QUIC v1 mandatory-to-implement)."""

    var max_idle_timeout_ms: UInt64
    """RFC 9000 §10.1 max-idle-timeout in milliseconds. The server
    advertises this to clients; connections idle for longer get
    silently dropped. The effective timeout is the minimum of this and
    the client's non-zero value, at least three PTOs; 0 here and from
    the client disables it. Default: 30_000 ms (30 s)."""

    var max_udp_payload_size: UInt64
    """RFC 9000 §18.2 max-udp-payload-size transport parameter --
    the largest UDP datagram payload the server is willing to
    receive. Default: 1452 bytes (Ethernet MTU 1500 minus IPv6 40
    byte header minus 8 byte UDP header)."""

    var initial_max_data: UInt64
    """RFC 9000 §4 connection-level flow-control limit -- total
    bytes the server is willing to receive across all streams
    before MAX_DATA is required. Default: 1 MiB."""

    var initial_max_streams_bidi: UInt64
    """RFC 9000 §4.6 client-initiated bidi streams limit. Default:
    100 -- matches the H3 server's working set (control + qpack-
    enc + qpack-dec + N request streams)."""

    var initial_max_streams_uni: UInt64
    """RFC 9000 §4.6 client-initiated uni streams limit. Default:
    3 -- H3 needs control + qpack-encoder + qpack-decoder."""

    var max_connections: Int
    """Most live connection slots. An Initial for a new connection past
    it is dropped. Slots were never reused, so a flood of Initials with
    random DCIDs grew every per-slot table without bound."""
    var local_cid_length: Int
    """Length in bytes of the Connection IDs this server issues
    to peers. RFC 9000 §5.1 caps at 20; 8 is the aioquic /
    quinn / quiche default and is what the dispatch loop assumes
    when parsing short-header packets after the handshake."""

    var early_data_strike_window_ms: UInt64
    """How long (ms) an accepted 0-RTT connection's original DCID is
    remembered for cross-connection replay defense
    (:class:`flare.quic._server_0rtt.EarlyDataStrikeSet`). A 0-RTT
    flight replayed within this window of the original is refused.
    Default: 10_000 ms (10 s) -- comfortably covers handshake +
    clock-skew while bounding memory. Only matters when 0-RTT is
    enabled (``rustls_config`` issues 0-RTT-capable tickets)."""

    var require_address_validation: Bool
    """RFC 9000 sec 8.1: when ``True``, the server answers a token-less
    Initial with a Retry packet (address-validation round-trip) instead
    of accepting immediately, and only accepts an Initial whose token
    validates. Default ``False`` (accept on first Initial) -- flip on
    under load / DDoS to force every new client to prove its source
    address before the server commits handshake state."""

    var retry_token_max_age_ms: UInt64
    """Maximum age (ms) a Retry token is accepted after issuance.
    Default: 10_000 ms (10 s) -- long enough for a client RTT + retry,
    short enough to bound replay. Only consulted when
    :attr:`require_address_validation` is set."""

    var num_workers: Int
    """Workers sharing this listener's port (``SO_REUSEPORT``); 1 for a
    single-socket listener. See :mod:`flare.quic._worker_route`."""
    var worker_id: Int
    """This listener's index among :attr:`num_workers`."""
    var cid_route_key: List[UInt8]
    """Key every worker uses to tell which worker owns a CID; drawn at
    bind time when empty and shared with the other workers."""
    var inbox_table: Int
    """Address of the workers' forwarded-datagram inboxes (0 when
    single-worker)."""
    var http3: Http3Config
    """HTTP/3 settings every accepted connection's driver is built with
    (field-section limit, QPACK capacity, extended CONNECT, GOAWAY
    threshold). They were always the defaults."""
    var key_update_interval: UInt64
    """1-RTT packets sent under one key before the server starts a key
    update (RFC 9001 sec 6). Default 2^23, the AES-GCM confidentiality
    limit of RFC 9001 sec 6.6, which also covers ChaCha20-Poly1305."""
    var ecn: Bool
    """Mark 1-RTT packets ECT(0) and treat the client's CE reports as
    congestion (RFC 9000 sec 13.4, RFC 9002 sec 7.1). Default True; a
    connection whose counts fail validation, or whose marked packets
    never come back acknowledged with counts, stops marking (sec
    13.4.2). Counts of what clients mark are reported either way."""
    var max_datagram_frame_size: UInt64
    """``max_datagram_frame_size`` to advertise (RFC 9221 sec 3); 0, the
    default, leaves DATAGRAM frames off and a peer that sends one is
    closed with PROTOCOL_VIOLATION."""
    var max_pto_count: Int
    """Consecutive probe timeouts before the connection is given up on.

    ``LossRecovery`` bounds the PTO *backoff* at 64x the base interval
    but nothing bounds how long the server keeps probing a peer that has
    gone dark. Past this count the slot is closed with CONNECTION_CLOSE
    instead of re-arming, which bounds both the wall-clock and the
    in-flight packet list a dead connection can hold.

    Default 10: comfortably past the 6-shift backoff cap, so a slow but
    live path is not punished, and well short of forever."""

    def __init__(out self):
        self.host = String("0.0.0.0")
        self.port = UInt16(0)
        self.rustls_config = RustlsQuicConfig()
        self.aead_choice = QuicAead.AES_128_GCM
        self.max_idle_timeout_ms = UInt64(30_000)
        self.max_udp_payload_size = UInt64(1452)
        self.initial_max_data = UInt64(1 << 20)  # 1 MiB
        self.initial_max_streams_bidi = UInt64(100)
        self.initial_max_streams_uni = UInt64(3)
        self.local_cid_length = 8
        self.max_connections = 10_000
        self.early_data_strike_window_ms = UInt64(10_000)
        self.require_address_validation = False
        self.retry_token_max_age_ms = UInt64(10_000)
        self.max_pto_count = 10
        self.max_datagram_frame_size = UInt64(0)
        self.ecn = True
        self.key_update_interval = UInt64(1) << 23
        self.http3 = Http3Config()
        self.num_workers = 1
        self.worker_id = 0
        self.cid_route_key = List[UInt8]()
        self.inbox_table = 0


# -- Per-connection driver ----------------------------------------------


struct QuicConnection(Copyable):
    """Per-connection driver wrapping :class:`flare.quic.state.Connection`.

    Owned by the reactor; one instance per active connection.
    Composes:

    - The sans-I/O :class:`flare.quic.state.Connection` state
      machine.
    - A :class:`flare.tls.rustls_quic.RustlsQuicSession`
      carrying the per-encryption-level keys + handshake state.

    The reactor's per-packet hot path runs:

    1. Parse the long/short header out of the datagram
       (``flare.quic.packet``) -- done in
       :meth:`QuicListener.dispatch_datagram`.
    2. Decrypt the protected payload via OpenSSL AEAD (Initial)
       or rustls (Handshake / 1-RTT).
    3. Dispatch each frame in the decrypted payload through
       :func:`flare.quic.state.handle_frame_buf`, which advances
       the per-stream + per-connection state machines.
    4. Build any reply packets the state machine queued and
       feed them to the rustls session for encryption.
    """

    var conn: Connection
    """Sans-I/O connection state. Carries per-stream state +
    flow-control accounting + handshake-complete flag."""

    var local_cid: ConnectionId
    """The Connection ID the server chose for this connection
    (RFC 9000 §5.1). Routed-on by the reactor's CID->connection
    dispatch table."""

    var initial_dcid: ConnectionId
    """The Destination CID of the client's first Initial. The Initial
    keys are derived from it in both directions (RFC 9001 sec 5.2) and
    it is the ``original_destination_connection_id`` transport
    parameter. The server's own CID is separate: it used to *be* this
    value, so a client that picked a 16- or 20-byte DCID had its short
    headers parsed with the server's 8-byte CID length and got a
    stateless reset for its own connection."""

    var peer_cid: ConnectionId
    """The Connection ID the client picked for incoming
    server-to-client packets."""

    var alive: Bool
    """Whether the connection is still in HANDSHAKE / ESTABLISHED
    state. Goes False once the state machine advances to CLOSING
    / DRAINING / CLOSED so the reactor's dispatch table can
    sweep the entry."""

    var idle_timer_id: UInt64
    """Timer-wheel id of the currently-scheduled idle-timeout
    entry (0 if none). Each `handle_packet` call cancels the
    previous idle timer and schedules a fresh one. Stored here
    so the reactor can find and cancel it on connection close."""
    var pto_timer_id: UInt64
    """Timer-wheel id of this slot's armed PTO, or 0 when nothing is
    in flight. Mirrors ``idle_timer_id``; ``_rearm_pto_timer`` cancels
    the old entry before scheduling a new one."""

    var rx_handshake_secret: List[UInt8]
    """Inbound Handshake-level readiness marker (RFC 9001 §5.1).
    Stamped with the readiness sentinel once rustls installs the
    Handshake keys. Empty until set: Handshake packets that
    arrive while the slot is empty drop silently (the peer will
    retransmit)."""

    var tx_handshake_secret: List[UInt8]
    """Outbound Handshake-level readiness marker. Stamped in
    lockstep with :attr:`rx_handshake_secret`; gates the
    Handshake egress builder."""

    var rx_1rtt_secret: List[UInt8]
    """Inbound 1-RTT readiness marker. Stamped once rustls
    reports handshake-complete. Empty until then; short-header
    packets dropped silently."""

    var tx_1rtt_secret: List[UInt8]
    """Outbound 1-RTT traffic secret. Populated alongside
    :attr:`rx_1rtt_secret`."""

    var rx_early_secret: List[UInt8]
    """Inbound 0-RTT (EarlyData) readiness marker (RFC 9001 §4.1).
    Empty by default -- 0-RTT is OFF unless the server is
    configured with ``max_early_data_size > 0`` AND the resumed
    ClientHello is accepted, at which point the listener stamps the
    readiness sentinel after ``RustlsQuicSession.install_early_keys``
    succeeds. While empty, inbound 0-RTT packets drop silently (the
    client replays the request in 1-RTT)."""

    var tx_initial_pn: UInt64
    """Next packet number to use on the outbound Initial path.
    Monotonic per RFC 9001 §5.3; incremented after every
    successful Initial send. Read + bumped when draining
    :attr:`QuicListener.tls_egress_queues` onto the wire."""

    var tx_initial_offset: UInt64
    """Cumulative offset of CRYPTO bytes the server has emitted
    at the Initial encryption level. Per RFC 9000 §19.6 each
    CRYPTO frame carries its starting offset; this counter
    advances by the byte length of every emitted CRYPTO frame
    so the peer can reassemble the TLS stream in order."""

    var tx_handshake_pn: UInt64
    """Next packet number to use on the outbound Handshake
    path."""

    var tx_handshake_offset: UInt64
    """Cumulative CRYPTO offset at the Handshake level."""

    var tx_1rtt_pn: UInt64
    """Next packet number to use on the outbound 1-RTT path."""

    var send_timer_id: UInt64
    """Armed timer that resumes egress once the pacer allows it (0 when
    none)."""
    var ctrl_off: UInt64
    """Bytes sent so far on the server's HTTP/3 control stream."""
    var ctrl_tx: List[UInt8]
    """Control-stream frames (GOAWAY) queued for the next 1-RTT flight."""
    var issued_cids: Dict[UInt64, CidKey]
    """Connection IDs we issued that are still routable, as table keys
    by sequence number (0 is the handshake CID). All are unrouted when
    the slot is reclaimed; one used to stay mapped to the reused slot."""
    var peer_cid_limit: UInt64
    """The peer's ``active_connection_id_limit`` (RFC 9000 sec 18.2)."""
    var cid_replenish: Int
    """Connection IDs to issue in the next 1-RTT flight, replacing ones
    the peer retired."""

    var key_phase: Bool
    """1-RTT key phase bit we send (RFC 9001 sec 6): flips on every key
    update, ours or the peer's."""
    var phase_first_pn: UInt64
    """First packet number sent in the current key phase. A new update
    waits until a packet from this phase is acknowledged (sec 6.1)."""

    var amp_rx: Int
    """Bytes received from the peer's address while it is unvalidated."""
    var amp_tx: Int
    """Bytes sent to it in that time. Until :attr:`addr_validated`, the
    server may send at most three times :attr:`amp_rx` (RFC 9000 sec
    8.1), so a spoofed Initial cannot turn the server into an
    amplifier aimed at the address it forged."""
    var addr_validated: Bool
    """Set by a valid Retry token or the first decrypted Handshake
    packet; lifts the 3x limit."""

    var fc_adv_max_data: UInt64
    """Connection-level stream data we have allowed the peer to send:
    the initial_max_data transport parameter, then each MAX_DATA sent."""
    var fc_adv_max_bidi: UInt64
    """Client bidi streams we have allowed: initial_max_streams_bidi,
    then each MAX_STREAMS sent."""
    var fc_stream_end: Dict[Int, UInt64]
    """Highest byte offset seen per open stream. Flow control counts
    offsets, not bytes (RFC 9000 sec 4.1), so a retransmit is not
    counted twice."""
    var fc_received: UInt64
    """Sum of :attr:`fc_stream_end` over every stream ever opened."""
    var fc_consumed: UInt64
    """Stream bytes the application is done with: answered request
    streams, and control / QPACK stream bytes as they are read. Credit
    is granted from this, not from what was received."""
    var fc_closed_bidi: UInt64
    """Client request streams answered and closed."""
    var fc_tx_sent: UInt64
    """New stream bytes sent, summed over streams; bounded by the
    peer's MAX_DATA (``conn.max_data_send``). Retransmits do not count."""
    var fc_blocked_at: UInt64
    """MAX_DATA we last sent DATA_BLOCKED for."""
    var fc_stream_window: UInt64
    """Receive window granted per stream beyond what has arrived.
    Doubles, up to the cap, whenever grants come faster than twice the
    smoothed RTT (receive-window auto-tuning, as quiche does)."""
    var fc_last_grant_ms: UInt64
    """Time of the last MAX_STREAM_DATA grant, for the auto-tuning."""
    var fc_grants: List[Int]
    """Streams whose receive limit was raised since the last 1-RTT
    flight; each gets a MAX_STREAM_DATA in the next one."""
    var h3_tx: Dict[Int, _StreamTx]
    """Response egress per request stream."""

    var rx_largest: List[UInt64]
    """Largest packet number received per packet-number space: [0]
    Initial, [1] Handshake, [2] application (0-RTT and 1-RTT share it,
    RFC 9000 sec 12.3). Truncated packet numbers are expanded against
    their own space's largest. There was one counter for all three, so
    a space's numbers were decoded against another space's largest."""

    var rx_lh_ranges: List[List[UInt64]]
    """Received packet numbers in the Initial [0] and Handshake [1]
    spaces, as ACK ranges, so each level is acknowledged in its own
    packets (RFC 9000 sec 13.1, 17.2)."""
    var lh_ack_pending: List[Bool]
    """Per long-header space: an ack-eliciting packet arrived there and
    has not been acknowledged yet."""

    var initial_keys_discarded: Bool
    """Set once a Handshake packet has decrypted: from then on the
    server drops Initial packets (RFC 9001 sec 4.9.1). Initial keys
    come from the public DCID, so accepting Initial for the life of
    the connection let anyone who had seen that DCID inject into it."""

    var early_guard: EarlyDataReplayGuard
    """Per-connection 0-RTT admission control (anti-replay window +
    byte budget). Disabled (budget 0) until the listener installs
    early keys on an accepted resumed ClientHello."""

    var closing: Bool
    """Set by ``_close_for`` once a CONNECTION_CLOSE went out (RFC 9000
    sec 10.2): the slot is no longer :attr:`alive` but stays routable and
    answers incoming packets with CONNECTION_CLOSE until the closing
    period (three PTOs) ends. Never set when no 1-RTT keys existed to
    send one."""
    var closing_rx: Int
    """Packets received while :attr:`closing`; the CONNECTION_CLOSE
    answers are rate limited by it (RFC 9000 sec 10.2.1)."""
    var close_frame: List[UInt8]
    """The encoded, padded CONNECTION_CLOSE sent on every answer."""

    var peer_idle_ms: UInt64
    """The client's ``max_idle_timeout`` (ms); 0 until its transport
    parameters were read, or when it advertises none. The idle timer uses
    the minimum of this and the local value (RFC 9000 sec 10.1)."""
    var idle_sent_since_rx: Bool
    """Whether an ack-eliciting packet was sent since the last packet
    that was received and processed. Only the first such send restarts
    the idle timer (RFC 9000 sec 10.1)."""
    var peer_max_datagram: UInt64
    """The client's ``max_datagram_frame_size`` (RFC 9221 sec 3); 0 until
    its transport parameters were read, or when it takes no DATAGRAMs."""
    var dg_rx: List[List[UInt8]]
    """DATAGRAM payloads received and not yet taken."""
    var dg_tx: List[List[UInt8]]
    """DATAGRAM payloads queued for the next drain."""
    var dg_rx_bytes: Int
    var dg_tx_bytes: Int
    var stop_tx: List[Int]
    """Streams answered before the client finished its request: each is
    sent STOP_SENDING (H3_NO_ERROR) so the rest of the upload stops
    (RFC 9114 sec 4.1.2)."""
    var ecn_rx: List[UInt64]
    """ECT(0), ECT(1) and CE counts of 1-RTT packets received, reported
    in ACK_ECN frames (RFC 9000 sec 13.4.1)."""
    var ecn_tx: EcnValidator
    var ecn_mark: Bool
    """1-RTT packets go out marked ECT(0) (``QuicServerConfig.ecn``),
    until validation fails on this path."""
    var pmtu: PmtuDiscovery
    """Datagram size validated on this path (RFC 9000 sec 14.3)."""
    var serial: UInt64
    """Distinguishes this connection from others given the same slot."""
    var fc_tunnel_credited: Dict[Int, UInt64]
    """Per tunnel stream, the bytes already counted as consumed when the
    application took them (:meth:`QuicListener.take_http3_tunnel`)."""

    def __init__(
        out self,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        idle_timeout_us: UInt64 = UInt64(30_000_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
    ):
        self.conn = new_connection(
            idle_timeout_us,
            initial_max_data,
            is_server=True,
            check_stream_ids=True,
        )
        self.local_cid = local_cid.copy()
        self.initial_dcid = local_cid.copy()
        self.peer_cid = peer_cid.copy()
        self.alive = True
        self.idle_timer_id = UInt64(0)
        self.pto_timer_id = UInt64(0)
        self.peer_idle_ms = UInt64(0)
        self.idle_sent_since_rx = False
        self.peer_max_datagram = 0
        self.dg_rx = List[List[UInt8]]()
        self.dg_tx = List[List[UInt8]]()
        self.dg_rx_bytes = 0
        self.dg_tx_bytes = 0
        self.serial = 0
        self.pmtu = PmtuDiscovery()
        self.stop_tx = List[Int]()
        self.ecn_rx = List[UInt64](length=3, fill=0)
        self.ecn_tx = EcnValidator()
        self.ecn_mark = False
        self.fc_tunnel_credited = Dict[Int, UInt64]()
        self.closing = False
        self.closing_rx = 0
        self.close_frame = List[UInt8]()
        self.rx_handshake_secret = List[UInt8]()
        self.tx_handshake_secret = List[UInt8]()
        self.rx_1rtt_secret = List[UInt8]()
        self.tx_1rtt_secret = List[UInt8]()
        self.rx_early_secret = List[UInt8]()
        self.tx_initial_pn = UInt64(0)
        self.tx_initial_offset = UInt64(0)
        self.tx_handshake_pn = UInt64(0)
        self.tx_handshake_offset = UInt64(0)
        self.tx_1rtt_pn = UInt64(0)
        self.send_timer_id = 0
        self.ctrl_off = 0
        self.ctrl_tx = List[UInt8]()
        self.issued_cids = Dict[UInt64, CidKey]()
        self.peer_cid_limit = UInt64(2)
        self.cid_replenish = 0
        self.key_phase = False
        self.phase_first_pn = UInt64(0)
        self.amp_rx = 0
        self.amp_tx = 0
        self.addr_validated = False
        self.fc_adv_max_data = initial_max_data
        self.fc_adv_max_bidi = UInt64(100)
        self.fc_stream_end = Dict[Int, UInt64]()
        self.fc_received = 0
        self.fc_consumed = 0
        self.fc_closed_bidi = 0
        self.fc_tx_sent = 0
        self.fc_blocked_at = UInt64.MAX
        self.fc_stream_window = initial_max_data
        self.fc_last_grant_ms = 0
        self.fc_grants = List[Int]()
        self.h3_tx = Dict[Int, _StreamTx]()
        # Nothing may be sent until the client's transport parameters
        # are known; _client_params_ok raises both limits.
        self.conn.max_data_send = 0
        self.conn.peer_initial_max_stream_data = 0
        self.rx_largest = List[UInt64](length=3, fill=UInt64(0))
        self.rx_lh_ranges = List[List[UInt64]](length=2, fill=List[UInt64]())
        self.lh_ack_pending = List[Bool](length=2, fill=False)
        self.initial_keys_discarded = False
        self.early_guard = EarlyDataReplayGuard()

    def install_handshake_keys(
        mut self,
        var rx_secret: List[UInt8],
        var tx_secret: List[UInt8],
    ):
        """Install per-direction Handshake traffic secrets
        (RFC 9001 §5.1), called when rustls emits its first
        ``KeyChange::Handshake``."""
        self.rx_handshake_secret = rx_secret^
        self.tx_handshake_secret = tx_secret^

    def install_1rtt_keys(
        mut self,
        var rx_secret: List[UInt8],
        var tx_secret: List[UInt8],
    ):
        """Install per-direction 1-RTT (application) traffic
        secrets, called on rustls's ``KeyChange::OneRtt`` -- the
        handshake-complete moment."""
        self.rx_1rtt_secret = rx_secret^
        self.tx_1rtt_secret = tx_secret^

    def install_early_data_keys(mut self, var rx_secret: List[UInt8]):
        """Stamp the inbound 0-RTT (EarlyData) readiness marker
        (RFC 9001 §4.1) once the listener has confirmed rustls
        accepted early data on a resumed ClientHello. Inbound-only:
        the server never sends 0-RTT, so there is no tx counterpart."""
        self.rx_early_secret = rx_secret^

    def on_idle_expired(mut self):
        """RFC 9000 §10.1.2 -- silent close on idle timeout.

        The state machine advances to ``CLOSED`` without emitting
        a CONNECTION_CLOSE frame (the peer must come to the same
        conclusion via its own idle timer). The reactor sweeps
        the slot on the next tick.
        """
        self.alive = False
        self.conn.state = CONN_STATE_CLOSED
        self.idle_timer_id = UInt64(0)
        self.pto_timer_id = UInt64(0)

    def handle_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int = QuicAead.AES_128_GCM,
    ) raises -> ConnectionEvents:
        """Drive one inbound datagram through the per-packet
        decrypt + frame dispatch pipeline.

        Dispatch by encryption level:

        - Long-header Initial: always handled -- the secret is
          derived from the connection's ``local_cid`` (RFC 9001
          §5.2). This is the first-flight path.
        - Long-header Handshake: handled iff
          :attr:`rx_handshake_secret` is non-empty.
        - Short-header 1-RTT: handled iff :attr:`rx_1rtt_secret`
          is non-empty.
        - Long-header 0-RTT + Retry: not handled (flare does not
          accept 0-RTT, and Retry is server-emit-only so it
          never arrives at this path).

        For each handled level the decrypted frame bytes feed
        :func:`flare.quic.state.handle_frame_buf`, which advances
        the sans-I/O state machine and reports back through
        :class:`flare.quic.state.ConnectionEvents`. Packets at a
        level whose secret is not yet installed are dropped
        silently (the peer's PTO-driven retransmission will
        re-deliver once the secret arrives).
        """
        var events = empty_events()
        if len(datagram) < 1:
            return events^
        var first = Int(datagram[0])
        var is_long = (first & 0x80) != 0
        if not is_long:
            return self._handle_1rtt_packet(datagram, now_us, aead_choice)
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return events^
        if lh.packet_type == PACKET_TYPE_INITIAL:
            return self._handle_initial_packet(datagram, now_us, aead_choice)
        if lh.packet_type == PACKET_TYPE_HANDSHAKE:
            return self._handle_handshake_packet(datagram, now_us, aead_choice)
        # 0-RTT (1) and Retry (3) are not handled here -- see
        # docstring.
        return events^

    def _handle_initial_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level Initial decrypt + frame dispatch. Carved out
        of :meth:`handle_packet` so the H + 1-RTT branches stay
        readable; behaviour is byte-identical to the prior inline
        version."""
        var events = empty_events()
        var up = unprotect_initial_packet(
            datagram,
            self.initial_dcid,
            is_server=True,
            largest_received_pn=self.rx_largest[0],
            aead_choice=aead_choice,
        )
        dispatch_frames(
            self.conn, Span[UInt8, _](up.payload), now_us, events, True
        )
        self._note_received(0, up.packet_number)
        return events^

    def _handle_handshake_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level Handshake decrypt + frame dispatch.

        Returns empty events until :attr:`rx_handshake_secret` is
        installed. The listener now decrypts post-Initial packets
        through rustls; this OpenSSL path is retained for unit
        tests that exercise the sans-I/O connection directly.
        """
        var events = empty_events()
        if len(self.rx_handshake_secret) == 0:
            return events^
        var up = unprotect_handshake_packet(
            datagram,
            Span[UInt8, _](self.rx_handshake_secret),
            self.rx_largest[1],
            aead_choice=aead_choice,
        )
        dispatch_frames(
            self.conn, Span[UInt8, _](up.payload), now_us, events, True
        )
        self._note_received(1, up.packet_number)
        return events^

    def _handle_1rtt_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int,
    ) raises -> ConnectionEvents:
        """Per-level 1-RTT decrypt + frame dispatch.

        Returns empty events until :attr:`rx_1rtt_secret` is
        installed. ``dcid_length`` comes from the connection's
        pinned ``local_cid`` length -- a short header carries the
        DCID bytes but not its length (RFC 9000 §17.3), so the
        receiver supplies it from per-connection state. Retained
        for unit tests; the listener decrypts 1-RTT via rustls.
        """
        var events = empty_events()
        if len(self.rx_1rtt_secret) == 0:
            return events^
        var up = unprotect_1rtt_packet(
            datagram,
            Span[UInt8, _](self.rx_1rtt_secret),
            self.rx_largest[2],
            self.local_cid.length(),
            aead_choice=aead_choice,
        )
        dispatch_frames(
            self.conn, Span[UInt8, _](up.payload), now_us, events, False
        )
        self._note_received(2, up.packet_number)
        return events^

    def _note_received(mut self, space: Int, pn: UInt64):
        """Record ``pn`` as received in ``space`` (see
        :attr:`rx_largest`, and the long-header ACK ranges);
        ``conn.largest_received_packet`` stays the largest across all
        spaces."""
        if space < 2:
            _ack_record(self.rx_lh_ranges[space], pn)
        if pn > self.rx_largest[space]:
            self.rx_largest[space] = pn
        if pn > self.conn.largest_received_packet:
            self.conn.largest_received_packet = pn

    def dispatch_plaintext(
        mut self,
        plaintext: Span[UInt8, _],
        now_us: UInt64,
        packet_number: UInt64,
        before_1rtt: Bool = False,
        space: Int = 2,
    ) raises -> ConnectionEvents:
        """Drive already-decrypted frame bytes through the
        sans-I/O state machine.

        The listener decrypts Handshake + 1-RTT packets through
        the rustls session (which holds the real AEAD keys) and
        hands the plaintext here, since the sans-I/O connection
        has no rustls handle. Mirrors the frame-dispatch loop in
        the per-level handlers minus the decrypt step.
        """
        var events = empty_events()
        dispatch_frames(self.conn, plaintext, now_us, events, before_1rtt)
        self._note_received(space, packet_number)
        return events^


# -- Connection ID table ------------------------------------------------


@fieldwise_init
struct CidKey(Copyable, Equatable, Hashable, ImplicitlyCopyable):
    """A Connection ID (at most 20 bytes, RFC 9000 sec 17.2) as a
    fixed-size key: the bytes packed into three words, with the length
    in the top byte of the last."""

    var a: UInt64
    var b: UInt64
    var c: UInt64

    def __init__(out self, cid: ConnectionId):
        self = CidKey.of(Span[UInt8, _](cid.bytes))

    @staticmethod
    def of(bytes: Span[UInt8, _]) -> CidKey:
        var w = (UInt64(0), UInt64(0), UInt64(0))
        var n = min(len(bytes), 20)
        for i in range(n):
            var v = UInt64(bytes[i]) << UInt64((i & 7) * 8)
            if i < 8:
                w[0] |= v
            elif i < 16:
                w[1] |= v
            else:
                w[2] |= v
        return CidKey(w[0], w[1], w[2] | (UInt64(n) << 56))

    def __eq__(self, other: Self) -> Bool:
        return self.a == other.a and self.b == other.b and self.c == other.c

    def __ne__(self, other: Self) -> Bool:
        return not self == other

    def __hash__[H: Hasher](self, mut hasher: H):
        self.a.__hash__(hasher)
        self.b.__hash__(hasher)
        self.c.__hash__(hasher)


struct ConnectionIdTable(Copyable, Defaultable, Sized):
    """Per-listener routing table from Connection ID to connection
    slot (RFC 9000 sec 5.1). A connection can have up to
    ``active_connection_id_limit`` CIDs at once, each pointing at the
    same slot."""

    var cid_to_slot: Dict[CidKey, Int]

    def __init__(out self):
        self.cid_to_slot = Dict[CidKey, Int]()

    def register(mut self, cid: CidKey, slot: Int):
        """Add (or overwrite) a CID -> slot mapping."""
        self.cid_to_slot[cid] = slot

    def lookup(self, cid: CidKey) -> Int:
        """The slot for ``cid``, or -1."""
        return self.cid_to_slot.get(cid, -1)

    def retire(mut self, cid: CidKey):
        """Drop a CID -> slot mapping, if present."""
        _ = self.cid_to_slot.pop(cid, -1)

    def __len__(self) -> Int:
        return len(self.cid_to_slot)


# -- CID hex helper (used by the dispatch table key) -------------------


@always_inline
def _hex_nibble(n: Int) -> UInt8:
    """Return the lowercase ASCII byte for a single hex nibble."""
    if n < 10:
        return UInt8(48 + n)  # '0'..'9'
    return UInt8(87 + n)  # 'a'..'f'


def cid_to_hex(cid: ConnectionId) -> String:
    """Encode a CID's bytes as lowercase hex. Used by the
    dispatch table key so :class:`ConnectionIdTable` can hash
    on a plain :class:`String`. An empty CID returns the empty
    string -- the routing layer rejects that case explicitly.
    """
    var out = List[UInt8]()
    for i in range(len(cid.bytes)):
        var b = Int(cid.bytes[i])
        out.append(_hex_nibble((b >> 4) & 0xF))
        out.append(_hex_nibble(b & 0xF))
    out.append(UInt8(0))  # null terminator for String constructor
    return String(unsafe_from_utf8=Span[UInt8, _](out[: len(out) - 1]))


# -- Transport-parameter encoding (handshake setup, cold path) ---------


def _encode_server_transport_params(
    config: QuicServerConfig,
    local_cid: ConnectionId,
    original_dcid: ConnectionId,
    retry_scid: List[UInt8] = List[UInt8](),
) raises -> List[UInt8]:
    """Encode the server's QUIC transport parameters for the TLS
    handshake.

    ``original_destination_connection_id`` is the client's
    first-Initial DCID (``original_dcid``) and
    ``initial_source_connection_id`` the server's own CID
    (``local_cid``), which RFC 9000 sec 7.2 has the server choose.
    After a Retry, ``original_dcid`` is the DCID the client first sent
    (recovered from the token) and ``retry_scid`` the Retry's Source CID,
    sent as ``retry_source_connection_id``. Both were wrong: the ODCID
    was the post-Retry DCID and the retry CID was never sent, so an
    RFC-compliant client aborted with TRANSPORT_PARAMETER_ERROR. The flow-control + stream limits come from
    ``config``; per-stream data windows mirror the connection-level
    ``initial_max_data``. The peer rejects a handshake whose
    transport parameters omit the source-CID (RFC 9000 sec 7.3), so
    these are always emitted.

    Cold path: runs once per accepted connection during handshake
    setup, hence a free function over ``config`` rather than a
    method on the hot reactor loop.
    """
    var tp = empty_transport_parameters()
    tp.original_destination_connection_id = original_dcid.bytes.copy()
    tp.initial_source_connection_id = local_cid.bytes.copy()
    tp.retry_source_connection_id = retry_scid.copy()
    tp.max_idle_timeout = Optional(config.max_idle_timeout_ms)
    tp.initial_max_data = Optional(config.initial_max_data)
    tp.initial_max_stream_data_bidi_local = Optional(config.initial_max_data)
    tp.initial_max_stream_data_bidi_remote = Optional(config.initial_max_data)
    tp.initial_max_stream_data_uni = Optional(config.initial_max_data)
    tp.initial_max_streams_bidi = Optional(config.initial_max_streams_bidi)
    tp.initial_max_streams_uni = Optional(config.initial_max_streams_uni)
    tp.active_connection_id_limit = Optional(UInt64(2))
    tp.max_udp_payload_size = Optional(config.max_udp_payload_size)
    tp.min_ack_delay = Optional(MIN_ACK_DELAY_US)
    if config.max_datagram_frame_size > 0:
        tp.max_datagram_frame_size = Optional(config.max_datagram_frame_size)
    return encode_transport_parameters(tp)
