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

from std.collections import Dict, List, Optional
from std.memory import Span

from ._server_0rtt import EarlyDataReplayGuard
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
from .state import (
    CONN_STATE_CLOSED,
    Connection,
    ConnectionEvents,
    empty_events,
    handle_frame_buf,
    new_connection,
)
from .transport_params import (
    empty_transport_parameters,
    encode_transport_parameters,
)
from ..tls.rustls_quic import RustlsQuicConfig


# -- Configuration carrier ----------------------------------------------


struct QuicServerConfig(Copyable, Defaultable, Movable):
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
    silently dropped. Default: 30_000 ms (30 s)."""

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
        self.early_data_strike_window_ms = UInt64(10_000)
        self.require_address_validation = False
        self.retry_token_max_age_ms = UInt64(10_000)


# -- Per-connection driver ----------------------------------------------


struct QuicConnection(Copyable, Movable):
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

    var early_guard: EarlyDataReplayGuard
    """Per-connection 0-RTT admission control (anti-replay window +
    byte budget). Disabled (budget 0) until the listener installs
    early keys on an accepted resumed ClientHello."""

    def __init__(
        out self,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        idle_timeout_us: UInt64 = UInt64(30_000_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
    ):
        self.conn = new_connection(idle_timeout_us, initial_max_data)
        self.local_cid = local_cid.copy()
        self.peer_cid = peer_cid.copy()
        self.alive = True
        self.idle_timer_id = UInt64(0)
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
            self.local_cid,
            is_server=True,
            largest_received_pn=self.conn.largest_received_packet,
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
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
            self.conn.largest_received_packet,
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
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
            self.conn.largest_received_packet,
            self.local_cid.length(),
            aead_choice=aead_choice,
        )
        var cursor = 0
        var payload = Span[UInt8, _](up.payload)
        while cursor < len(payload):
            var consumed = handle_frame_buf(
                self.conn, payload[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if up.packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = up.packet_number
        return events^

    def dispatch_plaintext(
        mut self,
        plaintext: Span[UInt8, _],
        now_us: UInt64,
        packet_number: UInt64,
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
        var cursor = 0
        while cursor < len(plaintext):
            var consumed = handle_frame_buf(
                self.conn, plaintext[cursor:], now_us, events
            )
            if consumed <= 0:
                break
            cursor += consumed
        if packet_number > self.conn.largest_received_packet:
            self.conn.largest_received_packet = packet_number
        return events^


# -- Connection ID table ------------------------------------------------


struct ConnectionIdTable(Copyable, Defaultable, Movable, Sized):
    """Per-listener routing table from Connection ID to connection.

    QUIC routes inbound datagrams to the right connection via
    the Destination Connection ID in the packet header (RFC 9000
    §5.1). The table maps each issued CID (server-side: the
    local_cid from :class:`QuicConnection`; client-side: the
    Source Connection IDs the server sent in NEW_CONNECTION_ID
    frames) to the connection slot it belongs to.

    The carrier uses :class:`Dict[String, Int]` where the key is
    the lowercase-hex CID and the value is the slot index into
    the listener's connection slab.
    """

    var cid_to_slot: Dict[String, Int]
    """CID (lowercase-hex of CID bytes) -> slot index. Empty
    string is invalid; a connection can have up to
    `active_connection_id_limit` (RFC 9000 §18.2) CIDs at once,
    each pointing at the same slot."""

    def __init__(out self):
        self.cid_to_slot = Dict[String, Int]()

    def register(mut self, cid_hex: String, slot: Int):
        """Add a CID -> slot mapping. Idempotent: overwriting
        an existing mapping is allowed (the server may reissue
        CIDs after migration)."""
        self.cid_to_slot[cid_hex] = slot

    def lookup(self, cid_hex: String) raises -> Int:
        """Look up the slot for a CID. Returns -1 if absent.
        The reactor uses -1 to gate the Initial packet path
        (no slot -> potentially new connection -> run the
        accept-handshake state machine)."""
        if cid_hex in self.cid_to_slot:
            return self.cid_to_slot[cid_hex]
        return -1

    def retire(mut self, cid_hex: String) raises:
        """Drop a CID -> slot mapping. Called when the connection
        retires a CID via RETIRE_CONNECTION_ID (RFC 9000 §19.16)
        or when the connection itself closes."""
        if cid_hex in self.cid_to_slot:
            _ = self.cid_to_slot.pop(cid_hex)

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
    config: QuicServerConfig, local_cid: ConnectionId
) raises -> List[UInt8]:
    """Encode the server's QUIC transport parameters for the TLS
    handshake.

    ``original_destination_connection_id`` + ``initial_source_
    connection_id`` are both the client's first-Initial DCID: the
    server reuses that CID as its own source CID (see
    :meth:`QuicListener._accept_initial`), so both equal
    ``local_cid``. The flow-control + stream limits come from
    ``config``; per-stream data windows mirror the connection-level
    ``initial_max_data``. The peer rejects a handshake whose
    transport parameters omit the source-CID (RFC 9000 sec 7.3), so
    these are always emitted.

    Cold path: runs once per accepted connection during handshake
    setup, hence a free function over ``config`` rather than a
    method on the hot reactor loop.
    """
    var tp = empty_transport_parameters()
    tp.original_destination_connection_id = local_cid.bytes.copy()
    tp.initial_source_connection_id = local_cid.bytes.copy()
    tp.max_idle_timeout = Optional(config.max_idle_timeout_ms)
    tp.initial_max_data = Optional(config.initial_max_data)
    tp.initial_max_stream_data_bidi_local = Optional(config.initial_max_data)
    tp.initial_max_stream_data_bidi_remote = Optional(config.initial_max_data)
    tp.initial_max_stream_data_uni = Optional(config.initial_max_data)
    tp.initial_max_streams_bidi = Optional(config.initial_max_streams_bidi)
    tp.initial_max_streams_uni = Optional(config.initial_max_streams_uni)
    tp.active_connection_id_limit = Optional(UInt64(2))
    return encode_transport_parameters(tp)
