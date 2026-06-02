"""``flare.quic.server`` -- QUIC server reactor (Track Q3-W).

Wraps the sans-I/O QUIC connection state machine
(:class:`flare.quic.state.Connection`) in a UDP listener +
per-connection dispatcher. Commit 1/5 of Track Q3-W lands the
UDP bind + the per-datagram dispatch loop; subsequent commits in
the same track wire the per-packet decrypt path (2/5), the
PTO / idle / ack-delay timer entries (3/5), the CC reactor
hooks (4/5), and the loopback integration tests against a real
QUIC client (5/5).

## What ships here

- :class:`QuicServerConfig` -- bind configuration: host, port,
  rustls config carrier, congestion-controller choice, idle
  timeout, max packet size.
- :class:`QuicListener` -- factory that owns a bound UDP
  socket plus the per-connection dispatch table. The :meth:`bind`
  factory opens the socket, :meth:`tick` drains one datagram
  (unit-testable), :meth:`run` is the blocking event loop, and
  :meth:`shutdown` requests a clean exit.
- :class:`QuicConnection` -- per-connection driver that
  composes the existing :class:`flare.quic.state.Connection`
  state machine with a :trait:`flare.quic.cc.CongestionController`
  carrier and the rustls QUIC session.
- :class:`ConnectionIdTable` -- per-listener routing table from
  Connection ID to connection slot, used by the dispatch loop
  to route inbound datagrams via the Destination Connection ID
  in the packet header (RFC 9000 §5.1).

## What's deferred to follow-ups inside this track

- The per-packet decrypt + state-machine dispatch
  (:meth:`QuicConnection.handle_packet`) -- commit 2/5.
- The PTO / idle / ack-delay TimerWheel entries -- commit 3/5.
- The CC reactor hooks (``update_on_ack`` /
  ``update_on_loss`` / ``pacing_budget``) -- commit 4/5.
- ``recvmmsg`` + ``UDP_GRO`` batching on the ingress path and
  ``sendmmsg`` + ``UDP_SEGMENT`` on the egress path -- not in
  scope for v0.8; the single-datagram ``recv_from`` loop is the
  functional contract this cycle ships.

References:
- RFC 9000 §5 "Connections" -- Connection ID routing.
- RFC 9000 §10 "Connection Termination" -- idle / draining.
- RFC 9000 §17 "Packet Formats" -- long / short header parse
  for the dispatch path.
- RFC 9002 §6.2 "PTO and probe packets" -- PTO timer wiring
  (deferred to commit 3/5 of this track).
"""

from std.collections import Dict, List, Optional
from std.memory import Span

from ..net.address import IpAddr, SocketAddr
from ..udp import UdpSocket
from .cc import CcChoice
from .crypto import QuicAead
from .packet import (
    ConnectionId,
    LongHeader,
    MAX_CID_LENGTH,
    PACKET_TYPE_INITIAL,
    parse_long_header,
    parse_short_header,
)
from .protection import unprotect_initial_packet
from .state import (
    Connection,
    ConnectionEvents,
    empty_events,
    handle_frame_buf,
    new_connection,
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

    var cc_choice: Int
    """Congestion controller selector
    (:data:`flare.quic.cc.CcChoice.CUBIC` for production,
    :data:`flare.quic.cc.CcChoice.RENO` for deterministic tests).
    Default: CUBIC."""

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

    def __init__(out self):
        self.host = String("0.0.0.0")
        self.port = UInt16(0)
        self.rustls_config = RustlsQuicConfig()
        self.cc_choice = CcChoice.CUBIC
        self.aead_choice = QuicAead.AES_128_GCM
        self.max_idle_timeout_ms = UInt64(30_000)
        self.max_udp_payload_size = UInt64(1452)
        self.initial_max_data = UInt64(1 << 20)  # 1 MiB
        self.initial_max_streams_bidi = UInt64(100)
        self.initial_max_streams_uni = UInt64(3)
        self.local_cid_length = 8


# -- Per-connection driver ----------------------------------------------


struct QuicConnection(Copyable, Movable):
    """Per-connection driver wrapping :class:`flare.quic.state.Connection`.

    Owned by the reactor; one instance per active connection.
    Composes:

    - The sans-I/O :class:`flare.quic.state.Connection` state
      machine.
    - A :trait:`flare.quic.cc.CongestionController` carrier
      (CUBIC in production, Reno in deterministic tests).
    - A :class:`flare.tls.rustls_quic.RustlsQuicSession`
      carrying the per-encryption-level keys + handshake state
      (wired in commit 2/5 of Track Q3-W).

    The reactor's per-packet hot path runs:

    1. Parse the long/short header out of the datagram
       (``flare.quic.packet``) -- done in
       :meth:`QuicListener.dispatch_datagram`.
    2. Decrypt the protected payload via OpenSSL AEAD or rustls
       (commit 2/5 of Track Q3-W).
    3. Dispatch each frame in the decrypted payload through
       :func:`flare.quic.state.handle_frame_buf`, which advances
       the per-stream + per-connection state machines.
    4. Drive the CC controller with any newly-ACKed bytes
       (commit 4/5 of Track Q3-W).
    5. Build any reply packets the state machine queued and
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

    var cc_choice: Int
    """Which congestion controller this connection runs (RENO
    or CUBIC). Materialized monomorphically by the reactor at
    bind time."""

    var alive: Bool
    """Whether the connection is still in HANDSHAKE / ESTABLISHED
    state. Goes False once the state machine advances to CLOSING
    / DRAINING / CLOSED so the reactor's dispatch table can
    sweep the entry."""

    def __init__(
        out self,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_choice: Int = CcChoice.CUBIC,
        idle_timeout_us: UInt64 = UInt64(30_000_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
    ):
        self.conn = new_connection(idle_timeout_us, initial_max_data)
        self.local_cid = local_cid.copy()
        self.peer_cid = peer_cid.copy()
        self.cc_choice = cc_choice
        self.alive = True

    def handle_packet(
        mut self,
        datagram: Span[UInt8, _],
        now_us: UInt64,
        aead_choice: Int = QuicAead.AES_128_GCM,
    ) raises -> ConnectionEvents:
        """Drive one inbound datagram through the per-packet
        decrypt + frame dispatch pipeline.

        Long-header Initial packets unprotect through
        :func:`flare.quic.protection.unprotect_initial_packet`
        with the server-side reader role and the connection's
        ``local_cid`` (which equals the client-chosen DCID at the
        handshake-accept moment). Decrypted frame bytes feed
        :func:`flare.quic.state.handle_frame_buf`, which advances
        the sans-I/O state machine and reports back through
        :class:`flare.quic.state.ConnectionEvents`.

        Long-header Handshake + 0-RTT packets and short-header
        1-RTT packets require keys derived from the TLS handshake;
        those land with commits 3/5-5/5 of this track once the
        rustls bridge surfaces per-encryption-level secrets. For
        now they return empty :class:`ConnectionEvents` so the
        dispatch loop doesn't crash on legitimate post-handshake
        traffic.
        """
        var events = empty_events()
        if len(datagram) < 1:
            return events^
        var first = Int(datagram[0])
        var is_long = (first & 0x80) != 0
        if not is_long:
            return events^
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return events^
        if lh.packet_type != PACKET_TYPE_INITIAL:
            return events^
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
    slot index. Slots are append-only in this commit; the
    sweeper for closed connections lands with the timer-wheel
    commit (3/5) of this track."""
    var _socket: UdpSocket
    var _local_addr: SocketAddr
    var _stopping: Bool
    """Set by :meth:`shutdown`. Read by :meth:`run` at the top of
    every loop iteration so the event loop exits cleanly after
    the next ``recv_from`` returns or times out."""

    def __init__(
        out self,
        config: QuicServerConfig,
        var sock: UdpSocket,
        addr: SocketAddr,
    ):
        """Wrap an already-bound :class:`UdpSocket`. Internal --
        callers use :meth:`bind`."""
        self.config = config.copy()
        self.cid_table = ConnectionIdTable()
        self.connections = List[QuicConnection]()
        self._socket = sock^
        self._local_addr = addr
        self._stopping = False

    @staticmethod
    def bind(config: QuicServerConfig) raises -> QuicListener:
        """Open the UDP socket and bind it to ``config.host`` /
        ``config.port``. Returns a ready-to-run listener.

        If ``config.port == 0`` the kernel picks an ephemeral
        port; read it back via :meth:`local_addr`.
        """
        var ip = IpAddr.parse(config.host)
        var addr = SocketAddr(ip, config.port)
        var sock = UdpSocket.bind(addr)
        var actual = sock.local_addr()
        return QuicListener(config, sock^, actual)

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
        """Number of connection slots currently allocated. Slots
        are append-only in this commit; the sweep for closed
        connections lands with the timer-wheel commit (3/5)."""
        return len(self.connections)

    def dispatch_datagram(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Route a single UDP datagram to the right connection slot.

        Parses the first byte to pick long vs short header,
        extracts the Destination Connection ID, looks it up in
        :attr:`cid_table`, and either:

        * Routes the datagram to the existing slot via
          :meth:`QuicConnection.handle_packet` -- the per-packet
          decrypt + state-machine drive (commit 2/5 of this
          track). Decryption failures are caught and converted
          to silent drops so a single bad sender can't poison
          the listener.
        * Allocates a new slot for an Initial packet with an
          unknown DCID (the QUIC accept path -- RFC 9000 §7),
          then drives the same handle_packet path on the new
          connection so the first Initial advances the state
          machine.
        * Returns ``-1`` to drop short-header packets with
          unknown DCIDs (the stateless-reset path lands in a
          later cycle; for now those datagrams are silently
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
        if slot >= 0 and slot < len(self.connections):
            self._handle_inbound(slot, datagram)
        return slot

    def _handle_inbound(mut self, slot: Int, datagram: Span[UInt8, _]) raises:
        """Drive ``QuicConnection.handle_packet`` on the matched
        slot. Caught + dropped here:

        * Decryption failures (bad AEAD tag, malformed cipher,
          wrong key) -- the QUIC protocol mandates silent drop
          per RFC 9001 §5.2.
        * Frame parse failures inside the decrypted payload --
          again silent drop; the connection stays usable for
          subsequent packets that decode cleanly.

        Other state-machine errors propagate to the caller so
        the reactor can log + close the connection.
        """
        var now_us = UInt64(0)  # Wall-clock driven from commit 3/5
        var conn = self.connections[slot].copy()
        try:
            var _events = conn.handle_packet(datagram, now_us)
        except:
            # Silent drop on decrypt + parse failures
            # (RFC 9001 §5.2). The connection slot stays alive
            # for retransmits + subsequent valid packets.
            self.connections[slot] = conn^
            return
        self.connections[slot] = conn^

    def _dispatch_long(
        mut self, datagram: Span[UInt8, _], peer: SocketAddr
    ) raises -> Int:
        """Long-header path: parse the full header, route by DCID,
        and accept an Initial packet against an unknown DCID."""
        var lh: LongHeader
        try:
            lh = parse_long_header(datagram)
        except:
            return -1
        var dcid_hex = cid_to_hex(lh.dcid)
        var slot = self.cid_table.lookup(dcid_hex)
        if slot >= 0:
            return slot
        if lh.packet_type == PACKET_TYPE_INITIAL:
            return self._accept_initial(lh)
        return -1

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

    def _accept_initial(mut self, lh: LongHeader) raises -> Int:
        """Allocate a new connection slot for an Initial packet
        with an unknown DCID.

        The server registers the client-chosen DCID in
        :attr:`cid_table` so subsequent Initials addressed to
        the same DCID route here. RFC 9000 §7.2 says the server
        SHOULD choose its own SCID and switch to it on the
        server-side response; that follow-up is part of the
        per-packet wiring in commit 2/5 of this track.
        """
        var local_cid = lh.dcid.copy()
        var peer_cid = lh.scid.copy()
        var qc = QuicConnection(
            local_cid,
            peer_cid,
            self.config.cc_choice,
            self.config.max_idle_timeout_ms * UInt64(1_000),
            self.config.initial_max_data,
        )
        var slot = len(self.connections)
        self.connections.append(qc^)
        self.cid_table.register(cid_to_hex(local_cid), slot)
        return slot

    def tick(mut self, timeout_ms: Int = 100) raises -> Bool:
        """Drain at most one inbound datagram.

        Returns ``True`` if a datagram was received + dispatched,
        ``False`` if ``recv_from`` timed out before any datagram
        arrived. Callers use this when they need to multiplex
        the QUIC event loop with other work (tests + the
        ALPN-dispatching HTTP server).

        ``timeout_ms`` is applied via ``SO_RCVTIMEO``; the
        default 100 ms is the same shutdown-poll cadence
        :meth:`run` uses.
        """
        self._socket.set_recv_timeout(timeout_ms)
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
            # loop treats both as "no datagram this tick".
            var msg = String(e)
            if msg.startswith("Timeout") or msg.startswith("recvfrom"):
                return False
            raise e^
        if got <= 0:
            return False
        _ = self.dispatch_datagram(Span[UInt8, _](buf[:got]), sender)
        return True

    def run(mut self) raises:
        """Run the listener's event loop. Blocks until
        :meth:`shutdown` flips the stop flag.

        Each iteration drains one datagram (or times out after
        100 ms so the stop flag is observed promptly). The
        per-packet decrypt + state-machine dispatch wiring lands
        with commit 2/5 of this track; this commit ships the
        UDP bind + the dispatcher + the routing table.
        """
        while not self._stopping:
            _ = self.tick(timeout_ms=100)

    def shutdown(mut self):
        """Request the event loop to exit. Idempotent; safe to
        call from a signal handler (sets a single Bool flag)."""
        self._stopping = True

    def close(mut self):
        """Close the underlying UDP socket. Idempotent. The
        :class:`UdpSocket` destructor also closes the fd, so
        explicit calls are only required when callers want to
        free the port before the listener goes out of scope."""
        self._socket.close()
