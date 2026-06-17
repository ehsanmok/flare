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
# functions. Allowlisted in tools/check_reactor_size.sh until then.

from std.collections import Dict, List
from std.memory import Span

from ..net.address import IpAddr, SocketAddr
from ..udp import UdpSocket
from .crypto import QuicAead
from .frame import (
    CryptoFrame,
    MaxDataFrame,
    MaxStreamsFrame,
    StreamFrame,
    encode_ack,
    encode_crypto,
    encode_handshake_done,
    encode_max_data,
    encode_max_streams,
)
from .packet import (
    ConnectionId,
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
from .state import (
    Connection,
    ConnectionEvents,
    empty_events,
)
from ..h3.server import H3Connection
from ..http.request import Request
from ..http.response import Response
from .timers import (
    TIMER_KIND_IDLE,
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
    _do_is_handshake_complete,
    _do_packet_decrypt,
    _do_packet_encrypt,
    _do_session_free,
    _do_take_crypto,
)
from .packet import encode_short_header
from ._server_support import (
    _ACK_MAX_RANGES,
    _CryptoReasm,
    _CryptoStream,
    _SessionSlot,
    _ack_from_ranges,
    _ack_record,
    _bufsize_from_env,
    _encode_h3_stream_frame,
    _inbound_level_for_datagram,
    _monotonic_ms,
    _ready_sentinel,
    _stream_id_from_key,
)
from ._server_types import (
    ConnectionIdTable,
    QuicConnection,
    QuicServerConfig,
    _encode_server_transport_params,
    cid_to_hex,
)


# Flow-control grant windows kept ahead of consumption so the peer
# never blocks mid-run (RFC 9000 sec 19.9 / 19.11). 64 MiB of
# connection credit and 4096 extra bidi streams comfortably cover a
# 30 s h2load run at the documented HTTP/3 rate.
comptime _MAX_DATA_WINDOW: UInt64 = 64 * 1024 * 1024
comptime _MAX_STREAMS_BIDI_WINDOW: UInt64 = 4096

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
    var tls_sessions: List[_SessionSlot]
    """Parallel slab to :attr:`connections`: one rustls QUIC
    session carrier per :class:`QuicConnection` slot. Each
    :class:`_SessionSlot` holds the raw rustls
    ``Box<Session>*`` (or 0 for the NULL-PEM sentinel) plus the
    current outbound encryption level. The slab owns the
    handles; :meth:`__del__` walks every non-zero handle through
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
    var h3_connections: List[H3Connection]
    """Per-slot HTTP/3 connection driver. Parallel slab to
    :attr:`connections` -- one :class:`flare.h3.H3Connection`
    instance per QUIC connection. Allocated in
    :meth:`_accept_initial` so every accepted connection has its
    H3 driver ready; STREAM frames from the post-handshake 1-RTT
    payload route through :meth:`_route_h3_stream_chunks` into
    the matching slot.

    The slab carries the H3 driver unconditionally rather than
    waiting for the ``h3`` ALPN to be negotiated. The QUIC
    layer cannot inspect ALPN without finishing the rustls
    handshake and we want the slab indices to stay in lockstep
    with :attr:`connections`. The H3 driver itself drops
    non-H3 traffic (the STREAM frames simply never reach
    :meth:`H3Connection.feed_stream_chunk` until 1-RTT keys
    install, at which point the peer already negotiated H3 via
    ALPN by definition)."""
    var h3_response_egress: Dict[String, List[UInt8]]
    """Per-(slot, stream_id) outbound H3 response bytes,
    awaiting QUIC STREAM frame egress. Key is
    ``str(slot) + ":" + str(stream_id)``; value is the byte
    buffer emitted by
    :meth:`flare.h3.H3Connection.take_response_frames` after a
    handler-produced :class:`Response` is encoded. Drained by
    the 1-RTT egress path once the per-connection 1-RTT keys
    are installed."""
    var timer_wheel: TimerWheel
    """Per-listener :class:`flare.runtime.timer_wheel.TimerWheel`
    driving idle timeouts. Each scheduled timer's token is
    :func:`flare.quic.timers.encode_timer_token(kind, slot)`;
    :meth:`advance_timers` dispatches each fired token to the
    matching :class:`QuicConnection` callback."""
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
        var tls_acceptor: RustlsQuicAcceptor,
    ):
        """Wrap an already-bound :class:`UdpSocket`. Internal --
        callers use :meth:`bind`."""
        self.config = config.copy()
        self.cid_table = ConnectionIdTable()
        self.connections = List[QuicConnection]()
        self.tls_acceptor = tls_acceptor^
        self.tls_sessions = List[_SessionSlot]()
        self.tls_egress_queues = List[List[UInt8]]()
        self.tls_handshake_egress_queues = List[List[UInt8]]()
        self.crypto_reasm = List[_CryptoReasm]()
        self.tls_1rtt_egress_queues = List[List[UInt8]]()
        self.peer_addrs = List[SocketAddr]()
        self.rx_1rtt_ranges = List[List[UInt64]]()
        self.rx_1rtt_ack_pending = List[Bool]()
        self.handshake_done_sent = List[Bool]()
        self.rx_stream_bytes = List[UInt64]()
        self.rx_bidi_stream_count = List[UInt64]()
        self.h3_connections = List[H3Connection]()
        self.h3_response_egress = Dict[String, List[UInt8]]()
        self.timer_wheel = TimerWheel(now_ms=UInt64(0))
        self._socket = sock^
        self._local_addr = addr
        self._stopping = False

    def __del__(deinit self):
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
        var ip = IpAddr.parse(config.host)
        var addr = SocketAddr(ip, config.port)
        var sock = UdpSocket.bind(addr)
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
        var acceptor = RustlsQuicAcceptor(config.rustls_config.copy())
        return QuicListener(config, sock^, actual, acceptor^)

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
        if slot >= 0 and slot < len(self.connections):
            self._handle_inbound(slot, datagram)
        return slot

    def _handle_inbound(mut self, slot: Int, datagram: Span[UInt8, _]) raises:
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
        """
        var now_us = UInt64(0)
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
                    else:
                        # 0-RTT / Retry: stop the coalescing scan.
                        break
                except:
                    break
                if packet_len <= 0 or offset + packet_len > n:
                    break
            else:
                packet_len = n - offset
            self._process_one_packet(
                slot, datagram[offset : offset + packet_len], lvl, now_us
            )
            processed_any = True
            offset += packet_len
        if processed_any:
            _ = self.schedule_idle_timeout(slot)

    def _process_one_packet(
        mut self,
        slot: Int,
        packet: Span[UInt8, _],
        inbound_lvl: Int,
        now_us: UInt64,
    ) raises:
        """Decrypt + dispatch a single (already de-coalesced) QUIC
        packet at ``inbound_lvl``. Initial decrypts in the sans-I/O
        connection; Handshake + 1-RTT decrypt through the slot's
        rustls session. Failures drop silently per RFC 9001 sec 5.2.
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
            try:
                events = self.connections[slot].handle_packet(packet, now_us)
            except:
                ok = False
        elif inbound_lvl == QuicEncryptionLevel.HANDSHAKE:
            if len(self.connections[slot].rx_handshake_secret) == 0:
                ok = False  # keys not installed yet; drop
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot, packet, inbound_lvl, local_cid_len
                    )
                    events = self.connections[slot].dispatch_plaintext(
                        Span[UInt8, _](dec[0]), now_us, dec[1]
                    )
                except:
                    ok = False
        elif inbound_lvl == QuicEncryptionLevel.APPLICATION:
            if len(self.connections[slot].rx_1rtt_secret) == 0:
                ok = False
            else:
                try:
                    var dec = self._decrypt_post_initial(
                        slot, packet, inbound_lvl, local_cid_len
                    )
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
        else:
            ok = False  # 0-RTT / Retry not handled here
        if not ok:
            return
        self._dispatch_crypto_frames(slot, events, inbound_lvl)
        self._route_h3_stream_chunks(slot, events)

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
        if level == QuicEncryptionLevel.HANDSHAKE:
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
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_decrypt(
            self.tls_acceptor._lib,
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
        var packet_number = decode_packet_number(
            truncated_pn,
            pn_length,
            self.connections[slot].conn.largest_received_packet,
        )
        # AAD is the unprotected header: first byte + bytes up to
        # the pn field + the pn_length real pn bytes.
        var header = List[UInt8]()
        header.append(first_local)
        for i in range(1, pn_offset):
            header.append(datagram[i])
        for i in range(pn_length):
            header.append(pn_local[i])
        var ciphertext_start = pn_offset + pn_length
        if ciphertext_start > packet_end:
            raise Error("_decrypt_post_initial: pn length exceeds packet end")
        var payload = List[UInt8]()
        for i in range(ciphertext_start, packet_end):
            payload.append(datagram[i])
        # decrypt_in_place verifies + strips the 16-byte AEAD tag,
        # writing plaintext over the ciphertext prefix of ``payload``.
        # The FFI also reports the plaintext length, but the QUIC
        # AEAD suites (AES-GCM / ChaCha20-Poly1305) always use a
        # 16-byte tag (RFC 9001 sec 5.3), so the plaintext is exactly
        # the leading ``len(payload) - 16`` bytes; we slice that
        # directly rather than depend on the out-parameter readback.
        _ = _do_packet_decrypt(
            self.tls_acceptor._lib,
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
        var plaintext = List[UInt8]()
        for i in range(plaintext_len):
            plaintext.append(payload[i])
        return (plaintext^, packet_number)

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
            for i in range(len(events.crypto_frames)):
                reasm.levels[inbound_lvl].insert(
                    events.crypto_frames[i].offset,
                    events.crypto_frames[i].data,
                )
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

    # -- H3 dispatch surface ----------------------------------------------

    def _route_h3_stream_chunks(
        mut self, slot: Int, events: ConnectionEvents
    ) raises:
        """Route every STREAM frame surfaced on ``events`` to the
        slot's :class:`flare.h3.H3Connection`.

        RFC 9114 §6 puts H3 traffic on QUIC bidirectional + uni
        streams; the stream id parity bits classify which kind a
        frame belongs to (RFC 9000 §2.1: even = client-initiated
        bidi / uni based on the low two bits). The H3 driver
        accepts both flavors through different entry points;
        this method picks the right one and also signals FIN
        when the QUIC layer observed end-of-stream.

        No-op if the slot is out of range or no STREAM frames
        were surfaced this tick. Empty payload chunks with FIN
        still drive :meth:`flare.h3.H3Connection.signal_end_of_stream`
        so the H3 driver can advance request state.
        """
        if slot < 0 or slot >= len(self.h3_connections):
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
        for i in range(len(events.stream_chunks)):
            var sid = Int(events.stream_chunks[i].stream_id)
            var is_uni = (sid & 0x2) != 0
            var plen = len(events.stream_chunks[i].data)
            if slot < len(self.rx_stream_bytes):
                self.rx_stream_bytes[slot] += UInt64(plen)
            if not is_uni and slot < len(self.rx_bidi_stream_count):
                var count = UInt64((sid >> 2) + 1)
                if count > self.rx_bidi_stream_count[slot]:
                    self.rx_bidi_stream_count[slot] = count
        # Pass 2: feed H3 in place. Mutating the slot through a ref
        # avoids deep-copying the whole H3Connection (its per-stream
        # state Dict) on every inbound datagram -- the dominant
        # per-request CPU cost under stream concurrency.
        ref h3 = self.h3_connections[slot]
        for i in range(len(events.stream_chunks)):
            var sid = Int(events.stream_chunks[i].stream_id)
            var is_uni = (sid & 0x2) != 0
            var is_fin = events.stream_chunks[i].fin
            var payload = events.stream_chunks[i].data.copy()
            if len(payload) > 0:
                if is_uni:
                    h3.feed_uni_stream_chunk(sid, payload^)
                else:
                    h3.feed_stream_chunk(sid, payload^)
            if is_fin and not is_uni:
                h3.signal_end_of_stream(sid)

    def take_h3_completed_streams(self, slot: Int) raises -> List[Int]:
        """Return the stream ids ready for handler dispatch on
        ``slot``. Delegates to
        :meth:`flare.h3.H3Connection.take_completed_streams`.
        Empty list if the slot is out of range or has no H3
        driver attached."""
        if slot < 0 or slot >= len(self.h3_connections):
            return List[Int]()
        return self.h3_connections[slot].take_completed_streams()

    def take_h3_request(mut self, slot: Int, stream_id: Int) raises -> Request:
        """Materialize the :class:`flare.http.Request` for
        ``(slot, stream_id)``. The dispatch caller invokes a
        Handler with this Request, then feeds the Response back
        through :meth:`emit_h3_response`.

        Raises if the slot is out of range or the H3 driver
        does not track the stream (see
        :meth:`flare.h3.H3Connection.take_request` for the
        underlying gating)."""
        if slot < 0 or slot >= len(self.h3_connections):
            raise Error(
                "take_h3_request: slot " + String(slot) + " out of range"
            )
        ref h3 = self.h3_connections[slot]
        return h3.take_request(stream_id)

    def emit_h3_response(
        mut self, slot: Int, stream_id: Int, var response: Response
    ) raises:
        """Encode ``response`` into the slot's H3 outbox + drain
        the resulting frame bytes into
        :attr:`h3_response_egress` keyed by ``slot:stream_id``.

        The byte buffer feeds the 1-RTT STREAM-frame egress pass
        in :meth:`_drain_1rtt_coalesced`, which emits on the
        wire once the slot's 1-RTT keys are installed.
        """
        if slot < 0 or slot >= len(self.h3_connections):
            raise Error(
                "emit_h3_response: slot " + String(slot) + " out of range"
            )
        ref h3 = self.h3_connections[slot]
        h3.emit_response(stream_id, response^)
        var frames = h3.take_response_frames(stream_id)
        var key = String(slot) + ":" + String(stream_id)
        if key in self.h3_response_egress:
            var existing = self.h3_response_egress[key].copy()
            for i in range(len(frames)):
                existing.append(frames[i])
            self.h3_response_egress[key] = existing^
        else:
            self.h3_response_egress[key] = frames^

    def take_h3_response_egress(
        mut self, slot: Int, stream_id: Int
    ) raises -> List[UInt8]:
        """Drain the per-stream response buffer accumulated by
        :meth:`emit_h3_response`. Returns an empty list when no
        bytes are queued. Caller (the QUIC STREAM egress path)
        wraps the bytes in STREAM frames + protects them with
        :func:`protect_1rtt_packet` -- the wiring lands once
        1-RTT keys flow through the rustls bridge."""
        var key = String(slot) + ":" + String(stream_id)
        if key not in self.h3_response_egress:
            return List[UInt8]()
        var out = self.h3_response_egress.pop(key)
        return out^

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
            return self._accept_initial(lh, peer)
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

    def _accept_initial(
        mut self, lh: LongHeader, peer: SocketAddr
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
        var local_cid = lh.dcid.copy()
        var peer_cid = lh.scid.copy()
        var qc = QuicConnection(
            local_cid,
            peer_cid,
            self.config.max_idle_timeout_ms * UInt64(1_000),
            self.config.initial_max_data,
        )
        var slot = len(self.connections)
        self.connections.append(qc^)
        self.tls_sessions.append(self._new_session_slot(local_cid))
        self.tls_egress_queues.append(List[UInt8]())
        self.tls_handshake_egress_queues.append(List[UInt8]())
        self.crypto_reasm.append(_CryptoReasm())
        self.tls_1rtt_egress_queues.append(List[UInt8]())
        self.peer_addrs.append(peer)
        self.rx_1rtt_ranges.append(List[UInt64]())
        self.rx_1rtt_ack_pending.append(False)
        self.handshake_done_sent.append(False)
        self.rx_stream_bytes.append(UInt64(0))
        self.rx_bidi_stream_count.append(UInt64(0))
        self.h3_connections.append(H3Connection())
        self.cid_table.register(cid_to_hex(local_cid), slot)
        _ = self.schedule_idle_timeout(slot)
        return slot

    def _new_session_slot(mut self, local_cid: ConnectionId) -> _SessionSlot:
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
            tp_blob = _encode_server_transport_params(self.config, local_cid)
        except:
            return _SessionSlot(handle=0)
        var handle = _do_accept(
            self.tls_acceptor._lib, self.tls_acceptor._opaque_handle, tp_blob
        )
        return _SessionSlot(handle=handle)

    def tick(mut self, timeout_ms: Int = 100) raises -> Bool:
        """Drain a burst of inbound datagrams and pump egress.

        Reactor I/O loop step:

        1. One blocking ``recv_from`` (``SO_RCVTIMEO``) wakes the
           tick when a datagram arrives or times out cleanly.
        2. Then ``try_recv_from`` (``MSG_DONTWAIT``) drains the
           rest of the socket queue, up to :data:`_RX_BATCH`
           datagrams, so the per-tick H3 pump / timer / egress
           bookkeeping in the serve loop is amortized over the
           whole burst instead of paid per datagram.
        3. Each datagram routes through :meth:`dispatch_datagram`
           by DCID; the matched slot's :meth:`_drain_and_send`
           flushes its ACK / response.

        Returns ``True`` if at least one datagram was dispatched,
        ``False`` if the initial ``recv_from`` timed out.
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
            # loop treats both as "no datagram this tick" but
            # still drains pending egress so an already-handshaking
            # session can flush its ServerHello fragments.
            var msg = String(e)
            if msg.startswith("Timeout") or msg.startswith("recvfrom"):
                _ = self.drain_all_egress()
                return False
            raise e^
        if got <= 0:
            _ = self.drain_all_egress()
            return False
        var slot = self.dispatch_datagram(Span[UInt8, _](buf[:got]), sender)
        if slot >= 0:
            _ = self._drain_and_send(slot)
        # Drain the rest of the socket queue without blocking so a
        # high-rate sender's burst is handled in one tick.
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
            if nslot >= 0:
                _ = self._drain_and_send(nslot)
        return True

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
        * ``h3_response_egress`` -- 1-RTT STREAM frames carrying
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
        var emitted = False
        var peer = self.peer_addrs[slot]
        # Initial-level (legacy OpenSSL path).
        if (
            slot < len(self.tls_egress_queues)
            and len(self.tls_egress_queues[slot]) > 0
        ):
            var initial_dg = self._build_initial_response(slot)
            if len(initial_dg) > 0:
                _ = self.send_to(Span[UInt8, _](initial_dg), peer)
                self.tls_egress_queues[slot] = List[UInt8]()
                emitted = True
        # Handshake-level (rustls path; gated on the readiness
        # sentinel via _build_handshake_response).
        if (
            slot < len(self.tls_handshake_egress_queues)
            and len(self.tls_handshake_egress_queues[slot]) > 0
        ):
            var hs_dg = self._build_handshake_response(slot)
            if len(hs_dg) > 0:
                _ = self.send_to(Span[UInt8, _](hs_dg), peer)
                self.tls_handshake_egress_queues[slot] = List[UInt8]()
                emitted = True
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
        if self._drain_1rtt_coalesced(slot, peer):
            emitted = True
        return emitted

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
        # datagram stays within max_udp_payload_size.
        var budget = Int(self.config.max_udp_payload_size) - 64
        if budget < 64:
            budget = 64
        var plaintext = List[UInt8](capacity=budget + 64)
        var emitted = False

        # ACK (+ HANDSHAKE_DONE once + flow-control credit) leads
        # the first datagram. These frames are small and always fit.
        if (
            self.rx_1rtt_ack_pending[slot]
            and len(self.rx_1rtt_ranges[slot]) >= 2
        ):
            var ack = _ack_from_ranges(self.rx_1rtt_ranges[slot], UInt64(0))
            encode_ack(ack, plaintext)
            if not self.handshake_done_sent[slot]:
                encode_handshake_done(plaintext)
            var max_data = MaxDataFrame(
                maximum_data=self.rx_stream_bytes[slot] + _MAX_DATA_WINDOW
            )
            encode_max_data(max_data, plaintext)
            var max_streams = MaxStreamsFrame(
                unidirectional=False,
                maximum_streams=self.rx_bidi_stream_count[slot]
                + _MAX_STREAMS_BIDI_WINDOW,
            )
            encode_max_streams(max_streams, plaintext)
            self.rx_1rtt_ack_pending[slot] = False
            self.handshake_done_sent[slot] = True

        # Collect this slot's ready responses.
        var slot_prefix = String(slot) + ":"
        var keys_to_drain = List[String]()
        for entry in self.h3_response_egress.items():
            if entry.key.startswith(slot_prefix):
                keys_to_drain.append(entry.key)

        for i in range(len(keys_to_drain)):
            var k = keys_to_drain[i]
            var bytes = self.h3_response_egress.pop(k)
            if len(bytes) == 0:
                continue
            var sid = _stream_id_from_key(k)
            if sid < 0:
                continue
            # STREAM frame overhead is <= ~16 bytes (type + 3
            # varints). Flush the in-progress datagram first if this
            # response would push it past the MTU budget.
            var frame_cost = len(bytes) + 16
            if len(plaintext) > 0 and len(plaintext) + frame_cost > budget:
                var dg = self._build_1rtt_response(slot, plaintext^)
                if len(dg) > 0:
                    _ = self.send_to(Span[UInt8, _](dg), peer)
                    emitted = True
                plaintext = List[UInt8](capacity=budget + 64)
            _encode_h3_stream_frame(
                plaintext, UInt64(sid), Span[UInt8, _](bytes), fin=True
            )
            # The response is complete (fin=True), so reclaim the
            # per-stream carriers now. Without this, completed
            # streams pile up in both the H3 driver's stream Dict
            # and the QUIC connection's stream Dict, and the
            # per-tick `take_completed_streams` scan degrades to
            # O(streams-ever-opened) -- quadratic over a long run.
            self.h3_connections[slot].close_request_stream(sid)
            if UInt64(sid) in self.connections[slot].conn.streams:
                _ = self.connections[slot].conn.streams.pop(UInt64(sid))

        if len(plaintext) > 0:
            var dg = self._build_1rtt_response(slot, plaintext^)
            if len(dg) > 0:
                _ = self.send_to(Span[UInt8, _](dg), peer)
                emitted = True
        return emitted

    def _build_initial_response(
        mut self, slot: Int, pn_length: Int = 2
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
        var qbytes = self.tls_egress_queues[slot].copy()
        var conn = self.connections[slot].copy()
        var crypto = CryptoFrame(
            offset=conn.tx_initial_offset, data=qbytes.copy()
        )
        var payload = List[UInt8]()
        encode_crypto(crypto, payload)
        # Build the long-header prefix: server DCID = peer's
        # client-chosen SCID; server SCID = local_cid (same the
        # peer sent in its first Initial's DCID). RFC 9000
        # §17.2.2: the Initial Source Connection ID is the
        # server's chosen CID -- here we echo local_cid so the
        # client's CID->slot routing stays stable.
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
            dcid=conn.local_cid,
            is_server=True,
        )
        # Advance the connection's outbound Initial-level
        # counters so the next drain emits a fresh pn + offset.
        conn.tx_initial_pn = pn + UInt64(1)
        conn.tx_initial_offset = conn.tx_initial_offset + UInt64(len(qbytes))
        self.connections[slot] = conn^
        return datagram^

    # -- Handshake + 1-RTT egress via rustls --------------------------------

    def _build_handshake_response(
        mut self, slot: Int, pn_length: Int = 2
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
        if len(self.tls_handshake_egress_queues[slot]) == 0:
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
        # 1. Encode the CRYPTO frame body that wraps the
        # rustls take_crypto output at Handshake level.
        var qbytes = self.tls_handshake_egress_queues[slot].copy()
        var crypto = CryptoFrame(
            offset=conn.tx_handshake_offset, data=qbytes.copy()
        )
        var payload = List[UInt8]()
        encode_crypto(crypto, payload)
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
            self.tls_acceptor._lib,
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
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._lib,
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
        self.connections[slot] = conn^
        return protected^

    def _build_1rtt_response(
        mut self,
        slot: Int,
        var plaintext: List[UInt8],
        pn_length: Int = 2,
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
        # Read only the fields this builder needs and bump the pn
        # counter in place at the end -- deep-copying the whole
        # QuicConnection (its streams Dict) per outbound packet is
        # the dominant egress-side CPU cost under concurrency.
        if len(self.connections[slot].tx_1rtt_secret) == 0:
            return List[UInt8]()
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
        var peer_cid = self.connections[slot].peer_cid.copy()
        # 1. Build the unprotected short-header prefix.
        # spin_bit + key_phase stay 0 (no key-update yet).
        var prefix = encode_short_header(
            peer_cid,
            spin_bit=False,
            key_phase=False,
            pn_length=pn_length,
        )
        # 2. Build unprotected header = prefix + pn bytes.
        var pn = self.connections[slot].tx_1rtt_pn
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
            self.tls_acceptor._lib,
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
        for i in range(len(encrypted_payload)):
            protected.append(encrypted_payload[i])
        for i in range(len(tag)):
            protected.append(tag[i])
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
        var first_addr = Int(UnsafePointer(to=first_local))
        _do_header_encrypt(
            self.tls_acceptor._lib,
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
        return self._build_1rtt_response(slot, plaintext^, pn_length)

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

    def shutdown(mut self):
        """Request the event loop to exit. Idempotent; safe to
        call from a signal handler (sets a single Bool flag)."""
        self._stopping = True

    # -- Timer scheduling -----------------------------------------------

    def schedule_idle_timeout(mut self, slot: Int) raises -> UInt64:
        """Arm the idle timer for ``slot`` at
        ``config.max_idle_timeout_ms`` from the current wheel
        tick. Cancels the slot's previous idle timer if any so
        every ``handle_packet`` only ever has one idle timer in
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
        var token = encode_timer_token(TIMER_KIND_IDLE, slot)
        var after_ms = Int(self.config.max_idle_timeout_ms)
        var id = self.timer_wheel.schedule(after_ms=after_ms, token=token)
        self.connections[slot].idle_timer_id = id
        return id

    def advance_timers(mut self, now_ms: UInt64) raises -> Int:
        """Advance the wheel to ``now_ms`` and dispatch every
        fired idle-timeout token to the matching
        :class:`QuicConnection` callback (per
        :mod:`flare.quic.timers`). Returns the number of tokens
        dispatched.

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
            if decoded.kind == TIMER_KIND_IDLE:
                self.connections[slot].on_idle_expired()
            if not self.connections[slot].alive:
                self._retire_slot_cids(slot)
        return len(fired)

    def _retire_slot_cids(mut self, slot: Int) raises:
        """Drop every CID -> slot mapping that points at this
        slot. Called when the slot's connection has closed so
        late retransmits don't route to a dead slot."""
        if slot < 0 or slot >= len(self.connections):
            return
        var cid_hex = cid_to_hex(self.connections[slot].local_cid)
        self.cid_table.retire(cid_hex)

    def close(mut self):
        """Close the underlying UDP socket. Idempotent. The
        :class:`UdpSocket` destructor also closes the fd, so
        explicit calls are only required when callers want to
        free the port before the listener goes out of scope."""
        self._socket.close()
