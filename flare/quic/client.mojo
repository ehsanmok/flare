"""``flare.quic.client`` -- QUIC v1 client connection driver.

The client-role mirror of :class:`flare.quic.server.QuicListener`'s
per-connection path, collapsed to a single connection over one
connected UDP flow. It reuses every codec the server reuses --
packet headers (:mod:`flare.quic.packet`), frames
(:mod:`flare.quic.frame`), the sans-I/O state machine
(:class:`flare.quic.state.Connection`), Initial-level AEAD
(:func:`flare.quic.protection.protect_initial_packet` /
``unprotect_initial_packet``), and the rustls QUIC session for
Handshake / 1-RTT protection -- and only adds the client-role
bits: a client-chosen Initial DCID, the ClientHello first flight,
client-direction Initial secrets (``is_server=False``), and the
client packet-number spaces.

## Handshake flow (RFC 9001 §4 + RFC 9000 §7)

1. :meth:`QuicClientConnection.start` picks a random Initial DCID
   (the value both ends derive Initial secrets from, RFC 9001
   §5.2) and a client Source CID, builds a
   :class:`flare.tls.rustls_quic.RustlsQuicSession` via the
   connector, drains the ClientHello, and emits the first Initial
   packet padded to >= 1200 bytes (RFC 9000 §14.1).
2. :meth:`poll` drains the inbound socket queue: the server's
   Initial (ServerHello) decrypts off the Initial secret; its
   Handshake flight (EncryptedExtensions / Certificate /
   CertificateVerify / Finished) decrypts through the rustls
   session. Inbound CRYPTO feeds rustls; outbound CRYPTO (the
   client Finished) drains back out and ships in a Handshake
   packet. ACKs are emitted per packet-number space.
3. Once rustls reports the handshake complete and installs 1-RTT
   keys, the connection is ESTABLISHED and the H3 layer (H3C-2)
   drives request / response STREAM frames through
   :meth:`send_stream` / :meth:`poll`.

## Scope / ceilings (ponytail)

This driver targets the common single-path, low-loss case the
HTTP/3 client needs:

- Minimal PTO-driven retransmission for the 1-RTT (request) path
  via :mod:`flare.quic._loss_recovery`: ack-eliciting 1-RTT packets
  are tracked, retired as ACKs arrive, and retransmitted on a probe
  timeout. ponytail: this is NOT full RFC 9002 -- it omits ACK-based
  loss detection, an RTT estimator + congestion control, and
  handshake-level (Initial / Handshake CRYPTO) + server-side
  response retransmit. Those are the tracked v0.9 loss-recovery
  follow-up. During the handshake a dropped Finished is still
  recovered by the peer re-driving our flight.
- ponytail: one STREAM frame per :meth:`send_stream` call, capped
  at the path MTU. A request body larger than one packet is
  rejected rather than fragmented across packets. Upgrade path:
  the same coalescing drain the server uses.
- ponytail: the server's advertised transport parameters are not
  decoded (rustls seals the peer extension); the client assumes
  the generous flare-server defaults for its own send limits.

References:
- RFC 9000 §7 "Cryptographic and Transport Handshake".
- RFC 9001 §4-§5 "Packet Protection" + "Initial secrets".
- RFC 9000 §14.1 "Initial datagram size" (>= 1200 bytes).
"""

from std.collections import Dict, List, Optional
from std.memory import Span, UnsafePointer

from ..net.address import IpAddr, SocketAddr
from ..udp import UdpSocket
from .crypto import QuicAead
from .frame import (
    AckFrame,
    ConnectionCloseFrame,
    CryptoFrame,
    PathChallengeFrame,
    PathResponseFrame,
    RetireConnectionIdFrame,
    StreamFrame,
    encode_ack,
    encode_connection_close,
    encode_crypto,
    encode_path_challenge,
    encode_path_response,
    encode_ping,
    encode_retire_connection_id,
    encode_stream,
)
from .packet import (
    ConnectionId,
    LongHeader,
    PACKET_TYPE_HANDSHAKE,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_ZERO_RTT,
    QUIC_VERSION_1,
    encode_long_header,
    encode_short_header,
    parse_initial_extras,
    parse_long_header,
    parse_short_header,
)
from .protection import (
    decode_packet_number,
    protect_initial_packet,
    unprotect_initial_packet,
)
from .state import (
    CONN_STATE_ESTABLISHED,
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
from .varint import decode_varint, encode_varint
from ._loss_recovery import LossRecovery
from ._server_support import (
    _CryptoReasm,
    _ack_from_ranges,
    _ack_record,
    _inbound_level_for_datagram,
    _monotonic_ms,
)
from ..tls.rustls_quic import (
    QuicEncryptionLevel,
    RustlsQuicConnector,
    RustlsQuicSession,
)


# Plaintext padding floor for the ClientHello-carrying Initial so
# the protected datagram clears the RFC 9000 §14.1 1200-byte
# minimum. 1162 plaintext bytes plus the long header (~26 bytes)
# and the 16-byte AEAD tag exceed 1200 comfortably for any 8-byte
# CID pair; PADDING frames are the all-zero 0x00 byte (RFC 9000
# §19.1) so we just append zeros.
comptime _INITIAL_PAD_FLOOR: Int = 1162

# Cap on datagrams drained per :meth:`poll`. One blocking recv
# followed by this many non-blocking drains lets a single poll
# consume the server's whole flight (separate Initial + Handshake
# datagrams) before the caller acts on the surfaced events.
comptime _POLL_BATCH: Int = 16

comptime _AEAD_TAG_LEN: Int = 16


def _random_cid(n: Int) -> ConnectionId:
    """Return a fresh random Connection ID of ``n`` bytes.

    Reads ``/dev/urandom`` for unpredictability (a guessable CID
    would let an off-path attacker spoof packets, RFC 9000 §5.1).
    Falls back to a clock-mixed deterministic fill only when
    urandom is unavailable, which should not happen on Linux /
    macOS.
    """
    var bytes = List[UInt8](capacity=n)
    try:
        with open("/dev/urandom", "r") as f:
            var raw = f.read_bytes(n)
            for i in range(n):
                bytes.append(raw[i])
    except:
        var seed = _monotonic_ms()
        for i in range(n):
            bytes.append(
                UInt8(
                    Int((seed >> UInt64(i * 8)) & UInt64(0xFF))
                    ^ (i * 31 + 0x5A)
                )
            )
    return ConnectionId(bytes=bytes^)


def _encode_client_transport_params(
    scid: ConnectionId,
    max_idle_timeout_ms: UInt64,
    initial_max_data: UInt64,
) raises -> List[UInt8]:
    """Encode the client's QUIC transport parameters (RFC 9000
    §18) for the ClientHello ``quic_transport_parameters``
    extension.

    The client advertises its own Source CID (mandatory per
    RFC 9000 §7.3 -- a handshake whose params omit the source CID
    is rejected), the connection-level + per-stream flow-control
    windows, and a generous stream count so the response side
    never blocks. ``original_destination_connection_id`` and the
    ``retry_source_connection_id`` are server-only and omitted.
    """
    var tp = empty_transport_parameters()
    tp.initial_source_connection_id = scid.bytes.copy()
    tp.max_idle_timeout = Optional(max_idle_timeout_ms)
    tp.initial_max_data = Optional(initial_max_data)
    tp.initial_max_stream_data_bidi_local = Optional(initial_max_data)
    tp.initial_max_stream_data_bidi_remote = Optional(initial_max_data)
    tp.initial_max_stream_data_uni = Optional(initial_max_data)
    tp.initial_max_streams_bidi = Optional(UInt64(16))
    tp.initial_max_streams_uni = Optional(UInt64(16))
    tp.active_connection_id_limit = Optional(UInt64(2))
    return encode_transport_parameters(tp)


struct _EarlySend(Copyable, Movable):
    """One application STREAM send made at 0-RTT (EarlyData).

    Buffered so the flight can be replayed at 1-RTT if the server
    rejects early data (RFC 9001 sec 4.6 -- a client that sent 0-RTT
    data the server did not accept retransmits it once the handshake
    completes). Records the exact ``(stream_id, data, fin)`` so the
    replay reproduces byte-identical STREAM frames on the same stream.
    """

    var stream_id: UInt64
    var data: List[UInt8]
    var fin: Bool

    def __init__(out self, stream_id: UInt64, var data: List[UInt8], fin: Bool):
        self.stream_id = stream_id
        self.data = data^
        self.fin = fin


struct QuicClientConnection(Movable):
    """A single client-role QUIC connection over a connected UDP flow.

    Owns the UDP socket, the rustls client session, and the
    sans-I/O :class:`flare.quic.state.Connection`. Construct via
    :meth:`start` (non-blocking: sends the first Initial) or
    :meth:`connect` (blocks until the handshake completes). After
    the handshake the H3 layer drives streams via
    :meth:`open_bidi_stream`, :meth:`send_stream`, and :meth:`poll`.
    """

    var conn: Connection
    """Sans-I/O connection state: per-stream + flow-control
    bookkeeping, reused unchanged from the server path."""

    var session: RustlsQuicSession
    """rustls client session: drives the TLS 1.3 handshake inside
    CRYPTO frames and holds the Handshake / 1-RTT AEAD keys."""

    var sock: UdpSocket
    var peer: SocketAddr

    var initial_dcid: ConnectionId
    """Client-chosen Destination CID placed on the first Initial.
    Both ends derive Initial secrets from this value (RFC 9001
    §5.2); it is the AEAD ``dcid`` for every Initial packet
    regardless of any later CID change."""

    var dcid: ConnectionId
    """Outbound Destination CID for routing. Starts equal to
    :attr:`initial_dcid`; switches to the server's Source CID once
    the first server long-header packet is parsed (RFC 9000 §7.2)."""

    var scid: ConnectionId
    """Client Source CID -- our own identity. Its length is the
    pinned DCID length for parsing inbound short-header 1-RTT
    packets (RFC 9000 §17.3)."""

    var aead_choice: Int
    var max_udp_payload_size: Int

    var tx_initial_pn: UInt64
    var tx_initial_offset: UInt64
    var tx_handshake_pn: UInt64
    var tx_handshake_offset: UInt64
    var tx_1rtt_pn: UInt64

    var tx_initial_crypto: List[UInt8]
    """Outbound Initial-level CRYPTO awaiting egress (the
    ClientHello before it is first sent; empty afterwards)."""
    var tx_handshake_crypto: List[UInt8]
    """Outbound Handshake-level CRYPTO (the client Finished)."""
    var tx_1rtt_crypto: List[UInt8]
    """Outbound 1-RTT-level CRYPTO (rare client post-handshake
    messages)."""

    var rx_initial_ranges: List[UInt64]
    var rx_handshake_ranges: List[UInt64]
    var rx_1rtt_ranges: List[UInt64]
    var rx_initial_ack_pending: Bool
    var rx_handshake_ack_pending: Bool
    var rx_1rtt_ack_pending: Bool
    var rx_initial_largest: UInt64
    var rx_handshake_largest: UInt64
    var rx_1rtt_largest: UInt64

    var reasm: _CryptoReasm
    var have_hs_keys: Bool
    var have_1rtt_keys: Bool
    var got_server_cid: Bool
    var established: Bool

    var next_bidi_stream: UInt64
    """Next client-initiated bidirectional stream id to hand out
    (RFC 9000 §2.1: client bidi ids are 0, 4, 8, ...)."""
    var next_uni_stream: UInt64
    """Next client-initiated unidirectional stream id to hand out
    (RFC 9000 §2.1: client uni ids are 2, 6, 10, ...). H3 opens
    three of these per connection: control + QPACK encoder/decoder.
    """
    var send_offsets: Dict[UInt64, UInt64]
    """Per-stream cumulative send offset for outbound STREAM
    frames."""
    var _loss: LossRecovery
    """Minimal PTO loss recovery (RFC 9002 §6.2) for ack-eliciting
    1-RTT packets: retransmits unacked request frames on a probe
    timeout. See :mod:`flare.quic._loss_recovery`."""
    var enable_0rtt: Bool
    """Opt-in TLS session resumption / 0-RTT (RFC 9001 §4.6). Off by
    default so the standard path is byte-for-byte unchanged. When the
    same :class:`RustlsQuicConnector` is reused for a later connection
    to a server that issued a 0-RTT-capable ticket, rustls resumes the
    session and (in-process only -- rustls 0.23 has no cross-process
    ticket export) exposes early keys."""
    var _early_keys_ready: Bool
    """Whether rustls installed 0-RTT (EarlyData) keys for this
    connection -- True only on a resumed connection whose ticket
    allowed early data. See :meth:`early_data_ready`."""
    var _early_flight: List[_EarlySend]
    """Application STREAM sends emitted at 0-RTT (via
    :meth:`send_stream_early`), retained so :meth:`finish_early_data`
    can replay them at 1-RTT if the server rejects early data. Empty on
    a non-0-RTT connection."""

    def __init__(
        out self,
        var conn: Connection,
        var session: RustlsQuicSession,
        var sock: UdpSocket,
        peer: SocketAddr,
        var initial_dcid: ConnectionId,
        var scid: ConnectionId,
        aead_choice: Int,
        max_udp_payload_size: Int,
    ):
        self.conn = conn^
        self.session = session^
        self.sock = sock^
        self.peer = peer
        self.dcid = initial_dcid.copy()
        self.initial_dcid = initial_dcid^
        self.scid = scid^
        self.aead_choice = aead_choice
        self.max_udp_payload_size = max_udp_payload_size
        self.tx_initial_pn = UInt64(0)
        self.tx_initial_offset = UInt64(0)
        self.tx_handshake_pn = UInt64(0)
        self.tx_handshake_offset = UInt64(0)
        self.tx_1rtt_pn = UInt64(0)
        self.tx_initial_crypto = List[UInt8]()
        self.tx_handshake_crypto = List[UInt8]()
        self.tx_1rtt_crypto = List[UInt8]()
        self.rx_initial_ranges = List[UInt64]()
        self.rx_handshake_ranges = List[UInt64]()
        self.rx_1rtt_ranges = List[UInt64]()
        self.rx_initial_ack_pending = False
        self.rx_handshake_ack_pending = False
        self.rx_1rtt_ack_pending = False
        self.rx_initial_largest = UInt64(0)
        self.rx_handshake_largest = UInt64(0)
        self.rx_1rtt_largest = UInt64(0)
        self.reasm = _CryptoReasm()
        self.have_hs_keys = False
        self.have_1rtt_keys = False
        self.got_server_cid = False
        self.established = False
        self.next_bidi_stream = UInt64(0)
        self.next_uni_stream = UInt64(2)
        self.send_offsets = Dict[UInt64, UInt64]()
        self._loss = LossRecovery()
        self.enable_0rtt = False
        self._early_keys_ready = False
        self._early_flight = List[_EarlySend]()

    @staticmethod
    def start(
        peer: SocketAddr,
        connector: RustlsQuicConnector,
        server_name: String,
        max_idle_timeout_ms: UInt64 = UInt64(30_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
        max_udp_payload_size: Int = 1452,
        aead_choice: Int = QuicAead.AES_128_GCM,
        enable_0rtt: Bool = False,
    ) raises -> QuicClientConnection:
        """Open a client connection and emit the first Initial
        (ClientHello) packet without blocking on the response.

        Picks the Initial DCID + client SCID, builds the rustls
        client session with the encoded client transport
        parameters, drains the ClientHello, and ships the padded
        Initial datagram. Drive the handshake to completion with
        :meth:`poll` (or use :meth:`connect` for the blocking
        convenience).
        """
        var initial_dcid = _random_cid(8)
        var scid = _random_cid(8)
        var tp = _encode_client_transport_params(
            scid, max_idle_timeout_ms, initial_max_data
        )
        var session = connector.connect(server_name, tp)
        # Bind an ephemeral local UDP port; the peer address is
        # carried explicitly on every send_to so a plain bound
        # socket (no connect(2)) is enough.
        var local = SocketAddr(IpAddr.parse("0.0.0.0"), UInt16(0))
        var sock = UdpSocket.bind(local)
        var conn = new_connection(
            max_idle_timeout_ms * UInt64(1_000), initial_max_data
        )
        var self = QuicClientConnection(
            conn^,
            session^,
            sock^,
            peer,
            initial_dcid^,
            scid^,
            aead_choice,
            max_udp_payload_size,
        )
        self.enable_0rtt = enable_0rtt
        self._send_first_initial()
        if enable_0rtt:
            # On a resumed connection (same connector reused, server
            # issued a 0-RTT-capable ticket) rustls exposes the
            # EarlyData keys once the ClientHello is written (the
            # first_initial drain above); capture them so a later send
            # can ride 0-RTT when the server driver pumps early-data
            # packets (tracked follow-up). A fresh connection returns
            # no early keys -- a harmless no-op.
            self._early_keys_ready = self.session.install_early_keys()
        return self^

    @staticmethod
    def connect(
        peer: SocketAddr,
        connector: RustlsQuicConnector,
        server_name: String,
        handshake_timeout_ms: Int = 5_000,
        max_idle_timeout_ms: UInt64 = UInt64(30_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
        max_udp_payload_size: Int = 1452,
        aead_choice: Int = QuicAead.AES_128_GCM,
        enable_0rtt: Bool = False,
    ) raises -> QuicClientConnection:
        """Open a client connection and block until the QUIC + TLS
        handshake completes (or ``handshake_timeout_ms`` elapses).

        Raises on timeout. On return the connection is
        ESTABLISHED and ready for :meth:`send_stream`.

        ``enable_0rtt`` opts into session resumption (RFC 9001 §4.6):
        reuse the same :class:`RustlsQuicConnector` across connections
        so a later one resumes the cached session. Off by default.
        """
        var self = QuicClientConnection.start(
            peer,
            connector,
            server_name,
            max_idle_timeout_ms,
            initial_max_data,
            max_udp_payload_size,
            aead_choice,
            enable_0rtt,
        )
        var deadline = _monotonic_ms() + UInt64(handshake_timeout_ms)
        while not self.established:
            if _monotonic_ms() > deadline:
                raise Error(
                    "quic client: handshake timed out after "
                    + String(handshake_timeout_ms)
                    + " ms"
                )
            _ = self.poll(timeout_ms=100)
        return self^

    # ── First flight ────────────────────────────────────────────────

    def _send_first_initial(mut self) raises:
        """Drain the ClientHello from rustls and emit the padded
        first Initial datagram (RFC 9000 §14.1)."""
        var ch = self.session.take_crypto(QuicEncryptionLevel.INITIAL)
        if len(ch) == 0:
            raise Error(
                "quic client: rustls produced no ClientHello on connect"
            )
        var dg = self._build_initial(ch, pad=True, with_ack=False)
        _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
        self.tx_initial_offset += UInt64(len(ch))

    # ── Poll loop ───────────────────────────────────────────────────

    def poll(mut self, timeout_ms: Int = 100) raises -> ConnectionEvents:
        """Receive a burst of inbound datagrams, advance the
        handshake / stream state, flush pending ACKs + CRYPTO, and
        return the per-call :class:`ConnectionEvents`.

        Blocks up to ``timeout_ms`` for the first datagram, then
        drains the rest of the socket queue non-blocking (up to
        :data:`_POLL_BATCH`) so one poll consumes a whole server
        flight. Returns empty events on a clean timeout.
        """
        var events = empty_events()
        var buf = List[UInt8]()
        buf.resize(self.max_udp_payload_size, 0)
        self.sock.set_recv_timeout(timeout_ms)
        var got: Int
        try:
            var pair = self.sock.recv_from(Span[UInt8, _](buf))
            got = pair[0]
        except e:
            var msg = String(e)
            if msg.startswith("Timeout") or msg.startswith("recvfrom"):
                self._drain_egress()
                self._check_pto()
                return events^
            raise e^
        if got > 0:
            self._process_datagram(Span[UInt8, _](buf[:got]), events)
        for _ in range(_POLL_BATCH - 1):
            var nb_got: Int
            try:
                var nb = self.sock.try_recv_from(Span[UInt8, _](buf))
                nb_got = nb[0]
            except:
                break
            if nb_got <= 0:
                break
            self._process_datagram(Span[UInt8, _](buf[:nb_got]), events)
        self._flush_migration(events)
        if len(events.acked_packets) > 0:
            _ = self._loss.on_ack(events.acked_packets)
        self._drain_egress()
        self._check_pto()
        if self.session.is_handshake_complete() and self.have_1rtt_keys:
            self.established = True
        return events^

    def _check_pto(mut self) raises:
        """Fire the PTO if the probe timer has elapsed with
        ack-eliciting 1-RTT data still in flight: retransmit the
        oldest unacked frames in a fresh packet (RFC 9002 §6.2).
        A no-op until 1-RTT keys are installed or when nothing is
        outstanding."""
        if not self.have_1rtt_keys:
            return
        if self._loss.outstanding() == 0:
            return
        var deadline = self._loss.pto_deadline()
        if deadline == UInt64(0) or _monotonic_ms() < deadline:
            return
        var frames = self._loss.fire_pto()
        if len(frames) == 0:
            return
        var dg = self._build_1rtt(frames^, ack_eliciting=True)
        if len(dg) > 0:
            _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)

    def _flush_migration(mut self, events: ConnectionEvents) raises:
        """Send the migration frames surfaced this poll: a
        PATH_RESPONSE for every inbound PATH_CHALLENGE (RFC 9000
        sec 8.2 -- proves our reachability when the peer probes a
        path) and a RETIRE_CONNECTION_ID for every peer CID a
        NEW_CONNECTION_ID's ``retire_prior_to`` obsoleted (sec
        5.1.2). Each frame rides its own padded 1-RTT packet."""
        if not self.have_1rtt_keys:
            return
        for i in range(len(events.path_responses)):
            var payload = List[UInt8]()
            encode_path_response(
                PathResponseFrame(data=events.path_responses[i].copy()), payload
            )
            self._send_padded_1rtt(payload^)
        for i in range(len(events.retire_connection_ids)):
            var payload = List[UInt8]()
            encode_retire_connection_id(
                RetireConnectionIdFrame(
                    sequence_number=events.retire_connection_ids[i]
                ),
                payload,
            )
            self._send_padded_1rtt(payload^)

    def _send_padded_1rtt(mut self, var payload: List[UInt8]) raises:
        """Pad a small frame buffer to the header-protection sample
        floor (RFC 9001 sec 5.4.2 needs 4 bytes past the pn offset +
        a 16-byte sample), wrap it in a 1-RTT packet, and send it to
        the current peer."""
        while len(payload) < 16:
            payload.append(UInt8(0))
        var dg = self._build_1rtt(payload^)
        if len(dg) > 0:
            _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)

    def _process_datagram(
        mut self, datagram: Span[UInt8, _], mut events: ConnectionEvents
    ) raises:
        """De-coalesce a datagram into its constituent packets
        (RFC 9000 §12.2) and dispatch each by encryption level.

        A long-header packet's self-describing length bounds the
        scan; a short-header (1-RTT) packet is always last and
        runs to the datagram end. Decrypt / parse failures drop
        the offending packet silently (RFC 9001 §5.2)."""
        var n = len(datagram)
        var offset = 0
        while offset < n:
            var first = Int(datagram[offset])
            if first == 0:
                break  # trailing PADDING
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
                        break  # 0-RTT / Retry: stop the scan
                except:
                    break
                if packet_len <= 0 or offset + packet_len > n:
                    break
            else:
                packet_len = n - offset
            self._process_one_packet(
                datagram[offset : offset + packet_len], lvl, events
            )
            offset += packet_len

    def _process_one_packet(
        mut self,
        packet: Span[UInt8, _],
        lvl: Int,
        mut events: ConnectionEvents,
    ) raises:
        """Decrypt + frame-dispatch one de-coalesced packet at
        ``lvl``. Initial decrypts off the client-direction Initial
        secret; Handshake + 1-RTT decrypt through rustls. Records
        the received packet number into the matching ACK range and
        feeds inbound CRYPTO to rustls."""
        if lvl == QuicEncryptionLevel.INITIAL:
            try:
                if not self.got_server_cid:
                    var lh = parse_long_header(packet)
                    self.dcid = lh.scid.copy()
                    self.got_server_cid = True
                var up = unprotect_initial_packet(
                    packet,
                    self.initial_dcid,
                    is_server=False,
                    largest_received_pn=self.rx_initial_largest,
                    aead_choice=self.aead_choice,
                )
                self._dispatch_frames(Span[UInt8, _](up.payload), events)
                if up.packet_number > self.rx_initial_largest:
                    self.rx_initial_largest = up.packet_number
                _ack_record(self.rx_initial_ranges, up.packet_number)
                self.rx_initial_ack_pending = True
            except:
                return
        elif lvl == QuicEncryptionLevel.HANDSHAKE:
            if not self.have_hs_keys:
                return
            try:
                var dec = self._decrypt_post_initial(packet, lvl)
                self._dispatch_frames(Span[UInt8, _](dec[0]), events)
                if dec[1] > self.rx_handshake_largest:
                    self.rx_handshake_largest = dec[1]
                _ack_record(self.rx_handshake_ranges, dec[1])
                self.rx_handshake_ack_pending = True
            except:
                return
        elif lvl == QuicEncryptionLevel.APPLICATION:
            if not self.have_1rtt_keys:
                return
            try:
                self.conn.ack_pending = False
                var dec = self._decrypt_post_initial(packet, lvl)
                self._dispatch_frames(Span[UInt8, _](dec[0]), events)
                if dec[1] > self.rx_1rtt_largest:
                    self.rx_1rtt_largest = dec[1]
                _ack_record(self.rx_1rtt_ranges, dec[1])
                if self.conn.ack_pending:
                    self.rx_1rtt_ack_pending = True
            except:
                return
        else:
            return
        self._pump_crypto(lvl, events)

    def _dispatch_frames(
        mut self, plaintext: Span[UInt8, _], mut events: ConnectionEvents
    ) raises:
        """Walk the decrypted packet payload frame by frame
        through the sans-I/O state machine (RFC 9000 §12.4)."""
        var cursor = 0
        while cursor < len(plaintext):
            var consumed = handle_frame_buf(
                self.conn, plaintext[cursor:], UInt64(0), events
            )
            if consumed <= 0:
                break
            cursor += consumed

    def _decrypt_post_initial(
        mut self, datagram: Span[UInt8, _], level: Int
    ) raises -> Tuple[List[UInt8], UInt64]:
        """Strip header protection + AEAD-decrypt a Handshake or
        1-RTT packet through the rustls session (mirror of the
        server's ``_decrypt_post_initial`` with client-side CID
        lengths and per-space largest-pn). Returns ``(plaintext,
        packet_number)``; raises on any bounds / FFI / AEAD
        failure so the caller drops the packet."""
        var pn_offset: Int
        var packet_end: Int
        var largest: UInt64
        if level == QuicEncryptionLevel.HANDSHAKE:
            var lh = parse_long_header(datagram)
            var len_var = decode_varint(datagram[lh.payload_offset :])
            pn_offset = lh.payload_offset + len_var.consumed
            packet_end = pn_offset + Int(len_var.value)
            if packet_end > len(datagram):
                raise Error("quic client: handshake length exceeds datagram")
            largest = self.rx_handshake_largest
        else:
            pn_offset = parse_short_header(
                datagram, self.scid.length()
            ).payload_offset
            packet_end = len(datagram)
            largest = self.rx_1rtt_largest
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(datagram):
            raise Error("quic client: HP sample window exceeds packet")
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(datagram[sample_offset + i])
        var first_local: UInt8 = datagram[0]
        var pn_local = List[UInt8]()
        for i in range(4):
            pn_local.append(datagram[pn_offset + i])
        var first_addr = Int(UnsafePointer(to=first_local))
        self.session.header_decrypt(
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
            truncated_pn, pn_length, largest
        )
        var header = List[UInt8]()
        header.append(first_local)
        for i in range(1, pn_offset):
            header.append(datagram[i])
        for i in range(pn_length):
            header.append(pn_local[i])
        var ciphertext_start = pn_offset + pn_length
        if ciphertext_start > packet_end:
            raise Error("quic client: pn length exceeds packet end")
        var payload = List[UInt8]()
        for i in range(ciphertext_start, packet_end):
            payload.append(datagram[i])
        _ = self.session.packet_decrypt(level, packet_number, header, payload)
        var plaintext_len = len(payload) - _AEAD_TAG_LEN
        if plaintext_len < 0:
            raise Error("quic client: payload shorter than AEAD tag")
        var plaintext = List[UInt8]()
        for i in range(plaintext_len):
            plaintext.append(payload[i])
        return (plaintext^, packet_number)

    def _pump_crypto(
        mut self, inbound_lvl: Int, mut events: ConnectionEvents
    ) raises:
        """Feed inbound CRYPTO (reassembled in order) to rustls,
        drain outbound CRYPTO at every level into the egress
        queues, and flip the per-level key-readiness flags once
        rustls installs Handshake / 1-RTT keys."""
        if 0 <= inbound_lvl < 4 and len(events.crypto_frames) > 0:
            for i in range(len(events.crypto_frames)):
                self.reasm.levels[inbound_lvl].insert(
                    events.crypto_frames[i].offset,
                    events.crypto_frames[i].data,
                )
            var ordered = self.reasm.levels[inbound_lvl].drain_contiguous()
            if len(ordered) > 0:
                self.session.feed_crypto(inbound_lvl, ordered)
        # New crypto frames consumed this pump must not leak into
        # the next packet's events; the caller reads stream_chunks
        # only, so clear the crypto list after feeding.
        events.crypto_frames = List[CryptoFrame]()
        try:
            var oi = self.session.take_crypto(QuicEncryptionLevel.INITIAL)
            for k in range(len(oi)):
                self.tx_initial_crypto.append(oi[k])
        except:
            pass
        try:
            var oh = self.session.take_crypto(QuicEncryptionLevel.HANDSHAKE)
            for k in range(len(oh)):
                self.tx_handshake_crypto.append(oh[k])
        except:
            pass
        try:
            var oa = self.session.take_crypto(QuicEncryptionLevel.APPLICATION)
            for k in range(len(oa)):
                self.tx_1rtt_crypto.append(oa[k])
        except:
            pass
        if self.session.have_keys(QuicEncryptionLevel.HANDSHAKE):
            self.have_hs_keys = True
        if self.session.have_keys(QuicEncryptionLevel.APPLICATION):
            self.have_1rtt_keys = True

    # ── Egress ──────────────────────────────────────────────────────

    def _drain_egress(mut self) raises:
        """Flush every pending egress flight: Initial ACK +
        leftover CRYPTO, the Handshake Finished + ACK, and the
        1-RTT ACK + post-handshake CRYPTO. Each level is its own
        datagram; the server de-coalesces and ACKs independently
        per packet-number space."""
        if self.rx_initial_ack_pending or len(self.tx_initial_crypto) > 0:
            var crypto = self.tx_initial_crypto^
            self.tx_initial_crypto = List[UInt8]()
            var dg = self._build_initial(crypto, pad=False, with_ack=True)
            if len(dg) > 0:
                _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
                self.tx_initial_offset += UInt64(len(crypto))
                self.rx_initial_ack_pending = False
        if self.have_hs_keys and (
            len(self.tx_handshake_crypto) > 0 or self.rx_handshake_ack_pending
        ):
            var crypto = self.tx_handshake_crypto^
            self.tx_handshake_crypto = List[UInt8]()
            var dg = self._build_handshake(crypto, with_ack=True)
            if len(dg) > 0:
                _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
                self.tx_handshake_offset += UInt64(len(crypto))
                self.rx_handshake_ack_pending = False
        if self.have_1rtt_keys and (
            self.rx_1rtt_ack_pending or len(self.tx_1rtt_crypto) > 0
        ):
            var payload = List[UInt8]()
            if len(self.rx_1rtt_ranges) >= 2:
                var ack = _ack_from_ranges(self.rx_1rtt_ranges, UInt64(0))
                encode_ack(ack, payload)
            var carries_crypto = len(self.tx_1rtt_crypto) > 0
            if carries_crypto:
                var cf = CryptoFrame(
                    offset=UInt64(0), data=self.tx_1rtt_crypto^
                )
                self.tx_1rtt_crypto = List[UInt8]()
                encode_crypto(cf, payload)
            if len(payload) > 0:
                # Ack-eliciting only when the packet carries CRYPTO;
                # an ACK-only packet must not be tracked for PTO.
                var dg = self._build_1rtt(
                    payload^, ack_eliciting=carries_crypto
                )
                if len(dg) > 0:
                    _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
            self.rx_1rtt_ack_pending = False

    def _build_initial(
        mut self,
        crypto_bytes: List[UInt8],
        pad: Bool,
        with_ack: Bool,
        pn_length: Int = 2,
    ) raises -> List[UInt8]:
        """Build a protected client Initial datagram carrying
        ``crypto_bytes`` (offset = :attr:`tx_initial_offset`),
        optionally an Initial-space ACK, and PADDING to the
        §14.1 floor when ``pad``. Advances :attr:`tx_initial_pn`."""
        var payload = List[UInt8]()
        if len(crypto_bytes) > 0:
            var cf = CryptoFrame(
                offset=self.tx_initial_offset, data=crypto_bytes.copy()
            )
            encode_crypto(cf, payload)
        if with_ack and len(self.rx_initial_ranges) >= 2:
            var ack = _ack_from_ranges(self.rx_initial_ranges, UInt64(0))
            encode_ack(ack, payload)
        if len(payload) == 0:
            return List[UInt8]()
        if pad:
            while len(payload) < _INITIAL_PAD_FLOOR:
                payload.append(UInt8(0))
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_INITIAL,
            QUIC_VERSION_1,
            self.dcid,
            self.scid,
            type_specific_bits=first_bits,
        )
        var token_len_var = encode_varint(UInt64(0))
        for i in range(len(token_len_var)):
            prefix.append(token_len_var[i])
        var payload_total = UInt64(len(payload) + pn_length + _AEAD_TAG_LEN)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        var pn = self.tx_initial_pn
        var dg = protect_initial_packet(
            Span[UInt8, _](prefix),
            packet_number=pn,
            pn_length=pn_length,
            plaintext=Span[UInt8, _](payload),
            dcid=self.initial_dcid,
            is_server=False,
            aead_choice=self.aead_choice,
        )
        self.tx_initial_pn = pn + UInt64(1)
        return dg^

    def _build_handshake(
        mut self,
        crypto_bytes: List[UInt8],
        with_ack: Bool,
        pn_length: Int = 2,
    ) raises -> List[UInt8]:
        """Build a protected client Handshake datagram carrying the
        Finished CRYPTO (offset = :attr:`tx_handshake_offset`) plus
        an optional Handshake-space ACK. AEAD + header protection
        route through rustls at level 2. Advances
        :attr:`tx_handshake_pn`."""
        var payload = List[UInt8]()
        if len(crypto_bytes) > 0:
            var cf = CryptoFrame(
                offset=self.tx_handshake_offset, data=crypto_bytes.copy()
            )
            encode_crypto(cf, payload)
        if with_ack and len(self.rx_handshake_ranges) >= 2:
            var ack = _ack_from_ranges(self.rx_handshake_ranges, UInt64(0))
            encode_ack(ack, payload)
        if len(payload) == 0:
            return List[UInt8]()
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_HANDSHAKE,
            QUIC_VERSION_1,
            self.dcid,
            self.scid,
            type_specific_bits=first_bits,
        )
        var payload_total = UInt64(len(payload) + pn_length + _AEAD_TAG_LEN)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        var pn = self.tx_handshake_pn
        var dg = self._protect_via_rustls(
            QuicEncryptionLevel.HANDSHAKE, prefix^, payload^, pn, pn_length
        )
        self.tx_handshake_pn = pn + UInt64(1)
        return dg^

    def _build_0rtt(
        mut self,
        var plaintext: List[UInt8],
        pn_length: Int = 2,
    ) raises -> List[UInt8]:
        """Build a protected 0-RTT (EarlyData) long-header datagram
        around an already-encoded ``plaintext`` frame buffer.

        Shape mirrors :meth:`_build_handshake` (long header with an
        explicit Length varint, RFC 9000 sec 17.2.3) but the packet
        type is ZERO_RTT and AEAD + header protection route through
        rustls at :data:`QuicEncryptionLevel.EARLY_DATA`. A 0-RTT
        packet carries no token (only Initial does) and no ACK (the
        client cannot acknowledge anything before the handshake).

        The packet number is drawn from the **shared application
        packet-number space** (:attr:`tx_1rtt_pn`), because 0-RTT and
        1-RTT are one number space (RFC 9000 sec 12.3); 1-RTT egress
        after the handshake therefore continues the sequence with no
        special handling. The DCID is the client-chosen
        :attr:`initial_dcid` (still in :attr:`dcid` at first-flight
        time), which the server routes on and binds the 0-RTT keys to.
        """
        if len(plaintext) == 0:
            return List[UInt8]()
        var first_bits = (pn_length - 1) & 0x3
        var prefix = encode_long_header(
            PACKET_TYPE_ZERO_RTT,
            QUIC_VERSION_1,
            self.dcid,
            self.scid,
            type_specific_bits=first_bits,
        )
        var payload_total = UInt64(len(plaintext) + pn_length + _AEAD_TAG_LEN)
        var len_var = encode_varint(payload_total)
        for i in range(len(len_var)):
            prefix.append(len_var[i])
        var pn = self.tx_1rtt_pn
        var dg = self._protect_via_rustls(
            QuicEncryptionLevel.EARLY_DATA, prefix^, plaintext^, pn, pn_length
        )
        self.tx_1rtt_pn = pn + UInt64(1)
        return dg^

    def _build_1rtt(
        mut self,
        var plaintext: List[UInt8],
        pn_length: Int = 2,
        ack_eliciting: Bool = False,
    ) raises -> List[UInt8]:
        """Build a protected 1-RTT short-header datagram around an
        already-encoded ``plaintext`` frame buffer. AEAD + header
        protection route through rustls at level 3. Advances
        :attr:`tx_1rtt_pn`.

        When ``ack_eliciting`` is True the plaintext frames are
        registered with the loss-recovery tracker (under this
        packet's number) so a PTO can retransmit them if the peer's
        ACK never arrives. ACK-only / PADDING-only packets pass
        False so they are not tracked (RFC 9002 §2 -- they are not
        ack-eliciting)."""
        var frames_copy = List[UInt8]()
        if ack_eliciting:
            frames_copy = plaintext.copy()
        var prefix = encode_short_header(
            self.dcid,
            spin_bit=False,
            key_phase=False,
            pn_length=pn_length,
        )
        var pn = self.tx_1rtt_pn
        var dg = self._protect_via_rustls(
            QuicEncryptionLevel.APPLICATION,
            prefix^,
            plaintext^,
            pn,
            pn_length,
        )
        self.tx_1rtt_pn = pn + UInt64(1)
        if ack_eliciting:
            self._loss.on_sent(pn, frames_copy^, _monotonic_ms())
        return dg^

    def _protect_via_rustls(
        mut self,
        level: Int,
        var prefix: List[UInt8],
        var payload: List[UInt8],
        pn: UInt64,
        pn_length: Int,
    ) raises -> List[UInt8]:
        """Shared AEAD + header-protection tail for Handshake +
        1-RTT egress: append the packet number to ``prefix`` to
        form the unprotected header (AAD), encrypt ``payload`` in
        place via rustls, append the tag, then header-protect the
        first byte + packet-number bytes (RFC 9001 §5.3-§5.4)."""
        if pn_length < 1 or pn_length > 4:
            raise Error("quic client: pn_length out of [1, 4]")
        var header = prefix^
        for i in range(pn_length):
            var shift = (pn_length - 1 - i) * 8
            header.append(UInt8((Int(pn) >> shift) & 0xFF))
        var encrypted = payload^
        var tag = self.session.packet_encrypt(level, pn, header, encrypted)
        var header_len = len(header)
        var protected = header^
        protected.reserve(header_len + len(encrypted) + len(tag))
        for i in range(len(encrypted)):
            protected.append(encrypted[i])
        for i in range(len(tag)):
            protected.append(tag[i])
        var pn_offset = header_len - pn_length
        var sample_offset = pn_offset + 4
        if sample_offset + 16 > len(protected):
            raise Error("quic client: ciphertext too short for HP sample")
        var sample = List[UInt8]()
        for i in range(16):
            sample.append(protected[sample_offset + i])
        var first_local: UInt8 = protected[0]
        var pn_local = List[UInt8]()
        for i in range(pn_length):
            pn_local.append(protected[pn_offset + i])
        var first_addr = Int(UnsafePointer(to=first_local))
        self.session.header_encrypt(
            level,
            sample,
            first_addr,
            Int(pn_local.unsafe_ptr()),
            pn_length,
        )
        protected[0] = first_local
        for i in range(pn_length):
            protected[pn_offset + i] = pn_local[i]
        return protected^

    # ── Stream surface (H3C-2 consumes this) ────────────────────────

    def open_bidi_stream(mut self) -> UInt64:
        """Allocate the next client-initiated bidirectional stream
        id (RFC 9000 §2.1: 0, 4, 8, ...). The H3 request layer
        opens one bidi stream per request."""
        var sid = self.next_bidi_stream
        self.next_bidi_stream += UInt64(4)
        return sid

    def open_uni_stream(mut self) -> UInt64:
        """Allocate the next client-initiated unidirectional stream
        id (RFC 9000 §2.1: 2, 6, 10, ...). H3 opens three of these
        per connection (control + QPACK encoder/decoder)."""
        var sid = self.next_uni_stream
        self.next_uni_stream += UInt64(4)
        return sid

    def _stream_chunk_cap(self) -> Int:
        """Max STREAM payload bytes that fit in one 1-RTT packet,
        leaving room for the short header (1 + dcid + up to a 4-byte
        packet number), the STREAM frame header (type + three
        varints, <= 25 bytes), and the 16-byte AEAD tag."""
        return self.max_udp_payload_size - len(self.dcid.bytes) - 46

    def send_stream(
        mut self, stream_id: UInt64, data: List[UInt8], fin: Bool
    ) raises:
        """Send ``data`` (with optional FIN) on ``stream_id``,
        fragmenting across as many 1-RTT STREAM frames / packets as
        the path MTU requires and advancing the per-stream offset.
        An empty FIN-only send emits a single zero-length frame so a
        body-less request still closes its stream."""
        if not self.have_1rtt_keys:
            raise Error("quic client: send_stream before 1-RTT keys")
        var cap = self._stream_chunk_cap()
        if cap < 1:
            raise Error("quic client: MTU too small for a STREAM frame")
        var off = UInt64(0)
        if stream_id in self.send_offsets:
            off = self.send_offsets[stream_id]
        var total = len(data)
        var sent = 0
        while True:
            var take = total - sent
            if take > cap:
                take = cap
            var is_last = (sent + take) >= total
            var chunk = List[UInt8](capacity=take)
            for i in range(take):
                chunk.append(data[sent + i])
            var sf = StreamFrame(
                stream_id=stream_id,
                offset=off,
                data=chunk^,
                fin=(fin and is_last),
            )
            var payload = List[UInt8]()
            encode_stream(sf, payload, emit_length=True)
            var dg = self._build_1rtt(payload^, ack_eliciting=True)
            if len(dg) > 0:
                _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
            off += UInt64(take)
            sent += take
            if is_last:
                break
        self.send_offsets[stream_id] = off

    def send_stream_early(
        mut self, stream_id: UInt64, data: List[UInt8], fin: Bool
    ) raises:
        """Send ``data`` (with optional FIN) on ``stream_id`` at 0-RTT
        (EarlyData), before the handshake completes.

        The 0-RTT counterpart of :meth:`send_stream`: same
        MTU-bounded STREAM-frame fragmentation and per-stream offset
        bookkeeping (it shares :attr:`send_offsets`), but each frame
        rides a :meth:`_build_0rtt` packet protected with the resumed
        connection's EarlyData keys. Requires
        :attr:`_early_keys_ready` (a resumed connection that installed
        0-RTT keys -- see :meth:`early_data_ready`).

        The full send is recorded in :attr:`_early_flight` so
        :meth:`finish_early_data` can replay it at 1-RTT if the server
        rejects early data. ponytail: 0-RTT packets are not registered
        with the loss-recovery tracker, so a lost-but-accepted 0-RTT
        packet is not retransmitted (fine on the lossless loopback the
        client targets; the upgrade path is registering the shared-pn
        send so :meth:`_check_pto` re-sends it as 1-RTT).
        """
        if not self._early_keys_ready:
            raise Error("quic client: send_stream_early before early keys")
        var cap = self._stream_chunk_cap()
        if cap < 1:
            raise Error("quic client: MTU too small for a STREAM frame")
        self._early_flight.append(_EarlySend(stream_id, data.copy(), fin))
        var off = UInt64(0)
        if stream_id in self.send_offsets:
            off = self.send_offsets[stream_id]
        var total = len(data)
        var sent = 0
        while True:
            var take = total - sent
            if take > cap:
                take = cap
            var is_last = (sent + take) >= total
            var chunk = List[UInt8](capacity=take)
            for i in range(take):
                chunk.append(data[sent + i])
            var sf = StreamFrame(
                stream_id=stream_id,
                offset=off,
                data=chunk^,
                fin=(fin and is_last),
            )
            var payload = List[UInt8]()
            encode_stream(sf, payload, emit_length=True)
            var dg = self._build_0rtt(payload^)
            if len(dg) > 0:
                _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
            off += UInt64(take)
            sent += take
            if is_last:
                break
        self.send_offsets[stream_id] = off

    def finish_early_data(mut self) raises -> Bool:
        """Resolve the 0-RTT flight after the handshake completes.

        Call once the connection is ESTABLISHED. Returns ``True`` when
        the server accepted early data (the 0-RTT flight stands, nothing
        more to send) and ``False`` when it rejected it (RFC 9001 sec
        4.6) -- in which case the recorded flight
        (:attr:`_early_flight`) is replayed at 1-RTT so the request
        still completes, transparently to the caller.

        A rejected 0-RTT flight leaves no stream state on the server
        (rustls drops the early data), so the replay resends the
        identical STREAM frames on the **same** stream ids from offset
        0: each distinct early stream's offset is reset, then every
        recorded send is re-emitted in order via :meth:`send_stream`
        (1-RTT). The H3 response reader keys on the stream id, so it is
        oblivious to which flight delivered the request.
        """
        if not self.enable_0rtt or len(self._early_flight) == 0:
            return True
        if self.early_data_accepted():
            self._early_flight = List[_EarlySend]()
            return True
        # Rejected: reset each distinct early stream's send offset, then
        # replay the recorded flight at 1-RTT in order.
        var flight = self._early_flight^
        self._early_flight = List[_EarlySend]()
        for i in range(len(flight)):
            self.send_offsets[flight[i].stream_id] = UInt64(0)
        for i in range(len(flight)):
            self.send_stream(flight[i].stream_id, flight[i].data, flight[i].fin)
        return False

    def keepalive(mut self) raises:
        """Send a 1-RTT PING to keep a pooled-idle connection alive
        and elicit a server ACK (RFC 9000 §10.1.2). A no-op until
        1-RTT keys are installed."""
        if not self.have_1rtt_keys:
            return
        var payload = List[UInt8]()
        encode_ping(payload)
        # Pad with PADDING frames (0x00) so the protected packet has
        # enough ciphertext for the header-protection sample (RFC 9001
        # sec 5.4.2 needs 4 bytes past the packet-number offset + a
        # 16-byte sample).
        while len(payload) < 16:
            payload.append(UInt8(0))
        var dg = self._build_1rtt(payload^, ack_eliciting=True)
        if len(dg) > 0:
            _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)

    # ── Connection migration (RFC 9000 §9) ──────────────────────────

    def migrate(mut self, rebind: Bool = True) raises -> Bool:
        """Migrate the connection to a fresh network path.

        Switches the active Destination CID to a spare the server
        granted via NEW_CONNECTION_ID (RFC 9000 §9.5 requires an
        unused CID per path so the two paths cannot be linked),
        optionally rebinds the local UDP socket to a new ephemeral
        port (the address change that defines a migration), and
        probes the new path with a PATH_CHALLENGE (§8.2). The peer
        echoes a PATH_RESPONSE which :meth:`poll` matches to mark
        :attr:`path_validated`. The old CID is retired.

        Returns ``False`` if the connection is not established or the
        server has not granted a spare CID yet (no migration is
        possible without one). Use :meth:`migrate_and_validate` for
        the blocking convenience that polls until the new path is
        confirmed.
        """
        if not self.established:
            return False
        var active = self.conn.active_dcid_seq
        var best_seq = active
        var found = False
        for entry in self.conn.peer_cids.items():
            if entry.key != active and (not found or entry.key > best_seq):
                best_seq = entry.key
                found = True
        if not found:
            return False
        var spare_cid = self.conn.peer_cids[best_seq].cid.copy()
        self.dcid = ConnectionId(bytes=spare_cid^)
        self.conn.active_dcid_seq = best_seq
        if rebind:
            var local = SocketAddr(IpAddr.parse("0.0.0.0"), UInt16(0))
            var newsock = UdpSocket.bind(local)
            self.sock.close()
            self.sock = newsock^
        var probe = _random_cid(8)
        var challenge = probe.bytes.copy()
        self.conn.outgoing_path_challenge = challenge.copy()
        self.conn.path_validated = False
        var cpayload = List[UInt8]()
        encode_path_challenge(PathChallengeFrame(data=challenge^), cpayload)
        self._send_padded_1rtt(cpayload^)
        var rpayload = List[UInt8]()
        encode_retire_connection_id(
            RetireConnectionIdFrame(sequence_number=active), rpayload
        )
        self._send_padded_1rtt(rpayload^)
        return True

    def migrate_and_validate(
        mut self, rebind: Bool = True, timeout_ms: Int = 2_000
    ) raises -> Bool:
        """Migrate (see :meth:`migrate`) then block until the new
        path is validated by a PATH_RESPONSE or ``timeout_ms``
        elapses. Returns ``True`` on a validated path."""
        if not self.migrate(rebind):
            return False
        var deadline = _monotonic_ms() + UInt64(timeout_ms)
        while not self.conn.path_validated:
            if _monotonic_ms() > deadline:
                return False
            _ = self.poll(timeout_ms=100)
        return True

    # ── Accessors ───────────────────────────────────────────────────

    def is_established(self) -> Bool:
        """Whether the QUIC + TLS handshake has completed and 1-RTT
        keys are installed."""
        return self.established

    def early_data_ready(self) -> Bool:
        """Whether this connection resumed a session and rustls
        installed 0-RTT (EarlyData) keys (RFC 9001 §4.6). True only
        when :attr:`enable_0rtt` was set, the same connector was
        reused, and the server's prior ticket allowed early data.

        When True, :meth:`send_stream_early` emits application STREAM
        frames in 0-RTT (EarlyData) packets and
        :meth:`finish_early_data` resolves acceptance after the
        handshake (replaying at 1-RTT on rejection)."""
        return self._early_keys_ready

    def early_data_accepted(self) -> Bool:
        """Whether the server accepted early data for this resumed
        connection (RFC 8446 §4.2.10; meaningful after the handshake
        completes). False on a fresh connection or when 0-RTT was not
        enabled. A client that sent 0-RTT data must replay it at
        1-RTT when this is False."""
        if not self.enable_0rtt:
            return False
        return self.session.is_early_data_accepted()

    def path_validated(self) -> Bool:
        """Whether the most recent :meth:`migrate` probe has been
        confirmed by a matching PATH_RESPONSE (RFC 9000 §8.2)."""
        return self.conn.path_validated

    def active_dcid_seq(self) -> UInt64:
        """Sequence number of the peer Connection ID currently used
        as the active Destination CID (0 is the handshake CID)."""
        return self.conn.active_dcid_seq

    def peer_cid_count(self) -> Int:
        """Number of spare peer Connection IDs learned via
        NEW_CONNECTION_ID. A migration needs at least one."""
        return len(self.conn.peer_cids)

    def alpn(self) raises -> String:
        """Negotiated ALPN identifier (e.g. ``"h3"``). Meaningful
        only after the handshake completes."""
        return self.session.selected_alpn()

    def local_addr(self) -> SocketAddr:
        """The ephemeral local UDP address the client bound to."""
        return self.sock.local_addr()

    def shutdown(mut self) raises:
        """Gracefully close: send a 1-RTT application-level
        CONNECTION_CLOSE (RFC 9000 sec 10.2, error 0) so the peer
        tears the connection down immediately instead of waiting out
        its idle timeout, then close the socket. A no-op send until
        1-RTT keys are installed."""
        if self.have_1rtt_keys:
            var cc = ConnectionCloseFrame(
                application=True,
                error_code=UInt64(0),
                frame_type=UInt64(0),
                reason_phrase=List[UInt8](),
            )
            var payload = List[UInt8]()
            encode_connection_close(cc, payload)
            while len(payload) < 16:
                payload.append(UInt8(0))
            var dg = self._build_1rtt(payload^)
            if len(dg) > 0:
                _ = self.sock.send_to(Span[UInt8, _](dg), self.peer)
        self.sock.close()

    def close(mut self):
        """Close the underlying UDP socket. Idempotent."""
        self.sock.close()
