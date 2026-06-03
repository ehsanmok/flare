"""`flare.ws.auto_client` -- ALPN-driven WebSocket client dispatcher.

WebSocket has two carrying wires:

* HTTP/1.1 ``Upgrade: websocket`` (RFC 6455) -- the original
  bootstrap. Always available.
* HTTP/2 Extended CONNECT (RFC 8441) -- the modern variant. The
  server MUST advertise ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1``
  for the client to use it.

The choice between the two is naturally ALPN-driven: when the
TLS handshake on a ``wss://`` URL negotiates ALPN ``"h2"`` and
the h2 SETTINGS frame includes ``ENABLE_CONNECT_PROTOCOL = 1``,
the client runs WS-over-h2; otherwise it falls back to the
HTTP/1.1 path.

Builds on the WS-over-h2 primitive
(:class:`flare.ws.WsOverH2Stream` +
:func:`flare.ws.bootstrap_ws_over_h2`). The pure decision logic
lives in :func:`decide_wire`; the 13-case test corpus in
:mod:`tests.ws.test_ws_autoclient` pins every observable outcome.

:meth:`WsAutoClient.connect` drives the TLS handshake, inspects
the negotiated ALPN, and routes to :class:`flare.ws.WsClient`
(HTTP/1.1 Upgrade) or :class:`flare.ws.WsOverH2Stream` (HTTP/2
Extended CONNECT). The caller queries :attr:`chosen_wire` after
:meth:`connect` returns to learn which path was taken; the
path-specific carrier is exposed via :meth:`take_h1_client` /
:meth:`take_h2_carrier`.

References:

- RFC 6455 "The WebSocket Protocol" -- HTTP/1.1 path.
- RFC 8441 "Bootstrapping WebSockets with HTTP/2" -- h2 path.
- RFC 7301 "ALPN" -- the wire-selection mechanism.
"""

from std.collections import List, Optional
from std.memory import UnsafePointer

from ..http.url import Url
from ..http2.client import Http2ClientConnection
from ..tls import TlsConfig, TlsStream
from .client import (
    WsClient,
    WsHandshakeError,
    _compute_accept,
    _generate_ws_key,
    _ws_url_to_http,
)
from .client_h2 import WsOverH2Stream, bootstrap_ws_over_h2


# ── Wire choice codepoints ─────────────────────────────────────────────


struct WsWireChoice:
    """Stable codepoints for the wire :class:`WsAutoClient` picks
    after the runtime negotiation completes. The reactor / call-
    site dispatches on these to pick the carrier driver.
    """

    comptime UNDETERMINED: Int = 0
    """The dispatcher hasn't run :meth:`WsAutoClient.connect` yet.
    The initial carrier state."""

    comptime HTTP_1_1: Int = 1
    """RFC 6455 over an HTTP/1.1 Upgrade stream.  Used when:
    - the URL scheme is ``ws://`` (no TLS, no ALPN), OR
    - ``prefer_h2 = False``, OR
    - the TLS handshake negotiated ALPN ``http/1.1``, OR
    - the negotiated h2 connection didn't advertise
      ``ENABLE_CONNECT_PROTOCOL = 1`` (RFC 8441 §3)."""

    comptime HTTP_2: Int = 2
    """RFC 8441 Extended CONNECT over an HTTP/2 stream.  Used
    when the URL scheme is ``wss://``, ``prefer_h2 = True``,
    the TLS handshake negotiated ALPN ``h2``, and the negotiated
    h2 connection's SETTINGS frame includes
    ``ENABLE_CONNECT_PROTOCOL = 1``."""

    comptime FAILED: Int = 3
    """The dispatcher attempted to connect but the underlying
    TCP / TLS / h2 handshake failed before reaching the
    application protocol decision.  See
    :attr:`WsAutoClient.last_error` for the per-attempt reason."""


# ── Configuration carrier ──────────────────────────────────────────────


struct WsAutoClientConfig(Copyable, Defaultable, Movable):
    """Inputs to :class:`WsAutoClient`'s wire-selection.

    The carrier holds the URL + the protocol preferences; the
    dispatcher consults this carrier when running its decision
    sequence.  The carrier is value-typed + copyable so call
    sites can build a base config, clone it, and tweak per-call.
    """

    var url: String
    """The target URL.  ``ws://`` skips TLS + uses the HTTP/1.1
    wire unconditionally; ``wss://`` runs TLS + consults
    :attr:`prefer_h2` and the ALPN outcome."""

    var prefer_h2: Bool
    """When True (default), the client advertises both ``h2``
    and ``http/1.1`` in ALPN and runs WS-over-h2 if the server
    picks ``h2`` AND advertises
    ``ENABLE_CONNECT_PROTOCOL = 1``.  When False the client
    advertises only ``http/1.1`` and skips the h2 path entirely.
    """

    var subprotocols: List[String]
    """RFC 6455 §1.9 / RFC 8441 §5.1 Sec-WebSocket-Protocol
    candidates.  Empty list means "no subprotocol request",
    which is the protocol's default."""

    var extensions: List[String]
    """RFC 6455 §9.1 / RFC 8441 §5.1 Sec-WebSocket-Extensions
    candidates (e.g. ``"permessage-deflate; client_no_context_takeover"``).
    Empty list means "no extension request"."""

    var tls_config: TlsConfig
    """Caller-supplied TLS configuration. The dispatcher rewrites
    :attr:`TlsConfig.alpn` based on :attr:`prefer_h2` but
    otherwise honours the verify-mode, CA-bundle, and mTLS
    inputs as-is."""

    def __init__(out self):
        self.url = String("")
        self.prefer_h2 = True
        self.subprotocols = List[String]()
        self.extensions = List[String]()
        self.tls_config = TlsConfig()


# ── Decision function ──────────────────────────────────────────────────


def decide_wire(
    url_scheme: String,
    prefer_h2: Bool,
    negotiated_alpn: String,
    h2_advertises_connect_protocol: Bool,
) -> Int:
    """The pure WS-wire decision the dispatcher executes after the
    TLS handshake completes.

    Inputs:

    - ``url_scheme`` -- ``"ws"`` (cleartext) or ``"wss"`` (TLS).
    - ``prefer_h2`` -- whether the carrier advertised ALPN ``h2``
      alongside ``http/1.1``.
    - ``negotiated_alpn`` -- the protocol the TLS handshake
      picked; empty when no ALPN was negotiated (cleartext or
      old TLS).
    - ``h2_advertises_connect_protocol`` -- whether the h2 peer's
      SETTINGS frame advertised ``ENABLE_CONNECT_PROTOCOL = 1``
      per RFC 8441 §3.  Only meaningful when the negotiated ALPN
      is ``h2``.

    The function is pure + testable without any I/O.  The runtime
    dispatcher (:meth:`WsAutoClient.connect`) plumbs the real
    values from the TLS + h2 layers into this call.
    """
    if url_scheme == "ws":
        return WsWireChoice.HTTP_1_1
    if url_scheme != "wss":
        return WsWireChoice.FAILED
    if not prefer_h2:
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "h2":
        if h2_advertises_connect_protocol:
            return WsWireChoice.HTTP_2
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "http/1.1":
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "":
        return WsWireChoice.HTTP_1_1
    return WsWireChoice.FAILED


# ── Internal h2 carrier ────────────────────────────────────────────────


struct _WsAutoH2Carrier(Movable):
    """Owns the live h2 carriers an h2-path connect produces.

    Holds the TLS stream the h2 connection rides on, the
    :class:`Http2ClientConnection` driver, the
    :class:`WsOverH2Stream` adapter, the stream id allocated for
    the Extended CONNECT tunnel, and the ``Sec-WebSocket-Key``
    used in the bootstrap headers (kept around so tests + future
    debug surface can compare against the expected ``Accept``).
    """

    var tls: TlsStream
    var h2: Http2ClientConnection
    var stream: WsOverH2Stream
    var stream_id: Int
    var sec_websocket_key: String

    def __init__(
        out self,
        var tls: TlsStream,
        var h2: Http2ClientConnection,
        var stream: WsOverH2Stream,
        stream_id: Int,
        sec_websocket_key: String,
    ):
        self.tls = tls^
        self.h2 = h2^
        self.stream = stream^
        self.stream_id = stream_id
        self.sec_websocket_key = sec_websocket_key


# ── Client carrier ─────────────────────────────────────────────────────


struct WsAutoClient(Movable):
    """High-level WebSocket client that picks the carrying wire
    at runtime based on negotiated ALPN + h2 SETTINGS.

    The carrier exposes the *decision*; the underlying I/O lives
    in the existing :class:`flare.ws.WsClient` (h1 path) and
    :class:`flare.ws.WsOverH2Stream` (h2 path).  The dispatcher
    is the small piece on top that picks between them.

    Call :meth:`connect` to drive the TLS handshake + ALPN
    inspection + per-path bootstrap; query :attr:`chosen_wire`
    + :meth:`is_h2_path` afterwards to learn which carrier won.
    The path-specific handle is accessible via
    :meth:`take_h1_client` (HTTP/1.1) or :meth:`take_h2_carrier`
    (HTTP/2).
    """

    var config: WsAutoClientConfig
    """The inputs the dispatcher consults."""

    var chosen_wire: Int
    """Set by :meth:`connect` once the wire-selection completes.
    Starts at :data:`WsWireChoice.UNDETERMINED`."""

    var last_error: String
    """Per-connection-attempt failure reason.  Empty until
    :attr:`chosen_wire` transitions to :data:`WsWireChoice.FAILED`.
    """

    var _h1_client: Optional[WsClient]
    """The HTTP/1.1 WS carrier when the dispatcher picked the h1
    path. Populated by :meth:`connect`; consumed by
    :meth:`take_h1_client`."""

    var _h2_carrier: Optional[_WsAutoH2Carrier]
    """The HTTP/2 Extended CONNECT carrier when the dispatcher
    picked the h2 path. Populated by :meth:`connect`; consumed
    by :meth:`take_h2_carrier`."""

    def __init__(out self, var config: WsAutoClientConfig):
        self.config = config^
        self.chosen_wire = WsWireChoice.UNDETERMINED
        self.last_error = String("")
        self._h1_client = None
        self._h2_carrier = None

    def url_scheme(self) -> String:
        """Return ``"ws"`` or ``"wss"`` -- the parsed scheme from
        ``config.url``.  Empty string when the URL doesn't start
        with one of those two schemes (caller-supplied bug)."""
        var bytes = self.config.url.as_bytes()
        if len(bytes) >= 6:
            if (
                bytes[0] == UInt8(0x77)
                and bytes[1] == UInt8(0x73)
                and bytes[2] == UInt8(0x73)
                and bytes[3] == UInt8(0x3A)
                and bytes[4] == UInt8(0x2F)
                and bytes[5] == UInt8(0x2F)
            ):
                return String("wss")
        if len(bytes) >= 5:
            if (
                bytes[0] == UInt8(0x77)
                and bytes[1] == UInt8(0x73)
                and bytes[2] == UInt8(0x3A)
                and bytes[3] == UInt8(0x2F)
                and bytes[4] == UInt8(0x2F)
            ):
                return String("ws")
        return String("")

    # ── Public state accessors ─────────────────────────────────────────

    def is_h1_path(self) -> Bool:
        """``True`` after a successful connect picked HTTP/1.1.
        Pairs with :meth:`take_h1_client`."""
        return self.chosen_wire == WsWireChoice.HTTP_1_1

    def is_h2_path(self) -> Bool:
        """``True`` after a successful connect picked HTTP/2
        Extended CONNECT. Pairs with :meth:`take_h2_carrier`."""
        return self.chosen_wire == WsWireChoice.HTTP_2

    def take_h1_client(mut self) raises -> WsClient:
        """Consume + return the HTTP/1.1 :class:`WsClient` the
        dispatcher opened. Must only be called after a successful
        connect that left :attr:`chosen_wire` at HTTP_1_1; raises
        otherwise. Idempotently transitions the dispatcher into a
        consumed state -- subsequent calls raise."""
        if self.chosen_wire != WsWireChoice.HTTP_1_1:
            raise Error(
                "WsAutoClient.take_h1_client: dispatcher did not pick"
                " the HTTP/1.1 path (chosen_wire = "
                + String(self.chosen_wire)
                + ")"
            )
        if not self._h1_client:
            raise Error(
                "WsAutoClient.take_h1_client: HTTP/1.1 carrier already"
                " consumed (idempotent guard)"
            )
        var carrier = self._h1_client.take()
        self._h1_client = None
        return carrier^

    def take_h2_carrier(
        mut self,
    ) raises -> _WsAutoH2Carrier:
        """Consume + return the h2 path carrier (TLS stream + h2
        driver + WS-over-h2 adapter). Must only be called after a
        successful connect that left :attr:`chosen_wire` at
        HTTP_2; raises otherwise. Idempotently transitions the
        dispatcher into a consumed state."""
        if self.chosen_wire != WsWireChoice.HTTP_2:
            raise Error(
                "WsAutoClient.take_h2_carrier: dispatcher did not pick"
                " the HTTP/2 path (chosen_wire = "
                + String(self.chosen_wire)
                + ")"
            )
        if not self._h2_carrier:
            raise Error(
                "WsAutoClient.take_h2_carrier: HTTP/2 carrier already"
                " consumed (idempotent guard)"
            )
        var c = self._h2_carrier.take()
        self._h2_carrier = None
        return c^

    # ── Connect ────────────────────────────────────────────────────────

    def connect(mut self) raises:
        """Run the runtime connection sequence:

        1. Parse the URL scheme.
        2. ``ws://``: open a cleartext :class:`WsClient` (no ALPN
           involved). Sets :attr:`chosen_wire` to HTTP_1_1.
        3. ``wss://`` + ``prefer_h2 = False``: open a TLS
           :class:`WsClient` with ALPN ``["http/1.1"]``. Sets
           :attr:`chosen_wire` to HTTP_1_1.
        4. ``wss://`` + ``prefer_h2 = True``: open a TLS handshake
           with ALPN ``["h2", "http/1.1"]``. Read
           :meth:`TlsStream.alpn_selected`:

           a. ``"h2"``: drive the h2 preface, wait for the peer's
              SETTINGS frame, gate on
              :meth:`Http2ClientConnection.peer_supports_extended_connect`,
              bootstrap_ws_over_h2 on a fresh stream id, await
              the server's :status = 200 response, and store the
              h2 carrier. Sets :attr:`chosen_wire` to HTTP_2.

           b. ``"http/1.1"`` or ``""`` (no ALPN extension): close
              the discovery TLS handshake + open a fresh TLS
              :class:`WsClient` advertising only ``http/1.1``.
              Sets :attr:`chosen_wire` to HTTP_1_1.

        On any failure :attr:`chosen_wire` flips to FAILED,
        :attr:`last_error` records the failing message, and the
        exception is re-raised.
        """
        try:
            self._connect_impl()
        except e:
            self.last_error = String(e)
            self.chosen_wire = WsWireChoice.FAILED
            raise e^

    def _connect_impl(mut self) raises:
        var scheme = self.url_scheme()
        if scheme == "":
            raise WsHandshakeError(
                "WsAutoClient.connect: URL must start with ws:// or"
                " wss://; got "
                + self.config.url
            )

        if scheme == "ws":
            var c = WsClient.connect(self.config.url)
            self._h1_client = Optional[WsClient](c^)
            self.chosen_wire = WsWireChoice.HTTP_1_1
            return

        if not self.config.prefer_h2:
            var cfg = self.config.tls_config.copy()
            cfg.alpn = List[String]()
            cfg.alpn.append("http/1.1")
            var c = WsClient.connect(self.config.url, cfg^)
            self._h1_client = Optional[WsClient](c^)
            self.chosen_wire = WsWireChoice.HTTP_1_1
            return

        var u = Url.parse(_ws_url_to_http(self.config.url))
        var probe_cfg = self.config.tls_config.copy()
        probe_cfg.alpn = List[String]()
        probe_cfg.alpn.append("h2")
        probe_cfg.alpn.append("http/1.1")
        var tls = TlsStream.connect(u.host, u.port, probe_cfg^)
        var alpn = tls.alpn_selected()

        if alpn == "h2":
            self._open_h2_path(tls^, u)
            self.chosen_wire = WsWireChoice.HTTP_2
            return

        # ALPN not h2 -- close the probe TLS + reconnect on http/1.1.
        # The reconnect costs a second TLS handshake but it's the
        # cleanest split: WsClient.connect owns its TCP / TLS setup
        # + its own response-line + Sec-WebSocket-Accept parse.
        # Production callers that want zero-cost negotiation should
        # set prefer_h2 = False up front when they know the peer
        # only speaks h1.
        _ = tls^
        var h1_cfg = self.config.tls_config.copy()
        h1_cfg.alpn = List[String]()
        h1_cfg.alpn.append("http/1.1")
        var c = WsClient.connect(self.config.url, h1_cfg^)
        self._h1_client = Optional[WsClient](c^)
        self.chosen_wire = WsWireChoice.HTTP_1_1

    def _open_h2_path(mut self, var tls: TlsStream, u: Url) raises:
        """Drive the h2 connection preface + SETTINGS exchange,
        then bootstrap the Extended CONNECT stream. Stores the
        resulting carrier on :attr:`_h2_carrier`.

        Note: the dispatcher does not enable
        ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` on its OWN
        :class:`Http2ClientConnection` (the client doesn't need
        the bit -- only the server advertises it). We do require
        the peer to advertise it; otherwise we raise so the
        caller can retry with ``prefer_h2 = False``.
        """
        var h2 = Http2ClientConnection()

        # 1. Flush the client preface + initial SETTINGS.
        var preface = h2.drain()
        if len(preface) > 0:
            tls.write_all(Span[UInt8, _](preface))

        # 2. Read until we observe the peer's initial SETTINGS.
        #    A bounded read loop (16 iterations x 4096 bytes ~=
        #    64 KiB max) is comfortably larger than any peer's
        #    initial SETTINGS + identifying frames; the dispatcher
        #    is intentionally non-clever here. If the peer never
        #    sends SETTINGS the TLS read either returns 0 (clean
        #    EOF) -- which we treat as a protocol error -- or
        #    blocks until the OS times out.
        var scratch = List[UInt8](capacity=4096)
        scratch.resize(4096, 0)
        # Bounded read loop: 16 iterations x 4096 bytes ~= 64 KiB
        # cap is comfortably larger than any peer's
        # initial SETTINGS + identifying frames. The h2 driver
        # doesn't expose a "peer SETTINGS received" signal, so
        # we use the latched `peer_supports_extended_connect`
        # bit as our terminator. If after N iterations the bit
        # is still false we treat that as "peer SETTINGS didn't
        # advertise it" -- the loop's outer guard captures both
        # "no SETTINGS yet" and "SETTINGS but no bit" cases.
        var settings_advertised = False
        for _ in range(16):
            var n = tls.read(scratch.unsafe_ptr(), 4096)
            if n <= 0:
                break
            # Mojo 1.0.0b1 destructor scheduling drops the temporary
            # ``scratch[:n]`` List before ``h2.feed`` returns, letting
            # the heap reuse the storage and double the parsed bytes
            # on the next ``tls.read`` (same shape as the fix in
            # ``flare/http/client.mojo`` line ~1948). Construct the
            # ``Span`` directly over ``scratch``'s backing storage so
            # the lifetime is the named local, not the slice's
            # anonymous temporary.
            h2.feed(Span[UInt8, _](ptr=scratch.unsafe_ptr(), length=n))
            var auto_out = h2.drain()
            if len(auto_out) > 0:
                tls.write_all(Span[UInt8, _](auto_out))
            if h2.peer_supports_extended_connect():
                settings_advertised = True
                break

        if not settings_advertised:
            raise WsHandshakeError(
                "WsAutoClient: peer did not advertise"
                " SETTINGS_ENABLE_CONNECT_PROTOCOL=1"
                " (RFC 8441 §3) before bounded read budget"
                " ran out; retry with prefer_h2 = False"
            )

        # 3. Bootstrap the Extended CONNECT stream.
        var sid = h2.next_stream_id()
        var ws_key = _generate_ws_key()
        var authority = u.host
        if u.port != UInt16(443):
            authority = authority + ":" + String(Int(u.port))
        bootstrap_ws_over_h2(
            h2,
            sid,
            authority,
            u.request_target(),
            ws_key,
            String(""),
            String(""),
            String("https"),
        )
        var post_bootstrap = h2.drain()
        if len(post_bootstrap) > 0:
            tls.write_all(Span[UInt8, _](post_bootstrap))

        # 4. Read until the server responds with HEADERS on this
        #    stream. Per RFC 8441 §5.2 the server confirms the
        #    tunnel with a 2xx response.
        var response_ready = False
        for _ in range(32):
            var n = tls.read(scratch.unsafe_ptr(), 4096)
            if n <= 0:
                break
            # Same destructor-ordering hazard as above; use the
            # explicit ptr+length Span form to keep the lifetime
            # tied to the named ``scratch`` rather than a slice
            # temporary that the heap may reuse.
            h2.feed(Span[UInt8, _](ptr=scratch.unsafe_ptr(), length=n))
            var auto_out = h2.drain()
            if len(auto_out) > 0:
                tls.write_all(Span[UInt8, _](auto_out))
            if h2.response_ready(sid):
                response_ready = True
                break
        if not response_ready:
            raise WsHandshakeError(
                "WsAutoClient: timed out waiting for Extended CONNECT"
                " response on stream "
                + String(sid)
            )

        var resp = h2.take_response(sid)
        if resp.status < 200 or resp.status >= 300:
            raise WsHandshakeError(
                "WsAutoClient: Extended CONNECT rejected, status = "
                + String(resp.status)
            )

        var stream = WsOverH2Stream(sid)
        self._h2_carrier = Optional[_WsAutoH2Carrier](
            _WsAutoH2Carrier(tls^, h2^, stream^, sid, ws_key)
        )
