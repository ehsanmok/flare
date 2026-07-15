"""HTTP/2 server glue (RFC 9113).

Connects :mod:`flare.http2.frame` + :mod:`flare.http2.hpack` +
:mod:`flare.http2.state` to flare's existing ``Handler`` interface.

The high-level surface:

- :class:`Http2Connection` — a synchronous, buffer-driven driver. The
  caller feeds it inbound bytes (``feed``) and pulls outbound bytes
  (``drain``). When a stream's request is complete, :meth:`take_request`
  yields a :class:`flare.http.Request` ready for a normal Handler.
  After the handler produces a :class:`flare.http.Response`,
  :meth:`emit_response` schedules the appropriate ``HEADERS [+ DATA]``
  frames.

- :func:`detect_h2c_upgrade` — sniff an inbound HTTP/1.1 request for
  ``Connection: Upgrade, HTTP2-Settings`` + ``Upgrade: h2c`` and
  return ``True`` when the connection should switch protocols. The
  caller is responsible for emitting the 101 response and then
  driving the connection through :class:`Http2Connection`.

- :func:`is_h2_alpn` — string match for ``"h2"`` so TLS code paths
  can dispatch from ALPN.

This is enough to ship a working server today while preserving the
plumbing for a future async / reactor integration: the driver does
not own its sockets, so the same code works in a unit test that
shoves bytes through it directly *and* in the reactor's per-fd
callback.
"""

from std.collections import Dict, Optional

from flare.http.wire import HeaderMap, Method, Request, Response

from .frame import (
    Frame,
    FrameFlags,
    FrameType,
    H2_DEFAULT_FRAME_SIZE,
    H2_PREFACE,
    encode_frame,
    parse_frame,
)
from .hpack import HpackHeader
from .state import Connection, Stream, StreamState


def _lower_ascii(k: String) -> String:
    """Lowercase ASCII ``A-Z`` in a header name (HTTP/2 requires
    lowercase field names, RFC 9113 8.2.1)."""
    var out = String(capacity=k.byte_length() + 1)
    var kp = k.unsafe_ptr()
    for j in range(k.byte_length()):
        var c = Int(kp[j])
        if c >= 65 and c <= 90:
            out += chr(c + 32)
        else:
            out += chr(c)
    return out^


# ── Http2Config ─────────────────────────────────────────────────────────────


comptime _H2_DEFAULT_MAX_CONCURRENT_STREAMS: Int = 100
"""RFC 9113 §5.1.2 has no protocol default; flare ships 100 to bound
per-connection memory under adversarial peers without breaking
common interactive workloads (a browser tab opening ~6 parallel
sub-requests sits well below this)."""

comptime _H2_DEFAULT_INITIAL_WINDOW_SIZE: Int = 65535
"""RFC 9113 §6.5.2 mandates 65535 as the default for new streams
until SETTINGS negotiates a different value. ``Http2Config`` ships
the same number so the default ``Http2Config()`` is observably
identical to the legacy ``Http2Connection()`` shape."""

comptime _H2_DEFAULT_MAX_FRAME_SIZE: Int = 16384
"""RFC 9113 §6.5.2 mandates 16384 (2^14) as both the protocol
default and the minimum any peer must accept."""

comptime _H2_DEFAULT_MAX_HEADER_LIST_SIZE: Int = 8192
"""RFC 9113 §6.5.2 default is unbounded; flare ships 8192 (8 KiB)
because every production proxy / origin we'd reasonably ship behind
caps the header list aggressively to defang request smuggling +
header pollution shaped at h2."""

comptime _H2_DEFAULT_HEADER_TABLE_SIZE: Int = 4096
"""RFC 7541 §4.2 default for the HPACK dynamic table size."""


@fieldwise_init
struct Http2Config(Copyable, Defaultable, Movable):
    """Tunable HTTP/2 SETTINGS for an :class:`Http2Connection`.

    All five fields map 1:1 to RFC 9113 §6.5.2 SETTINGS identifiers
    (plus the RFC 7541 HPACK header-table size). Defaults are the
    production-shape numbers flare's reactor wiring uses for both
    the inline test driver in :mod:`tests.test_h2_server` and the
    reactor-attached driver.

    The ``allow_huffman_decode`` flag gates HPACK Huffman decoding
    on the inbound HEADERS path. The default H=0 encoder + raw-
    literal decoder is CRIME-class-side-channel-free by construction;
    the scalar Huffman decoder is wired through ``HpackDecoder``
    when this flag is ``True``. Default ``False`` keeps the
    legacy wire format byte-identical for upgrading peers.

    The ``allow_huffman_encode`` flag mirrors the decoder side: when
    ``True`` the server's outbound HEADERS encoder picks the shorter
    of raw vs Huffman per literal. Default ``False`` keeps the
    legacy H=0-only emit byte-identical.

    Example:

    ```mojo
    from flare.http2 import Http2Connection, Http2Config

    var cfg = Http2Config(
        max_concurrent_streams=200,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=False,
        allow_huffman_encode=False,
    )
    var conn = Http2Connection.with_config(cfg)
    ```

    Fields:
        max_concurrent_streams: SETTINGS_MAX_CONCURRENT_STREAMS
            (RFC 9113 §6.5.2). Bounds the per-connection live-stream
            count.
        initial_window_size: SETTINGS_INITIAL_WINDOW_SIZE
            (RFC 9113 §6.5.2). Per-stream flow-control receive
            window the server advertises on inbound connections.
            Must be ``<= 2^31 - 1`` per RFC 9113 §6.9.2.
        max_frame_size: SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
            Largest frame payload the server is willing to accept.
            Must be in ``[16384, 16777215]`` per RFC 9113 §6.5.2.
        max_header_list_size: SETTINGS_MAX_HEADER_LIST_SIZE
            (RFC 9113 §6.5.2). Header-list size cap (uncompressed,
            including 32-byte per-entry overhead).
        header_table_size: SETTINGS_HEADER_TABLE_SIZE (RFC 7541
            §4.2). HPACK dynamic-table size budget.
        allow_huffman_decode: When ``True``, the HPACK decoder
            accepts H=1 literals (Huffman-encoded) via the RFC
            7541 Appendix B codec. Defaults to ``False`` --
            reject-by-default until soak data justifies flipping
            it on.
        allow_huffman_encode: When ``True``, the HPACK encoder
            picks the shorter of raw vs Huffman per emitted
            literal (size-only optimisation; H=1 frames remain
            CRIME-safe because the encoder dynamic table stays
            empty). Defaults to ``False`` -- H=0-only wire
            output until peers and soak data confirm interop.
    """

    var max_concurrent_streams: Int
    var initial_window_size: Int
    var max_frame_size: Int
    var max_header_list_size: Int
    var header_table_size: Int
    var allow_huffman_decode: Bool
    var allow_huffman_encode: Bool
    var enable_connect_protocol: Bool
    # ``enable_connect_protocol``: when True, the server advertises
    # SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 8441) in its initial
    # SETTINGS frame, allowing peers to issue Extended CONNECT
    # requests (the WebSocket-over-HTTP/2 bootstrap). Default
    # False -- the unified flare.http.HttpServer flips this on
    # automatically when the WebSocket-over-HTTP/2 bridge is
    # wired in (Phase 6).

    def __init__(out self):
        """Default to the production-shape SETTINGS pinned in
        the design doc: 100 concurrent streams, 64 KiB-1 initial
        window, 16 KiB max frame, 8 KiB max header list, 4 KiB
        HPACK dynamic table, Huffman decode/encode both disabled
        (legacy wire-compatible default), Extended CONNECT
        disabled.
        """
        self.max_concurrent_streams = _H2_DEFAULT_MAX_CONCURRENT_STREAMS
        self.initial_window_size = _H2_DEFAULT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _H2_DEFAULT_MAX_FRAME_SIZE
        self.max_header_list_size = _H2_DEFAULT_MAX_HEADER_LIST_SIZE
        self.header_table_size = _H2_DEFAULT_HEADER_TABLE_SIZE
        self.allow_huffman_decode = False
        self.allow_huffman_encode = False
        self.enable_connect_protocol = False

    def validate(self) raises -> None:
        """Raise if any field violates the RFC 9113 / RFC 7541 bounds.

        The reactor-side wiring calls this once at acceptor handoff
        so a misconfigured server fails fast at boot rather than
        emitting malformed SETTINGS frames mid-handshake.
        """
        if self.max_concurrent_streams < 0:
            raise Error("Http2Config: max_concurrent_streams must be >= 0")
        if self.initial_window_size < 0:
            raise Error("Http2Config: initial_window_size must be >= 0")
        if self.initial_window_size > 0x7FFFFFFF:
            raise Error(
                "Http2Config: initial_window_size must be <= 2^31-1"
                " (RFC 9113 §6.9.2)"
            )
        if self.max_frame_size < H2_DEFAULT_FRAME_SIZE:
            raise Error(
                "Http2Config: max_frame_size must be >= 16384 (RFC 9113 §6.5.2)"
            )
        if self.max_frame_size > 16777215:
            raise Error(
                "Http2Config: max_frame_size must be <= 2^24-1"
                " (RFC 9113 §6.5.2)"
            )
        if self.max_header_list_size < 0:
            raise Error("Http2Config: max_header_list_size must be >= 0")
        if self.header_table_size < 0:
            raise Error("Http2Config: header_table_size must be >= 0")


# ── ALPN / h2c detection ────────────────────────────────────────────────


def is_h2_alpn(alpn: String) -> Bool:
    """Return True when the negotiated ALPN protocol is HTTP/2."""
    return alpn == "h2"


def detect_h2c_upgrade(headers: HeaderMap) -> Bool:
    """RFC 7540 §3.2 — detect inbound ``Upgrade: h2c`` request.

    Delegates to :func:`flare.http.proto.h2c_upgrade.detect_h2c_upgrade`,
    the canonical sans-I/O implementation. The decoded
    ``HTTP2-Settings`` payload is fed into the connection during
    initialisation by the caller via
    :meth:`Http2Connection.feed_settings_payload` — that step is the
    reactor-bound side of the upgrade and does not happen here.
    """
    from flare.http.proto.h2c_upgrade import (
        detect_h2c_upgrade as _proto_detect_h2c_upgrade,
    )

    return _proto_detect_h2c_upgrade(headers)


# ── Http2Connection driver ─────────────────────────────────────────────────


struct Http2Connection(Defaultable, Movable):
    """Synchronous HTTP/2 driver with separate I/O sides.

    A pure state object: the caller drives I/O. It exposes:

    - :meth:`feed` — push inbound bytes; returns any reply frames
      (already encoded) that the state machine generated.
    - :meth:`drain` — pull queued outbound frames as bytes.
    - :meth:`take_completed_streams` — pop ids whose request is
      ready for handler dispatch.
    - :meth:`take_request` — convert one stream into a plain
      ``Request`` (a :class:`flare.http.Request`).
    - :meth:`emit_response` — schedule the response frames for a
      finished handler invocation.
    """

    var conn: Connection
    var inbox: List[UInt8]
    var outbox: List[UInt8]
    var greeted: Bool
    var config: Http2Config
    """The :class:`Http2Config` the driver was constructed with.
    Kept on the driver so the reactor wiring can re-read
    individual fields per-stream (e.g. the
    ``max_header_list_size`` cap when applying inbound HEADERS)
    without threading it through every per-frame call site."""

    def __init__(out self):
        """Default-construct with :class:`Http2Config` defaults.

        Equivalent to ``Http2Connection.with_config(Http2Config())``;
        kept as a separate ``__init__`` so callers (``Http2Connection()``
        in tests + the inline driver) work byte-for-byte without
        an explicit config argument.
        """
        self.conn = Connection()
        self.inbox = List[UInt8]()
        self.outbox = List[UInt8]()
        self.greeted = False
        self.config = Http2Config()

    @staticmethod
    def with_config(var config: Http2Config) raises -> Http2Connection:
        """Construct an :class:`Http2Connection` whose underlying
        :class:`Connection` SETTINGS are populated from ``config``.

        Validates ``config`` first (RFC 9113 / RFC 7541 bounds);
        raises if any field is out of range. The resulting driver's
        first-emitted SETTINGS frame advertises
        ``max_concurrent_streams`` per the config; later inbound
        SETTINGS from the peer can lower the negotiated values per
        RFC 9113 §6.5.

        The HPACK dynamic-table size budget is propagated to the
        decoder. The ``allow_huffman_decode`` flag is plumbed
        into ``conn.hpack_decoder.allow_huffman``; the
        ``allow_huffman_encode`` flag into
        ``conn.hpack_encoder.allow_huffman``. Both default to
        ``False`` so the wire format stays byte-identical to the
        legacy default unless the user opts in.
        """
        config.validate()
        var out = Http2Connection()
        out.config = config^
        out.conn.max_concurrent_streams = out.config.max_concurrent_streams
        out.conn.initial_window_size = out.config.initial_window_size
        out.conn.send_window = out.config.initial_window_size
        out.conn.recv_window = out.config.initial_window_size
        out.conn.max_frame_size = out.config.max_frame_size
        out.conn.max_header_list_size = out.config.max_header_list_size
        out.conn.hpack_decoder.max_size = out.config.header_table_size
        out.conn.hpack_decoder.allow_huffman = out.config.allow_huffman_decode
        out.conn.hpack_encoder.allow_huffman = out.config.allow_huffman_encode
        out.conn.enable_connect_protocol = out.config.enable_connect_protocol
        # The ``HpackEncoder`` does not maintain a dynamic table
        # (always Literal-without-Indexing per RFC 7541 §6.2.2);
        # the ``header_table_size`` field on ``Http2Config`` is
        # consumed by the decoder side only until the encoder
        # grows a dynamic table. The peer's announced
        # HEADER_TABLE_SIZE is still honoured on inbound
        # SETTINGS via ``Connection.handle_frame``.
        return out^

    def _emit_initial_settings(mut self):
        """Server-side handshake: send our SETTINGS once."""
        if self.greeted:
            return
        var f = self.conn.initial_settings()
        var bytes = encode_frame(f)
        for i in range(len(bytes)):
            self.outbox.append(bytes[i])
        self.greeted = True

    @staticmethod
    def from_h2c_upgrade(
        var config: Http2Config,
        req: Request,
        settings_payload: List[UInt8],
    ) raises -> Http2Connection:
        """Build a server-side :class:`Http2Connection` seeded for an h2c upgrade.

        Per RFC 7540 §3.2 ("Starting HTTP/2 for HTTP URIs"), the original
        HTTP/1.1 request becomes stream id 1 (implicitly half-closed from
        the client side), and the ``HTTP2-Settings`` header value (the
        raw SETTINGS payload, base64url-decoded) is applied to the
        connection immediately. The server emits its initial SETTINGS
        frame as the server connection preface; the client's connection
        preface (``PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n`` + a SETTINGS
        frame) still arrives over the same TCP fd and is processed by
        :meth:`feed` as usual.

        Args:
            config: Server SETTINGS to advertise. Validated by
                :meth:`with_config`.
            req: The original HTTP/1.1 request that triggered the
                upgrade. Becomes stream id 1 in
                ``HALF_CLOSED_REMOTE`` state with
                ``headers_complete = data_complete = True`` so the
                handler dispatch loop picks it up immediately.
            settings_payload: Raw bytes of the
                ``HTTP2-Settings`` header value (base64url-decoded).
                Format is identical to a SETTINGS frame body
                (repeated 6-byte ``(id, value)`` pairs). Applied
                directly to the connection state without emitting a
                SETTINGS_ACK -- the ACK on the wire is reserved for
                the proper SETTINGS frame the client sends inside
                its connection preface.

        Returns:
            An :class:`Http2Connection` whose ``outbox`` already holds
            the server's initial SETTINGS frame and whose ``conn.streams``
            already contains stream 1 ready for handler dispatch via
            :meth:`take_completed_streams`.
        """
        var out = Http2Connection.with_config(config^)
        # Apply the upgrade-time SETTINGS payload manually so the
        # subsequent ``handle_frame`` loop doesn't auto-emit a
        # SETTINGS_ACK for these (RFC 7540 §3.2.1: the client expects
        # an ACK only for the SETTINGS frame in its connection
        # preface, not for the ``HTTP2-Settings`` header).
        if (len(settings_payload) % 6) != 0:
            raise Error("h2c upgrade: HTTP2-Settings payload not multiple of 6")
        var i = 0
        while i + 6 <= len(settings_payload):
            var id = (Int(settings_payload[i]) << 8) | Int(
                settings_payload[i + 1]
            )
            var v = (
                (Int(settings_payload[i + 2]) << 24)
                | (Int(settings_payload[i + 3]) << 16)
                | (Int(settings_payload[i + 4]) << 8)
                | Int(settings_payload[i + 5])
            )
            if id == 0x1:
                out.conn.hpack_decoder.max_size = v
            elif id == 0x4:
                out.conn.initial_window_size = v
            elif id == 0x5:
                out.conn.max_frame_size = v
            elif id == 0x8:
                out.conn.peer_enable_connect_protocol = v != 0
            i += 6

        # Pre-create stream 1 with the original request, half-closed
        # from the client side (RFC 7540 §3.2: the upgrade request is
        # implicitly END_STREAM-ed on stream 1).
        var s = Stream()
        s.id = 1
        s.state = StreamState.HALF_CLOSED_REMOTE()
        s.send_window = out.conn.initial_window_size
        s.recv_window = out.conn.initial_window_size
        s.headers.append(HpackHeader(":method", req.method))
        s.headers.append(HpackHeader(":scheme", "http"))
        var path = req.url
        s.headers.append(HpackHeader(":path", path))
        var host = req.headers.get("host")
        if host.byte_length() == 0:
            host = req.headers.get("Host")
        if host.byte_length() > 0:
            s.headers.append(HpackHeader(":authority", host))
        # Carry over the user headers, skipping the connection-level
        # ones that don't apply on h2 (RFC 9113 §8.2.2).
        for j in range(len(req.headers._keys)):
            var k = req.headers._keys[j]
            var lk = String("")
            for c in range(k.byte_length()):
                var ch = Int(k.unsafe_ptr()[c])
                if ch >= 65 and ch <= 90:
                    lk += chr(ch + 32)
                else:
                    lk += chr(ch)
            if (
                lk == "host"
                or lk == "connection"
                or lk == "upgrade"
                or lk == "http2-settings"
                or lk == "transfer-encoding"
                or lk == "keep-alive"
                or lk == "proxy-connection"
            ):
                continue
            s.headers.append(HpackHeader(lk, req.headers._values[j]))
        for j in range(len(req.body)):
            s.data.append(req.body[j])
        s.headers_complete = True
        s.data_complete = True
        out.conn.streams[1] = s^

        # Emit the server's initial SETTINGS frame as the server
        # connection preface so the client sees it before its own
        # connection preface arrives. ``greeted = True`` afterwards
        # means a subsequent ``feed`` won't double-emit.
        out._emit_initial_settings()

        return out^

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Push ``data`` (bytes from the socket) into the driver."""
        for i in range(len(data)):
            self.inbox.append(data[i])

        # Strip the 24-byte preface once.
        if not self.conn.preface_seen:
            if len(self.inbox) < 24:
                return
            var preface = String(H2_PREFACE)
            var pp = preface.unsafe_ptr()
            for i in range(24):
                if self.inbox[i] != pp[i]:
                    raise Error("h2: bad preface")
            # Drop the preface from the inbox.
            var rest = List[UInt8](capacity=len(self.inbox) - 24)
            for i in range(24, len(self.inbox)):
                rest.append(self.inbox[i])
            self.inbox = rest^
            self.conn.preface_seen = True
            self._emit_initial_settings()

        # Drain frames until we run out of complete ones.
        while True:
            var span = Span[UInt8, _](self.inbox)
            var got = parse_frame(span)
            if not got:
                return
            var frame = got.value().copy()
            var consumed = 9 + frame.header.length
            var rest = List[UInt8](capacity=len(self.inbox) - consumed)
            for i in range(consumed, len(self.inbox)):
                rest.append(self.inbox[i])
            self.inbox = rest^
            var reply = self.conn.handle_frame(frame^)
            for i in range(len(reply)):
                var rb = encode_frame(reply[i])
                for j in range(len(rb)):
                    self.outbox.append(rb[j])

    def drain(mut self) -> List[UInt8]:
        """Return all queued outbound bytes and clear the buffer."""
        var out = self.outbox.copy()
        self.outbox = List[UInt8]()
        return out^

    def take_completed_streams(self) -> List[Int]:
        """Return stream ids whose request is fully buffered."""
        var ids = List[Int]()
        for entry in self.conn.streams.items():
            # ``StreamSlab.items()`` returns ``List[Tuple[Int, Stream]]``;
            # ``entry[1]`` is the per-stream record. Stream is copied
            # eagerly inside ``items()`` so this loop never aliases the
            # slab's owned storage.
            var s = entry[1].copy()
            # Skip streams already dispatched: ``emit_response`` moves a
            # served stream to ``CLOSED``, but ``headers_complete`` /
            # ``data_complete`` stay set. Without this guard a second
            # ``on_readable`` (e.g. an EAGAIN re-pump on macOS loopback,
            # or any later readable event in the live reactor) would
            # re-return the same id and double-dispatch the handler.
            if (
                s.headers_complete
                and s.data_complete
                and s.state.value != StreamState.CLOSED().value
            ):
                ids.append(s.id)
        return ids^

    def take_reset_streams(mut self) -> List[Int]:
        """Pop the list of stream ids reset by the peer since the
        last call.

        Each id corresponds to an inbound RST_STREAM frame
        (RFC 9113 §6.4) processed by :class:`Connection.handle_frame`.
        Used by :class:`flare.http._h2_conn_handle.Http2ConnHandle` to
        flip the matching per-stream :class:`CancelCell` so the
        in-flight handler can short-circuit cooperatively. The list
        is drained -- a second call returns an empty list unless a
        new RST_STREAM has arrived in the meantime.
        """
        var out = self.conn.reset_streams^
        self.conn.reset_streams = List[Int]()
        return out^

    def goaway_received_flag(self) -> Bool:
        """Return ``True`` once the peer has sent a GOAWAY frame
        (RFC 9113 §6.8). The reactor checks this between dispatches
        to flip the per-stream cancel cells before draining the
        connection."""
        return self.conn.goaway_received

    def take_request(mut self, sid: Int) raises -> Request:
        """Convert stream ``sid`` into a :class:`flare.http.Request`."""
        if sid not in self.conn.streams:
            raise Error("h2: take_request on unknown stream")
        var s = self.conn.streams[sid].copy()
        var req = Request(method="GET", url="/", version="HTTP/2")
        # Pseudo headers come first per RFC 9113 §8.1.2.1.
        for i in range(len(s.headers)):
            var n = s.headers[i].name
            var v = s.headers[i].value
            if n == ":method":
                req.method = v
            elif n == ":path":
                req.url = v
            elif n == ":authority":
                req.headers.set("Host", v)
            elif n == ":scheme":
                pass  # the reactor knows the scheme already
            else:
                req.headers.set(n, v)
        for i in range(len(s.data)):
            req.body.append(s.data[i])
        return req^

    def emit_response(mut self, sid: Int, var resp: Response) raises:
        """Encode + queue the response for ``sid``.

        The connection's stream state is advanced to ``CLOSED`` after
        the response is queued, mirroring HTTP/1.1's per-request
        lifetime in the server. When ``resp.trailers`` is non-empty the
        response is framed as HEADERS [+ DATA] + trailing HEADERS with
        END_STREAM on the trailing block (the gRPC-over-HTTP/2 shape);
        otherwise it frames as a single buffered response.

        There are still no streaming-response bodies on h2 here (one
        buffered DATA frame per stream). Chunked/flow-controlled h2
        response bodies come with the streaming reactor wiring.
        """
        if sid not in self.conn.streams:
            raise Error("h2: emit_response on unknown stream")
        # Build HpackHeader list from the response's HeaderMap.
        # HTTP/2 forbids ``Connection`` / ``Transfer-Encoding`` / ``Keep-Alive``
        # / ``Proxy-Connection`` / ``Upgrade`` per RFC 9113 §8.2.2.
        var hdrs = List[HpackHeader]()
        for i in range(len(resp.headers._keys)):
            var k = resp.headers._keys[i]
            var v = resp.headers._values[i]
            var lk = String(capacity=k.byte_length() + 1)
            var kp = k.unsafe_ptr()
            for j in range(k.byte_length()):
                var c = Int(kp[j])
                if c >= 65 and c <= 90:
                    lk += chr(c + 32)
                else:
                    lk += chr(c)
            if (
                lk == "connection"
                or lk == "transfer-encoding"
                or lk == "keep-alive"
                or lk == "proxy-connection"
                or lk == "upgrade"
            ):
                continue
            hdrs.append(HpackHeader(lk, v))
        # Trailing HEADERS (e.g. gRPC ``grpc-status``): only regular
        # field names are legal after the leading block, and the
        # forbidden-connection-header filter is unnecessary because
        # trailers never carry hop-by-hop fields in practice.
        var trailers = List[HpackHeader]()
        for i in range(len(resp.trailers._keys)):
            var tk = resp.trailers._keys[i]
            var tv = resp.trailers._values[i]
            var ltk = String(capacity=tk.byte_length() + 1)
            var tkp = tk.unsafe_ptr()
            for j in range(tk.byte_length()):
                var tc = Int(tkp[j])
                if tc >= 65 and tc <= 90:
                    ltk += chr(tc + 32)
                else:
                    ltk += chr(tc)
            trailers.append(HpackHeader(ltk, tv))
        var frames = self.conn.make_response_with_trailers(
            sid,
            resp.status,
            Span[HpackHeader, _](hdrs),
            Span[UInt8, _](resp.body),
            Span[HpackHeader, _](trailers),
        )
        for i in range(len(frames)):
            var bytes = encode_frame(frames[i])
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
        var s = self.conn.streams[sid].copy()
        s.state = StreamState.CLOSED()
        self.conn.streams[sid] = s^

    # ── WebSocket-over-HTTP/2 bridge (RFC 8441) ────────────────────────────

    def take_extended_connect_streams(self) -> List[Int]:
        """Return stream ids of open Extended CONNECT tunnels awaiting
        acceptance: ``:method=CONNECT`` + ``:protocol=websocket``, headers
        complete, not yet END_STREAM'd, still OPEN (RFC 8441). The
        ``:protocol`` marker is cleared by :meth:`accept_ws_over_h2`, so an
        accepted tunnel is not re-returned."""
        var ids = List[Int]()
        for entry in self.conn.streams.items():
            var s = entry[1].copy()
            if (
                s.headers_complete
                and not s.data_complete
                and s.extended_connect_protocol == "websocket"
                and s.state.value == StreamState.OPEN().value
            ):
                ids.append(s.id)
        return ids^

    def accept_ws_over_h2(mut self, sid: Int) raises:
        """Accept a WebSocket Extended CONNECT tunnel on ``sid``: emit a
        ``:status=200`` HEADERS block WITHOUT END_STREAM (RFC 8441 5.2)
        so the stream stays open for bidirectional WS DATA. Clears the
        ``:protocol`` marker so the tunnel is not re-surfaced."""
        if sid not in self.conn.streams:
            raise Error("h2: accept_ws_over_h2 on unknown stream")
        self.begin_stream_response(sid, Response(200))
        var s = self.conn.streams[sid].copy()
        s.extended_connect_protocol = String("")
        self.conn.streams[sid] = s^

    def drain_stream_data(mut self, sid: Int) raises -> List[UInt8]:
        """Move any inbound DATA accumulated for ``sid`` out of the stream
        record (the WS-over-h2 read path pulls client frames from here)."""
        if sid not in self.conn.streams:
            return List[UInt8]()
        var s = self.conn.streams[sid].copy()
        var out = s.data^
        s.data = List[UInt8]()
        self.conn.streams[sid] = s^
        return out^

    def begin_stream_response(mut self, sid: Int, var resp: Response) raises:
        """Queue the leading HEADERS of an incremental streaming response.

        Filters hop-by-hop fields (RFC 9113 8.2.2) and encodes a
        no-END_STREAM HEADERS block into the outbox. The stream is left
        open; :meth:`queue_stream_data` sends the body and
        :meth:`end_stream_response` closes it (trailers captured by the
        caller from ``resp.trailers`` before this move).
        """
        if sid not in self.conn.streams:
            raise Error("h2: begin_stream_response on unknown stream")
        var hdrs = List[HpackHeader]()
        for i in range(len(resp.headers._keys)):
            var lk = _lower_ascii(resp.headers._keys[i])
            if (
                lk == "connection"
                or lk == "transfer-encoding"
                or lk == "keep-alive"
                or lk == "proxy-connection"
                or lk == "upgrade"
            ):
                continue
            hdrs.append(HpackHeader(lk, resp.headers._values[i]))
        var hf = self.conn.make_stream_headers(
            sid, resp.status, Span[HpackHeader, _](hdrs)
        )
        var bytes = encode_frame(hf)
        for j in range(len(bytes)):
            self.outbox.append(bytes[j])

    def queue_stream_data(
        mut self, sid: Int, data: Span[UInt8, _]
    ) raises -> Int:
        """Frame as much of ``data`` as the send windows allow.

        Emits DATA frames (each <= ``max_frame_size``) bounded by the
        min of the connection and per-stream send windows, decrements
        both, and returns the number of bytes consumed. Returns 0 when
        the window is exhausted -- the caller stashes the remainder and
        re-pumps on the next WINDOW_UPDATE.
        """
        if sid not in self.conn.streams:
            return 0
        var s = self.conn.streams[sid].copy()
        var budget = (
            self.conn.send_window if self.conn.send_window
            < s.send_window else s.send_window
        )
        if budget <= 0:
            return 0
        var mfs = self.conn.max_frame_size
        var total = len(data)
        var sent = 0
        while sent < total and budget > 0:
            var take = total - sent
            if take > mfs:
                take = mfs
            if take > budget:
                take = budget
            var df = Frame()
            df.header.type = FrameType.DATA()
            df.header.stream_id = sid
            df.header.flags = FrameFlags()
            var pl = List[UInt8](capacity=take)
            for i in range(take):
                pl.append(data[sent + i])
            df.payload = pl^
            var bytes = encode_frame(df)
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
            sent += take
            budget -= take
        self.conn.send_window -= sent
        s.send_window -= sent
        self.conn.streams[sid] = s^
        return sent

    def end_stream_response(
        mut self,
        sid: Int,
        trailers_k: List[String],
        trailers_v: List[String],
    ) raises:
        """Close a streaming response.

        Emits trailing HEADERS with END_STREAM when trailers are present,
        otherwise an empty DATA frame with END_STREAM, and advances the
        stream to CLOSED.
        """
        if sid not in self.conn.streams:
            return
        if len(trailers_k) > 0:
            var trailers = List[HpackHeader]()
            for i in range(len(trailers_k)):
                trailers.append(
                    HpackHeader(_lower_ascii(trailers_k[i]), trailers_v[i])
                )
            var tf = self.conn.make_stream_trailers(
                sid, Span[HpackHeader, _](trailers)
            )
            var bytes = encode_frame(tf)
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
        else:
            var df = Frame()
            df.header.type = FrameType.DATA()
            df.header.stream_id = sid
            df.header.flags = FrameFlags(FrameFlags.END_STREAM())
            df.payload = List[UInt8]()
            var bytes = encode_frame(df)
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
        var s = self.conn.streams[sid].copy()
        s.state = StreamState.CLOSED()
        self.conn.streams[sid] = s^
