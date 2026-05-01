"""HTTP/2 server glue (RFC 9113).

Connects :mod:`flare.http2.frame` + :mod:`flare.http2.hpack` +
:mod:`flare.http2.state` to flare's existing ``Handler`` interface.

The high-level surface:

- :class:`H2Connection` — a synchronous, buffer-driven driver. The
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
  driving the connection through :class:`H2Connection`.

- :func:`is_h2_alpn` — string match for ``"h2"`` so TLS code paths
  can dispatch from ALPN.

This is enough to ship a working server today while preserving the
plumbing for a future async / reactor integration: the driver does
not own its sockets, so the same code works in a unit test that
shoves bytes through it directly *and* in the reactor's per-fd
callback.
"""

from std.collections import Dict, Optional

from flare.http import HeaderMap, Method, Request, Response

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
identical to the v0.6 ``H2Connection()`` shape."""

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
    """Tunable HTTP/2 SETTINGS for an :class:`H2Connection`.

    All five fields map 1:1 to RFC 9113 §6.5.2 SETTINGS identifiers
    (plus the RFC 7541 HPACK header-table size). Defaults are the
    production-shape numbers flare's reactor wiring uses for both
    the inline test driver in :mod:`tests.test_h2_server` and the
    reactor-attached driver shipping under the v0.7 Track A wiring.

    The ``allow_huffman_decode`` flag gates HPACK Huffman decoding
    on the inbound HEADERS path. v0.6 ships H=0-only encoder + raw-
    literal decoder (CRIME-class side channels are zero by
    construction); v0.7 lands the scalar decoder behind this flag,
    defaulting to ``False`` so production stays on the safe path
    until soak data is in (the SIMD decoder lands as a B9 follow-up
    once the flag flips default-on in a v0.7.x patch).

    Example:

    ```mojo
    from flare.http2 import H2Connection, Http2Config

    var cfg = Http2Config(
        max_concurrent_streams=200,
        initial_window_size=131072,
        max_frame_size=32768,
        max_header_list_size=16384,
        header_table_size=8192,
        allow_huffman_decode=False,
    )
    var conn = H2Connection.with_config(cfg)
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
            accepts H=1 literals (Huffman-encoded). v0.7 default
            ``False`` keeps the v0.6 reject-by-default safe path
            until soak data is in.
    """

    var max_concurrent_streams: Int
    var initial_window_size: Int
    var max_frame_size: Int
    var max_header_list_size: Int
    var header_table_size: Int
    var allow_huffman_decode: Bool

    def __init__(out self):
        """Default to the production-shape SETTINGS pinned in
        the design doc: 100 concurrent streams, 64 KiB-1 initial
        window, 16 KiB max frame, 8 KiB max header list, 4 KiB
        HPACK dynamic table, Huffman-decode disabled (v0.6 safe
        default).
        """
        self.max_concurrent_streams = _H2_DEFAULT_MAX_CONCURRENT_STREAMS
        self.initial_window_size = _H2_DEFAULT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _H2_DEFAULT_MAX_FRAME_SIZE
        self.max_header_list_size = _H2_DEFAULT_MAX_HEADER_LIST_SIZE
        self.header_table_size = _H2_DEFAULT_HEADER_TABLE_SIZE
        self.allow_huffman_decode = False

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
    """RFC 9113 §3.2 — detect inbound ``Upgrade: h2c`` request.

    The full RFC requires ``HTTP2-Settings: <base64>``
    too; we accept the upgrade as long as both ``Upgrade: h2c``
    and ``HTTP2-Settings`` are present. The decoded ``HTTP2-Settings``
    payload is fed into the connection during initialisation by the
    caller via :meth:`H2Connection.feed_settings_payload`.
    """
    var upg = headers.get("upgrade")
    if upg.byte_length() == 0:
        return False
    if upg != "h2c":
        return False
    var s = headers.get("http2-settings")
    return s.byte_length() > 0


# ── H2Connection driver ─────────────────────────────────────────────────


struct H2Connection(Defaultable, Movable):
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
    """The :class:`Http2Config` the driver was constructed with. Kept
    on the driver so the reactor wiring (v0.7 Track A1) can re-read
    individual fields per-stream (e.g. the ``max_header_list_size``
    cap when applying inbound HEADERS) without threading it through
    every per-frame call site."""

    def __init__(out self):
        """Default-construct with :class:`Http2Config` defaults.

        Equivalent to ``H2Connection.with_config(Http2Config())``;
        kept as a separate ``__init__`` so the v0.6 callers
        (``H2Connection()`` in tests + the inline driver) keep
        working byte-for-byte.
        """
        self.conn = Connection()
        self.inbox = List[UInt8]()
        self.outbox = List[UInt8]()
        self.greeted = False
        self.config = Http2Config()

    @staticmethod
    def with_config(var config: Http2Config) raises -> H2Connection:
        """Construct an :class:`H2Connection` whose underlying
        :class:`Connection` SETTINGS are populated from ``config``.

        Validates ``config`` first (RFC 9113 / RFC 7541 bounds);
        raises if any field is out of range. The resulting driver's
        first-emitted SETTINGS frame advertises
        ``max_concurrent_streams`` per the config; later inbound
        SETTINGS from the peer can lower the negotiated values per
        RFC 9113 §6.5.

        The HPACK dynamic-table size budget is propagated to the
        decoder. The ``allow_huffman_decode`` flag is read by the
        v0.7 Track A3 Huffman path; on v0.6 + the v0.7 scaffolding
        commit (this one) the field is stored but not yet acted on
        — Huffman literals on the inbound side still raise the
        v0.6 reject-by-default error.
        """
        config.validate()
        var out = H2Connection()
        out.config = config^
        out.conn.max_concurrent_streams = out.config.max_concurrent_streams
        out.conn.initial_window_size = out.config.initial_window_size
        out.conn.send_window = out.config.initial_window_size
        out.conn.recv_window = out.config.initial_window_size
        out.conn.max_frame_size = out.config.max_frame_size
        out.conn.max_header_list_size = out.config.max_header_list_size
        out.conn.hpack_decoder.max_size = out.config.header_table_size
        # The v0.6 ``HpackEncoder`` is stateless (always emits H=0
        # raw literals; no dynamic table). The ``header_table_size``
        # field on ``Http2Config`` is consumed by the decoder side
        # only until the encoder gains a dynamic table in a v0.7.x
        # / v0.8 follow-up. The peer's announced HEADER_TABLE_SIZE
        # is still honoured on inbound SETTINGS via
        # ``Connection.handle_frame``.
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
            var s = entry.value.copy()
            if s.headers_complete and s.data_complete:
                ids.append(s.id)
        return ids^

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
        lifetime in the server (no trailers, no streaming
        responses on h2 yet — those come with the reactor wiring).
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
        var frames = self.conn.make_response(
            sid,
            resp.status,
            Span[HpackHeader, _](hdrs),
            Span[UInt8, _](resp.body),
        )
        for i in range(len(frames)):
            var bytes = encode_frame(frames[i])
            for j in range(len(bytes)):
                self.outbox.append(bytes[j])
        var s = self.conn.streams[sid].copy()
        s.state = StreamState.CLOSED()
        self.conn.streams[sid] = s^
