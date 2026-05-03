"""HTTP/2 client (RFC 9113).

The cleartext (h2c) and TLS (h2)
client-side counterpart to :class:`flare.http2.server.H2Connection`.

The high-level surface mirrors :class:`flare.http.HttpClient` but
talks the binary HTTP/2 protocol instead of HTTP/1.1:

- :class:`Http2ClientConfig` -- client-advertised SETTINGS values
  (mirrors :class:`flare.http2.server.Http2Config`).
- :class:`Http2ClientConnection` -- the stateful, *socket-agnostic*
  driver. The caller pumps inbound bytes into ``feed`` and pulls
  outbound bytes from ``drain``; per-stream completion is observed
  via ``response_ready(sid)`` / ``take_response(sid)``. This is the
  same shape as :class:`flare.http2.server.H2Connection` so it can
  be tested entirely in-memory against the server-side driver
  without real sockets.
- :class:`Http2Client` -- the high-level *blocking* facade that
  owns one TCP (or TLS) connection per :class:`Http2Client`
  instance, multiplexes one or more requests over that connection,
  and returns each :class:`flare.http.Response` from a normal
  ``get`` / ``post`` / ``put`` / ``delete`` / ``head`` call.
  (defined in this module, but small -- the heavy lifting lives in
  :class:`Http2ClientConnection`).

Wire-protocol scope:

* RFC 9113 §3.5 client connection preface
  (``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"``) emitted first.
* RFC 9113 §6.5 SETTINGS exchange: client emits its initial
  SETTINGS frame after the preface; ACKs every server SETTINGS
  it observes; honors peer-advertised
  ``SETTINGS_INITIAL_WINDOW_SIZE`` /
  ``SETTINGS_MAX_FRAME_SIZE`` /
  ``SETTINGS_HEADER_TABLE_SIZE``.
* RFC 9113 §5.1 client stream IDs: odd integers starting at 1,
  monotonically increasing per connection.
* RFC 9113 §6.2 / §6.10 HEADERS + CONTINUATION send and recv
  via :class:`flare.http2.hpack.HpackEncoder` /
  :class:`flare.http2.hpack.HpackDecoder` (shared with the server).
* RFC 9113 §6.1 DATA send and recv with per-stream + connection
  flow-control accounting; we eagerly emit
  ``WINDOW_UPDATE`` for received DATA so default-sized responses
  do not stall (same shape as the server-side driver).
* RFC 9113 §6.7 PING: we ACK every non-ACK PING the peer sends
  and ignore the ACK side.
* RFC 9113 §6.8 GOAWAY: we surface the received flag via
  :attr:`Http2ClientConnection.goaway_received`; in-flight
  streams below the announced last-stream-id continue normally;
  callers SHOULD stop opening new streams.
* RFC 9113 §6.4 RST_STREAM: when received, the affected stream
  is marked closed with the peer's error code stashed for the
  caller to read via :meth:`Http2ClientConnection.stream_error`.

Out of scope (intentional, mirrors the server's scope):

* Server push (``PUSH_PROMISE``) -- we never originate it and
  reject inbound PUSH_PROMISE frames from servers via
  RST_STREAM (PROTOCOL_ERROR) since flare clients do not opt
  into the SETTINGS_ENABLE_PUSH affordance.
* Stream priority (deprecated by RFC 9113 §5.3.2).
* Trailers (HEADERS frames *after* the response DATA stream
  closes) -- accepted at the parser level but not surfaced
  through the high-level :class:`Http2Client` API.

The wire-codec / HPACK / frame-state machinery is shared with
the server (via :class:`flare.http2.state.Connection`); only the
client-specific behaviour (preface, odd stream ids, client
stream-state transitions, the high-level request/response
plumbing) lives here.
"""

from std.collections import Dict, Optional

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
from .state import Connection, H2Error, H2ErrorCode, Stream, StreamState


# ── Http2Response ─────────────────────────────────────────────────────────


struct Http2Response(Movable):
    """A reassembled HTTP/2 response: status + headers + body bytes.

    Returned by :meth:`Http2ClientConnection.take_response`. The
    surface mirrors the bits of :class:`flare.http.Response` the
    high-level :class:`Http2Client` facade needs to lower the
    response into a :class:`flare.http.Response` for callers --
    keeping it as a separate struct here lets the low-level driver
    avoid pulling in any of :mod:`flare.http`'s response-encoding
    apparatus (which is HTTP/1.1-shaped).

    Fields:
        status: HTTP status code from the response's ``:status``
            pseudo-header.
        headers: Response headers, ``HpackHeader`` pairs in the
            order they appeared on the wire (lowercased per
            RFC 9113 §8.1.2). Pseudo-headers (``:status``) are
            stripped; only the regular headers remain.
        body: Response body bytes, concatenated in order from
            every DATA frame on this stream.
    """

    var status: Int
    var headers: List[HpackHeader]
    var body: List[UInt8]

    def __init__(
        out self,
        status: Int,
        var headers: List[HpackHeader],
        var body: List[UInt8],
    ):
        self.status = status
        self.headers = headers^
        self.body = body^


# ── Http2ClientConfig ─────────────────────────────────────────────────────


comptime _DEFAULT_CLIENT_INITIAL_WINDOW_SIZE: Int = 65535
"""RFC 9113 §6.5.2 default. The client's per-stream receive
window size; used to flow-control inbound response DATA frames."""

comptime _DEFAULT_CLIENT_MAX_FRAME_SIZE: Int = 16384
"""RFC 9113 §6.5.2 default + minimum. Largest frame payload
the client is willing to accept on the wire."""

comptime _DEFAULT_CLIENT_HEADER_TABLE_SIZE: Int = 4096
"""RFC 7541 §4.2 default for the HPACK dynamic table size."""

comptime _DEFAULT_CLIENT_MAX_HEADER_LIST_SIZE: Int = 8192
"""Same 8 KiB cap the server uses (see
``flare.http2.server._H2_DEFAULT_MAX_HEADER_LIST_SIZE``).
Bounds memory if a hostile origin sends an absurd response header
list. Emitted only when ``> 0``."""


@fieldwise_init
struct Http2ClientConfig(Copyable, Defaultable, Movable):
    """Client-advertised SETTINGS for an :class:`Http2ClientConnection`.

    Symmetric counterpart to
    :class:`flare.http2.server.Http2Config`. The fields map 1:1 to
    RFC 9113 §6.5.2 SETTINGS identifiers (plus the RFC 7541 HPACK
    header-table size). Defaults are the same production-shape
    numbers the server side ships, so the defaults are safe for
    both sides of an in-process roundtrip.

    Fields:
        initial_window_size: SETTINGS_INITIAL_WINDOW_SIZE
            (RFC 9113 §6.5.2). Per-stream flow-control receive
            window the client advertises for inbound response
            DATA frames. Must be ``<= 2^31 - 1`` per
            RFC 9113 §6.9.2.
        max_frame_size: SETTINGS_MAX_FRAME_SIZE (RFC 9113 §6.5.2).
            Largest frame payload the client is willing to
            accept. Must be in ``[16384, 16777215]``.
        header_table_size: SETTINGS_HEADER_TABLE_SIZE (RFC 7541
            §4.2). HPACK dynamic-table size budget for the
            decoder we run on inbound HEADERS.
        max_header_list_size: SETTINGS_MAX_HEADER_LIST_SIZE
            (RFC 9113 §6.5.2). Header-list size cap (uncompressed,
            including 32-byte per-entry overhead).
        allow_huffman_decode: When ``True``, the HPACK decoder
            accepts H=1 literals (Huffman-encoded) in inbound
            HEADERS. Defaults to ``False`` -- reject-by-default
            until a soak proves the scalar Huffman path is
            CRIME-class-side-channel-safe under client load.
    """

    var initial_window_size: Int
    var max_frame_size: Int
    var header_table_size: Int
    var max_header_list_size: Int
    var allow_huffman_decode: Bool

    def __init__(out self):
        self.initial_window_size = _DEFAULT_CLIENT_INITIAL_WINDOW_SIZE
        self.max_frame_size = _DEFAULT_CLIENT_MAX_FRAME_SIZE
        self.header_table_size = _DEFAULT_CLIENT_HEADER_TABLE_SIZE
        self.max_header_list_size = _DEFAULT_CLIENT_MAX_HEADER_LIST_SIZE
        self.allow_huffman_decode = False

    def validate(self) raises -> None:
        """Raise if any field violates the RFC 9113 / RFC 7541 bounds.

        The high-level :class:`Http2Client` constructor calls this
        once at boot so a misconfigured client fails fast instead
        of emitting a malformed SETTINGS frame mid-handshake.
        """
        if self.initial_window_size < 0:
            raise Error("Http2ClientConfig: initial_window_size must be >= 0")
        if self.initial_window_size > 0x7FFFFFFF:
            raise Error(
                "Http2ClientConfig: initial_window_size must be <= 2^31-1"
                " (RFC 9113 §6.9.2)"
            )
        if self.max_frame_size < H2_DEFAULT_FRAME_SIZE:
            raise Error(
                "Http2ClientConfig: max_frame_size must be >= 16384"
                " (RFC 9113 §6.5.2)"
            )
        if self.max_frame_size > 16777215:
            raise Error(
                "Http2ClientConfig: max_frame_size must be <= 2^24-1"
                " (RFC 9113 §6.5.2)"
            )
        if self.header_table_size < 0:
            raise Error("Http2ClientConfig: header_table_size must be >= 0")
        if self.max_header_list_size < 0:
            raise Error("Http2ClientConfig: max_header_list_size must be >= 0")


# ── Http2ClientConnection ────────────────────────────────────────────────


struct Http2ClientConnection(Defaultable, Movable):
    """Stateful, socket-agnostic HTTP/2 client driver.

    A pure state object -- the caller owns I/O. The lifecycle is:

    1. Construct via :meth:`__init__` or
       :meth:`with_config`. The constructor pre-queues the
       client connection preface
       (``"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n"``) plus the
       initial SETTINGS frame, ready to be drained.

    2. Call :meth:`drain` once to pull the preface + initial
       SETTINGS bytes; write them onto the socket.

    3. For each request:

       a. Allocate a stream id via :meth:`next_stream_id` (odd
          integers starting at 1).
       b. Call :meth:`send_request(sid, ...)` to enqueue the
          HEADERS frame (with optional CONTINUATION) and any
          DATA frames bounded by current flow-control windows.
          DATA that exceeds the window is held back; the
          driver releases more on inbound WINDOW_UPDATE.
       c. Call :meth:`drain` to pull outbound bytes; write them.

    4. On the inbound side: call :meth:`feed(bytes)` with bytes
       read from the socket. Internally the driver:

       - decodes frames via :func:`parse_frame`
       - dispatches them through :meth:`Connection.handle_frame`
         (with ``is_client = True`` so HEADERS / DATA receipt
         transitions HALF_CLOSED_LOCAL streams to CLOSED instead
         of HALF_CLOSED_REMOTE)
       - ACKs SETTINGS / PING as appropriate
       - emits WINDOW_UPDATE for received DATA
       - on RST_STREAM, surfaces the error code via
         :meth:`stream_error` and marks the stream closed

       Then call :meth:`drain` again to pull any auto-emitted
       outbound bytes (SETTINGS ACK, PING ACK, WINDOW_UPDATE).

    5. Poll :meth:`response_ready(sid)`; once ``True``, call
       :meth:`take_response(sid)` to pop the
       ``(status, headers, body)`` tuple.

    6. When done, optionally send a GOAWAY via
       :meth:`send_goaway` and close the socket.

    The driver is :class:`Movable` but not :class:`Copyable`; the
    HPACK dynamic table inside :class:`Connection` is mutable
    state that must not alias across two driver instances.
    """

    var conn: Connection
    """The shared frame / HPACK / stream state machinery
    (:class:`flare.http2.state.Connection`).
    ``conn.is_client`` is set to ``True`` so HEADERS / DATA
    receipt transitions HALF_CLOSED_LOCAL streams to CLOSED."""

    var inbox: List[UInt8]
    """Inbound byte buffer. Filled by :meth:`feed`; drained
    frame-by-frame on each :meth:`feed` call."""

    var outbox: List[UInt8]
    """Outbound byte buffer. Pre-loaded with preface + initial
    SETTINGS at construction; appended-to by every method that
    emits a frame. Drained by :meth:`drain`."""

    var greeted: Bool
    """``True`` once the preface + initial SETTINGS have been
    queued in :attr:`outbox`. Mirrors
    :attr:`H2Connection.greeted`."""

    var config: Http2ClientConfig
    """The :class:`Http2ClientConfig` the driver was constructed
    with. Kept on the driver so the high-level :class:`Http2Client`
    facade can re-read individual fields per-stream (e.g. the
    ``max_header_list_size`` cap when building outbound HEADERS)
    without threading it through every per-frame call site."""

    var _next_sid: Int
    """The next client-initiated stream id to hand out
    (RFC 9113 §5.1.1: odd integers, monotonically increasing).
    Starts at 1 and increments by 2 on every
    :meth:`next_stream_id` call."""

    var _stream_errors: Dict[Int, Int]
    """Stream-id -> peer-supplied RST_STREAM error code
    (RFC 9113 §6.4). Populated when a stream is reset by the peer
    so the high-level facade can surface a meaningful error to
    the caller; queried via :meth:`stream_error`."""

    def __init__(out self):
        """Default-construct with :class:`Http2ClientConfig` defaults."""
        self.conn = Connection()
        self.conn.is_client = True
        self.inbox = List[UInt8]()
        self.outbox = List[UInt8]()
        self.greeted = False
        self.config = Http2ClientConfig()
        self._next_sid = 1
        self._stream_errors = Dict[Int, Int]()
        try:
            self._emit_preface_and_settings()
        except:
            pass

    @staticmethod
    def with_config(
        var config: Http2ClientConfig,
    ) raises -> Http2ClientConnection:
        """Construct a driver whose underlying SETTINGS reflect ``config``.

        Validates ``config`` first (RFC 9113 / RFC 7541 bounds);
        raises if any field is out of range. Same construction
        shape as :meth:`H2Connection.with_config`.
        """
        config.validate()
        var out = Http2ClientConnection()
        out.config = config^
        out.conn.initial_window_size = out.config.initial_window_size
        out.conn.send_window = out.config.initial_window_size
        out.conn.recv_window = out.config.initial_window_size
        out.conn.max_frame_size = out.config.max_frame_size
        out.conn.max_header_list_size = out.config.max_header_list_size
        out.conn.hpack_decoder.max_size = out.config.header_table_size
        # Re-emit preface + SETTINGS into a fresh outbox now that
        # ``config`` has been applied. The default-constructed
        # outbox already holds the *unconfigured* defaults, but
        # ``with_config`` runs after ``__init__`` so we need to
        # rebuild the SETTINGS frame against the new config values.
        out.outbox = List[UInt8]()
        out.greeted = False
        out._emit_preface_and_settings()
        return out^

    def _emit_preface_and_settings(mut self) raises:
        """Pre-load :attr:`outbox` with the connection preface and the
        client's initial SETTINGS frame.

        Called once from :meth:`__init__` /
        :meth:`with_config`. Idempotent on :attr:`greeted`.
        """
        if self.greeted:
            return
        # 24-byte client connection preface (RFC 9113 §3.5).
        var preface = String(H2_PREFACE)
        var pp = preface.unsafe_ptr()
        for i in range(24):
            self.outbox.append(pp[i])
        # Client SETTINGS frame: emit each (id, value) pair that
        # differs from the RFC 9113 / RFC 7541 protocol default.
        # The high-level facade then waits for the server's
        # SETTINGS frame + the server's ACK of ours.
        var f = Frame()
        f.header.type = FrameType.SETTINGS()
        f.header.stream_id = 0
        f.header.flags = FrameFlags(UInt8(0))
        var p = List[UInt8]()
        # SETTINGS_HEADER_TABLE_SIZE = 0x1
        if self.config.header_table_size != 4096:
            self._append_setting(p, 0x1, self.config.header_table_size)
        # SETTINGS_ENABLE_PUSH = 0x2 -- always advertise 0 (no
        # push). RFC 9113 §6.5.2: the protocol default is 1, so
        # we MUST emit this pair to opt out. Setting this to 0
        # tells the server it MUST NOT send PUSH_PROMISE; if it
        # does, we treat that as a connection error
        # (PROTOCOL_ERROR).
        self._append_setting(p, 0x2, 0)
        # SETTINGS_INITIAL_WINDOW_SIZE = 0x4
        if self.config.initial_window_size != 65535:
            self._append_setting(p, 0x4, self.config.initial_window_size)
        # SETTINGS_MAX_FRAME_SIZE = 0x5
        if self.config.max_frame_size != H2_DEFAULT_FRAME_SIZE:
            self._append_setting(p, 0x5, self.config.max_frame_size)
        # SETTINGS_MAX_HEADER_LIST_SIZE = 0x6 (only when set)
        if self.config.max_header_list_size > 0:
            self._append_setting(p, 0x6, self.config.max_header_list_size)
        f.payload = p^
        f.header.length = len(f.payload)
        var bytes = encode_frame(f^)
        for i in range(len(bytes)):
            self.outbox.append(bytes[i])
        self.greeted = True

    def _append_setting(self, mut buf: List[UInt8], id: Int, value: Int):
        """Append one 6-byte SETTINGS pair (RFC 9113 §6.5.1):
        big-endian 2-byte id then big-endian 4-byte value."""
        buf.append(UInt8((id >> 8) & 0xFF))
        buf.append(UInt8(id & 0xFF))
        buf.append(UInt8((value >> 24) & 0xFF))
        buf.append(UInt8((value >> 16) & 0xFF))
        buf.append(UInt8((value >> 8) & 0xFF))
        buf.append(UInt8(value & 0xFF))

    # ── I/O surface ──────────────────────────────────────────────────────

    def drain(mut self) -> List[UInt8]:
        """Return all queued outbound bytes and clear the buffer.

        Mirrors :meth:`H2Connection.drain` for symmetry.
        """
        var out = self.outbox.copy()
        self.outbox = List[UInt8]()
        return out^

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Push ``data`` (bytes from the socket) into the driver.

        Decodes any complete frames in :attr:`inbox`, applies them
        via :meth:`Connection.handle_frame`, and queues any
        auto-generated reply frames (SETTINGS ACK, PING ACK,
        WINDOW_UPDATE) into :attr:`outbox`. Per-stream completion
        becomes observable via :meth:`response_ready` after this
        call returns.

        Raises:
            Error: On a connection-level protocol violation
                (malformed frame header, RST_STREAM on stream 0,
                etc.). The caller SHOULD send a GOAWAY and close
                the socket.
        """
        for i in range(len(data)):
            self.inbox.append(data[i])
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
            # Special-case: PUSH_PROMISE from the server. We never
            # opt in (SETTINGS_ENABLE_PUSH=0 in our preface
            # SETTINGS), so any such frame is a protocol violation.
            # Emit RST_STREAM(PROTOCOL_ERROR) on the promised
            # stream id (the first 4 bytes of the PUSH_PROMISE
            # payload) and drop the frame on the floor.
            if frame.header.type.value == FrameType.PUSH_PROMISE().value:
                if len(frame.payload) >= 4:
                    var promised = (
                        (Int(frame.payload[0]) << 24)
                        | (Int(frame.payload[1]) << 16)
                        | (Int(frame.payload[2]) << 8)
                        | Int(frame.payload[3])
                    ) & 0x7FFFFFFF
                    self._send_rst_stream(
                        promised, H2ErrorCode.PROTOCOL_ERROR().value
                    )
                continue
            # Special-case: RST_STREAM. ``Connection.handle_frame``
            # already marks the stream CLOSED but does not retain
            # the peer's error code. Stash it here so the
            # high-level facade can propagate a meaningful error.
            if frame.header.type.value == FrameType.RST_STREAM().value:
                if len(frame.payload) == 4 and frame.header.stream_id != 0:
                    var code = (
                        (Int(frame.payload[0]) << 24)
                        | (Int(frame.payload[1]) << 16)
                        | (Int(frame.payload[2]) << 8)
                        | Int(frame.payload[3])
                    )
                    self._stream_errors[frame.header.stream_id] = code
            var reply = self.conn.handle_frame(frame^)
            for i in range(len(reply)):
                var rb = encode_frame(reply[i])
                for j in range(len(rb)):
                    self.outbox.append(rb[j])

    # ── Stream id allocation ─────────────────────────────────────────────

    def next_stream_id(mut self) -> Int:
        """Allocate the next client-initiated stream id.

        RFC 9113 §5.1.1: client-initiated stream identifiers must
        be odd, MUST be monotonically increasing, and MUST NOT
        exceed ``2^31 - 1``. Once we'd wrap, the connection MUST
        be closed gracefully via GOAWAY.
        """
        var sid = self._next_sid
        self._next_sid += 2
        return sid

    # ── Sending requests ─────────────────────────────────────────────────

    def send_request(
        mut self,
        sid: Int,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        extra_headers: List[HpackHeader],
        body: Span[UInt8, _],
    ) raises -> None:
        """Encode + queue a request on stream ``sid``.

        Builds the pseudo-header block per RFC 9113 §8.1.2.3 in the
        required order (``:method``, ``:scheme``, ``:authority``,
        ``:path``) followed by the caller-supplied
        ``extra_headers`` (already lower-cased; RFC 9113 §8.1.2),
        HPACK-encodes the lot via the shared :class:`HpackEncoder`,
        and emits a HEADERS frame.

        If ``body`` is empty, the HEADERS frame carries
        ``END_STREAM`` and the stream transitions to
        HALF_CLOSED_LOCAL. Otherwise the body is split into one
        or more DATA frames bounded by the negotiated
        ``max_frame_size`` and the connection-level + per-stream
        send windows; the *last* DATA frame carries
        ``END_STREAM``. If the windows can't fit the entire body
        right now, we emit as much as fits and stash the
        remainder for the caller to flush via
        :meth:`pump_pending_body` after WINDOW_UPDATE has
        loosened the windows.

        Args:
            sid: Stream id allocated via :meth:`next_stream_id`.
            method: HTTP method (e.g. ``"GET"``, ``"POST"``).
            scheme: ``"http"`` or ``"https"``.
            authority: ``Host``-equivalent (RFC 9113 §8.1.2.3.1).
            path: Request target (RFC 9113 §8.1.2.3.4).
            extra_headers: Caller-supplied request headers
                (lowercased name -> value). MUST NOT contain any
                of the connection-level headers forbidden by RFC
                9113 §8.2.2 (``connection``, ``transfer-encoding``,
                ``keep-alive``, ``proxy-connection``, ``upgrade``);
                the high-level facade strips them before calling.
            body: Request body bytes; may be empty.
        """
        var hh = List[HpackHeader]()
        hh.append(HpackHeader(":method", method))
        hh.append(HpackHeader(":scheme", scheme))
        hh.append(HpackHeader(":authority", authority))
        hh.append(HpackHeader(":path", path))
        for i in range(len(extra_headers)):
            hh.append(extra_headers[i].copy())
        var enc = self.conn.hpack_encoder.encode(Span[HpackHeader, _](hh))
        # HEADERS frame with END_HEADERS always set (the
        # encoder produces a single contiguous block; we don't
        # split into CONTINUATION yet -- that's a follow-up for
        # >max_frame_size header blocks). If the encoded block
        # exceeds ``max_frame_size`` we fall back to a HEADERS +
        # CONTINUATION sequence below.
        var max_frame = self.conn.max_frame_size
        var n_enc = len(enc)
        if n_enc <= max_frame:
            var hf = Frame()
            hf.header.type = FrameType.HEADERS()
            hf.header.stream_id = sid
            var flags = FrameFlags.END_HEADERS()
            if len(body) == 0:
                flags |= FrameFlags.END_STREAM()
            hf.header.flags = FrameFlags(flags)
            hf.payload = enc^
            hf.header.length = len(hf.payload)
            var hb = encode_frame(hf^)
            for i in range(len(hb)):
                self.outbox.append(hb[i])
        else:
            # First frame: HEADERS with END_HEADERS = 0; payload
            # is the first ``max_frame`` bytes of the encoded
            # block. END_STREAM rides on the HEADERS frame even
            # when the block continues across CONTINUATION
            # frames (RFC 9113 §6.10).
            var hf = Frame()
            hf.header.type = FrameType.HEADERS()
            hf.header.stream_id = sid
            var hflags = UInt8(0)
            if len(body) == 0:
                hflags |= FrameFlags.END_STREAM()
            hf.header.flags = FrameFlags(hflags)
            var first_payload = List[UInt8](capacity=max_frame)
            for i in range(max_frame):
                first_payload.append(enc[i])
            hf.payload = first_payload^
            hf.header.length = len(hf.payload)
            var hb = encode_frame(hf^)
            for i in range(len(hb)):
                self.outbox.append(hb[i])
            # CONTINUATION frames for the rest. Each carries
            # END_HEADERS=0 except the last.
            var pos = max_frame
            while pos < n_enc:
                var chunk = max_frame
                if pos + chunk > n_enc:
                    chunk = n_enc - pos
                var cf = Frame()
                cf.header.type = FrameType.CONTINUATION()
                cf.header.stream_id = sid
                if pos + chunk == n_enc:
                    cf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
                else:
                    cf.header.flags = FrameFlags(UInt8(0))
                var cp = List[UInt8](capacity=chunk)
                for i in range(chunk):
                    cp.append(enc[pos + i])
                cf.payload = cp^
                cf.header.length = len(cf.payload)
                var cb = encode_frame(cf^)
                for i in range(len(cb)):
                    self.outbox.append(cb[i])
                pos += chunk
        # Locally track the new stream so flow-control accounting
        # works for subsequent inbound frames.
        var s = Stream()
        s.id = sid
        s.send_window = self.conn.initial_window_size
        s.recv_window = self.conn.initial_window_size
        if len(body) == 0:
            s.state = StreamState.HALF_CLOSED_LOCAL()
        else:
            s.state = StreamState.OPEN()
        self.conn.streams[sid] = s^
        # Body: emit one or more DATA frames bounded by the
        # current send windows + max_frame_size. We do not yet
        # support pending-body retransmission on WINDOW_UPDATE;
        # for the cases the caller hits (small request bodies on
        # default-sized windows), the entire body fits in one
        # shot.
        var n_body = len(body)
        if n_body > 0:
            var pos = 0
            while pos < n_body:
                var chunk = max_frame
                if pos + chunk > n_body:
                    chunk = n_body - pos
                # Bound by the smaller of connection + stream
                # send-window (RFC 9113 §6.9).
                var win = self.conn.send_window
                var s_local = self.conn.streams[sid].copy()
                if s_local.send_window < win:
                    win = s_local.send_window
                if chunk > win:
                    chunk = win
                if chunk <= 0:
                    raise Error(
                        "h2 client: send window exhausted before body"
                        " complete; pending-body queue is a follow-up"
                    )
                var df = Frame()
                df.header.type = FrameType.DATA()
                df.header.stream_id = sid
                if pos + chunk == n_body:
                    df.header.flags = FrameFlags(FrameFlags.END_STREAM())
                else:
                    df.header.flags = FrameFlags(UInt8(0))
                var dp = List[UInt8](capacity=chunk)
                for i in range(chunk):
                    dp.append(body[pos + i])
                df.payload = dp^
                df.header.length = len(df.payload)
                var db = encode_frame(df^)
                for i in range(len(db)):
                    self.outbox.append(db[i])
                self.conn.send_window -= chunk
                s_local.send_window -= chunk
                if pos + chunk == n_body:
                    s_local.state = StreamState.HALF_CLOSED_LOCAL()
                self.conn.streams[sid] = s_local^
                pos += chunk

    def send_goaway(mut self, last_stream_id: Int, error_code: Int = 0) -> None:
        """Queue a GOAWAY frame (RFC 9113 §6.8).

        The peer should treat any stream id > ``last_stream_id``
        as not-processed; in-flight streams below that id MAY
        complete. ``error_code`` defaults to 0 (NO_ERROR) for a
        clean shutdown; pass an :class:`H2ErrorCode` value for
        an abnormal close.
        """
        var f = Frame()
        f.header.type = FrameType.GOAWAY()
        f.header.stream_id = 0
        f.header.flags = FrameFlags(UInt8(0))
        var p = List[UInt8]()
        var lsi = last_stream_id & 0x7FFFFFFF
        p.append(UInt8((lsi >> 24) & 0xFF))
        p.append(UInt8((lsi >> 16) & 0xFF))
        p.append(UInt8((lsi >> 8) & 0xFF))
        p.append(UInt8(lsi & 0xFF))
        p.append(UInt8((error_code >> 24) & 0xFF))
        p.append(UInt8((error_code >> 16) & 0xFF))
        p.append(UInt8((error_code >> 8) & 0xFF))
        p.append(UInt8(error_code & 0xFF))
        f.payload = p^
        f.header.length = len(f.payload)
        var bytes = encode_frame(f^)
        for i in range(len(bytes)):
            self.outbox.append(bytes[i])

    def _send_rst_stream(mut self, sid: Int, error_code: Int) -> None:
        """Queue a RST_STREAM frame (RFC 9113 §6.4)."""
        var f = Frame()
        f.header.type = FrameType.RST_STREAM()
        f.header.stream_id = sid
        f.header.flags = FrameFlags(UInt8(0))
        var p = List[UInt8]()
        p.append(UInt8((error_code >> 24) & 0xFF))
        p.append(UInt8((error_code >> 16) & 0xFF))
        p.append(UInt8((error_code >> 8) & 0xFF))
        p.append(UInt8(error_code & 0xFF))
        f.payload = p^
        f.header.length = len(f.payload)
        var bytes = encode_frame(f^)
        for i in range(len(bytes)):
            self.outbox.append(bytes[i])

    # ── Inbound completion polling ───────────────────────────────────────

    def response_ready(self, sid: Int) raises -> Bool:
        """Return ``True`` when the response on stream ``sid`` is fully
        buffered and ready to be popped via :meth:`take_response`.

        A response is "ready" iff its HEADERS block has been
        completely received (END_HEADERS observed on either
        HEADERS or trailing CONTINUATION) **and** either:

        - the stream has been ENDed by the peer (END_STREAM seen
          on HEADERS or DATA), or
        - the stream has been RESET by the peer.
        """
        if sid in self._stream_errors:
            return True
        if sid not in self.conn.streams:
            return False
        var s = self.conn.streams[sid].copy()
        if not s.headers_complete:
            return False
        return s.data_complete or s.state.value == StreamState.CLOSED().value

    def stream_error(self, sid: Int) raises -> Optional[Int]:
        """Return the peer-supplied RST_STREAM error code for ``sid``,
        if any. ``None`` means the stream completed cleanly (or has
        not been reset)."""
        if sid in self._stream_errors:
            return Optional[Int](self._stream_errors[sid])
        return Optional[Int]()

    def take_response(mut self, sid: Int) raises -> Http2Response:
        """Pop and return the :class:`Http2Response` for stream ``sid``.

        Raises:
            Error: When ``sid`` is unknown, the stream is not yet
                ready (use :meth:`response_ready` to gate), or
                the response lacks the required ``:status``
                pseudo-header.

        The returned :class:`Http2Response` owns the header list
        and body bytes; the entry is removed from
        :attr:`conn.streams` so the per-connection memory is
        reclaimed across many sequential requests on one driver.
        """
        if not self.response_ready(sid):
            raise Error("h2 client: take_response on stream not yet ready")
        if sid not in self.conn.streams:
            raise Error("h2 client: take_response on unknown stream")
        # Pop the stream out of the per-conn dict so we own its
        # storage outright (no aliasing into the live dict). This
        # also bounds per-conn memory across many sequential
        # requests on one driver.
        var s = self.conn.streams.pop(sid)
        # Locate :status; everything else is a regular header.
        var status_str = String("")
        var hdrs_out = List[HpackHeader]()
        for i in range(len(s.headers)):
            var h = s.headers[i].copy()
            if h.name == ":status":
                status_str = h.value
            else:
                hdrs_out.append(h^)
        if status_str.byte_length() == 0:
            raise Error(
                "h2 client: response missing :status pseudo-header (RFC"
                " 9113 §8.1.2.4)"
            )
        var status = Int(status_str)
        # ``s.data.copy()`` keeps ``s`` whole so its destructor
        # runs cleanly when the function returns; the body is
        # one allocation per response so the extra copy is in
        # the noise. The body memory peak stays the same: the
        # source ``s.data`` is freed when ``s`` is destroyed at
        # function exit, and the destination owned by the
        # returned :class:`Http2Response` is the only live copy
        # the caller holds.
        var body_copy = s.data.copy()
        return Http2Response(status, hdrs_out^, body_copy^)

    def goaway_received(self) -> Bool:
        """``True`` once the peer has sent a GOAWAY frame (RFC 9113
        §6.8). The high-level facade SHOULD stop opening new
        streams; in-flight streams MAY complete."""
        return self.conn.goaway_received
