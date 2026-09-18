"""HTTP/2 state machines (RFC 9113 §5).

This module pairs the byte-level :mod:`frame` codec and the
:mod:`hpack` codec with the per-stream / per-connection state
machines that make a sequence of frames a *valid* HTTP/2 session.

What lives here:

- :class:`StreamState` — the 6 RFC 9113 §5.1 stream states.
- :class:`Stream` — per-stream record (id, state, flow-control
  windows, accumulated header / data buffers).
- :class:`Connection` — connection-level state: open streams,
  next-stream-id watermark, peer + local SETTINGS, the receive
  window, and the GOAWAY / RST_STREAM machinery.
- :class:`Http2Error` — typed connection / stream errors with their
  RFC 9113 §7 error codes.

The state machine is enforced by :meth:`Connection.handle_frame`
which is the one entry point higher layers (the server reactor)
call for every parsed frame. Returns a list of *outgoing* frames
the caller must enqueue (e.g. SETTINGS ACK, RST_STREAM, GOAWAY).

Connection-level concerns *not* implemented :

- Priority dependency tree (deprecated by RFC 9113 §5.3.2 — frames
  are accepted and ignored).
- Server push (we never originate PUSH_PROMISE).
- Per-stream flow control beyond the basic window accounting; we
  emit WINDOW_UPDATE eagerly so default-sized requests don't stall.
"""

from std.collections import Dict, Optional

from .frame import (
    Frame,
    FrameFlags,
    FrameHeader,
    FrameType,
    H2_DEFAULT_FRAME_SIZE,
    encode_frame,
)
from .hpack import HpackDecoder, HpackEncoder, HpackHeader
from .stream_slab import StreamSlab


# ── H2 error codes (RFC 9113 §7) ────────────────────────────────────────


struct Http2ErrorCode(Copyable, Defaultable):
    """One of the 14 RFC 9113 §7 error codes."""

    var value: Int

    def __init__(out self):
        self.value = 0

    def __init__(out self, v: Int):
        self.value = v

    @staticmethod
    def NO_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x0)

    @staticmethod
    def PROTOCOL_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x1)

    @staticmethod
    def INTERNAL_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x2)

    @staticmethod
    def FLOW_CONTROL_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x3)

    @staticmethod
    def SETTINGS_TIMEOUT() -> Http2ErrorCode:
        return Http2ErrorCode(0x4)

    @staticmethod
    def STREAM_CLOSED() -> Http2ErrorCode:
        return Http2ErrorCode(0x5)

    @staticmethod
    def FRAME_SIZE_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x6)

    @staticmethod
    def REFUSED_STREAM() -> Http2ErrorCode:
        return Http2ErrorCode(0x7)

    @staticmethod
    def CANCEL() -> Http2ErrorCode:
        return Http2ErrorCode(0x8)

    @staticmethod
    def COMPRESSION_ERROR() -> Http2ErrorCode:
        return Http2ErrorCode(0x9)

    @staticmethod
    def ENHANCE_YOUR_CALM() -> Http2ErrorCode:
        return Http2ErrorCode(0xB)


# ── DoS mitigation caps (RFC 9113 security considerations) ───────────────
comptime _CONTINUATION_FRAME_CAP: Int = 64
"""Max CONTINUATION frames per header block before the stream is
RST'd (CVE-2024-27316 CONTINUATION flood)."""
comptime _DEFAULT_HARD_HEADER_CAP: Int = 1 << 20
"""Fallback header-list byte ceiling when ``max_header_list_size``
is unset (0), so an unbounded HEADERS+CONTINUATION accumulation
still cannot grow without limit."""
comptime _MAX_WINDOW: Int = 2147483647
"""RFC 9113 sec 6.9.1: a flow-control window may not exceed 2^31-1."""
comptime _RST_FLOOD_THRESHOLD: Int = 500
"""Connection-lifetime inbound RST_STREAM count that trips a
GOAWAY(ENHANCE_YOUR_CALM) (CVE-2023-44487 rapid reset).
ponytail: lifetime cap, not a time-windowed token bucket --
``handle_frame`` is sans-clock. A legitimate peer that cancels
>500 streams on one connection gets GOAWAY and reconnects; the
upgrade path is a clock-fed bucket if that ever bites."""


struct Http2Error(Copyable, Defaultable):
    """A typed HTTP/2 error. ``stream_id == 0`` means connection error."""

    var code: Http2ErrorCode
    var stream_id: Int
    var debug: String

    def __init__(out self):
        self.code = Http2ErrorCode()
        self.stream_id = 0
        self.debug = ""

    def __init__(
        out self, var code: Http2ErrorCode, stream_id: Int, var debug: String
    ):
        self.code = code^
        self.stream_id = stream_id
        self.debug = debug^


# ── Stream state machine (RFC 9113 §5.1) ────────────────────────────────


struct StreamState(Copyable, Defaultable):
    """Stream lifecycle states. Numeric values are intentional."""

    var value: Int

    def __init__(out self):
        self.value = 0  # IDLE

    def __init__(out self, v: Int):
        self.value = v

    @staticmethod
    def IDLE() -> StreamState:
        return StreamState(0)

    @staticmethod
    def OPEN() -> StreamState:
        return StreamState(1)

    @staticmethod
    def HALF_CLOSED_LOCAL() -> StreamState:
        return StreamState(2)

    @staticmethod
    def HALF_CLOSED_REMOTE() -> StreamState:
        return StreamState(3)

    @staticmethod
    def CLOSED() -> StreamState:
        return StreamState(4)


comptime StreamId = Int


struct Stream(Copyable, Defaultable):
    """Per-stream record."""

    var id: StreamId
    var state: StreamState
    var headers: List[HpackHeader]
    var data: List[UInt8]
    var send_window: Int
    var recv_window: Int
    var headers_complete: Bool
    var data_complete: Bool
    var header_list_bytes: Int
    """Running RFC 9113 6.5.2 header-list size (sum of
    ``name + value + 32`` over every field decoded so far for this
    stream, across HEADERS + CONTINUATION). Enforced against the
    connection cap to reject oversized header blocks."""
    var continuation_count: Int
    """CONTINUATION frames seen for this stream's header block;
    capped to stop a CONTINUATION flood."""
    var content_length: Int
    """Declared ``content-length``, or ``-1`` when absent. RFC 9113
    sec 8.1.2.6 makes a mismatch against the DATA actually received a
    malformed request."""
    var extended_connect_protocol: String
    """RFC 8441 ``:protocol`` pseudo-header value when the stream
    was opened with ``:method = CONNECT``. Empty string otherwise.
    The unified WebSocket-over-HTTP/2 dispatcher uses this to
    route ``"websocket"`` Extended CONNECT streams to the WS
    handler instead of treating them as a regular CONNECT proxy
    request."""

    def __init__(out self):
        self.id = 0
        self.state = StreamState()
        self.headers = List[HpackHeader]()
        self.data = List[UInt8]()
        self.send_window = 65535
        self.recv_window = 65535
        self.headers_complete = False
        self.data_complete = False
        self.header_list_bytes = 0
        self.continuation_count = 0
        self.content_length = -1
        self.extended_connect_protocol = ""


# ── Connection ──────────────────────────────────────────────────────────


struct Connection(Copyable, Defaultable):
    """Per-connection HTTP/2 state."""

    var streams: StreamSlab[Stream]
    """Per-connection stream table. See :mod:`flare.http2.stream_slab`
    for the design rationale -- dense small-int keys hit a
    flat-array fast path; large IDs spill into a Dict overflow.
    Drop-in API parity with the prior ``Dict[StreamId, Stream]``."""
    var hpack_decoder: HpackDecoder
    var hpack_encoder: HpackEncoder
    var max_frame_size: Int
    var max_concurrent_streams: Int
    var initial_window_size: Int
    var max_header_list_size: Int
    """SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 §6.5.2). ``0`` means
    unset / advertise no cap (the RFC default). ``Http2Config``
    sets this to 8192 by default; emitted only when ``> 0``."""

    var send_window: Int
    var recv_window: Int
    var goaway_received: Bool
    var preface_seen: Bool
    var settings_acked: Bool
    var is_client: Bool
    """When ``True``, this :class:`Connection` is driven from the
    client side (``flare.http2.client.Http2ClientConnection``).
    Affects the :meth:`handle_frame` HEADERS-receive transition:
    a stream we sent HEADERS+END_STREAM on (HALF_CLOSED_LOCAL)
    that receives HEADERS+END_STREAM transitions to CLOSED, not
    HALF_CLOSED_REMOTE. Defaults to ``False`` (server semantics)
    so existing server callers are unchanged."""
    var enable_connect_protocol: Bool
    """When ``True``, the server advertises
    ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`` (RFC 8441) in its
    initial SETTINGS frame. Required for clients to issue an
    ``Extended CONNECT`` request (the WebSocket-over-HTTP/2
    bootstrap). Default ``False`` so existing servers don't
    accidentally opt into bootstrapping protocols they can't
    speak; flipped to ``True`` by the unified
    :class:`flare.http.HttpServer` once the unified
    :class:`flare.ws.WsServer` is wired in (Phase 6)."""
    var peer_enable_connect_protocol: Bool
    """When ``True``, the *peer* advertised
    ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`` in its initial
    SETTINGS. The HTTP/2 client checks this before issuing an
    Extended CONNECT (RFC 8441 §3 SHOULD); if the server didn't
    advertise the setting, the client falls back to the
    HTTP/1.1 Upgrade dance for WebSocket."""
    var rst_stream_count: Int
    """Connection-lifetime count of inbound RST_STREAM frames.
    Trips a GOAWAY(ENHANCE_YOUR_CALM) past ``_RST_FLOOD_THRESHOLD``
    (rapid-reset mitigation)."""
    var goaway_sent: Bool
    """Set once the driver has queued a GOAWAY so it is emitted at
    most once."""
    var last_peer_stream_id: Int
    """Highest peer-initiated stream id seen. Feeds the GOAWAY
    last-stream-id field and the RFC 9113 sec 5.1.1 monotonicity check
    (a peer must not open a stream numbered below one it already
    opened)."""
    var local_max_frame_size: Int
    """The SETTINGS_MAX_FRAME_SIZE *we* advertise, and therefore the
    largest inbound frame we accept (RFC 9113 sec 4.2).

    Distinct from ``max_frame_size``, which the peer's SETTINGS
    overwrites to describe what *it* accepts and which egress sizes
    against. Sharing one field would let a peer raise our own inbound
    ceiling by advertising a large value."""
    var continuing_stream: Int
    """Stream whose header block is still open, ``0`` when none.

    RFC 9113 sec 6.10 makes a header block an atomic unit: between a
    HEADERS without END_HEADERS and the CONTINUATION that carries it,
    no other frame -- on any stream -- may appear."""
    var header_block: List[UInt8]
    """Accumulated header-block fragments for ``continuing_stream``.

    Decoding must wait for END_HEADERS: HPACK is a stream cipher over
    the whole block, so a field can straddle the HEADERS/CONTINUATION
    boundary and per-fragment decoding corrupts it."""
    var header_block_end_stream: Bool
    """END_STREAM seen on the HEADERS that opened ``header_block``."""
    var reset_streams: List[Int]
    """Stream ids that received an inbound RST_STREAM since the
    last :meth:`take_reset_streams` call (RFC 9113 §6.4). Drained
    by :class:`flare.http._h2_conn_handle.Http2ConnHandle` before each
    handler-dispatch round so per-stream :class:`CancelCell`
    plumbing can flip the right cell. The driver also tracks the
    transition via :class:`StreamState.CLOSED`; the explicit list
    exists so the reactor can react in O(1) per RST_STREAM rather
    than scanning every open stream."""

    def __init__(out self):
        self.streams = StreamSlab[Stream]()
        self.hpack_decoder = HpackDecoder()
        self.hpack_encoder = HpackEncoder()
        self.max_frame_size = H2_DEFAULT_FRAME_SIZE
        self.max_concurrent_streams = 100
        self.initial_window_size = 65535
        self.max_header_list_size = 0  # unset / unbounded (RFC default)
        self.send_window = 65535
        self.recv_window = 65535
        self.goaway_received = False
        self.preface_seen = False
        self.settings_acked = False
        self.is_client = False
        self.enable_connect_protocol = False
        self.peer_enable_connect_protocol = False
        self.rst_stream_count = 0
        self.goaway_sent = False
        self.last_peer_stream_id = 0
        self.local_max_frame_size = H2_DEFAULT_FRAME_SIZE
        self.continuing_stream = 0
        self.header_block = List[UInt8]()
        self.header_block_end_stream = False
        self.reset_streams = List[Int]()

    def _make_settings(self, ack: Bool) -> Frame:
        """Server-side initial SETTINGS frame (or empty ACK).

        Emits one (id, value) pair for every server SETTING that
        differs from its RFC 9113 / RFC 7541 protocol default. The
        legacy default ``Connection()`` shape (``max_concurrent_streams
        = 100``, all others at RFC defaults) emits a single
        ``SETTINGS_MAX_CONCURRENT_STREAMS = 100`` pair so the wire
        bytes stay byte-for-byte identical to the original driver
        (``test_preface_only_emits_settings`` still passes
        unchanged). ``Http2Connection.with_config(Http2Config(...))``
        with non-default fields adds the corresponding pairs.
        """
        var f = Frame()
        f.header.type = FrameType.SETTINGS()
        f.header.stream_id = 0
        if ack:
            f.header.flags = FrameFlags(FrameFlags.ACK())
            return f^
        var p = List[UInt8]()

        # SETTINGS_HEADER_TABLE_SIZE = 0x1 — only when != RFC 7541 default.
        if self.hpack_decoder.max_size != 4096:
            self._append_setting(p, 0x1, self.hpack_decoder.max_size)

        # SETTINGS_MAX_CONCURRENT_STREAMS = 0x3 — flare always
        # advertises its bound (RFC 9113 §6.5.2 has no protocol
        # default; not advertising it lets a hostile peer open
        # arbitrarily many streams).
        self._append_setting(p, 0x3, self.max_concurrent_streams)

        # SETTINGS_INITIAL_WINDOW_SIZE = 0x4 — only when != RFC default.
        if self.initial_window_size != 65535:
            self._append_setting(p, 0x4, self.initial_window_size)

        # SETTINGS_MAX_FRAME_SIZE = 0x5 — only when != RFC default.
        if self.max_frame_size != H2_DEFAULT_FRAME_SIZE:
            self._append_setting(p, 0x5, self.max_frame_size)

        # SETTINGS_MAX_HEADER_LIST_SIZE = 0x6 — only when set
        # (``0`` = unset, RFC default is "unlimited").
        if self.max_header_list_size > 0:
            self._append_setting(p, 0x6, self.max_header_list_size)

        # SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x8 (RFC 8441) --
        # only when the server has opted in. Tells the peer it
        # MAY use Extended CONNECT (``:method = CONNECT`` +
        # ``:protocol = websocket``) on this connection. Skipped
        # by default so a vanilla HTTP/2 server never accidentally
        # advertises a capability it can't service.
        if self.enable_connect_protocol:
            self._append_setting(p, 0x8, 1)

        f.payload = p^
        return f^

    def _append_setting(self, mut buf: List[UInt8], id: Int, value: Int):
        """Append one 6-byte SETTINGS pair (RFC 9113 §6.5.1):
        big-endian 2-byte id then big-endian 4-byte value."""
        buf.append(UInt8((id >> 8) & 0xFF))
        buf.append(UInt8(id & 0xFF))
        buf.append(UInt8((value >> 24) & 0xFF))
        buf.append(UInt8((value >> 16) & 0xFF))
        buf.append(UInt8((value >> 8) & 0xFF))
        buf.append(UInt8(value & 0xFF))

    def initial_settings(self) -> Frame:
        """The first SETTINGS frame the server emits after preface."""
        return self._make_settings(False)

    def _ensure_stream(mut self, sid: StreamId) raises -> Stream:
        if sid in self.streams:
            return self.streams[sid].copy()
        var s = Stream()
        s.id = sid
        s.state = StreamState.IDLE()
        s.send_window = self.initial_window_size
        s.recv_window = self.initial_window_size
        return s^

    def _put_stream(mut self, var s: Stream):
        self.streams[s.id] = s^

    def _header_list_cap(self) -> Int:
        """Effective header-list byte ceiling: the negotiated
        ``max_header_list_size`` when set, else the hard fallback."""
        if self.max_header_list_size > 0:
            return self.max_header_list_size
        return _DEFAULT_HARD_HEADER_CAP

    def _rst_stream_frame(self, sid: Int, error_code: Int) -> Frame:
        """Build a RST_STREAM frame (RFC 9113 6.4)."""
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
        return f^

    def _goaway_frame(self, last_stream_id: Int, error_code: Int) -> Frame:
        """Build a GOAWAY frame (RFC 9113 6.8)."""
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
        return f^

    def _conn_error(mut self, code: Int) -> List[Frame]:
        """Queue a GOAWAY carrying ``code`` and return it as the frame
        list for a connection error.

        RFC 9113 sec 5.4.1: a connection error is reported with GOAWAY
        before closing. Raising instead drops the connection with no
        frame at all, which leaves a conforming peer unable to tell a
        protocol rejection from a crash or a dead network."""
        var out = List[Frame]()
        if not self.goaway_sent:
            self.goaway_sent = True
            out.append(self._goaway_frame(self.last_peer_stream_id, code))
        return out^

    def _strip_pad_and_priority(
        self, f: Frame, has_priority_field: Bool
    ) raises -> List[UInt8]:
        """Return the frame's real payload with the RFC 9113 sec 6.1 /
        sec 6.2 padding and priority prefixes removed.

        Raises when the declared pad length does not leave room for
        itself, which sec 6.1 makes a connection error."""
        var p = f.payload.copy()
        var start = 0
        var end = len(p)
        if f.header.flags.has(FrameFlags.PADDED()):
            if end < 1:
                raise Error("h2: PADDED frame with empty payload")
            var pad = Int(p[0])
            start = 1
            if pad > end - 1:
                raise Error("h2: pad length exceeds payload")
            end -= pad
        if has_priority_field and f.header.flags.has(FrameFlags.PRIORITY()):
            if end - start < 5:
                raise Error("h2: PRIORITY prefix truncated")
            start += 5
        var out = List[UInt8](capacity=end - start)
        for i in range(start, end):
            out.append(p[i])
        return out^

    @staticmethod
    def _is_connection_specific(name: String) -> Bool:
        """RFC 9113 sec 8.2.2: fields that carry HTTP/1.1 connection
        semantics and are malformed in HTTP/2."""
        return (
            name == "connection"
            or name == "keep-alive"
            or name == "proxy-connection"
            or name == "transfer-encoding"
            or name == "upgrade"
        )

    @staticmethod
    def _is_request_pseudo(name: String) -> Bool:
        return (
            name == ":method"
            or name == ":scheme"
            or name == ":path"
            or name == ":authority"
            or name == ":protocol"
        )

    def _validate_request_headers(
        self, hdrs: List[HpackHeader], is_trailers: Bool
    ) -> Bool:
        """Return ``True`` when ``hdrs`` is a well-formed HTTP/2 request
        header list (RFC 9113 sec 8.1.2 and sec 8.3).

        A ``False`` return is a malformed request: the caller answers
        with RST_STREAM(PROTOCOL_ERROR) rather than serving it."""
        var seen_regular = False
        var n_method = 0
        var n_scheme = 0
        var n_path = 0
        var n_authority = 0
        var path_empty = False
        var is_connect = False
        var has_protocol = False
        for i in range(len(hdrs)):
            var name = hdrs[i].name
            if name.byte_length() == 0:
                return False
            # sec 8.2.1: field names are lowercase on the wire.
            var np = name.unsafe_ptr()
            for k in range(name.byte_length()):
                var c = np[unsafe_offset=k]
                if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
                    return False
            if name.unsafe_ptr()[unsafe_offset=0] == UInt8(ord(":")):
                # sec 8.3: pseudo-headers never appear in trailers, and
                # sec 8.1.2.1 puts them all before the regular fields.
                if is_trailers or seen_regular:
                    return False
                if not Connection._is_request_pseudo(name):
                    return False
                if name == ":method":
                    n_method += 1
                    is_connect = hdrs[i].value == "CONNECT"
                elif name == ":scheme":
                    n_scheme += 1
                elif name == ":path":
                    n_path += 1
                    path_empty = hdrs[i].value.byte_length() == 0
                elif name == ":authority":
                    n_authority += 1
                elif name == ":protocol":
                    has_protocol = True
            else:
                seen_regular = True
                if Connection._is_connection_specific(name):
                    return False
                # sec 8.2.2: TE is allowed, but only as "trailers".
                if name == "te" and hdrs[i].value != "trailers":
                    return False
        if is_trailers:
            return True
        if n_method != 1:
            return False
        if n_scheme > 1 or n_path > 1 or n_authority > 1:
            return False
        if is_connect and not has_protocol:
            # sec 8.5: a classic CONNECT carries :authority only, and
            # omitting :scheme / :path is required rather than a fault.
            return n_scheme == 0 and n_path == 0 and n_authority == 1
        # Extended CONNECT (RFC 8441) and every other method need the
        # full request triple.
        if n_scheme != 1 or n_path != 1:
            return False
        if path_empty:
            return False
        return True

    @staticmethod
    def _declared_content_length(hdrs: List[HpackHeader]) -> Int:
        """The request's ``content-length``, or ``-1`` when absent or
        unparseable."""
        for i in range(len(hdrs)):
            if hdrs[i].name == "content-length":
                var v = hdrs[i].value
                if v.byte_length() == 0:
                    return -1
                var acc = 0
                var p = v.unsafe_ptr()
                for k in range(v.byte_length()):
                    var c = Int(p[unsafe_offset=k])
                    if c < 48 or c > 57:
                        return -1
                    acc = acc * 10 + (c - 48)
                return acc
        return -1

    def _active_stream_count(self) -> Int:
        """Streams that count against SETTINGS_MAX_CONCURRENT_STREAMS
        (RFC 9113 sec 5.1.2: open plus either half-closed state)."""
        var n = 0
        for entry in self.streams.items():
            var st = entry[1].state.value
            if (
                st == StreamState.OPEN().value
                or st == StreamState.HALF_CLOSED_LOCAL().value
                or st == StreamState.HALF_CLOSED_REMOTE().value
            ):
                n += 1
        return n

    def _commit_header_block(mut self, sid: StreamId) raises -> List[Frame]:
        """Decode the accumulated header block for ``sid``, validate it,
        and apply the resulting stream-state transition.

        Decoding happens here rather than per frame because HPACK is
        stateful across the whole block."""
        var out = List[Frame]()
        var block = self.header_block^
        self.header_block = List[UInt8]()
        var end_stream = self.header_block_end_stream
        self.header_block_end_stream = False

        var hdrs: List[HpackHeader]
        try:
            hdrs = self.hpack_decoder.decode(Span[UInt8, _](block))
        except:
            # sec 4.3: the HPACK context is connection-wide, so a
            # decode failure poisons every later block.
            return self._conn_error(Http2ErrorCode.COMPRESSION_ERROR().value)

        var s = self._ensure_stream(sid)
        var is_trailers = s.headers_complete

        # Size cap first: it is the DoS guard, so it should fire on an
        # oversized list whether or not the list is also malformed.
        var cap = self._header_list_cap()
        for j in range(len(hdrs)):
            s.header_list_bytes += (
                hdrs[j].name.byte_length() + hdrs[j].value.byte_length() + 32
            )
            if s.header_list_bytes > cap:
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.ENHANCE_YOUR_CALM().value
                    )
                )
                s.state = StreamState.CLOSED()
                self._put_stream(s^)
                return out^

        if not self.is_client:
            if not self._validate_request_headers(hdrs, is_trailers):
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                )
                s.state = StreamState.CLOSED()
                self._put_stream(s^)
                return out^

        for j in range(len(hdrs)):
            s.headers.append(hdrs[j].copy())
            # RFC 8441 sec 4: capture ``:protocol`` on Extended CONNECT
            # so the WsServer bridge can route it.
            if hdrs[j].name == ":protocol":
                s.extended_connect_protocol = hdrs[j].value
        if not is_trailers:
            s.content_length = Connection._declared_content_length(hdrs)
        s.headers_complete = True

        if end_stream:
            # sec 8.1.2.6: a declared content-length must match the DATA
            # actually delivered.
            if s.content_length >= 0 and len(s.data) != s.content_length:
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                )
                s.state = StreamState.CLOSED()
                self._put_stream(s^)
                return out^
            s.data_complete = True
            if (
                self.is_client
                and s.state.value == StreamState.HALF_CLOSED_LOCAL().value
            ):
                s.state = StreamState.CLOSED()
            else:
                s.state = StreamState.HALF_CLOSED_REMOTE()
        else:
            if (
                self.is_client
                and s.state.value == StreamState.HALF_CLOSED_LOCAL().value
            ):
                pass
            else:
                s.state = StreamState.OPEN()
        self._put_stream(s^)
        return out^

    def handle_frame(mut self, var f: Frame) raises -> List[Frame]:
        """Apply ``f`` to the connection state, return reply frames."""
        var out = List[Frame]()
        var ft = f.header.type.value
        var sid = f.header.stream_id
        # Payload length, not ``header.length``: the wire decoder keeps
        # the two in step, but in-process callers build a frame by
        # setting ``payload`` alone and leave the header field at zero.
        var plen = len(f.payload)

        # ── RFC 9113 sec 6.10: an open header block is atomic ────────
        # Between a HEADERS without END_HEADERS and its closing
        # CONTINUATION nothing else may arrive, on this stream or any
        # other. Checked before everything else because a frame that
        # interleaves here is a connection error whatever else is wrong
        # with it.
        if self.continuing_stream != 0:
            if ft != FrameType.CONTINUATION().value or sid != (
                self.continuing_stream
            ):
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            var cs = self.streams[sid].copy()
            cs.continuation_count += 1
            if cs.continuation_count > _CONTINUATION_FRAME_CAP:
                # CONTINUATION flood (CVE-2024-27316).
                self.continuing_stream = 0
                self.header_block = List[UInt8]()
                return self._conn_error(
                    Http2ErrorCode.ENHANCE_YOUR_CALM().value
                )
            self._put_stream(cs^)
            var cfrag: List[UInt8]
            try:
                cfrag = self._strip_pad_and_priority(f, False)
            except:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            for i in range(len(cfrag)):
                self.header_block.append(cfrag[i])
            if not f.header.flags.has(FrameFlags.END_HEADERS()):
                return out^
            self.continuing_stream = 0
            return self._commit_header_block(sid)

        # ── RFC 9113 sec 6 frame-shape validation ────────────────────
        # Each of these is a connection error the peer must be told
        # about. Checked before any per-type handling so a malformed
        # frame never reaches state that assumes it is well-formed.
        if ft == FrameType.PING().value:
            if sid != 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if plen != 8:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
        elif ft == FrameType.GOAWAY().value:
            if sid != 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
        elif ft == FrameType.SETTINGS().value:
            if sid != 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if f.header.flags.has(FrameFlags.ACK()) and plen != 0:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
            if (plen % 6) != 0:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
        elif ft == FrameType.PRIORITY().value:
            if sid == 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if plen != 5:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
            # sec 5.3.1: a stream cannot depend on itself.
            var dep = (
                (Int(f.payload[0]) << 24)
                | (Int(f.payload[1]) << 16)
                | (Int(f.payload[2]) << 8)
                | Int(f.payload[3])
            ) & 0x7FFFFFFF
            if dep == sid:
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                )
                return out^
        elif ft == FrameType.RST_STREAM().value:
            if sid == 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if plen != 4:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
            # sec 6.4: RST_STREAM on a stream the peer never opened.
            if sid not in self.streams and sid > self.last_peer_stream_id:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
        elif ft == FrameType.WINDOW_UPDATE().value:
            if plen != 4:
                return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)
        elif ft == FrameType.DATA().value:
            if sid == 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
        elif ft == FrameType.PUSH_PROMISE().value:
            # sec 8.4: we advertise SETTINGS_ENABLE_PUSH = 0, so a
            # client sending one is a protocol violation. flare never
            # originates push either.
            return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)

        # sec 4.2: any frame larger than the size we advertised.
        if plen > self.local_max_frame_size:
            return self._conn_error(Http2ErrorCode.FRAME_SIZE_ERROR().value)

        # sec 5.1.1: peer-initiated stream ids are odd and must only
        # increase. A lower id that is not still in the table refers to
        # a stream the peer already finished with.
        if ft == FrameType.HEADERS().value and not self.is_client:
            if sid != 0 and (sid % 2) == 0:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if sid < self.last_peer_stream_id and sid not in self.streams:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            if sid > self.last_peer_stream_id:
                self.last_peer_stream_id = sid

        if ft == FrameType.SETTINGS().value:
            if f.header.flags.has(FrameFlags.ACK()):
                self.settings_acked = True
                return out^
            # Apply each (id, value) pair.
            if (f.header.length % 6) != 0:
                raise Error("h2: SETTINGS payload not a multiple of 6")
            var i = 0
            while i + 6 <= len(f.payload):
                var id = (Int(f.payload[i]) << 8) | Int(f.payload[i + 1])
                var v = (
                    (Int(f.payload[i + 2]) << 24)
                    | (Int(f.payload[i + 3]) << 16)
                    | (Int(f.payload[i + 4]) << 8)
                    | Int(f.payload[i + 5])
                )
                # RFC 9113 sec 6.5.2 bounds. Out-of-range values are
                # connection errors, not values to clamp: accepting one
                # silently desynchronises both ends' idea of the window.
                if id == 0x2:  # SETTINGS_ENABLE_PUSH
                    if v != 0 and v != 1:
                        return self._conn_error(
                            Http2ErrorCode.PROTOCOL_ERROR().value
                        )
                elif id == 0x4:  # SETTINGS_INITIAL_WINDOW_SIZE
                    if v > 0x7FFFFFFF:
                        return self._conn_error(
                            Http2ErrorCode.FLOW_CONTROL_ERROR().value
                        )
                elif id == 0x5:  # SETTINGS_MAX_FRAME_SIZE
                    if v < H2_DEFAULT_FRAME_SIZE or v > 16777215:
                        return self._conn_error(
                            Http2ErrorCode.PROTOCOL_ERROR().value
                        )

                if id == 0x4:  # SETTINGS_INITIAL_WINDOW_SIZE
                    # sec 6.9.2: the change is a delta applied to every
                    # existing stream's send window, and the result may
                    # legitimately go negative (the peer over-sent
                    # against the older, larger window).
                    var delta = v - self.initial_window_size
                    self.initial_window_size = v
                    if delta != 0:
                        var ids = List[Int]()
                        for entry in self.streams.items():
                            ids.append(entry[0])
                        for k in range(len(ids)):
                            var st2 = self.streams[ids[k]].copy()
                            if st2.send_window + delta > _MAX_WINDOW:
                                return self._conn_error(
                                    Http2ErrorCode.FLOW_CONTROL_ERROR().value
                                )
                            st2.send_window += delta
                            self._put_stream(st2^)
                elif id == 0x5:  # SETTINGS_MAX_FRAME_SIZE
                    self.max_frame_size = v
                elif id == 0x1:  # SETTINGS_HEADER_TABLE_SIZE
                    self.hpack_decoder.max_size = v
                elif id == 0x8:  # SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441)
                    # Peer is advertising whether Extended CONNECT
                    # is allowed. RFC 8441 §3: on the server side
                    # only the client's value is significant (server
                    # MUST NOT send 0 after sending 1). We just
                    # latch whatever the peer sent so the
                    # client-side facade can read it.
                    self.peer_enable_connect_protocol = v != 0
                i += 6
            out.append(self._make_settings(True))
            return out^

        if ft == FrameType.PING().value:
            if f.header.flags.has(FrameFlags.ACK()):
                return out^
            var ack = Frame()
            ack.header.type = FrameType.PING()
            ack.header.flags = FrameFlags(FrameFlags.ACK())
            ack.header.stream_id = 0
            ack.payload = f.payload.copy()
            out.append(ack^)
            return out^

        if ft == FrameType.WINDOW_UPDATE().value:
            var inc = (
                (Int(f.payload[0]) << 24)
                | (Int(f.payload[1]) << 16)
                | (Int(f.payload[2]) << 8)
                | Int(f.payload[3])
            ) & 0x7FFFFFFF
            if inc == 0:
                # sec 6.9: zero is a connection error on stream 0 and a
                # stream error otherwise.
                if sid == 0:
                    return self._conn_error(
                        Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                )
                return out^
            if sid == 0:
                # sec 6.9.1: a window may not grow past 2^31-1.
                if self.send_window + inc > _MAX_WINDOW:
                    return self._conn_error(
                        Http2ErrorCode.FLOW_CONTROL_ERROR().value
                    )
                self.send_window += inc
            else:
                if sid not in self.streams:
                    # sec 5.1: WINDOW_UPDATE on an idle stream.
                    if sid > self.last_peer_stream_id:
                        return self._conn_error(
                            Http2ErrorCode.PROTOCOL_ERROR().value
                        )
                    return out^
                var s = self.streams[sid].copy()
                if s.send_window + inc > _MAX_WINDOW:
                    out.append(
                        self._rst_stream_frame(
                            sid, Http2ErrorCode.FLOW_CONTROL_ERROR().value
                        )
                    )
                    s.state = StreamState.CLOSED()
                    self._put_stream(s^)
                    return out^
                s.send_window += inc
                self._put_stream(s^)
            return out^

        if ft == FrameType.HEADERS().value:
            if f.header.stream_id == 0:
                raise Error("h2: HEADERS on stream 0")
            # sec 5.1: a stream the peer already ended, or one it has
            # closed, must not carry another HEADERS. A second HEADERS
            # on an open stream is trailers and must end the stream.
            if f.header.stream_id in self.streams:
                var prev = self.streams[f.header.stream_id].copy()
                var st = prev.state.value
                if st == StreamState.CLOSED().value:
                    return self._conn_error(
                        Http2ErrorCode.STREAM_CLOSED().value
                    )
                if (
                    not self.is_client
                    and st == StreamState.HALF_CLOSED_REMOTE().value
                ):
                    return self._conn_error(
                        Http2ErrorCode.STREAM_CLOSED().value
                    )
                if (
                    not self.is_client
                    and prev.headers_complete
                    and not f.header.flags.has(FrameFlags.END_STREAM())
                ):
                    # sec 8.1: trailers must carry END_STREAM.
                    out.append(
                        self._rst_stream_frame(
                            f.header.stream_id,
                            Http2ErrorCode.PROTOCOL_ERROR().value,
                        )
                    )
                    prev.state = StreamState.CLOSED()
                    self._put_stream(prev^)
                    return out^
            # sec 5.1.2: refuse a stream past the concurrency limit we
            # advertised instead of serving it.
            if (
                not self.is_client
                and f.header.stream_id not in self.streams
                and self.max_concurrent_streams > 0
                and self._active_stream_count() >= self.max_concurrent_streams
            ):
                out.append(
                    self._rst_stream_frame(
                        f.header.stream_id,
                        Http2ErrorCode.REFUSED_STREAM().value,
                    )
                )
                return out^
            # sec 5.3.1: the priority prefix must not name this stream.
            if f.header.flags.has(FrameFlags.PRIORITY()):
                var off = 1 if f.header.flags.has(FrameFlags.PADDED()) else 0
                if len(f.payload) >= off + 4:
                    var hdep = (
                        (Int(f.payload[off]) << 24)
                        | (Int(f.payload[off + 1]) << 16)
                        | (Int(f.payload[off + 2]) << 8)
                        | Int(f.payload[off + 3])
                    ) & 0x7FFFFFFF
                    if hdep == f.header.stream_id:
                        return self._conn_error(
                            Http2ErrorCode.PROTOCOL_ERROR().value
                        )
            var frag: List[UInt8]
            try:
                frag = self._strip_pad_and_priority(f, True)
            except:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            self.header_block = frag^
            self.header_block_end_stream = f.header.flags.has(
                FrameFlags.END_STREAM()
            )
            var s = self._ensure_stream(f.header.stream_id)
            s.continuation_count = 0
            self._put_stream(s^)
            if not f.header.flags.has(FrameFlags.END_HEADERS()):
                # Block stays open; only CONTINUATION on this stream may
                # follow (sec 6.10).
                self.continuing_stream = f.header.stream_id
                return out^
            return self._commit_header_block(f.header.stream_id)

        if ft == FrameType.CONTINUATION().value:
            # Reaching here means no block is open: a CONTINUATION that
            # matched ``continuing_stream`` was handled above.
            return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)

        if ft == FrameType.DATA().value:
            if sid not in self.streams:
                # sec 5.1: DATA on a stream that was never opened is
                # PROTOCOL_ERROR; on one already gone, STREAM_CLOSED.
                if sid > self.last_peer_stream_id:
                    return self._conn_error(
                        Http2ErrorCode.PROTOCOL_ERROR().value
                    )
                return self._conn_error(Http2ErrorCode.STREAM_CLOSED().value)
            var s = self.streams[sid].copy()
            var st = s.state.value
            if (
                st == StreamState.CLOSED().value
                or st == StreamState.HALF_CLOSED_REMOTE().value
            ):
                # The peer already ended its half; more DATA is not
                # allowed to arrive on it.
                return self._conn_error(Http2ErrorCode.STREAM_CLOSED().value)
            var body: List[UInt8]
            try:
                body = self._strip_pad_and_priority(f, False)
            except:
                return self._conn_error(Http2ErrorCode.PROTOCOL_ERROR().value)
            # Flow control is accounted on the whole frame payload,
            # padding included (sec 6.9.1).
            s.recv_window -= len(f.payload)
            if s.recv_window < 0:
                out.append(
                    self._rst_stream_frame(
                        sid, Http2ErrorCode.FLOW_CONTROL_ERROR().value
                    )
                )
                s.state = StreamState.CLOSED()
                self._put_stream(s^)
                return out^
            for j in range(len(body)):
                s.data.append(body[j])
            if f.header.flags.has(FrameFlags.END_STREAM()):
                # sec 8.1.2.6: content-length must match what arrived.
                if s.content_length >= 0 and len(s.data) != s.content_length:
                    out.append(
                        self._rst_stream_frame(
                            sid, Http2ErrorCode.PROTOCOL_ERROR().value
                        )
                    )
                    s.state = StreamState.CLOSED()
                    self._put_stream(s^)
                    return out^
                s.data_complete = True
                # Client-side: a stream we've already half-closed
                # locally that the peer ends fully closes.
                if (
                    self.is_client
                    and s.state.value == StreamState.HALF_CLOSED_LOCAL().value
                ):
                    s.state = StreamState.CLOSED()
                else:
                    s.state = StreamState.HALF_CLOSED_REMOTE()
            self._put_stream(s^)
            # Send a generous WINDOW_UPDATE to keep things flowing.
            if len(f.payload) > 0:
                var wu = Frame()
                wu.header.type = FrameType.WINDOW_UPDATE()
                wu.header.stream_id = 0
                var n = len(f.payload)
                wu.payload = List[UInt8]()
                wu.payload.append(UInt8((n >> 24) & 0x7F))
                wu.payload.append(UInt8((n >> 16) & 0xFF))
                wu.payload.append(UInt8((n >> 8) & 0xFF))
                wu.payload.append(UInt8(n & 0xFF))
                out.append(wu^)
            return out^

        if ft == FrameType.GOAWAY().value:
            self.goaway_received = True
            return out^

        if ft == FrameType.RST_STREAM().value:
            if f.header.stream_id in self.streams:
                var s = self.streams[f.header.stream_id].copy()
                s.state = StreamState.CLOSED()
                self._put_stream(s^)
                self.reset_streams.append(f.header.stream_id)
            # Rapid-reset mitigation (CVE-2023-44487): a flood of
            # RST_STREAMs forces stream churn without tripping the
            # concurrency limit. Past the lifetime threshold, GOAWAY
            # the connection with ENHANCE_YOUR_CALM (once).
            self.rst_stream_count += 1
            if (
                self.rst_stream_count > _RST_FLOOD_THRESHOLD
                and not self.goaway_sent
            ):
                self.goaway_sent = True
                out.append(
                    self._goaway_frame(
                        f.header.stream_id,
                        Http2ErrorCode.ENHANCE_YOUR_CALM().value,
                    )
                )
            return out^

        if ft == FrameType.PRIORITY().value:
            # Accept and ignore (RFC 9113 §5.3.2 deprecated).
            return out^

        # Unknown frame types MUST be ignored (RFC 9113 §4.1).
        return out^

    def make_response(
        mut self,
        sid: StreamId,
        status: Int,
        headers: Span[HpackHeader, _],
        body: Span[UInt8, _],
    ) -> List[Frame]:
        """Produce ``HEADERS [+ DATA]`` frames for ``sid``."""
        var frames = List[Frame]()
        # Build pseudo-header :status, then real headers.
        var hh = List[HpackHeader]()
        hh.append(HpackHeader(":status", String(status)))
        for i in range(len(headers)):
            hh.append(headers[i].copy())
        var enc = self.hpack_encoder.encode(Span[HpackHeader, _](hh))
        var hf = Frame()
        hf.header.type = FrameType.HEADERS()
        hf.header.stream_id = sid
        var flags = FrameFlags.END_HEADERS()
        if len(body) == 0:
            flags |= FrameFlags.END_STREAM()
        hf.header.flags = FrameFlags(flags)
        hf.payload = enc^
        frames.append(hf^)
        if len(body) > 0:
            var df = Frame()
            df.header.type = FrameType.DATA()
            df.header.stream_id = sid
            df.header.flags = FrameFlags(FrameFlags.END_STREAM())
            var pl = List[UInt8](capacity=len(body))
            for i in range(len(body)):
                pl.append(body[i])
            df.payload = pl^
            frames.append(df^)
        return frames^

    def make_response_with_trailers(
        mut self,
        sid: StreamId,
        status: Int,
        headers: Span[HpackHeader, _],
        body: Span[UInt8, _],
        trailers: Span[HpackHeader, _],
    ) -> List[Frame]:
        """Produce ``HEADERS [+ DATA] + trailing-HEADERS`` frames for ``sid``.

        Unlike :meth:`make_response`, END_STREAM rides on the trailing
        HEADERS block (RFC 9113 6.10), not on the initial HEADERS or the
        DATA frame. This is the gRPC-over-HTTP/2 response shape: the
        ``grpc-status`` (and optional ``grpc-message``) live in trailers
        that close the stream. The trailing block carries only regular
        fields -- pseudo-headers are forbidden after the leading block,
        so the caller must pass non-colon names only.

        If ``trailers`` is empty this degrades to plain
        :meth:`make_response` semantics so callers can route every
        response through one path.
        """
        if len(trailers) == 0:
            return self.make_response(sid, status, headers, body)
        var frames = List[Frame]()
        # Leading HEADERS: :status + real headers, never END_STREAM
        # (a body and/or the trailers still follow).
        var hh = List[HpackHeader]()
        hh.append(HpackHeader(":status", String(status)))
        for i in range(len(headers)):
            hh.append(headers[i].copy())
        var enc = self.hpack_encoder.encode(Span[HpackHeader, _](hh))
        var hf = Frame()
        hf.header.type = FrameType.HEADERS()
        hf.header.stream_id = sid
        hf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
        hf.payload = enc^
        frames.append(hf^)
        if len(body) > 0:
            var df = Frame()
            df.header.type = FrameType.DATA()
            df.header.stream_id = sid
            # No END_STREAM: the trailing HEADERS below closes the stream.
            df.header.flags = FrameFlags()
            var pl = List[UInt8](capacity=len(body))
            for i in range(len(body)):
                pl.append(body[i])
            df.payload = pl^
            frames.append(df^)
        var tl = List[HpackHeader]()
        for i in range(len(trailers)):
            tl.append(trailers[i].copy())
        var tenc = self.hpack_encoder.encode(Span[HpackHeader, _](tl))
        var tf = Frame()
        tf.header.type = FrameType.HEADERS()
        tf.header.stream_id = sid
        tf.header.flags = FrameFlags(
            FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
        )
        tf.payload = tenc^
        frames.append(tf^)
        return frames^

    def make_stream_headers(
        mut self,
        sid: StreamId,
        status: Int,
        headers: Span[HpackHeader, _],
    ) -> Frame:
        """Leading HEADERS for an incremental streaming response.

        Carries ``:status`` + real headers with END_HEADERS but never
        END_STREAM -- DATA frames (and possibly trailing HEADERS) follow
        on later writable edges. Companion to :meth:`make_response` for
        the h2 server-streaming path (K1).
        """
        var hh = List[HpackHeader]()
        hh.append(HpackHeader(":status", String(status)))
        for i in range(len(headers)):
            hh.append(headers[i].copy())
        var enc = self.hpack_encoder.encode(Span[HpackHeader, _](hh))
        var hf = Frame()
        hf.header.type = FrameType.HEADERS()
        hf.header.stream_id = sid
        hf.header.flags = FrameFlags(FrameFlags.END_HEADERS())
        hf.payload = enc^
        return hf^

    def make_stream_trailers(
        mut self,
        sid: StreamId,
        trailers: Span[HpackHeader, _],
    ) -> Frame:
        """Trailing HEADERS closing a streaming response (RFC 9113 6.10).

        END_HEADERS | END_STREAM ride on this block; only regular field
        names are legal after the leading block.
        """
        var tl = List[HpackHeader]()
        for i in range(len(trailers)):
            tl.append(trailers[i].copy())
        var tenc = self.hpack_encoder.encode(Span[HpackHeader, _](tl))
        var tf = Frame()
        tf.header.type = FrameType.HEADERS()
        tf.header.stream_id = sid
        tf.header.flags = FrameFlags(
            FrameFlags.END_HEADERS() | FrameFlags.END_STREAM()
        )
        tf.payload = tenc^
        return tf^
