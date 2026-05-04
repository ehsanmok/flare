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
- :class:`H2Error` — typed connection / stream errors with their
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


# ── H2 error codes (RFC 9113 §7) ────────────────────────────────────────


struct H2ErrorCode(Copyable, Defaultable, Movable):
    """One of the 14 RFC 9113 §7 error codes."""

    var value: Int

    def __init__(out self):
        self.value = 0

    def __init__(out self, v: Int):
        self.value = v

    @staticmethod
    def NO_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x0)

    @staticmethod
    def PROTOCOL_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x1)

    @staticmethod
    def INTERNAL_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x2)

    @staticmethod
    def FLOW_CONTROL_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x3)

    @staticmethod
    def SETTINGS_TIMEOUT() -> H2ErrorCode:
        return H2ErrorCode(0x4)

    @staticmethod
    def STREAM_CLOSED() -> H2ErrorCode:
        return H2ErrorCode(0x5)

    @staticmethod
    def FRAME_SIZE_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x6)

    @staticmethod
    def REFUSED_STREAM() -> H2ErrorCode:
        return H2ErrorCode(0x7)

    @staticmethod
    def CANCEL() -> H2ErrorCode:
        return H2ErrorCode(0x8)

    @staticmethod
    def COMPRESSION_ERROR() -> H2ErrorCode:
        return H2ErrorCode(0x9)


struct H2Error(Copyable, Defaultable, Movable):
    """A typed HTTP/2 error. ``stream_id == 0`` means connection error."""

    var code: H2ErrorCode
    var stream_id: Int
    var debug: String

    def __init__(out self):
        self.code = H2ErrorCode()
        self.stream_id = 0
        self.debug = ""

    def __init__(
        out self, var code: H2ErrorCode, stream_id: Int, var debug: String
    ):
        self.code = code^
        self.stream_id = stream_id
        self.debug = debug^


# ── Stream state machine (RFC 9113 §5.1) ────────────────────────────────


struct StreamState(Copyable, Defaultable, Movable):
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


struct Stream(Copyable, Defaultable, Movable):
    """Per-stream record."""

    var id: StreamId
    var state: StreamState
    var headers: List[HpackHeader]
    var data: List[UInt8]
    var send_window: Int
    var recv_window: Int
    var headers_complete: Bool
    var data_complete: Bool
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
        self.extended_connect_protocol = ""


# ── Connection ──────────────────────────────────────────────────────────


struct Connection(Copyable, Defaultable, Movable):
    """Per-connection HTTP/2 state."""

    var streams: Dict[StreamId, Stream]
    var hpack_decoder: HpackDecoder
    var hpack_encoder: HpackEncoder
    var max_frame_size: Int
    var max_concurrent_streams: Int
    var initial_window_size: Int
    var max_header_list_size: Int
    """SETTINGS_MAX_HEADER_LIST_SIZE (RFC 9113 §6.5.2). ``0`` means
    unset / advertise no cap (the RFC default). v0.7 ``Http2Config``
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

    def __init__(out self):
        self.streams = Dict[StreamId, Stream]()
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

    def _make_settings(self, ack: Bool) -> Frame:
        """Server-side initial SETTINGS frame (or empty ACK).

        Emits one (id, value) pair for every server SETTING that
        differs from its RFC 9113 / RFC 7541 protocol default. The
        v0.6 default ``Connection()`` shape (``max_concurrent_streams
        = 100``, all others at RFC defaults) emits a single
        ``SETTINGS_MAX_CONCURRENT_STREAMS = 100`` pair so the wire
        bytes stay byte-for-byte identical to the v0.6 driver
        (``test_preface_only_emits_settings`` still passes
        unchanged). ``H2Connection.with_config(Http2Config(...))``
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

    def handle_frame(mut self, var f: Frame) raises -> List[Frame]:
        """Apply ``f`` to the connection state, return reply frames."""
        var out = List[Frame]()
        var ft = f.header.type.value

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
                if id == 0x4:  # SETTINGS_INITIAL_WINDOW_SIZE
                    self.initial_window_size = v
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
            if len(f.payload) != 4:
                raise Error("h2: WINDOW_UPDATE payload != 4")
            var inc = (
                (Int(f.payload[0]) << 24)
                | (Int(f.payload[1]) << 16)
                | (Int(f.payload[2]) << 8)
                | Int(f.payload[3])
            ) & 0x7FFFFFFF
            if inc == 0:
                raise Error("h2: WINDOW_UPDATE increment 0")
            if f.header.stream_id == 0:
                self.send_window += inc
            else:
                if f.header.stream_id in self.streams:
                    var s = self.streams[f.header.stream_id].copy()
                    s.send_window += inc
                    self._put_stream(s^)
            return out^

        if ft == FrameType.HEADERS().value:
            if f.header.stream_id == 0:
                raise Error("h2: HEADERS on stream 0")
            var hdrs = self.hpack_decoder.decode(Span[UInt8, _](f.payload))
            var s = self._ensure_stream(f.header.stream_id)
            for j in range(len(hdrs)):
                s.headers.append(hdrs[j].copy())
                # RFC 8441 §4: capture the ``:protocol``
                # pseudo-header on Extended CONNECT so the
                # higher-level dispatcher (``H2Connection`` ->
                # WsServer bridge) can route it. We snapshot
                # eagerly here rather than scanning the headers
                # list later because the field stays
                # well-defined even if a future trailers feature
                # mutates ``s.headers``.
                if hdrs[j].name == ":protocol":
                    s.extended_connect_protocol = hdrs[j].value
            if f.header.flags.has(FrameFlags.END_HEADERS()):
                s.headers_complete = True
            # Stream-state transition on HEADERS receipt depends on
            # whose perspective we're driving (RFC 9113 §5.1):
            #  * Server-side (``is_client = False``, default): receiving
            #    HEADERS opens an inbound request stream;
            #    ``+ END_STREAM`` puts it in HALF_CLOSED_REMOTE
            #    (request fully buffered, response still to come).
            #  * Client-side (``is_client = True``): we sent HEADERS
            #    first (transitioning IDLE -> OPEN or
            #    HALF_CLOSED_LOCAL); receiving HEADERS is the response
            #    headers. ``+ END_STREAM`` from a HALF_CLOSED_LOCAL
            #    stream closes it; from OPEN it transitions to
            #    HALF_CLOSED_REMOTE (server still has DATA to send,
            #    but typically a HEADERS-only response carries
            #    END_STREAM directly).
            if f.header.flags.has(FrameFlags.END_STREAM()):
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
                    # We've sent END_STREAM, peer responded with HEADERS
                    # but hasn't ended the stream yet (DATA frames to
                    # follow). Stay in HALF_CLOSED_LOCAL.
                    pass
                else:
                    s.state = StreamState.OPEN()
            self._put_stream(s^)
            return out^

        if ft == FrameType.DATA().value:
            if f.header.stream_id == 0:
                raise Error("h2: DATA on stream 0")
            if f.header.stream_id not in self.streams:
                raise Error("h2: DATA on unknown stream")
            var s = self.streams[f.header.stream_id].copy()
            for j in range(len(f.payload)):
                s.data.append(f.payload[j])
            s.recv_window -= len(f.payload)
            if f.header.flags.has(FrameFlags.END_STREAM()):
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
            return out^

        if ft == FrameType.PRIORITY().value:
            # Accept and ignore (RFC 9113 §5.3.2 deprecated).
            return out^

        if ft == FrameType.CONTINUATION().value:
            if f.header.stream_id == 0:
                raise Error("h2: CONTINUATION on stream 0")
            if f.header.stream_id not in self.streams:
                raise Error("h2: CONTINUATION on unknown stream")
            var hdrs = self.hpack_decoder.decode(Span[UInt8, _](f.payload))
            var s = self.streams[f.header.stream_id].copy()
            for j in range(len(hdrs)):
                s.headers.append(hdrs[j].copy())
            if f.header.flags.has(FrameFlags.END_HEADERS()):
                s.headers_complete = True
            self._put_stream(s^)
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
