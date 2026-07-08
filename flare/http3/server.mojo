"""``flare.http3.server`` -- HTTP/3 server connection driver.

Wraps the sans-I/O HTTP/3 codec primitives
(:class:`flare.http3.Http3RequestReader`,
:func:`flare.http3.encode_response_headers`) and the QUIC connection
driver (:class:`flare.quic.server.QuicConnection`) into a per-
connection HTTP/3 server.

## Stream layout (RFC 9114 §6)

HTTP/3 over QUIC uses four families of streams:

* **Bidirectional request streams** -- one per request/response
  exchange. The client opens, sends HEADERS + DATA frames; the
  server replies on the same stream with HEADERS + DATA + (FIN).
* **Unidirectional control stream** (type 0x00) -- exactly one
  per direction; carries SETTINGS first, then GOAWAY /
  MAX_PUSH_ID over the connection lifetime.
* **Unidirectional push stream** (type 0x01) -- server-initiated.
  Not implemented (RFC 9114 deprecates push as of revision 9).
* **Unidirectional QPACK encoder stream** (type 0x02) +
  **decoder stream** (type 0x03) -- carry dynamic-table
  instructions. The driver mirrors the peer encoder's inserts
  into a per-connection dynamic table (RFC 9204) so request
  field sections referencing dynamic entries decode, and emits
  Insert Count Increment back on the decoder stream. Dynamic-
  table use is gated on the ``qpack_max_table_capacity`` the
  SETTINGS advertise: the default (0) keeps static-only behavior.

## What ships here

- :class:`Http3Config` -- per-connection HTTP/3 config:
  max field section size, max blocked streams, the GOAWAY
  threshold above which the server stops accepting new
  request streams.
- :class:`Http3Connection` -- the per-connection driver carrier.
  Owns the per-stream :class:`Http3RequestReader` instances (keyed
  by QUIC stream ID), the per-stream accumulated request state,
  and the per-stream pending outbound bytes.
- :class:`Http3StreamType` -- the unidirectional-stream type
  codepoints from RFC 9114 §6.2.

The driver is sans-I/O: the QUIC reactor feeds reassembled stream
chunks in via :meth:`Http3Connection.feed_stream_chunk` and drains
pending outbound frames via :meth:`Http3Connection.take_response_frames`.
The Handler dispatch sits on the QUIC reactor side; the H3
layer surfaces the Request once it's fully reassembled and
the reactor calls :meth:`Http3Connection.emit_response` once the
Handler returns.

References:
- RFC 9114 "HTTP/3".
- RFC 9204 "QPACK: Field Compression for HTTP/3".
"""

from std.collections import Dict, List, Optional
from std.memory import ArcPointer, Span

from flare.http3.frame import (
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_SETTINGS,
    H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
    H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
    H3_SETTINGS_QPACK_BLOCKED_STREAMS,
    H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
    Http3Setting,
    decode_http3_settings,
    encode_http3_frame,
    encode_http3_settings,
)
from flare.http3.request_reader import (
    H3_REQUEST_STATE_DONE,
    Http3RequestEventHandler,
    Http3RequestReader,
    feed_into,
)
from flare.http3.response_writer import (
    encode_response_data,
    encode_response_headers,
)
from flare.http.wire import Request, Response
from flare.qpack import QpackHeader
from flare.qpack.dynamic import (
    QpackDynamicTable,
    apply_encoder_instructions_partial,
    encode_insert_count_increment,
)
from flare.quic.varint import decode_varint, encode_varint


# ── Unidirectional stream type codepoints (RFC 9114 §6.2) ───────────────


struct Http3StreamType:
    """RFC 9114 §6.2 unidirectional stream types.

    Each uni stream's first varint is the stream type; the reader
    dispatches on this varint to the matching internal state
    machine (control / push / qpack-enc / qpack-dec).
    """

    comptime CONTROL: Int = 0x00
    """RFC 9114 §6.2.1 -- control stream. Carries SETTINGS,
    GOAWAY, MAX_PUSH_ID. Exactly one per direction."""

    comptime PUSH: Int = 0x01
    """RFC 9114 §6.2.2 -- push stream. Server-initiated.
    Deprecated as of RFC 9114 revision 9; this codepoint is
    carried so the reader can reject incoming push streams with
    H3_STREAM_CREATION_ERROR."""

    comptime QPACK_ENCODER: Int = 0x02
    """RFC 9204 §4.2 -- QPACK encoder stream. Carries dynamic-
    table insert instructions."""

    comptime QPACK_DECODER: Int = 0x03
    """RFC 9204 §4.2 -- QPACK decoder stream. Carries
    section-acknowledgement + stream-cancellation instructions."""


# ── Configuration carrier ──────────────────────────────────────────────


struct Http3Config(Copyable, Defaultable, Movable):
    """Per-connection HTTP/3 settings.

    The server advertises these via the control stream's SETTINGS
    frame (RFC 9114 §7.2.4). Production defaults match the values
    the OpenAPI gen + the cookbook examples expect.
    """

    var max_field_section_size: UInt64
    """RFC 9114 §7.2.4.2 -- maximum total size (in bytes) the
    server will accept for a single field section. Default:
    65536. The reader rejects oversize header blocks with
    H3_EXCESSIVE_LOAD."""

    var qpack_max_table_capacity: UInt64
    """RFC 9204 §3.2.2 -- maximum bytes the server is willing to
    spend on the QPACK dynamic table. Default 0 means static-
    table-only mode; the SETTINGS we emit tell the peer not to
    send dynamic-table inserts."""

    var qpack_blocked_streams: UInt64
    """RFC 9204 §3.2.3 -- maximum streams the server is willing
    to leave blocked on QPACK dynamic-table insertions. Default
    0 (paired with qpack_max_table_capacity=0)."""

    var enable_connect_protocol: Bool
    """RFC 9220 §3 -- whether to advertise CONNECT-Protocol
    support for WebSocket / WebTransport bootstrapping. Default
    True since the rest of flare supports CONNECT semantics."""

    var goaway_threshold_streams: UInt64
    """Local soft cap on the stream count above which the server
    emits GOAWAY and refuses new request streams. Default
    UINT64_MAX (effectively no cap; mirrors the H2 server's
    behaviour)."""

    def __init__(out self):
        self.max_field_section_size = UInt64(65536)
        self.qpack_max_table_capacity = UInt64(0)
        self.qpack_blocked_streams = UInt64(0)
        self.enable_connect_protocol = True
        self.goaway_threshold_streams = UInt64((1 << 63) - 1)


# ── Per-stream accumulator + event collector ──────────────────────────


struct _Http3StreamState(Copyable, Defaultable, Movable):
    """Per-bidirectional-stream H3 server state.

    Carries everything that accumulates over the lifetime of a
    request stream: the reader's frame-by-frame state machine,
    the reassembled request bytes/headers, the pending outbound
    response bytes, and the protocol-level flags the reactor
    consults to decide when a stream is ready for handler
    dispatch + when it's safe to retire.
    """

    var reader: Http3RequestReader
    """Sans-I/O frame reader. ``feed_stream_chunk`` advances this
    one frame at a time."""

    var inbox: List[UInt8]
    """Inbound bytes accumulated across stream-chunk arrivals.
    The frame reader can require multiple chunks before a single
    frame is complete (NEEDS_MORE)."""

    var headers: List[QpackHeader]
    """Decoded request HEADERS. Populated by the first
    ``on_headers`` callback."""

    var body: List[UInt8]
    """Reassembled request body across one or more ``on_data``
    callbacks."""

    var trailers: List[QpackHeader]
    """Decoded trailing HEADERS (empty if the client didn't send
    trailers)."""

    var headers_complete: Bool
    """Set after the first ``on_headers`` callback fires. The
    reactor uses this to decide when a stream is ready for
    handler dispatch even when the body is still streaming."""

    var fin_received: Bool
    """Set when the QUIC stream signals end-of-stream (the FIN
    bit on the last STREAM frame). The reactor calls
    :meth:`Http3Connection.signal_end_of_stream` to flip this; the
    sans-I/O reader has no FIN signal of its own."""

    var protocol_error: String
    """Empty when the reader hasn't hit a protocol error; the
    error message on ``on_protocol_error``. The reactor maps
    this to an H3_FRAME_UNEXPECTED / QPACK_DECOMPRESSION_FAILED
    stream-level error to the QUIC peer."""

    var unknown_frames: List[UInt64]
    """List of unknown frame-type identifiers the reader saw
    (RFC 9114 §7.2.8 says receivers MUST ignore unknown frames;
    we keep the list so the reactor can optionally log them)."""

    var outbox: List[UInt8]
    """Pending outbound response bytes produced by
    :meth:`Http3Connection.emit_response`. Drained by
    :meth:`Http3Connection.take_response_frames`."""

    var response_emitted: Bool
    """Set when ``emit_response`` has been called for this
    stream. The reactor flips this False between requests if
    pipelining over the same QUIC stream is enabled (RFC 9114
    forbids HTTP/3 pipelining on a single bidi stream, so this
    stays True until the stream closes)."""

    var request_taken: Bool
    """Set when the reactor has called :meth:`take_request`.
    Guards against the reactor double-dispatching the same
    request through a Handler."""

    def __init__(out self):
        self.reader = Http3RequestReader.new()
        self.inbox = List[UInt8]()
        self.headers = List[QpackHeader]()
        self.body = List[UInt8]()
        self.trailers = List[QpackHeader]()
        self.headers_complete = False
        self.fin_received = False
        self.protocol_error = String("")
        self.unknown_frames = List[UInt64]()
        self.outbox = List[UInt8]()
        self.response_emitted = False
        self.request_taken = False

    @staticmethod
    def with_limits(max_field_section_bytes: UInt64) -> Self:
        var out = Self()
        out.reader = Http3RequestReader.new(max_field_section_bytes)
        return out^


@fieldwise_init
struct _Http3EventCollector(Http3RequestEventHandler, Movable):
    """Internal handler the H3 server passes to ``feed_into``.

    Records callback invocations into typed buffers; the
    surrounding :meth:`Http3Connection.feed_stream_chunk` drains
    these into the per-stream :class:`_Http3StreamState` after the
    frame-reader returns. Splitting the recorder from the
    state-update step keeps the event-handler trait surface
    small (no driver-context plumbing through callbacks)."""

    var headers: List[QpackHeader]
    """Buffered headers from the most-recent ``on_headers``
    callback. Empty unless the reader fired ``on_headers``
    during the current ``feed_into`` invocation."""

    var headers_fired: Bool
    """True iff the current ``feed_into`` fired ``on_headers``."""

    var data: List[UInt8]
    """Buffered body bytes from the most-recent ``on_data``
    callback. Empty unless the reader fired ``on_data``."""

    var data_fired: Bool
    """True iff the current ``feed_into`` fired ``on_data``."""

    var trailers: List[QpackHeader]
    """Buffered trailers from the most-recent ``on_trailers``
    callback."""

    var trailers_fired: Bool
    """True iff the current ``feed_into`` fired ``on_trailers``."""

    var unknown_frame_type: UInt64
    """Most-recent unknown-frame type id from
    ``on_unknown_frame``."""

    var unknown_fired: Bool
    """True iff the current ``feed_into`` fired
    ``on_unknown_frame``."""

    var error_message: String
    """Protocol-error message from ``on_protocol_error``."""

    var error_fired: Bool
    """True iff the current ``feed_into`` fired
    ``on_protocol_error``."""

    @staticmethod
    def new() -> Self:
        return Self(
            headers=List[QpackHeader](),
            headers_fired=False,
            data=List[UInt8](),
            data_fired=False,
            trailers=List[QpackHeader](),
            trailers_fired=False,
            unknown_frame_type=UInt64(0),
            unknown_fired=False,
            error_message=String(""),
            error_fired=False,
        )

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        self.headers = headers.copy()
        self.headers_fired = True

    def on_data(mut self, data: List[UInt8]) raises:
        self.data = data.copy()
        self.data_fired = True

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        self.trailers = trailers.copy()
        self.trailers_fired = True

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        self.unknown_frame_type = type_id
        self.unknown_fired = True

    def on_protocol_error(mut self, message: String) raises:
        self.error_message = message
        self.error_fired = True


# ── Per-connection driver ──────────────────────────────────────────────


struct Http3Connection(Copyable, Defaultable, Movable):
    """Per-connection HTTP/3 server driver.

    Owned by the QUIC reactor. One instance per QUIC connection
    that negotiated the ``h3`` ALPN identifier. The driver:

    * Tracks per-bidirectional-stream :class:`_Http3StreamState`
      instances keyed by QUIC stream ID. Each carrier owns the
      sans-I/O frame reader, the accumulated request bytes /
      headers / body / trailers, and the pending outbound
      response bytes.
    * Carries the SETTINGS the server announced + the client
      announced.
    * Tracks the control-stream lifecycle (whether the peer's
      SETTINGS arrived yet, whether GOAWAY was emitted).
    * Carries the QPACK state, including a per-connection dynamic
      table (RFC 9204) mirroring the peer encoder's inserts when
      ``qpack_max_table_capacity`` is advertised non-zero.

    The driver is sans-I/O: the QUIC reactor feeds reassembled
    stream chunks in via :meth:`feed_stream_chunk` and drains
    pending outbound frames via :meth:`take_response_frames`.
    The Handler dispatch happens on the reactor side -- the H3
    layer surfaces the assembled :class:`Request` via
    :meth:`take_request` and accepts the matching
    :class:`Response` via :meth:`emit_response`.
    """

    var config: Http3Config
    """Local configuration -- the values the server advertises
    via SETTINGS."""

    var peer_settings_received: Bool
    """Whether the peer's SETTINGS frame has arrived on the
    control stream yet. Until True, the driver buffers any
    application traffic that would depend on the negotiated
    field-section-size + QPACK parameters."""

    var goaway_emitted: Bool
    """Whether the server has emitted GOAWAY. Once True, new
    request streams are rejected with H3_REQUEST_CANCELLED."""

    var streams: Dict[Int, _Http3StreamState]
    """Per-stream state carriers. Keys are QUIC stream IDs.
    Streams are removed via :meth:`close_request_stream` once
    the response is fully drained from the outbox."""

    var control_stream_id: Int
    """QUIC stream ID of the locally-opened control stream. -1
    until the driver opens the control stream during connection
    setup."""

    var qpack_encoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK encoder
    stream. -1 in static-only mode."""

    var qpack_decoder_stream_id: Int
    """QUIC stream ID of the locally-opened QPACK decoder
    stream. -1 in static-only mode."""

    var peer_control_stream_id: Int
    """QUIC stream ID of the peer's control stream once observed.
    -1 until the peer's uni-stream type prefix (0x00) is read.
    RFC 9114 §6.2.1: at most one peer control stream per
    direction; a second control stream is H3_STREAM_CREATION_ERROR."""

    var peer_qpack_encoder_stream_id: Int
    """RFC 9204 §4.2 -- peer's QPACK encoder uni-stream. -1 until
    the type prefix (0x02) arrives."""

    var peer_qpack_decoder_stream_id: Int
    """RFC 9204 §4.2 -- peer's QPACK decoder uni-stream. -1 until
    the type prefix (0x03) arrives."""

    var peer_settings_max_field_section_size: UInt64
    """RFC 9114 §7.2.4.2 -- peer-advertised maximum field section
    size. UINT64_MAX until the peer's SETTINGS frame arrives."""

    var peer_settings_qpack_max_table_capacity: UInt64
    """RFC 9204 §3.2.2 -- peer-advertised QPACK dynamic-table
    capacity. 0 until the peer's SETTINGS frame arrives + only
    non-zero if the peer opts into dynamic-table inserts."""

    var peer_settings_qpack_blocked_streams: UInt64
    """RFC 9204 §3.2.3 -- peer-advertised blocked-streams budget.
    0 until the peer's SETTINGS frame arrives."""

    var peer_settings_enable_connect_protocol: Bool
    """RFC 9220 §3 -- whether the peer advertises CONNECT-
    Protocol support."""

    var peer_goaway_max_stream_id: UInt64
    """RFC 9114 §5.2 -- peer-emitted GOAWAY identifier. UINT64_MAX
    means no GOAWAY has arrived yet; once a GOAWAY arrives this
    holds the maximum stream id the peer will accept. Stream ids
    >= this value are aborted by the H3 layer."""

    var peer_uni_buffers: Dict[Int, List[UInt8]]
    """Per-uni-stream inbound buffer. The stream-type varint may
    span multiple chunks (it's at most 8 bytes but the QUIC
    layer may split smaller); we buffer until the type is
    resolvable. Once resolved, the buffer carries the remainder
    of the stream payload."""

    var peer_uni_kinds: Dict[Int, Int]
    """Per-uni-stream resolved type: 0 (control), 1 (push),
    2 (qpack-enc), 3 (qpack-dec), -1 (unknown grease /
    reserved). Empty means the type varint has not been
    resolved yet on that stream."""

    var qpack_table: ArcPointer[QpackDynamicTable]
    """RFC 9204 QPACK dynamic table mirroring the peer encoder's
    insert log. Shared (by ``ArcPointer``) with every per-stream
    reader so a request HEADERS field section can resolve dynamic
    references the peer streamed over its encoder stream. Capacity
    is 0 (static-only) unless :attr:`config` advertises a non-zero
    ``qpack_max_table_capacity``."""

    var pending_qpack_increment: Int
    """Count of peer inserts applied since the last Insert Count
    Increment we emitted on our QPACK decoder stream (RFC 9204
    §4.4.3). Drained by :meth:`take_qpack_decoder_frames`."""

    def __init__(out self):
        self.config = Http3Config()
        self.peer_settings_received = False
        self.goaway_emitted = False
        self.streams = Dict[Int, _Http3StreamState]()
        self.control_stream_id = -1
        self.qpack_encoder_stream_id = -1
        self.qpack_decoder_stream_id = -1
        self.peer_control_stream_id = -1
        self.peer_qpack_encoder_stream_id = -1
        self.peer_qpack_decoder_stream_id = -1
        self.peer_settings_max_field_section_size = UInt64((1 << 63) - 1)
        self.peer_settings_qpack_max_table_capacity = UInt64(0)
        self.peer_settings_qpack_blocked_streams = UInt64(0)
        self.peer_settings_enable_connect_protocol = False
        self.peer_goaway_max_stream_id = UInt64((1 << 63) - 1)
        self.peer_uni_buffers = Dict[Int, List[UInt8]]()
        self.peer_uni_kinds = Dict[Int, Int]()
        self.qpack_table = ArcPointer[QpackDynamicTable](
            QpackDynamicTable(UInt64(0))
        )
        self.pending_qpack_increment = 0

    @staticmethod
    def with_config(config: Http3Config) -> Self:
        """Construct with a non-default config carrier."""
        var out = Self()
        out.config = config.copy()
        out.qpack_table = ArcPointer[QpackDynamicTable](
            QpackDynamicTable(config.qpack_max_table_capacity)
        )
        return out^

    def open_request_stream(mut self, stream_id: Int) raises:
        """Allocate a per-stream carrier for an inbound
        bidirectional QUIC stream. Idempotent: re-opening the
        same stream ID is a no-op (the QUIC reactor occasionally
        fires the open event redundantly when a stream sees
        both HEADERS and DATA before the dispatcher polls).
        """
        if stream_id in self.streams:
            return
        if self.goaway_emitted:
            raise Error(
                "Http3Connection.open_request_stream: GOAWAY emitted;"
                " new request streams are rejected"
            )
        var state = _Http3StreamState.with_limits(
            self.config.max_field_section_size
        )
        state.reader.qpack_table = self.qpack_table
        self.streams[stream_id] = state^

    def close_request_stream(mut self, stream_id: Int) raises:
        """Drop the per-stream carrier. Called after the
        response FIN has been emitted (so the server doesn't
        keep parser state around for a stream that's done)."""
        if stream_id in self.streams:
            _ = self.streams.pop(stream_id)

    def has_stream(self, stream_id: Int) -> Bool:
        """Whether the driver currently tracks a carrier for
        this stream ID. Useful for testing the open / close
        lifecycle without needing the full reactor."""
        return stream_id in self.streams

    def active_request_count(self) -> Int:
        """Number of active per-stream carriers. The reactor
        uses this to decide when to emit GOAWAY (above
        ``goaway_threshold_streams``)."""
        return len(self.streams)

    def stream_has_headers(self, stream_id: Int) raises -> Bool:
        """Whether the first HEADERS frame has been fully parsed
        on ``stream_id``. The reactor checks this to decide when
        a stream is ready for handler dispatch (HEADERS alone is
        enough for a GET; DATA + FIN is required for methods
        with a body)."""
        if stream_id not in self.streams:
            return False
        return self.streams[stream_id].headers_complete

    def stream_fin_received(self, stream_id: Int) raises -> Bool:
        """Whether the QUIC layer has signalled FIN on
        ``stream_id``. Set via :meth:`signal_end_of_stream`."""
        if stream_id not in self.streams:
            return False
        return self.streams[stream_id].fin_received

    def stream_protocol_error(self, stream_id: Int) raises -> String:
        """Per-stream protocol-error message; empty when the
        reader has not hit a protocol error."""
        if stream_id not in self.streams:
            return String("")
        return String(self.streams[stream_id].protocol_error)

    def feed_stream_chunk(
        mut self, stream_id: Int, var chunk: List[UInt8]
    ) raises:
        """Feed a reassembled stream-data chunk into the per-
        stream reader.

        Idempotently allocates the stream's carrier if it isn't
        tracked yet (a chunk arriving for an unseen bidi stream
        is the open-stream signal). Appends the chunk to the
        per-stream inbox, then drains the inbox one frame at a
        time via :func:`feed_into`. Each frame's callback fires
        through a transient :class:`_Http3EventCollector`; the
        collector's contents are merged into the per-stream
        accumulator after the call returns.

        Returns when either:

        * ``feed_into`` returns NEEDS_MORE (the inbox doesn't
          yet hold a complete next frame).
        * The reader transitions to ``DONE`` (trailers fired,
          protocol error, or stream-level shutdown).
        """
        if stream_id not in self.streams:
            self.open_request_stream(stream_id)
        # Mutate the stream state in place; deep-copying the whole
        # _Http3StreamState (inbox + headers + body) on every inbound
        # chunk is the dominant per-request cost under concurrency.
        ref state = self.streams[stream_id]
        for i in range(len(chunk)):
            state.inbox.append(chunk[i])
        var cursor = 0
        while cursor < len(state.inbox):
            var collector = _Http3EventCollector.new()
            var view = state.inbox[cursor:]
            var consumed = feed_into(
                state.reader, Span[UInt8, _](view), collector
            )
            if consumed == 0:
                break
            cursor += consumed
            if collector.headers_fired:
                if state.headers_complete:
                    # A second HEADERS frame is the trailers
                    # frame; the reader fires on_trailers for
                    # that path. Anything else means we somehow
                    # got two on_headers callbacks; treat as a
                    # protocol error so the reactor can clean
                    # the stream up.
                    state.protocol_error = String(
                        "h3 server: unexpected duplicate HEADERS"
                    )
                else:
                    state.headers = collector.headers.copy()
                    state.headers_complete = True
            if collector.data_fired:
                for j in range(len(collector.data)):
                    state.body.append(collector.data[j])
            if collector.trailers_fired:
                state.trailers = collector.trailers.copy()
            if collector.unknown_fired:
                state.unknown_frames.append(collector.unknown_frame_type)
            if collector.error_fired:
                state.protocol_error = String(collector.error_message)
                break
            if state.reader.state == H3_REQUEST_STATE_DONE:
                break
        # Drop the consumed prefix from the inbox so the next
        # chunk doesn't re-parse old bytes.
        if cursor > 0:
            var rest = List[UInt8](capacity=len(state.inbox) - cursor)
            for k in range(cursor, len(state.inbox)):
                rest.append(state.inbox[k])
            state.inbox = rest^

    def signal_end_of_stream(mut self, stream_id: Int) raises:
        """Signal that the QUIC layer observed FIN on
        ``stream_id``. The reader's sans-I/O frame state has
        no FIN signal of its own, so the reactor must inform
        the H3 driver via this method when the last STREAM
        frame on the request side carries the FIN bit. Used by
        the reactor to decide when a request-with-body has
        been fully reassembled."""
        if stream_id not in self.streams:
            return
        ref state = self.streams[stream_id]
        state.fin_received = True

    def take_completed_streams(self) raises -> List[Int]:
        """Return the IDs of streams that have a request ready
        for handler dispatch.

        A stream is ready when:

        * The first HEADERS frame has been fully parsed
          (``headers_complete=True``), AND
        * Either the request has no body (FIN observed) or the
          reader has reached DONE (trailers fired), AND
        * The reactor has not already pulled this request via
          :meth:`take_request`, AND
        * No protocol error has fired on the stream.
        """
        var ready = List[Int]()
        for entry in self.streams.items():
            # Read fields through the dict ref; copying each
            # _Http3StreamState here just to test four flags would be
            # O(open streams) deep copies every tick.
            if entry.value.request_taken:
                continue
            if not entry.value.headers_complete:
                continue
            if entry.value.protocol_error.byte_length() != 0:
                continue
            var done = entry.value.fin_received or (
                entry.value.reader.state == H3_REQUEST_STATE_DONE
            )
            if not done:
                continue
            ready.append(entry.key)
        return ready^

    def take_request(mut self, stream_id: Int) raises -> Request:
        """Assemble + return the :class:`Request` for
        ``stream_id``. Idempotent guard: subsequent calls on the
        same stream raise so the reactor can't accidentally
        dispatch the same request through a Handler twice."""
        if stream_id not in self.streams:
            raise Error(
                "Http3Connection.take_request: stream not tracked: "
                + String(stream_id)
            )
        ref state = self.streams[stream_id]
        if state.request_taken:
            raise Error(
                "Http3Connection.take_request: request already taken on stream "
                + String(stream_id)
            )
        if not state.headers_complete:
            raise Error(
                "Http3Connection.take_request: HEADERS frame not yet parsed on"
                " stream "
                + String(stream_id)
            )
        var method = String("GET")
        var path = String("/")
        for i in range(len(state.headers)):
            var name = state.headers[i].name
            var value = state.headers[i].value
            if name == ":method":
                method = String(value)
            elif name == ":path":
                path = String(value)
        var req = Request(method=method^, url=path^, body=state.body.copy())
        for i in range(len(state.headers)):
            var name = state.headers[i].name
            if (
                name == ":method"
                or name == ":path"
                or name == ":scheme"
                or name == ":authority"
            ):
                continue
            req.headers.set(state.headers[i].name, state.headers[i].value)
        state.request_taken = True
        return req^

    def emit_response(mut self, stream_id: Int, var response: Response) raises:
        """Encode ``response`` into the per-stream outbox so the
        reactor can drain it via :meth:`take_response_frames`.

        Emits HEADERS + (zero or more) DATA frames. Trailers
        and the FIN bit are handled by the reactor (FIN is a
        QUIC-level signal); this method only buffers the H3
        frame bytes. Idempotent guard: emitting twice for the
        same stream raises so the reactor can't accidentally
        write a stale response after the stream is finalized.
        """
        if stream_id not in self.streams:
            raise Error(
                "Http3Connection.emit_response: stream not tracked: "
                + String(stream_id)
            )
        ref state = self.streams[stream_id]
        if state.response_emitted:
            raise Error(
                "Http3Connection.emit_response: response already emitted on"
                " stream "
                + String(stream_id)
            )
        var headers = List[QpackHeader]()
        for i in range(response.headers.len()):
            var name = response.headers._keys[i]
            var value = response.headers._values[i]
            headers.append(QpackHeader(String(name), String(value)))
        encode_response_headers(response.status, headers, state.outbox)
        if len(response.body) != 0:
            encode_response_data(Span[UInt8, _](response.body), state.outbox)
        state.response_emitted = True

    # -- Unidirectional stream type dispatch (RFC 9114 §6.2) ----------

    def feed_uni_stream_chunk(
        mut self, stream_id: Int, var chunk: List[UInt8]
    ) raises:
        """Feed reassembled bytes from a peer-initiated
        unidirectional QUIC stream into the H3 driver.

        The first varint on each uni stream is the stream-type
        codepoint (RFC 9114 §6.2). Once resolved, the driver
        dispatches subsequent bytes to the matching state
        machine:

        * 0x00 (Control) -- parses SETTINGS first, then
          GOAWAY / MAX_PUSH_ID over the stream's lifetime.
        * 0x01 (Push) -- the server records but ignores the
          stream (push is deprecated as of RFC 9114 revision
          9; the reactor STOP_SENDINGs at the QUIC layer).
        * 0x02 (QPACK encoder) -- replayed into the connection
          dynamic table via
          :meth:`_feed_peer_qpack_encoder_stream`; each insert
          owes an Insert Count Increment back on our decoder
          stream (drained by :meth:`take_qpack_decoder_frames`).
        * 0x03 (QPACK decoder) -- captured but unused (we emit
          only static-table field sections, so the peer never
          acknowledges dynamic inserts to us).

        The stream-type varint may span multiple chunks (it is
        at most 8 bytes per RFC 9000 §16). The driver buffers
        until the type is resolvable + drains the buffer once
        resolution succeeds.
        """
        var buf = List[UInt8]()
        if stream_id in self.peer_uni_buffers:
            buf = self.peer_uni_buffers.pop(stream_id)
        for i in range(len(chunk)):
            buf.append(chunk[i])

        var kind: Int
        if stream_id in self.peer_uni_kinds:
            kind = self.peer_uni_kinds[stream_id]
        else:
            # Try to decode the type varint. NEEDS_MORE buffers
            # for the next chunk; structural errors (duplicate
            # control stream) propagate to the reactor.
            var type_consumed: Int
            var type_value: UInt64
            try:
                var v = decode_varint(Span[UInt8, _](buf))
                type_consumed = v.consumed
                type_value = v.value
            except _:
                self.peer_uni_buffers[stream_id] = buf^
                return
            kind = self._classify_uni_kind(type_value, stream_id)
            self.peer_uni_kinds[stream_id] = kind
            var rest = List[UInt8](capacity=len(buf) - type_consumed)
            for k in range(type_consumed, len(buf)):
                rest.append(buf[k])
            buf = rest^

        if kind == Http3StreamType.CONTROL:
            self._feed_peer_control_stream(buf^)
        elif kind == Http3StreamType.QPACK_ENCODER:
            self._feed_peer_qpack_encoder_stream(stream_id, buf^)
        elif kind == Http3StreamType.QPACK_DECODER:
            pass
        elif kind == Http3StreamType.PUSH:
            pass
        else:
            pass

    @always_inline
    def _classify_uni_kind(
        mut self, type_code: UInt64, stream_id: Int
    ) raises -> Int:
        """Map a varint stream-type code to the kind id stored
        in :attr:`peer_uni_kinds`. Also records the peer's
        stream IDs (control / qpack-enc / qpack-dec) for the
        reactor's duplicate-stream check."""
        if type_code == UInt64(Http3StreamType.CONTROL):
            if self.peer_control_stream_id >= 0:
                raise Error(
                    "h3 server: peer opened a second control stream "
                    "(RFC 9114 6.2.1 H3_STREAM_CREATION_ERROR)"
                )
            self.peer_control_stream_id = stream_id
            return Http3StreamType.CONTROL
        if type_code == UInt64(Http3StreamType.PUSH):
            return Http3StreamType.PUSH
        if type_code == UInt64(Http3StreamType.QPACK_ENCODER):
            self.peer_qpack_encoder_stream_id = stream_id
            return Http3StreamType.QPACK_ENCODER
        if type_code == UInt64(Http3StreamType.QPACK_DECODER):
            self.peer_qpack_decoder_stream_id = stream_id
            return Http3StreamType.QPACK_DECODER
        return -1

    def _feed_peer_control_stream(mut self, var bytes: List[UInt8]) raises:
        """Parse one or more SETTINGS / GOAWAY / MAX_PUSH_ID
        frames from the peer's control stream. RFC 9114 §7.2.4:
        SETTINGS MUST be the first frame; receiving anything
        else first is H3_MISSING_SETTINGS. Subsequent SETTINGS
        frames are H3_FRAME_UNEXPECTED. GOAWAY is allowed any
        time after the first SETTINGS."""
        var cursor = 0
        while cursor < len(bytes):
            var view = Span[UInt8, _](bytes[cursor:])
            var type_var = decode_varint(view)
            if type_var.consumed >= len(view):
                break
            var rest = view[type_var.consumed :]
            var len_var = decode_varint(rest)
            var header_size = type_var.consumed + len_var.consumed
            var payload_size = Int(len_var.value)
            if header_size + payload_size > len(view):
                break
            var payload_start = cursor + header_size
            var payload_end = payload_start + payload_size
            var payload = Span[UInt8, _](bytes[payload_start:payload_end])
            self._dispatch_control_frame(type_var.value, payload)
            cursor = payload_end
        if cursor < len(bytes):
            var carry = List[UInt8](capacity=len(bytes) - cursor)
            for k in range(cursor, len(bytes)):
                carry.append(bytes[k])
            self.peer_uni_buffers[self.peer_control_stream_id] = carry^

    def _feed_peer_qpack_encoder_stream(
        mut self, stream_id: Int, var bytes: List[UInt8]
    ) raises:
        """Replay peer QPACK encoder-stream inserts into the
        connection's dynamic table (RFC 9204 section 4.3). ``bytes``
        already carries any tail re-buffered after the previous chunk
        (the caller consolidates :attr:`peer_uni_buffers` before
        dispatch), so we apply every whole instruction and re-buffer
        the unconsumed remainder for the next chunk. Each applied insert
        owes one Insert Count Increment back on our decoder stream."""
        var result = apply_encoder_instructions_partial(
            self.qpack_table[], Span[UInt8, _](bytes)
        )
        self.pending_qpack_increment += result[0]
        var consumed = result[1]
        if consumed < len(bytes):
            var carry = List[UInt8](capacity=len(bytes) - consumed)
            for k in range(consumed, len(bytes)):
                carry.append(bytes[k])
            self.peer_uni_buffers[stream_id] = carry^

    def take_qpack_decoder_frames(mut self) -> List[UInt8]:
        """Drain the QPACK decoder-stream bytes the connection owes the
        peer: an Insert Count Increment covering every encoder-stream
        insert applied since the last drain (RFC 9204 section 4.4.3).
        Returns empty when nothing is pending.

        The default config advertises ``qpack_max_table_capacity
        = 0``, so a conforming peer never streams dynamic inserts and this
        never has anything to drain. Routing the drained bytes onto a
        locally-opened QPACK decoder uni-stream is the reactor-side
        upgrade path, gated on advertising a non-zero capacity. Section
        Acknowledgment / Stream Cancellation are likewise deferred -- with
        our static-only encoder the peer never blocks on them."""
        var out = List[UInt8]()
        if self.pending_qpack_increment > 0:
            encode_insert_count_increment(out, self.pending_qpack_increment)
            self.pending_qpack_increment = 0
        return out^

    def _dispatch_control_frame(
        mut self, frame_type: UInt64, payload: Span[UInt8, _]
    ) raises:
        """Apply one parsed control-stream frame to the driver
        state. RFC 9114 enforces:

        * SETTINGS is the first frame.
        * SETTINGS twice on the same stream -> H3_FRAME_UNEXPECTED.
        * Any other frame before SETTINGS -> H3_MISSING_SETTINGS.
        * GOAWAY may arrive after SETTINGS; subsequent GOAWAYs
          must monotonically decrease (RFC 9114 §5.2).
        """
        if frame_type == H3_FRAME_TYPE_SETTINGS:
            if self.peer_settings_received:
                raise Error(
                    "h3 server: peer sent SETTINGS twice "
                    "(RFC 9114 7.2.4 H3_FRAME_UNEXPECTED)"
                )
            var settings = decode_http3_settings(payload)
            self._apply_peer_settings(settings^)
            self.peer_settings_received = True
            return
        if not self.peer_settings_received:
            raise Error(
                "h3 server: control-stream frame "
                + String(frame_type)
                + " before SETTINGS (RFC 9114 7.2.4 H3_MISSING_SETTINGS)"
            )
        if frame_type == H3_FRAME_TYPE_GOAWAY:
            if len(payload) == 0:
                raise Error("h3 server: empty GOAWAY payload")
            var goaway_id = decode_varint(payload)
            if (
                self.peer_goaway_max_stream_id != UInt64((1 << 63) - 1)
                and goaway_id.value > self.peer_goaway_max_stream_id
            ):
                raise Error(
                    "h3 server: peer GOAWAY id increased "
                    "(RFC 9114 5.2 forbids monotonic increase)"
                )
            self.peer_goaway_max_stream_id = goaway_id.value
            return

    def _apply_peer_settings(mut self, var settings: List[Http3Setting]) raises:
        """Update the connection's view of the peer's announced
        SETTINGS. Unknown settings identifiers are ignored per
        RFC 9114 §7.2.4.1; the codec already rejects malformed
        pairs."""
        for i in range(len(settings)):
            var id_ = settings[i].identifier
            var v = settings[i].value
            if id_ == H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
                self.peer_settings_max_field_section_size = v
            elif id_ == H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
                self.peer_settings_qpack_max_table_capacity = v
            elif id_ == H3_SETTINGS_QPACK_BLOCKED_STREAMS:
                self.peer_settings_qpack_blocked_streams = v
            elif id_ == H3_SETTINGS_ENABLE_CONNECT_PROTOCOL:
                self.peer_settings_enable_connect_protocol = v != UInt64(0)

    def emit_initial_settings(self) raises -> List[UInt8]:
        """Build the server's outbound control-stream prefix:
        the stream-type varint (0x00) followed by a SETTINGS
        frame carrying the local
        :class:`Http3Config` values.

        The reactor opens a local control uni-stream via QUIC
        and emits these bytes as the very first payload (RFC
        9114 §6.2.1: SETTINGS MUST be the first frame). This
        is the only frame the server is required to send
        proactively; GOAWAY / MAX_PUSH_ID are emitted on
        demand."""
        var out = List[UInt8]()
        var type_var = encode_varint(UInt64(Http3StreamType.CONTROL))
        for i in range(len(type_var)):
            out.append(type_var[i])
        var settings = List[Http3Setting]()
        settings.append(
            Http3Setting(
                identifier=H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
                value=self.config.max_field_section_size,
            )
        )
        settings.append(
            Http3Setting(
                identifier=H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
                value=self.config.qpack_max_table_capacity,
            )
        )
        settings.append(
            Http3Setting(
                identifier=H3_SETTINGS_QPACK_BLOCKED_STREAMS,
                value=self.config.qpack_blocked_streams,
            )
        )
        if self.config.enable_connect_protocol:
            settings.append(
                Http3Setting(
                    identifier=H3_SETTINGS_ENABLE_CONNECT_PROTOCOL,
                    value=UInt64(1),
                )
            )
        var payload = List[UInt8]()
        encode_http3_settings(settings, payload)
        encode_http3_frame(H3_FRAME_TYPE_SETTINGS, Span[UInt8, _](payload), out)
        return out^

    def emit_goaway(mut self, max_stream_id: UInt64) raises -> List[UInt8]:
        """Build a GOAWAY frame announcing ``max_stream_id`` (RFC
        9114 §5.2). The reactor writes the result onto the
        locally-opened control stream immediately and flips
        :attr:`goaway_emitted` so the next open_request_stream
        rejects with H3_REQUEST_CANCELLED."""
        if self.goaway_emitted:
            raise Error("h3 server: GOAWAY already emitted")
        var out = List[UInt8]()
        var payload = encode_varint(max_stream_id)
        encode_http3_frame(H3_FRAME_TYPE_GOAWAY, Span[UInt8, _](payload), out)
        self.goaway_emitted = True
        return out^

    def take_response_frames(mut self, stream_id: Int) raises -> List[UInt8]:
        """Drain pending outbound bytes for ``stream_id`` and
        return them to the reactor for emission as QUIC stream-
        data. Returns an empty list when nothing is queued. The
        reactor calls this repeatedly until it returns empty;
        each call is destructive (drained bytes are not held
        for re-reads)."""
        if stream_id not in self.streams:
            raise Error(
                "Http3Connection.take_response_frames: stream not tracked: "
                + String(stream_id)
            )
        ref state = self.streams[stream_id]
        # Swap the outbox out through the ref (a transfer-move out of
        # a ref-bound field isn't allowed); leaves an empty list in
        # the stream state and hands the bytes to the caller.
        var drained = List[UInt8]()
        swap(drained, state.outbox)
        return drained^
