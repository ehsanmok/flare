"""HTTP/3 client connection driver -- QUIC + H3 composition.

Stitches the QUIC client driver
(:class:`flare.quic.client.QuicClientConnection`) to the sans-I/O H3
client codecs (:mod:`flare.h3.request_writer` +
:mod:`flare.h3.response_reader`) into a request/response engine.

Per RFC 9114 a client:

1. opens its unidirectional control stream and sends ``SETTINGS``
   first, plus the (empty, static-only) QPACK encoder/decoder
   uni-streams (:meth:`open_streams`),
2. opens a client-initiated bidirectional stream per request and
   writes ``HEADERS [+ DATA]`` with FIN (:meth:`send_request`),
3. reads the response ``HEADERS [+ DATA]`` off that same bidi
   stream until the QUIC FIN (:meth:`read_response` /
   :meth:`fetch`).

Three driving styles are exposed so the engine is usable from a
single-threaded loopback test (server + client pumped in lockstep
on one thread), from a real network client (the server is remote,
so a blocking poll loop is fine), and as a multiplexer that keeps
many requests in flight over the one connection:

* granular -- :meth:`open_streams`, :meth:`send_request`, and
  :meth:`read_response` (one poll burst into a caller-owned reader,
  returns whether the response is complete) so a test can
  interleave server ticks,
* blocking -- :meth:`fetch`, which polls until the response
  completes or a poll budget is exhausted,
* multiplexed -- :meth:`request` (register an owned reader),
  :meth:`poll_responses` (one burst fanned out across every
  in-flight stream), and :meth:`take_if_complete` so any number of
  concurrent requests can share the single QUIC connection.

Inbound STREAM frames are reassembled in offset order by
:class:`_StreamReasm` before reaching the response reader: a
reordered, duplicated, or overlapping STREAM frame (multi-packet
responses, retransmits) is buffered and only the contiguous prefix
is delivered, so the reader always sees the response bytes in order
and FIN fires only once every byte up to the final offset arrived.
"""

from std.collections import Dict, List, Optional
from std.memory import Span

from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.state import ConnectionEvents

from .request_writer import (
    encode_client_control_stream,
    encode_qpack_decoder_stream,
    encode_qpack_encoder_stream,
    encode_request_data,
    encode_request_headers,
)
from .response_reader import H3BodyChunk, H3Response, H3ResponseReader


def is_idempotent_method(method: String) -> Bool:
    """Whether ``method`` is idempotent per RFC 9110 sec 9.2.2 -- safe
    to send more than once with the same effect.

    The 0-RTT replay hazard (RFC 9001 sec 9.2) is exactly that an
    on-path attacker can re-send the captured early-data flight, so
    only idempotent requests are ever eligible to ride 0-RTT
    (:meth:`H3ClientConnection.fetch_0rtt`). POST / PATCH / CONNECT
    are excluded -- a replay could double a side effect."""
    var m = method.upper()
    return (
        m == "GET"
        or m == "HEAD"
        or m == "OPTIONS"
        or m == "PUT"
        or m == "DELETE"
        or m == "TRACE"
    )


struct H3ZeroRttOutcome(Copyable, Movable):
    """Result of :meth:`H3ClientConnection.fetch_0rtt`: the response
    plus how the request was actually carried.

    ``used_0rtt`` is True only when the request was 0-RTT-eligible
    *and* the server accepted early data; ``replayed`` is True when
    0-RTT was attempted but the server rejected it and the request
    completed at 1-RTT instead (transparent to the caller)."""

    var response: H3Response
    var used_0rtt: Bool
    var replayed: Bool

    def __init__(
        out self, var response: H3Response, used_0rtt: Bool, replayed: Bool
    ):
        self.response = response^
        self.used_0rtt = used_0rtt
        self.replayed = replayed


struct _StreamReasm(Copyable, Movable):
    """Per-stream offset-ordered byte reassembler.

    QUIC STREAM frames carry a per-stream byte ``offset`` and may
    arrive out of order, be duplicated, or overlap (retransmits).
    :class:`H3ResponseReader` assumes in-order bytes, so this buffer
    sits in front of it: it delivers the contiguous prefix starting
    at :attr:`next_offset`, stashes any gap-ahead chunk in
    :attr:`pending` keyed by its start offset, and drains stashed
    chunks as the gaps fill. FIN is recorded as the absolute end
    offset (:attr:`fin_offset`) and only signalled to the reader
    once every byte up to it has been delivered.

    ponytail: ``_drain_pending`` rescans ``pending`` each step
    (O(n^2) in the number of buffered gap chunks). A single response
    rarely buffers more than a couple of out-of-order frames, so the
    quadratic scan is a non-issue; the upgrade path is an
    offset-sorted structure if a pathological reorder depth ever
    shows up.
    """

    var next_offset: UInt64
    var pending: Dict[UInt64, List[UInt8]]
    var fin_offset: Optional[UInt64]
    var fin_signaled: Bool

    def __init__(out self):
        self.next_offset = UInt64(0)
        self.pending = Dict[UInt64, List[UInt8]]()
        self.fin_offset = None
        self.fin_signaled = False

    def push(
        mut self,
        mut reader: H3ResponseReader,
        offset: UInt64,
        data: Span[UInt8, _],
        fin: Bool,
    ) raises:
        """Ingest one STREAM chunk: deliver / stash / dedupe by
        offset, then drain any now-contiguous stashed chunks and
        signal FIN if the stream is fully delivered."""
        if fin:
            self.fin_offset = Optional(offset + UInt64(len(data)))
        var end = offset + UInt64(len(data))
        if end > self.next_offset:
            if offset <= self.next_offset:
                var skip = Int(self.next_offset - offset)
                reader.feed(data[skip:])
                self.next_offset = end
                self._drain_pending(reader)
            else:
                # Gap ahead of the contiguous frontier: stash a copy
                # (the inbound span is borrowed from the event).
                var copy = List[UInt8](capacity=len(data))
                for i in range(len(data)):
                    copy.append(data[i])
                self.pending[offset] = copy^
        self._maybe_fin(reader)

    def _drain_pending(mut self, mut reader: H3ResponseReader) raises:
        """Deliver every stashed chunk that has become contiguous
        with (or is wholly behind) :attr:`next_offset`."""
        var made_progress = True
        while made_progress:
            made_progress = False
            var chosen = Optional[UInt64](None)
            for entry in self.pending.items():
                var k = entry.key
                if k <= self.next_offset:
                    chosen = Optional(k)
                    break
            if chosen:
                var key = chosen.value()
                var chunk = self.pending.pop(key)
                var end = key + UInt64(len(chunk))
                if end > self.next_offset:
                    var skip = Int(self.next_offset - key)
                    reader.feed(Span[UInt8, _](chunk)[skip:])
                    self.next_offset = end
                made_progress = True

    def _maybe_fin(mut self, mut reader: H3ResponseReader):
        if self.fin_signaled:
            return
        if self.fin_offset and self.next_offset >= self.fin_offset.value():
            reader.signal_fin()
            self.fin_signaled = True


struct _PendingRequest(Copyable, Movable):
    """An in-flight multiplexed request: its offset-ordered
    reassembler plus the response reader that owns the decoded
    state. One per concurrent request stream, keyed by stream id in
    :attr:`H3ClientConnection._pending`."""

    var reasm: _StreamReasm
    var reader: H3ResponseReader

    def __init__(
        out self, var reasm: _StreamReasm, var reader: H3ResponseReader
    ):
        self.reasm = reasm^
        self.reader = reader^


struct H3ClientConnection(Movable):
    """An HTTP/3 client over an established QUIC connection.

    Wraps a :class:`QuicClientConnection` (whose handshake must
    already be complete -- 1-RTT keys installed) and drives H3
    request/response exchanges on it. Multiplexes any number of
    concurrent requests over the single QUIC connection: each
    :meth:`request` opens its own bidi stream and registers a
    :class:`_PendingRequest`; :meth:`poll_responses` demuxes one
    QUIC burst across every in-flight stream.
    """

    var quic: QuicClientConnection
    var streams_opened: Bool
    var max_field_section_size: UInt64
    var _pending: Dict[UInt64, _PendingRequest]
    """In-flight requests with reader ownership, keyed by stream id
    (the multiplexed :meth:`request`/:meth:`poll_responses` API)."""
    var _ext_reasms: Dict[UInt64, _StreamReasm]
    """Per-stream reassemblers for the external-reader
    :meth:`read_response` API, keyed by stream id."""

    def __init__(
        out self,
        var quic: QuicClientConnection,
        max_field_section_size: UInt64 = UInt64(1 << 16),
    ):
        self.quic = quic^
        self.streams_opened = False
        self.max_field_section_size = max_field_section_size
        self._pending = Dict[UInt64, _PendingRequest]()
        self._ext_reasms = Dict[UInt64, _StreamReasm]()

    def _send_stream(
        mut self,
        stream_id: UInt64,
        var data: List[UInt8],
        fin: Bool,
        early: Bool,
    ) raises:
        """Route one STREAM send to the 1-RTT path or, when ``early``,
        the 0-RTT (EarlyData) path on the underlying QUIC connection.
        The single switch that makes :meth:`open_streams` /
        :meth:`send_request` emit either flight without duplicating the
        H3 encoding."""
        if early:
            self.quic.send_stream_early(stream_id, data^, fin)
        else:
            self.quic.send_stream(stream_id, data^, fin)

    def open_streams(mut self, early: Bool = False) raises:
        """Open the client control + QPACK uni-streams (RFC 9114
        §6.2). The control stream carries the mandatory first
        ``SETTINGS`` frame; the QPACK streams are empty in flare's
        static-table-only mode. Idempotent. When ``early`` the streams
        are emitted at 0-RTT (EarlyData) instead of 1-RTT."""
        if self.streams_opened:
            return
        var ctrl = self.quic.open_uni_stream()
        var ctrl_bytes = List[UInt8]()
        encode_client_control_stream(self.max_field_section_size, ctrl_bytes)
        self._send_stream(ctrl, ctrl_bytes^, False, early)

        var enc = self.quic.open_uni_stream()
        var enc_bytes = List[UInt8]()
        encode_qpack_encoder_stream(enc_bytes)
        self._send_stream(enc, enc_bytes^, False, early)

        var dec = self.quic.open_uni_stream()
        var dec_bytes = List[UInt8]()
        encode_qpack_decoder_stream(dec_bytes)
        self._send_stream(dec, dec_bytes^, False, early)
        self.streams_opened = True

    def send_request(
        mut self,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        headers: List[QpackHeader],
        body: List[UInt8],
        early: Bool = False,
    ) raises -> UInt64:
        """Open a fresh bidi stream, write the request
        ``HEADERS [+ DATA]`` with FIN, and return the stream id the
        response will arrive on. Opens the control/QPACK streams
        first if not already open. When ``early`` the control/QPACK
        streams and the request ride 0-RTT (EarlyData) packets."""
        self.open_streams(early)
        var sid = self.quic.open_bidi_stream()
        var wire = List[UInt8]()
        encode_request_headers(method, scheme, authority, path, headers, wire)
        if len(body) > 0:
            encode_request_data(Span[UInt8, _](body), wire)
        self._send_stream(sid, wire^, True, early)
        return sid

    def read_response(
        mut self,
        stream_id: UInt64,
        mut reader: H3ResponseReader,
        timeout_ms: Int = 100,
    ) raises -> Bool:
        """Poll one QUIC burst, route this stream's STREAM chunks
        into the caller-owned ``reader`` through its offset-ordered
        reassembler, and return whether the response is complete.
        Chunks for other streams (server control / QPACK uni-streams
        / other requests) are ignored. This is the external-reader
        single-stream API; :meth:`poll_responses` is the multiplexed
        owned-reader counterpart."""
        var events = self.quic.poll(timeout_ms)
        self._feed_ext(stream_id, events, reader)
        return reader.is_complete()

    def _feed_ext(
        mut self,
        stream_id: UInt64,
        events: ConnectionEvents,
        mut reader: H3ResponseReader,
    ) raises:
        if stream_id not in self._ext_reasms:
            self._ext_reasms[stream_id] = _StreamReasm()
        # Pop/reinsert so the reassembler and the caller's reader are
        # both locals while pushing (no Dict-entry aliasing).
        var reasm = self._ext_reasms.pop(stream_id)
        for i in range(len(events.stream_chunks)):
            if events.stream_chunks[i].stream_id != stream_id:
                continue  # server uni-streams / other requests
            reasm.push(
                reader,
                events.stream_chunks[i].offset,
                Span[UInt8, _](events.stream_chunks[i].data),
                events.stream_chunks[i].fin,
            )
        self._ext_reasms[stream_id] = reasm^

    def request(
        mut self,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        headers: List[QpackHeader],
        body: List[UInt8],
        early: Bool = False,
    ) raises -> UInt64:
        """Multiplexed request: open a bidi stream, write
        ``HEADERS [+ DATA]`` with FIN, register an owned reader, and
        return the stream id. Any number of requests can be in flight
        at once over the one QUIC connection; drive them with
        :meth:`poll_responses` and collect with
        :meth:`take_if_complete`. When ``early`` the request is emitted
        at 0-RTT (EarlyData)."""
        var sid = self.send_request(
            method, scheme, authority, path, headers, body, early
        )
        self._pending[sid] = _PendingRequest(
            _StreamReasm(), H3ResponseReader(self.max_field_section_size)
        )
        return sid

    def poll_responses(mut self, timeout_ms: Int = 100) raises -> Bool:
        """Poll one QUIC burst and fan its STREAM chunks out across
        every in-flight request registered by :meth:`request`.
        Returns whether at least one pending response is now
        complete."""
        var events = self.quic.poll(timeout_ms)
        var sids = List[UInt64]()
        for entry in self._pending.items():
            sids.append(entry.key)
        for s in range(len(sids)):
            var sid = sids[s]
            var pr = self._pending.pop(sid)
            for i in range(len(events.stream_chunks)):
                if events.stream_chunks[i].stream_id != sid:
                    continue
                pr.reasm.push(
                    pr.reader,
                    events.stream_chunks[i].offset,
                    Span[UInt8, _](events.stream_chunks[i].data),
                    events.stream_chunks[i].fin,
                )
            self._pending[sid] = pr^
        var any_done = False
        for entry in self._pending.items():
            if entry.value.reader.is_complete():
                any_done = True
        return any_done

    def take_if_complete(
        mut self, stream_id: UInt64
    ) raises -> Optional[H3Response]:
        """If the request on ``stream_id`` has a fully assembled
        response, remove it from the in-flight set and return it;
        otherwise return ``None`` (the request stays registered)."""
        if stream_id not in self._pending:
            return None
        var pr = self._pending.pop(stream_id)
        if not pr.reader.is_complete():
            self._pending[stream_id] = pr^
            return None
        return Optional(pr.reader.take_response())

    def head_ready(mut self, stream_id: UInt64) raises -> Bool:
        """Whether the response head (status + headers) for a
        multiplexed request has been parsed yet, so a streaming
        caller can read :meth:`stream_status` / :meth:`stream_headers`
        before draining the body."""
        if stream_id not in self._pending:
            return False
        var pr = self._pending.pop(stream_id)
        var ready = pr.reader.head_ready()
        self._pending[stream_id] = pr^
        return ready

    def stream_status(mut self, stream_id: UInt64) raises -> Int:
        """The ``:status`` of a multiplexed request (0 until the head
        is parsed -- check :meth:`head_ready`)."""
        if stream_id not in self._pending:
            return 0
        var pr = self._pending.pop(stream_id)
        var s = pr.reader.status_code()
        self._pending[stream_id] = pr^
        return s

    def stream_headers(mut self, stream_id: UInt64) raises -> List[QpackHeader]:
        """A copy of the application response headers of a multiplexed
        request (valid once :meth:`head_ready`)."""
        if stream_id not in self._pending:
            return List[QpackHeader]()
        var pr = self._pending.pop(stream_id)
        var h = pr.reader.headers_copy()
        self._pending[stream_id] = pr^
        return h^

    def poll_body(
        mut self, stream_id: UInt64, timeout_ms: Int = 100
    ) raises -> H3BodyChunk:
        """Streaming body read: poll one QUIC burst (fanning chunks
        out across every in-flight request so none stall), then move
        out the body bytes that became available on ``stream_id``
        without ever buffering the whole body. Returns the new bytes
        plus whether the stream has finished (FIN). After ``done`` is
        True the trailers / final response are still retrievable with
        :meth:`take_if_complete`. An unknown / already-taken stream id
        returns an empty, ``done=True`` chunk."""
        var events = self.quic.poll(timeout_ms)
        var sids = List[UInt64]()
        for entry in self._pending.items():
            sids.append(entry.key)
        for s in range(len(sids)):
            var sid = sids[s]
            var pr = self._pending.pop(sid)
            for i in range(len(events.stream_chunks)):
                if events.stream_chunks[i].stream_id != sid:
                    continue
                pr.reasm.push(
                    pr.reader,
                    events.stream_chunks[i].offset,
                    Span[UInt8, _](events.stream_chunks[i].data),
                    events.stream_chunks[i].fin,
                )
            self._pending[sid] = pr^
        if stream_id not in self._pending:
            return H3BodyChunk(List[UInt8](), True)
        var target = self._pending.pop(stream_id)
        var chunk = target.reader.drain_body()
        var done = target.reader.is_complete()
        self._pending[stream_id] = target^
        return H3BodyChunk(chunk^, done)

    def fetch(
        mut self,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        headers: List[QpackHeader],
        body: List[UInt8],
        timeout_ms: Int = 100,
        max_polls: Int = 100,
    ) raises -> H3Response:
        """Blocking single-request round-trip for the real-network
        client: send the request, then poll until the response is
        complete or the poll budget is exhausted. Raises on a
        budget timeout (the caller falls back to h2/h1). A thin
        wrapper over :meth:`request`/:meth:`poll_responses`."""
        var sid = self.request(method, scheme, authority, path, headers, body)
        for _ in range(max_polls):
            _ = self.poll_responses(timeout_ms)
            var resp = self.take_if_complete(sid)
            if resp:
                return resp.value().copy()
        raise Error("h3 client: response did not complete within poll budget")

    def fetch_0rtt(
        mut self,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        headers: List[QpackHeader],
        body: List[UInt8],
        timeout_ms: Int = 100,
        max_polls: Int = 100,
    ) raises -> H3ZeroRttOutcome:
        """Idempotent-only 0-RTT request with transparent 1-RTT
        fallback.

        Gates strictly: a request is 0-RTT-eligible only when its
        method is idempotent (:func:`is_idempotent_method` -- a replay
        is safe) AND the connection resumed a session with rustls
        early keys installed
        (:meth:`flare.quic.client.QuicClientConnection.early_data_ready`).
        A non-idempotent method, or a fresh (unresumed) connection,
        is carried normally at 1-RTT.

        The request is emitted in the first 0-RTT flight (the
        control/QPACK streams + the request ride EarlyData packets via
        :meth:`QuicClientConnection.send_stream_early`). After the
        handshake, if the server *rejected* early data
        (:meth:`QuicClientConnection.early_data_accepted` is False),
        :meth:`QuicClientConnection.finish_early_data` transparently
        replays the identical flight at 1-RTT on the same stream, the
        request still completes, and the result reports
        ``replayed=True`` -- the caller never observes a
        rejected-0-RTT failure. ``used_0rtt`` is True only when the
        server accepted the early data.

        ponytail: 0-RTT packets are not wired into loss recovery, so a
        lost-but-accepted 0-RTT packet is not retransmitted (fine on
        the lossless loopback this client targets; the upgrade path is
        the shared-pn loss-recovery registration in
        :class:`QuicClientConnection`).
        """
        var eligible = is_idempotent_method(method) and (
            self.quic.early_data_ready()
        )
        if not eligible:
            var resp = self.fetch(
                method,
                scheme,
                authority,
                path,
                headers,
                body,
                timeout_ms,
                max_polls,
            )
            return H3ZeroRttOutcome(resp^, used_0rtt=False, replayed=False)

        var sid = self.request(
            method, scheme, authority, path, headers, body, early=True
        )
        var finished_early = False
        for _ in range(max_polls):
            _ = self.poll_responses(timeout_ms)
            # Resolve early data once the handshake lands: on rejection
            # this replays the flight at 1-RTT on the same stream, so a
            # later poll completes the response transparently.
            if not finished_early and self.quic.is_established():
                _ = self.quic.finish_early_data()
                finished_early = True
            var done = self.take_if_complete(sid)
            if done:
                var accepted = self.quic.early_data_accepted()
                return H3ZeroRttOutcome(
                    done.value().copy(),
                    used_0rtt=accepted,
                    replayed=not accepted,
                )
        raise Error("h3 client: 0-RTT response did not complete within budget")

    def is_established(self) -> Bool:
        return self.quic.is_established()

    def close(mut self):
        self.quic.close()
