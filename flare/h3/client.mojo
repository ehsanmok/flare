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

Two driving styles are exposed so the engine is usable both from a
single-threaded loopback test (server + client pumped in lockstep
on one thread) and from a real network client (the server is
remote, so a blocking poll loop is fine):

* granular -- :meth:`open_streams`, :meth:`send_request`, and
  :meth:`read_response` (one poll burst, returns whether the
  response is complete) so a test can interleave server ticks,
* blocking -- :meth:`fetch`, which polls until the response
  completes or a poll budget is exhausted.

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
from .response_reader import H3Response, H3ResponseReader


struct _StreamReasm(Movable):
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


struct H3ClientConnection(Movable):
    """An HTTP/3 client over an established QUIC connection.

    Wraps a :class:`QuicClientConnection` (whose handshake must
    already be complete -- 1-RTT keys installed) and drives H3
    request/response exchanges on it.
    """

    var quic: QuicClientConnection
    var streams_opened: Bool
    var max_field_section_size: UInt64
    var _reasm: _StreamReasm
    """Offset-ordered reassembler for the current request stream.
    Reset whenever :meth:`read_response` sees a new stream id."""
    var _reasm_sid: Int
    """Stream id the :attr:`_reasm` currently tracks (-1 = none).
    A single sequential request at a time, so one reassembler
    suffices; it is reset per stream rather than kept per id."""

    def __init__(
        out self,
        var quic: QuicClientConnection,
        max_field_section_size: UInt64 = UInt64(1 << 16),
    ):
        self.quic = quic^
        self.streams_opened = False
        self.max_field_section_size = max_field_section_size
        self._reasm = _StreamReasm()
        self._reasm_sid = -1

    def open_streams(mut self) raises:
        """Open the client control + QPACK uni-streams (RFC 9114
        §6.2). The control stream carries the mandatory first
        ``SETTINGS`` frame; the QPACK streams are empty in flare's
        static-table-only mode. Idempotent."""
        if self.streams_opened:
            return
        var ctrl = self.quic.open_uni_stream()
        var ctrl_bytes = List[UInt8]()
        encode_client_control_stream(self.max_field_section_size, ctrl_bytes)
        self.quic.send_stream(ctrl, ctrl_bytes, fin=False)

        var enc = self.quic.open_uni_stream()
        var enc_bytes = List[UInt8]()
        encode_qpack_encoder_stream(enc_bytes)
        self.quic.send_stream(enc, enc_bytes, fin=False)

        var dec = self.quic.open_uni_stream()
        var dec_bytes = List[UInt8]()
        encode_qpack_decoder_stream(dec_bytes)
        self.quic.send_stream(dec, dec_bytes, fin=False)
        self.streams_opened = True

    def send_request(
        mut self,
        method: String,
        scheme: String,
        authority: String,
        path: String,
        headers: List[QpackHeader],
        body: List[UInt8],
    ) raises -> UInt64:
        """Open a fresh bidi stream, write the request
        ``HEADERS [+ DATA]`` with FIN, and return the stream id the
        response will arrive on. Opens the control/QPACK streams
        first if not already open."""
        self.open_streams()
        var sid = self.quic.open_bidi_stream()
        var wire = List[UInt8]()
        encode_request_headers(method, scheme, authority, path, headers, wire)
        if len(body) > 0:
            encode_request_data(Span[UInt8, _](body), wire)
        self.quic.send_stream(sid, wire, fin=True)
        return sid

    def read_response(
        mut self,
        stream_id: UInt64,
        mut reader: H3ResponseReader,
        timeout_ms: Int = 100,
    ) raises -> Bool:
        """Poll one QUIC burst, route this stream's STREAM chunks
        into ``reader`` through the offset-ordered reassembler, and
        return whether the response is complete. Chunks for other
        streams (server control / QPACK uni-streams) are ignored."""
        var events = self.quic.poll(timeout_ms)
        self._feed(stream_id, events, reader)
        return reader.is_complete()

    def _feed(
        mut self,
        stream_id: UInt64,
        events: ConnectionEvents,
        mut reader: H3ResponseReader,
    ) raises:
        if Int(stream_id) != self._reasm_sid:
            self._reasm = _StreamReasm()
            self._reasm_sid = Int(stream_id)
        for i in range(len(events.stream_chunks)):
            if events.stream_chunks[i].stream_id != stream_id:
                continue  # server uni-streams / other requests
            self._reasm.push(
                reader,
                events.stream_chunks[i].offset,
                Span[UInt8, _](events.stream_chunks[i].data),
                events.stream_chunks[i].fin,
            )

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
        budget timeout (the caller falls back to h2/h1)."""
        var sid = self.send_request(
            method, scheme, authority, path, headers, body
        )
        var reader = H3ResponseReader(self.max_field_section_size)
        for _ in range(max_polls):
            if self.read_response(sid, reader, timeout_ms):
                return reader.take_response()
        raise Error("h3 client: response did not complete within poll budget")

    def is_established(self) -> Bool:
        return self.quic.is_established()

    def close(mut self):
        self.quic.close()
