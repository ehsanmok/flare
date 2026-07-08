"""Multiplexed duplex framed transport over one connection.

A streaming-proxy front otherwise opens one backend connection *per
request* -- fd churn and a connect(2) round trip on the hot path at high
concurrency, plus an ad-hoc length prefix re-invented at each call site.
This module replaces that with a persistent multiplexed transport: many
concurrent logical streams ride one ``UnixStream``, demuxed by a 64-bit
``request_id``, framed once here.

Wire frame (all integers big-endian)::

    | u32 payload_len | u64 request_id | u8 kind | payload[payload_len] |

``kind`` is one of ``FrameKind.{OPEN, CHUNK, DONE, ERROR, CANCEL}``. The
13-byte fixed header means a reader knows the full frame size after the
first 13 bytes, so partial reads reassemble deterministically.

Three layers, smallest first (each is independently testable):

- ``encode_frame`` / ``decode_frame`` -- the pure codec over
  ``ByteWriter`` / ``ByteReader``. No I/O, no allocation beyond the
  payload copy. This is the fuzz/ASan core.
- ``FrameDemux`` -- a sans-I/O reassembly buffer: ``feed(bytes)`` appends
  raw bytes (possibly splitting or coalescing frames arbitrarily) and
  routes every *complete* frame into a per-``request_id`` FIFO inbox.
  ``poll(id)`` / ``take_all(id)`` drain a stream's inbox. One stream's
  malformed payload never reaches another stream's inbox (isolation);
  frames within a stream keep arrival order (ordering).
- ``FrameMux`` -- ties a ``FrameDemux`` and an outbound ``ByteWriter`` to
  one owned ``UnixStream``: ``open`` / ``send_chunk`` / ``done`` /
  ``cancel`` queue outbound frames, ``flush`` writes them, ``pump`` reads
  inbound bytes and demuxes. No call ever reconnects -- the connection is
  opened once and owned for the mux's lifetime.

``FrameDemux`` accumulates into a single ``List[UInt8]`` and
compacts the consumed prefix after each drain (so a slow consumer cannot
make the buffer grow without bound across the *consumed* bytes). The
limit is one in-flight frame's payload held contiguously; a frame
larger than ``MAX_FRAME_PAYLOAD`` is rejected as a protocol error rather
than allocated. ``open`` returns nothing here; the single-stream
``UpstreamChunkSource`` (``flare.http.async_body``) is the reactor-
integrated wrapper over one logical stream.
"""

from std.collections import Dict, Optional

from flare.io import ByteReader, ByteWriter
from flare.uds.stream import UnixStream


comptime HEADER_LEN: Int = 13
"""Fixed frame header size: u32 len + u64 request_id + u8 kind."""

comptime MAX_FRAME_PAYLOAD: Int = 64 * 1024 * 1024
"""Reject any frame claiming a payload larger than this (protocol-error
guard against a corrupt/hostile 4-byte length blowing up allocation).
64 MiB is generous for a token-streaming relay; raise it only
with a matching backpressure story."""


struct FrameKind:
    """The five frame kinds. Plain ``UInt8`` tags (no enum in b2)."""

    comptime OPEN = UInt8(0)
    """Begin a logical stream for ``request_id``."""
    comptime CHUNK = UInt8(1)
    """A payload chunk for an open stream."""
    comptime DONE = UInt8(2)
    """Stream completed normally; no more frames for this id."""
    comptime ERROR = UInt8(3)
    """Stream failed; payload may carry a diagnostic. Isolated to this id."""
    comptime CANCEL = UInt8(4)
    """Caller abandoned the stream; peer should stop producing."""


struct Frame(Copyable, Movable):
    """One decoded frame: ``request_id`` + ``kind`` + owned ``payload``."""

    var request_id: UInt64
    """The logical stream this frame belongs to."""
    var kind: UInt8
    """One of ``FrameKind.*``."""
    var payload: List[UInt8]
    """Owned payload bytes (empty for OPEN/DONE/CANCEL typically)."""

    def __init__(
        out self, request_id: UInt64, kind: UInt8, var payload: List[UInt8]
    ):
        self.request_id = request_id
        self.kind = kind
        self.payload = payload^


# ── Pure codec ──────────────────────────────────────────────────────────────


def encode_frame(
    mut w: ByteWriter, request_id: UInt64, kind: UInt8, payload: Span[UInt8, _]
) raises:
    """Append one framed message to ``w``.

    Raises if ``payload`` exceeds ``MAX_FRAME_PAYLOAD`` (the same ceiling
    the decoder enforces, so an encoder cannot emit a frame its own
    decoder would reject).
    """
    if len(payload) > MAX_FRAME_PAYLOAD:
        raise Error("encode_frame: payload exceeds MAX_FRAME_PAYLOAD")
    w.write_u32_be(UInt32(len(payload)))
    w.write_u64_be(request_id)
    w.write_u8(kind)
    w.write_bytes(payload)


def decode_frame(mut r: ByteReader) raises -> Frame:
    """Decode exactly one frame from ``r`` (which must hold a full frame).

    Raises on a short buffer (via ``ByteReader``) or a payload length
    above ``MAX_FRAME_PAYLOAD``. Used by ``FrameDemux``; also directly
    fuzzable.
    """
    var plen = r.read_u32_be()
    if Int(plen) > MAX_FRAME_PAYLOAD:
        raise Error("decode_frame: payload exceeds MAX_FRAME_PAYLOAD")
    var rid = r.read_u64_be()
    var kind = r.read_u8()
    var span = r.read_bytes(Int(plen))
    var payload = List[UInt8](capacity=Int(plen))
    for i in range(len(span)):
        payload.append(span[i])
    return Frame(rid, kind, payload^)


# ── Reassembly + demux ───────────────────────────────────────────────────────


struct FrameDemux(Movable):
    """Sans-I/O frame reassembler with per-stream inboxes.

    Feed it arbitrary byte runs (frames may be split across feeds or
    several frames may arrive in one feed); it routes every complete
    frame into a FIFO keyed by ``request_id``.
    """

    var buf: List[UInt8]
    """Bytes received but not yet forming a complete frame's worth past
    the parse cursor. Compacted after each drain."""
    var inbox: Dict[UInt64, List[Frame]]
    """Per-stream FIFO of decoded frames awaiting consumption."""

    def __init__(out self):
        self.buf = List[UInt8]()
        self.inbox = Dict[UInt64, List[Frame]]()

    @always_inline
    def _peek_len(self, at: Int) -> Int:
        """Big-endian u32 payload length at offset ``at`` (caller ensures
        ``at + 4 <= len(buf)``)."""
        return (
            (Int(self.buf[at]) << 24)
            | (Int(self.buf[at + 1]) << 16)
            | (Int(self.buf[at + 2]) << 8)
            | Int(self.buf[at + 3])
        )

    def _route(mut self, var frame: Frame) raises:
        """Append ``frame`` to its stream's inbox (creating it on first
        sight, so an unsolicited id is still isolated, not dropped)."""
        var rid = frame.request_id
        if rid in self.inbox:
            self.inbox[rid].append(frame^)
        else:
            var q = List[Frame]()
            q.append(frame^)
            self.inbox[rid] = q^

    def feed(mut self, data: Span[UInt8, _]) raises:
        """Append ``data`` and route every complete frame now available.

        Raises only on a protocol error (a payload length above
        ``MAX_FRAME_PAYLOAD``); a merely incomplete trailing frame is
        retained for the next ``feed``.
        """
        for i in range(len(data)):
            self.buf.append(data[i])
        var consumed = 0
        var total = len(self.buf)
        while True:
            var avail = total - consumed
            if avail < HEADER_LEN:
                break
            var plen = self._peek_len(consumed)
            if plen > MAX_FRAME_PAYLOAD:
                raise Error(
                    "FrameDemux: frame payload exceeds MAX_FRAME_PAYLOAD"
                )
            var need = HEADER_LEN + plen
            if avail < need:
                break
            var frame_span = Span[UInt8, _](self.buf)[
                consumed : consumed + need
            ]
            var r = ByteReader(frame_span)
            var frame = decode_frame(r)
            self._route(frame^)
            consumed += need
        if consumed > 0:
            self._compact(consumed)

    def _compact(mut self, consumed: Int):
        """Drop the first ``consumed`` already-decoded bytes of ``buf``."""
        var rem = len(self.buf) - consumed
        if rem <= 0:
            self.buf.clear()
            return
        var nb = List[UInt8](capacity=rem)
        for i in range(rem):
            nb.append(self.buf[consumed + i])
        self.buf = nb^

    def poll(mut self, request_id: UInt64) raises -> Optional[Frame]:
        """Pop the oldest queued frame for ``request_id`` (FIFO), or
        ``None`` if its inbox is empty / absent."""
        if request_id not in self.inbox:
            return None
        ref q = self.inbox[request_id]
        if len(q) == 0:
            return None
        var head = q[0].copy()
        # Shift left by one (inboxes are short in steady state).
        var nq = List[Frame]()
        for i in range(1, len(q)):
            nq.append(q[i].copy())
        self.inbox[request_id] = nq^
        return head^

    def pending(self, request_id: UInt64) raises -> Int:
        """Number of queued frames for ``request_id``."""
        if request_id not in self.inbox:
            return 0
        return len(self.inbox[request_id])

    def drop(mut self, request_id: UInt64) raises:
        """Discard a stream's inbox entirely (e.g. after CANCEL)."""
        if request_id in self.inbox:
            _ = self.inbox.pop(request_id)


# ── Connection-backed mux ────────────────────────────────────────────────────


struct FrameMux(Movable):
    """Multiplexes many logical streams over one owned ``UnixStream``.

    Outbound frames are queued in ``out`` and written by ``flush``;
    inbound bytes are read by ``pump`` and demuxed into per-stream
    inboxes drained via ``poll`` / ``pending``. The connection is opened
    once by the caller and owned here -- no method ever reconnects.
    """

    var stream: UnixStream
    """The single owned backend connection."""
    var demux: FrameDemux
    """Inbound reassembly + per-stream inboxes."""
    var out: ByteWriter
    """Queued outbound frame bytes (flushed by ``flush``)."""
    var _next_id: UInt64
    """Monotonic id allocator for ``open_auto`` (caller may also pass
    explicit ids to ``open``)."""

    def __init__(out self, var stream: UnixStream):
        self.stream = stream^
        self.demux = FrameDemux()
        self.out = ByteWriter()
        self._next_id = 1

    def next_id(mut self) -> UInt64:
        """Allocate a fresh, never-reused ``request_id``."""
        var id = self._next_id
        self._next_id += 1
        return id

    def open(mut self, request_id: UInt64) raises:
        """Queue an OPEN frame to begin ``request_id``. No connect(2)."""
        var empty = List[UInt8]()
        encode_frame(
            self.out, request_id, FrameKind.OPEN, Span[UInt8, _](empty)
        )

    def send_chunk(
        mut self, request_id: UInt64, payload: Span[UInt8, _]
    ) raises:
        """Queue a CHUNK frame carrying ``payload`` for ``request_id``."""
        encode_frame(self.out, request_id, FrameKind.CHUNK, payload)

    def done(mut self, request_id: UInt64) raises:
        """Queue a DONE frame closing ``request_id`` normally."""
        var empty = List[UInt8]()
        encode_frame(
            self.out, request_id, FrameKind.DONE, Span[UInt8, _](empty)
        )

    def cancel(mut self, request_id: UInt64) raises:
        """Queue a CANCEL frame and drop the local inbox for
        ``request_id`` (the upstream-cancel path builds on this)."""
        var empty = List[UInt8]()
        encode_frame(
            self.out, request_id, FrameKind.CANCEL, Span[UInt8, _](empty)
        )
        self.demux.drop(request_id)

    def flush(mut self) raises:
        """Write all queued outbound frames to the connection."""
        if self.out.len() == 0:
            return
        var bytes = self.out.take()
        self.stream.write_all(Span[UInt8, _](bytes))

    def pump(mut self, max_bytes: Int = 65536) raises -> Int:
        """Read up to ``max_bytes`` inbound bytes and demux them.

        Returns the number of bytes read (0 means the peer closed the
        connection). Routes any complete frames into per-stream inboxes.
        """
        var tmp = List[UInt8](capacity=max_bytes)
        tmp.resize(max_bytes, UInt8(0))
        var n = self.stream.read(tmp.unsafe_ptr(), max_bytes)
        if n <= 0:
            return n
        self.demux.feed(Span[UInt8, _](tmp)[0:n])
        return n

    def poll(mut self, request_id: UInt64) raises -> Optional[Frame]:
        """Pop the oldest reassembled frame for ``request_id``."""
        return self.demux.poll(request_id)

    def pending(self, request_id: UInt64) raises -> Int:
        """Queued inbound frame count for ``request_id``."""
        return self.demux.pending(request_id)
