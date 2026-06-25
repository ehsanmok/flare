"""HTTP/3 response-stream reader -- sans-I/O stateful decoder.

The client-side mirror of :mod:`flare.h3.request_reader`. Where the
server's request reader fires a callback per frame, the client side
almost always wants the *assembled* response, so this reader is
stateful: feed it the reassembled bytes of a request (bidi) stream
as they arrive and it accumulates the response into an
:class:`H3Response` (status + headers + body + trailers).

A response stream carries, in order (RFC 9114 §4.1):

  HEADERS frame  (``:status`` pseudo-header + application headers)
  DATA frame     (zero or more, response body)
  HEADERS frame  (optional trailers)

then the QUIC stream FIN. Control-stream frame types (SETTINGS,
GOAWAY, ...) are illegal on a request stream and surface a protocol
error (RFC 9114 §6.2).

Usage:

```mojo
var reader = H3ResponseReader.new()
reader.feed(chunk0)
reader.feed(chunk1)
reader.signal_fin()
if reader.is_complete():
    var resp = reader.take_response()
```

Sans-I/O contract: the reader holds zero socket / QUIC references;
the QUIC client driver feeds it the per-stream reassembled bytes.

References:
- RFC 9114 §4 (HTTP Message Exchanges) + §7 (Frames).
- RFC 9204 (QPACK) -- field-section decoder used for HEADERS.
"""

from std.collections import List
from std.memory import Span

from flare.qpack import QpackHeader, decode_field_section
from flare.quic.varint import decode_varint

from .frame import (
    H3_FRAME_TYPE_CANCEL_PUSH,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_MAX_PUSH_ID,
    H3_FRAME_TYPE_PUSH_PROMISE,
    H3_FRAME_TYPE_SETTINGS,
)


# ── State tags ─────────────────────────────────────────────────────────────

comptime H3_RESPONSE_STATE_INIT: Int = 0
"""Awaiting the first HEADERS frame (the response head)."""
comptime H3_RESPONSE_STATE_BODY: Int = 1
"""HEADERS received; reading DATA + optional trailers."""
comptime H3_RESPONSE_STATE_TRAILERS: Int = 2
"""Trailers received; no further frames are legal."""
comptime H3_RESPONSE_STATE_DONE: Int = 3
"""Protocol error or shutdown; further feeds are no-ops."""


@fieldwise_init
struct H3Response(Copyable, Movable):
    """An assembled HTTP/3 response.

    ``status`` is the ``:status`` pseudo-header (RFC 9114 §4.3.2);
    ``headers`` are the application response headers (``:status``
    stripped); ``body`` is the concatenation of every DATA frame;
    ``trailers`` is the optional trailing field section.
    """

    var status: Int
    var headers: List[QpackHeader]
    var body: List[UInt8]
    var trailers: List[QpackHeader]


@fieldwise_init
struct H3BodyChunk(Copyable, Movable):
    """One incremental slice of a streaming HTTP/3 response body.

    Returned by :meth:`flare.h3.client.H3ClientConnection.poll_body`.
    ``data`` is the body bytes that became available on this poll
    (possibly empty); ``done`` is True once the response stream has
    finished (QUIC FIN), after which no further DATA will arrive and
    the trailers / final status are retrievable via
    :meth:`take_if_complete`."""

    var data: List[UInt8]
    var done: Bool


struct H3ResponseReader(Copyable, Movable):
    """Per-stream stateful HTTP/3 response decoder.

    Feed reassembled request-stream bytes via :meth:`feed`; the
    reader drains every complete frame it can and accumulates the
    response. A partial trailing frame is buffered in :attr:`inbox`
    until the next :meth:`feed`. Mark the QUIC FIN with
    :meth:`signal_fin`; once HEADERS are parsed and FIN is seen
    :meth:`is_complete` returns True and :meth:`take_response`
    yields the assembled :class:`H3Response`.
    """

    var state: Int
    var inbox: List[UInt8]
    var status: Int
    var headers: List[QpackHeader]
    var body: List[UInt8]
    var trailers: List[QpackHeader]
    var fin_received: Bool
    var error: String
    var max_field_section_bytes: UInt64

    def __init__(out self, max_field_section_bytes: UInt64 = UInt64(1 << 16)):
        self.state = H3_RESPONSE_STATE_INIT
        self.inbox = List[UInt8]()
        self.status = 0
        self.headers = List[QpackHeader]()
        self.body = List[UInt8]()
        self.trailers = List[QpackHeader]()
        self.fin_received = False
        self.error = String("")
        self.max_field_section_bytes = max_field_section_bytes

    @staticmethod
    def new(max_field_section_bytes: UInt64 = UInt64(1 << 16)) -> Self:
        return Self(max_field_section_bytes)

    def feed(mut self, chunk: Span[UInt8, _]) raises:
        """Append ``chunk`` to the inbox and drain every complete
        frame. Stops at the first incomplete frame (buffered) or
        on a protocol error (state -> DONE, message in
        :attr:`error`)."""
        for i in range(len(chunk)):
            self.inbox.append(chunk[i])
        self._drain()

    def signal_fin(mut self):
        """Record that the QUIC layer signalled end-of-stream."""
        self.fin_received = True

    def is_complete(self) -> Bool:
        """Whether a full response head has been parsed and the
        stream has finished (FIN), or the reader is DONE."""
        if self.state == H3_RESPONSE_STATE_DONE:
            return True
        var have_head = self.state != H3_RESPONSE_STATE_INIT
        return have_head and self.fin_received

    def has_error(self) -> Bool:
        return len(self.error.as_bytes()) > 0

    def head_ready(self) -> Bool:
        """Whether the response head (``:status`` + headers) has been
        parsed. True as soon as the first HEADERS frame is decoded --
        before the body or FIN arrive -- so a streaming caller can
        read :meth:`status_code` / :meth:`headers_copy` and begin
        draining the body with :meth:`drain_body` while DATA is still
        in flight. False on a protocol error before the head."""
        return (
            self.state == H3_RESPONSE_STATE_BODY
            or self.state == H3_RESPONSE_STATE_TRAILERS
        )

    def status_code(self) -> Int:
        """The parsed ``:status`` (0 until :meth:`head_ready`)."""
        return self.status

    def headers_copy(self) -> List[QpackHeader]:
        """A copy of the application response headers parsed so far
        (``:status`` already stripped). Valid once :meth:`head_ready`
        is True."""
        var out = List[QpackHeader](capacity=len(self.headers))
        for i in range(len(self.headers)):
            out.append(self.headers[i].copy())
        return out^

    def drain_body(mut self) -> List[UInt8]:
        """Move out the body bytes accumulated since the last drain,
        leaving the reader ready to accumulate more DATA. This is the
        streaming counterpart to :meth:`take_response`: a caller polls
        the connection, drains the available body chunk, and repeats
        until :meth:`is_complete`, never holding the whole body in
        memory at once. Trailers (if any) are still available via
        :meth:`take_response` after completion."""
        var out = self.body^
        self.body = List[UInt8]()
        return out^

    def take_response(mut self) raises -> H3Response:
        """Move out the assembled response. Raises if a protocol
        error fired or the response head was never parsed."""
        if self.has_error():
            raise Error("h3 response reader: " + self.error)
        if self.state == H3_RESPONSE_STATE_INIT:
            raise Error("h3 response reader: no HEADERS frame parsed")
        var out = H3Response(
            status=self.status,
            headers=self.headers^,
            body=self.body^,
            trailers=self.trailers^,
        )
        self.headers = List[QpackHeader]()
        self.body = List[UInt8]()
        self.trailers = List[QpackHeader]()
        return out^

    def _fail(mut self, message: String):
        self.state = H3_RESPONSE_STATE_DONE
        self.error = message

    def _drain(mut self) raises:
        """Consume as many complete frames from :attr:`inbox` as
        are present, compacting the inbox afterward."""
        var cursor = 0
        while self.state != H3_RESPONSE_STATE_DONE and cursor < len(self.inbox):
            var view = Span[UInt8, _](self.inbox)[cursor:]
            # Frame header = type varint + length varint.
            var ftype: UInt64
            var flen: UInt64
            var header_size: Int
            try:
                var tvar = decode_varint(view)
                var rest = view[tvar.consumed :]
                if len(rest) == 0:
                    break  # NEEDS_MORE: length varint not present yet
                var lvar = decode_varint(rest)
                ftype = tvar.value
                flen = lvar.value
                header_size = tvar.consumed + lvar.consumed
            except:
                break  # NEEDS_MORE: truncated varint
            var total = header_size + Int(flen)
            if total > len(view):
                break  # NEEDS_MORE: frame body not fully buffered
            # Copy the payload out of the inbox before mutating self
            # so the frame slice never aliases a mutable self field.
            var payload = List[UInt8](capacity=Int(flen))
            for i in range(header_size, total):
                payload.append(view[i])
            self._consume_frame(ftype, Span[UInt8, _](payload))
            cursor += total
        # Compact the inbox: drop the consumed prefix.
        if cursor > 0:
            var keep = List[UInt8]()
            for i in range(cursor, len(self.inbox)):
                keep.append(self.inbox[i])
            self.inbox = keep^

    def _consume_frame(mut self, ftype: UInt64, payload: Span[UInt8, _]) raises:
        """Apply one fully-buffered frame to the accumulators."""
        if ftype == H3_FRAME_TYPE_HEADERS:
            if self.state == H3_RESPONSE_STATE_TRAILERS:
                self._fail(String("HEADERS after trailers"))
                return
            if UInt64(len(payload)) > self.max_field_section_bytes:
                self._fail(String("HEADERS field section above limit"))
                return
            var fields: List[QpackHeader]
            try:
                fields = decode_field_section(payload)
            except:
                self._fail(String("QPACK decode failed"))
                return
            if self.state == H3_RESPONSE_STATE_INIT:
                self._apply_head(fields^)
                self.state = H3_RESPONSE_STATE_BODY
            else:
                # Trailing HEADERS frame.
                for i in range(len(fields)):
                    self.trailers.append(fields[i].copy())
                self.state = H3_RESPONSE_STATE_TRAILERS
            return
        if ftype == H3_FRAME_TYPE_DATA:
            if self.state != H3_RESPONSE_STATE_BODY:
                self._fail(String("DATA outside body window"))
                return
            for i in range(len(payload)):
                self.body.append(payload[i])
            return
        # Control-stream frame types are illegal on a request
        # stream (RFC 9114 §6.2) -> hard protocol error.
        if (
            ftype == H3_FRAME_TYPE_SETTINGS
            or ftype == H3_FRAME_TYPE_GOAWAY
            or ftype == H3_FRAME_TYPE_MAX_PUSH_ID
            or ftype == H3_FRAME_TYPE_CANCEL_PUSH
            or ftype == H3_FRAME_TYPE_PUSH_PROMISE
        ):
            self._fail(String("control-stream frame type on request stream"))
            return
        # Unknown / grease -- ignore per RFC 9114 §7.2.8 (payload
        # already skipped by the caller's cursor advance).

    def _apply_head(mut self, var fields: List[QpackHeader]) raises:
        """Split the first field section into ``:status`` + the
        application response headers."""
        var saw_status = False
        for i in range(len(fields)):
            if fields[i].name == ":status":
                self.status = _parse_status(fields[i].value)
                saw_status = True
            elif len(fields[i].name.as_bytes()) > 0 and fields[
                i
            ].name.as_bytes()[0] == UInt8(ord(":")):
                # Unknown response pseudo-header -> protocol error.
                self._fail(
                    String("unexpected response pseudo-header ")
                    + fields[i].name
                )
                return
            else:
                self.headers.append(fields[i].copy())
        if not saw_status:
            self._fail(String("response HEADERS missing :status"))


def _parse_status(value: String) raises -> Int:
    """Parse the ``:status`` pseudo-header value (a 3-digit status
    code, RFC 9114 §4.3.2) into an Int. Raises on a non-numeric or
    out-of-range value."""
    var bytes = value.as_bytes()
    if len(bytes) == 0:
        raise Error("h3 response reader: empty :status")
    var code = 0
    for i in range(len(bytes)):
        var b = Int(bytes[i])
        if b < 0x30 or b > 0x39:
            raise Error("h3 response reader: non-numeric :status")
        code = code * 10 + (b - 0x30)
    if code < 100 or code > 599:
        raise Error("h3 response reader: :status out of range")
    return code
