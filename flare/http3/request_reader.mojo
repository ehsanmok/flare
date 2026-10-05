"""HTTP/3 request-stream reader -- sans-I/O state machine.

An HTTP/3 request lives on a single bidirectional QUIC stream:
the client emits a HEADERS frame (QPACK-encoded request pseudo-
headers + application headers), zero or more DATA frames carrying
the request body, and optionally a trailing HEADERS frame for
trailers. The stream's FIN bit closes the request side of the
exchange.

This module ships the codec-side reader that turns a stream of
bytes into a typed callback sequence on a caller-supplied
:trait:`Http3RequestEventHandler`:

* :meth:`Http3RequestEventHandler.on_headers`  -- the first HEADERS
  frame has been parsed and QPACK-decoded.
* :meth:`Http3RequestEventHandler.on_data`     -- a DATA frame's
  payload is ready.
* :meth:`Http3RequestEventHandler.on_trailers` -- the trailing
  HEADERS frame closing the request side has been parsed.
* :meth:`Http3RequestEventHandler.on_unknown_frame` -- an unknown /
  grease frame type was parsed; receivers MUST ignore (RFC 9114
  §7.2.8). The reader skips the payload bytes and fires the
  callback so the caller can log it.
* :meth:`Http3RequestEventHandler.on_protocol_error` -- the byte
  stream is malformed (truncated varint, oversize length, QPACK
  decode failure, repeated HEADERS, an unknown frame declaring more than
  ``max_field_section_bytes``); the caller surfaces this as
  an H3_FRAME_UNEXPECTED stream-level error to the QUIC peer. A
  QPACK decode failure is tagged ``QPACK_DECOMPRESSION_FAILED``:
  :class:`flare.http3.Http3Connection` raises it as a connection
  error (RFC 9204 section 2.2.3).

The dispatcher entry point :func:`feed_into[H]` returns the
number of bytes consumed. A return of ``0`` means NEEDS_MORE --
the buffer does not yet hold a complete next frame; the caller
accumulates more bytes and calls again. The reader fires at most
one callback per ``feed_into`` invocation.

Sans-I/O contract: the reader holds zero socket / QUIC
references; it operates on byte spans that the QUIC stream
reassembly layer hands it. The H3 server reactor wraps this in a
per-stream loop that calls ``feed_into`` after every QUIC DATA
chunk arrival.

References:
- RFC 9114 §4 (HTTP Message Exchanges) + §7 (Frames).
- RFC 9204 (QPACK) -- field-section decoder used for HEADERS.
"""

from std.collections import List
from std.memory import ArcPointer
from std.collections.span import Span

from flare.qpack import QpackHeader
from flare.qpack.dynamic import QpackDynamicTable, decode_field_section_dynamic
from flare.quic.varint import decode_varint

from .frame import (
    H3_FRAME_TYPE_CANCEL_PUSH,
    H3_FRAME_TYPE_DATA,
    H3_FRAME_TYPE_GOAWAY,
    H3_FRAME_TYPE_H2_CONTINUATION,
    H3_FRAME_TYPE_H2_PING,
    H3_FRAME_TYPE_H2_PRIORITY,
    H3_FRAME_TYPE_H2_WINDOW_UPDATE,
    H3_FRAME_TYPE_HEADERS,
    H3_FRAME_TYPE_MAX_PUSH_ID,
    H3_FRAME_TYPE_PUSH_PROMISE,
    H3_FRAME_TYPE_SETTINGS,
)


# ── State tags ─────────────────────────────────────────────────────────────


comptime H3_REQUEST_STATE_INIT: Int = 0
"""Awaiting the first HEADERS frame on this request stream."""
comptime H3_REQUEST_STATE_BODY: Int = 1
"""HEADERS received; reading DATA + optional trailers."""
comptime H3_REQUEST_STATE_TRAILERS: Int = 2
"""Trailers received; the next event must be NEEDS_MORE or
end-of-stream signalled by the caller. Receiving any further
frame is a protocol error."""
comptime H3_REQUEST_STATE_DONE: Int = 3
"""Stream is closed; further calls are no-ops."""


# ── Event-handler trait ────────────────────────────────────────────────────


trait Http3RequestEventHandler(Deinitable, Movable):
    """Per-event callback contract :func:`feed_into` fires.

    The dispatcher reads one wire frame at the start of the
    request-stream buffer and invokes exactly one callback per
    successful parse (HEADERS, DATA, TRAILERS, UNKNOWN_FRAME, or
    PROTOCOL_ERROR). NEEDS_MORE returns ``0`` without firing any
    callback -- the caller accumulates more bytes and re-invokes
    the dispatcher.

    Callbacks own their payload arguments by value so the handler
    can stash them (e.g. into a per-stream request accumulator)
    without lifetime gymnastics.
    """

    def on_headers(mut self, headers: List[QpackHeader]) raises:
        """A complete first HEADERS frame has been parsed and
        QPACK-decoded. The reader's state advances to ``BODY``.
        """
        ...

    def on_data(mut self, data: List[UInt8]) raises:
        """A complete DATA frame has been parsed. ``data`` carries
        the payload bytes."""
        ...

    def on_trailers(mut self, trailers: List[QpackHeader]) raises:
        """A trailing HEADERS frame closing the request side has
        been parsed. The reader's state advances to ``TRAILERS``.
        """
        ...

    def on_unknown_frame(mut self, type_id: UInt64) raises:
        """An unknown / grease frame type fired. Receivers MUST
        ignore per RFC 9114 §7.2.8; the reader skips the payload
        bytes and fires this so the caller may log."""
        ...

    def on_protocol_error(mut self, message: String) raises:
        """The byte stream is malformed (truncated varint,
        oversize length, QPACK decode failure, out-of-order
        frame). The reader's state has already advanced to
        ``DONE`` before this fires; the caller surfaces this as
        a stream-level error to the QUIC peer.
        """
        ...


# ── Reader ─────────────────────────────────────────────────────────────────


@fieldwise_init
struct Http3RequestReader(Copyable):
    """Per-stream H3 request-side reader.

    The reader is stateful: it tracks whether the initial HEADERS
    frame has been seen so a second HEADERS frame can be classified
    as either trailers (legal, after at least one DATA frame in
    practice but the spec allows zero) or a protocol error
    (e.g. when the state has already advanced to TRAILERS).
    """

    var state: Int
    var max_field_section_bytes: UInt64
    var max_body_bytes: UInt64
    """Most request-body bytes accepted across all DATA frames."""
    var body_bytes: UInt64
    """Request-body bytes delivered so far."""
    var qpack_table: ArcPointer[QpackDynamicTable]
    """RFC 9204 dynamic table shared (by ``ArcPointer``) from the
    owning :class:`Http3Connection`. Defaults to an empty (capacity-0)
    table so a standalone reader decodes static-only field sections
    identically to the static path; the connection injects its real
    table at :meth:`Http3Connection.open_request_stream` so dynamic
    references resolve."""

    @staticmethod
    def new(
        max_field_section_bytes: UInt64 = UInt64(8192),
        max_body_bytes: UInt64 = UInt64(10 * 1024 * 1024),
    ) -> Self:
        return Self(
            state=H3_REQUEST_STATE_INIT,
            max_field_section_bytes=max_field_section_bytes,
            max_body_bytes=max_body_bytes,
            body_bytes=UInt64(0),
            qpack_table=ArcPointer[QpackDynamicTable](
                QpackDynamicTable(UInt64(0))
            ),
        )


def _parse_frame_header(
    buf: Span[UInt8, _],
) raises -> Tuple[UInt64, UInt64, Int]:
    """Decode the (type-varint, length-varint) header that
    prefixes every H3 frame and return ``(type, length,
    header_size)``.
    """
    if len(buf) == 0:
        raise Error("h3 reader: empty buffer at frame header")
    var type_var = decode_varint(buf)
    var rest = buf[type_var.consumed :]
    if len(rest) == 0:
        raise Error("h3 reader: type without length")
    var len_var = decode_varint(rest)
    return Tuple[UInt64, UInt64, Int](
        type_var.value,
        len_var.value,
        type_var.consumed + len_var.consumed,
    )


def feed_into[
    H: Http3RequestEventHandler
](
    mut reader: Http3RequestReader,
    buf: Span[UInt8, _],
    mut handler: H,
) raises -> Int:
    """Try to parse the next H3 frame at the start of ``buf`` and
    fire the matching :trait:`Http3RequestEventHandler` callback.

    Returns the number of bytes consumed:

    * ``0`` -- NEEDS_MORE: the buffer is truncated or the reader
      is already DONE. No callback fires; the caller accumulates
      more bytes and re-invokes the dispatcher.
    * ``> 0`` -- exactly one callback fired
      (``on_headers`` / ``on_data`` / ``on_trailers`` /
      ``on_unknown_frame`` / ``on_protocol_error``). The caller
      advances its cursor by the returned count and re-invokes
      the dispatcher to drain the remainder.

    Protocol errors advance the reader's state to ``DONE`` before
    the callback fires; subsequent ``feed_into`` calls return
    ``0`` and never fire another callback.
    """
    if reader.state == H3_REQUEST_STATE_DONE:
        return 0
    if len(buf) == 0:
        return 0

    # Try to read the frame header without committing to advancing
    # the reader state -- a truncated input must be NEEDS_MORE,
    # not PROTOCOL_ERROR.
    var ftype: UInt64
    var flen: UInt64
    var header_size: Int
    try:
        var t = _parse_frame_header(buf)
        ftype = t[0]
        flen = t[1]
        header_size = t[2]
    except:
        return 0
    # Limits are checked from the frame header, before the payload is
    # waited for. They used to come after the NEEDS_MORE return, so a
    # HEADERS or DATA frame declaring gigabytes had its bytes buffered
    # by the caller for as long as the peer cared to send them.
    if ftype == H3_FRAME_TYPE_HEADERS and flen > reader.max_field_section_bytes:
        reader.state = H3_REQUEST_STATE_DONE
        handler.on_protocol_error(
            String("h3 reader: HEADERS field section above limit")
        )
        return header_size
    if (
        ftype == H3_FRAME_TYPE_DATA
        and reader.body_bytes + flen > reader.max_body_bytes
    ):
        reader.state = H3_REQUEST_STATE_DONE
        handler.on_protocol_error(String("h3 reader: request body above limit"))
        return header_size
    # Every other type (unknown / grease, and the control types that are
    # rejected anyway) was NEEDS_MORE until its whole declared payload,
    # up to 2^62 - 1 bytes, was buffered (H3-01). Its payload would be
    # discarded, so a frame that large is refused from the header: the
    # most the caller ever holds is bounded (RFC 9114 sec 10.5).
    if (
        ftype != H3_FRAME_TYPE_HEADERS
        and ftype != H3_FRAME_TYPE_DATA
        and flen > reader.max_field_section_bytes
    ):
        reader.state = H3_REQUEST_STATE_DONE
        handler.on_protocol_error(
            String(
                "h3 reader: H3_EXCESSIVE_LOAD: frame of "
                + String(flen)
                + " bytes above the limit"
            )
        )
        return header_size
    var total = header_size + Int(flen)
    if total > len(buf):
        return 0

    # Frame is fully present. Dispatch on type + state.
    if ftype == H3_FRAME_TYPE_HEADERS:
        if reader.state == H3_REQUEST_STATE_TRAILERS:
            reader.state = H3_REQUEST_STATE_DONE
            handler.on_protocol_error(
                String("h3 reader: HEADERS after trailers")
            )
            return total
        if flen > reader.max_field_section_bytes:
            reader.state = H3_REQUEST_STATE_DONE
            handler.on_protocol_error(
                String("h3 reader: HEADERS field section above limit")
            )
            return total
        var payload = buf[header_size:total]
        var headers: List[QpackHeader]
        try:
            headers = decode_field_section_dynamic(
                payload, reader.qpack_table[]
            )
        except:
            reader.state = H3_REQUEST_STATE_DONE
            # An undecodable field section is a connection error of type
            # QPACK_DECOMPRESSION_FAILED (RFC 9204 sec 2.2.3, 4.5.1.1);
            # the tag lets Http3Connection raise it to the QUIC layer.
            handler.on_protocol_error(
                String(
                    "h3 reader: QPACK decode failed"
                    " (QPACK_DECOMPRESSION_FAILED)"
                )
            )
            return total
        if reader.state == H3_REQUEST_STATE_INIT:
            reader.state = H3_REQUEST_STATE_BODY
            handler.on_headers(headers^)
            return total
        # In BODY -- this is the trailers frame.
        reader.state = H3_REQUEST_STATE_TRAILERS
        handler.on_trailers(headers^)
        return total

    if ftype == H3_FRAME_TYPE_DATA:
        if reader.state != H3_REQUEST_STATE_BODY:
            reader.state = H3_REQUEST_STATE_DONE
            handler.on_protocol_error(
                String("h3 reader: DATA outside body window")
            )
            return total
        var data = List[UInt8](capacity=Int(flen))
        for i in range(header_size, total):
            data.append(buf[i])
        reader.body_bytes += flen
        handler.on_data(data^)
        return total

    # CANCEL_PUSH / SETTINGS / PUSH_PROMISE / GOAWAY / MAX_PUSH_ID
    # are all illegal on a request stream (RFC 9114 §6.2). The
    # control-frame types belong on the unidirectional control
    # streams; emitting them here is a hard protocol error.
    if (
        ftype == H3_FRAME_TYPE_SETTINGS
        or ftype == H3_FRAME_TYPE_GOAWAY
        or ftype == H3_FRAME_TYPE_MAX_PUSH_ID
        or ftype == H3_FRAME_TYPE_CANCEL_PUSH
        or ftype == H3_FRAME_TYPE_PUSH_PROMISE
    ):
        reader.state = H3_REQUEST_STATE_DONE
        handler.on_protocol_error(
            String("h3 reader: control-stream frame type on request stream")
        )
        return total

    # 0x02 / 0x06 / 0x08 / 0x09 are the HTTP/2 PRIORITY, PING,
    # WINDOW_UPDATE and CONTINUATION frame types, reserved by RFC 9114
    # §7.2.8 and §11.2.1: "their receipt MUST be treated as a
    # connection error of type H3_FRAME_UNEXPECTED". They were handed to
    # ``on_unknown_frame`` and skipped (H3-02).
    if (
        ftype == H3_FRAME_TYPE_H2_PRIORITY
        or ftype == H3_FRAME_TYPE_H2_PING
        or ftype == H3_FRAME_TYPE_H2_WINDOW_UPDATE
        or ftype == H3_FRAME_TYPE_H2_CONTINUATION
    ):
        reader.state = H3_REQUEST_STATE_DONE
        handler.on_protocol_error(
            String(
                "h3 reader: H3_FRAME_UNEXPECTED: HTTP/2-reserved frame type "
                + String(ftype)
                + " on request stream"
            )
        )
        return total

    # Unknown / grease -- ignore per RFC 9114 §7.2.8.
    handler.on_unknown_frame(ftype)
    return total
