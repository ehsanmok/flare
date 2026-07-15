"""``flare.grpc.server_stream`` -- server-streaming gRPC adapter.

A server-streaming call maps onto a single HTTP/2 stream that
carries *one* request message and *zero or more* response
messages before the trailing HEADERS:

* Request HEADERS + a single request LPM frame (same shape as a
  unary call -- see :mod:`flare.grpc.server`).
* Response HEADERS: ``:status=200``, ``content-type:
  application/grpc``, optional ``grpc-encoding``.
* Response DATA: one back-to-back LPM frame per yielded message.
* Response trailing HEADERS: ``grpc-status`` (REQUIRED), optional
  ``grpc-message`` + trailing metadata.

The wire shape of N response frames inside one DATA stream is
exactly N LPM frames concatenated, so this adapter reuses the
unary :func:`flare.grpc.server.encode_unary_response` per message
and the unary :func:`_response_from_outcome` glue -- the only new
surface is the handler trait (which yields a *list* of messages)
and the per-message encode loop.

This adapter is *buffered* -- the handler returns the
full message list and the adapter encodes them all into one
:class:`Response` body, which the reactor flushes once at
END_STREAM. That means an unbounded / large stream holds every
message in memory before the first byte ships. A streaming-friendly
variant would write each LPM frame onto the live H2 DATA path via
:mod:`flare.http.streaming_server` and only frame the trailers at the
end.
"""

from std.collections import List, Optional
from std.memory import Span
from std.time import perf_counter_ns

from flare.http.body import ChunkSource
from flare.http.cancel import Cancel
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.response_stream import ChunkSourceBox

from .metadata import GrpcMetadata
from .server import (
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcRequestHeaders,
    _grpc_headers_from_request,
    _negotiate_response_encoding,
    emit_trailing_headers_status,
    encode_unary_response,
    parse_request_headers,
    stitch_request_data,
    _parse_grpc_timeout,
)
from .status import (
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_INVALID_ARGUMENT,
    GrpcStatus,
)


# ── Server-streaming handler reply ─────────────────────────────────────────


@fieldwise_init
struct GrpcServerStreamReply(Copyable, Movable):
    """Typed return value for a server-streaming gRPC handler.

    ``messages`` is the ordered list of response bodies the handler
    yields; each becomes one LPM frame on the wire. ``status`` is the
    final call outcome (OK or a typed error) carried on the trailers,
    and ``trailing_metadata`` is the optional application trailer set.

    A non-OK status SHOULD ship an empty ``messages`` list -- a stream
    that fails mid-way still carries whatever it already yielded plus
    the error trailer, but the two factory methods keep the common
    "all messages then OK" / "no messages, just an error" shapes
    one-liners.
    """

    var messages: List[List[UInt8]]
    var status: GrpcStatus
    var trailing_metadata: GrpcMetadata

    @staticmethod
    def ok(
        var messages: List[List[UInt8]],
        var trailing_metadata: GrpcMetadata = GrpcMetadata(),
    ) -> Self:
        """Build an OK server-streaming reply yielding ``messages``."""
        return Self(
            messages=messages^,
            status=GrpcStatus.ok(),
            trailing_metadata=trailing_metadata^,
        )

    @staticmethod
    def err(
        var status: GrpcStatus,
        var trailing_metadata: GrpcMetadata = GrpcMetadata(),
    ) -> Self:
        """Build a non-OK reply: no messages, just the error trailer."""
        return Self(
            messages=List[List[UInt8]](),
            status=status^,
            trailing_metadata=trailing_metadata^,
        )


# ── Server-streaming handler trait ─────────────────────────────────────────


trait GrpcServerStreaming(Movable):
    """Server-streaming gRPC handler.

    The handler receives the decoded request bytes (LPM-stitched +
    decompressed, exactly like a unary handler) and returns a
    :class:`GrpcServerStreamReply` carrying the ordered list of
    response messages + the final status + trailing metadata.
    """

    def serve_server_streaming(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcServerStreamReply:
        ...


def _outcome_from_stream_reply(
    var reply: GrpcServerStreamReply,
    accept_encoding: String = String(""),
) -> GrpcCallOutcome:
    """Pack a :class:`GrpcServerStreamReply` into a
    :class:`GrpcCallOutcome` whose ``response_data`` is the
    concatenation of one LPM frame per yielded message.

    Compression is negotiated once for the whole stream
    (``grpc-accept-encoding``); each message frame is individually
    compressed when the body clears the size threshold, matching the
    per-frame flag semantics of the unary encoder. An encode failure
    folds into an empty body + INTERNAL status so the driver always
    has a well-formed outcome.
    """
    var response_data = List[UInt8]()
    var status = reply.status.copy()
    var used_encoding = _negotiate_response_encoding(accept_encoding)
    try:
        for i in range(len(reply.messages)):
            encode_unary_response(
                reply.messages[i].copy(), response_data, used_encoding
            )
    except:
        response_data = List[UInt8]()
        used_encoding = String("")
        status = GrpcStatus.err(
            GRPC_STATUS_INTERNAL,
            String("grpc adapter: response stream LPM encode failed"),
        )
    var trailing_copy = reply.trailing_metadata.copy()
    return GrpcCallOutcome(
        response_data=response_data^,
        status=status^,
        trailing_metadata=trailing_copy^,
        encoding=used_encoding^,
    )


def _drive_stream_reply[
    H: GrpcServerStreaming
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcServerStreamReply:
    """Validate + dispatch a server-streaming call to its handler.

    Folds failures into typed replies exactly like
    :func:`flare.grpc.server.run_unary_call`: HEADERS validation and
    LPM-stitch failures map to ``INVALID_ARGUMENT``; a handler ``raises``
    maps to ``INTERNAL``. Returns the raw :class:`GrpcServerStreamReply`
    (messages + status) so callers can either buffer it
    (:func:`run_server_streaming_call`) or stream it incrementally
    (:func:`_streaming_response_from_reply`).
    """
    var ctx: GrpcCallContext
    try:
        ctx = parse_request_headers(headers)
    except e:
        return GrpcServerStreamReply.err(
            GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
        )
    var req_encoding = String("")
    if Bool(headers.encoding):
        req_encoding = headers.encoding.value()
    var request_bytes: List[UInt8]
    try:
        request_bytes = stitch_request_data(request_data, req_encoding)
    except e:
        return GrpcServerStreamReply.err(
            GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
        )
    try:
        return handler.serve_server_streaming(
            ctx, Span[UInt8, _](request_bytes)
        )
    except e:
        return GrpcServerStreamReply.err(
            GrpcStatus.err(GRPC_STATUS_INTERNAL, String(e))
        )


def run_server_streaming_call[
    H: GrpcServerStreaming
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcCallOutcome:
    """End-to-end (buffered) driver for a server-streaming call.

    Same failure folding as :func:`flare.grpc.server.run_unary_call`.
    The OK path encodes every yielded message into one response body.
    The reactor-mounted service prefers the incremental path
    (:func:`_streaming_response_from_reply`); this buffered outcome
    remains for direct/unit-test use.
    """
    var accept = String("")
    if Bool(headers.accept_encoding):
        accept = headers.accept_encoding.value()
    var reply = _drive_stream_reply[H](handler, headers, request_data)
    return _outcome_from_stream_reply(reply^, accept)


# ── Incremental (per-message DATA-frame) streaming path ────────────────────


struct _GrpcStreamMessageSource(ChunkSource, Movable):
    """A :trait:`ChunkSource` that emits one LPM frame per ``next`` call.

    Wraps the handler's materialized message list so each response
    message ships as its own HTTP/2 DATA frame on a writable edge
    (flow-controlled) instead of one buffered blob. Compression is
    negotiated once for the whole stream and applied per frame, matching
    the buffered encoder's semantics.

    ponytail: the handler still returns the full ``List[List[UInt8]]``
    up front, so this bounds *wire flushing*, not handler-side memory.
    A pull-based ``GrpcServerStreaming`` variant (yield one message per
    call) is the upgrade path for unbounded streams.
    """

    var messages: List[List[UInt8]]
    var encoding: String
    var idx: Int

    def __init__(
        out self, var messages: List[List[UInt8]], var encoding: String
    ):
        self.messages = messages^
        self.encoding = encoding^
        self.idx = 0

    def next(mut self, cancel: Cancel) raises -> Optional[List[UInt8]]:
        if cancel.cancelled() or self.idx >= len(self.messages):
            return Optional[List[UInt8]]()
        var frame = List[UInt8]()
        encode_unary_response(
            self.messages[self.idx].copy(), frame, self.encoding
        )
        self.idx += 1
        return Optional[List[UInt8]](frame^)


def _streaming_response_from_reply(
    var reply: GrpcServerStreamReply,
    accept_encoding: String = String(""),
) raises -> Response:
    """Build a streaming :class:`Response` from a server-stream reply.

    Leading HEADERS carry ``:status=200`` + ``content-type`` (+
    ``grpc-encoding``); each message ships incrementally as its own DATA
    frame via :class:`_GrpcStreamMessageSource`; ``grpc-status`` + any
    text trailing metadata ride the trailing HEADERS block that the H2
    reactor emits at END_STREAM.
    """
    var used_encoding = _negotiate_response_encoding(accept_encoding)
    var resp = Response(200)
    resp.headers.set("content-type", "application/grpc")
    if used_encoding != "":
        resp.headers.set("grpc-encoding", used_encoding)
    var status_trailers = emit_trailing_headers_status(reply.status)
    for i in range(len(status_trailers)):
        resp.trailers.set(status_trailers[i][0], status_trailers[i][1])
    var entries = reply.trailing_metadata.entries()
    for i in range(len(entries)):
        if entries[i].is_binary:
            continue
        resp.trailers.set(
            entries[i].key,
            String(unsafe_from_utf8=Span[UInt8, _](entries[i].value)),
        )
    var src = _GrpcStreamMessageSource(reply.messages.copy(), used_encoding^)
    resp.body_stream = Optional[ChunkSourceBox](
        ChunkSourceBox.create[_GrpcStreamMessageSource](src^)
    )
    return resp^


# ── Reactor-mounted server-streaming service ──────────────────────────────


@fieldwise_init
struct GrpcStreamingService[
    H: Copyable & GrpcServerStreaming & ImplicitlyDestructible
](Copyable, Handler, Movable):
    """Adapt a :class:`GrpcServerStreaming` handler into a plain
    :trait:`Handler` so it serves over the unified
    :class:`flare.http.HttpServer` H2 reactor path.

    Mount it like any other handler::

        var svc = GrpcStreamingService(TickHandler())
        server.serve(svc)

    One H2 stream maps to one server-streaming call: the reactor hands
    the assembled :class:`Request` (HEADERS + the single request DATA
    frame), the adapter runs :func:`run_server_streaming_call`, and
    returns a :class:`Response` whose body carries every response LPM
    frame and whose trailers carry ``grpc-status``.

    Deadline enforcement mirrors the unary
    :class:`flare.grpc.server.GrpcService`: a post-hoc elapsed check
    against ``grpc-timeout``. Same ceiling -- a runaway handler runs to
    completion before the status flips.
    """

    var handler: Self.H

    def serve(self, req: Request) raises -> Response:
        var headers = _grpc_headers_from_request(req)
        var accept = String("")
        if Bool(headers.accept_encoding):
            accept = headers.accept_encoding.value()
        var budget_us = UInt64(0)
        if Bool(headers.timeout):
            var ts = headers.timeout.value()
            if ts.byte_length() > 0:
                try:
                    budget_us = _parse_grpc_timeout(ts)
                except:
                    budget_us = UInt64(0)
        var start_ns = perf_counter_ns()
        var h = self.handler.copy()
        var reply = _drive_stream_reply[Self.H](
            h, headers, Span[UInt8, _](req.body)
        )
        # Deadline is a post-hoc elapsed check (the handler ran to
        # completion producing the message list); on overrun the reply
        # is replaced with a DEADLINE_EXCEEDED trailer, no messages.
        if budget_us > UInt64(0):
            var elapsed_us = UInt64((perf_counter_ns() - start_ns) // 1_000)
            if elapsed_us > budget_us:
                reply = GrpcServerStreamReply.err(
                    GrpcStatus.err(
                        GRPC_STATUS_DEADLINE_EXCEEDED,
                        String("deadline exceeded"),
                    )
                )
        # Incremental flush: each message ships as its own DATA frame on
        # a writable edge, trailers close the stream at END_STREAM.
        return _streaming_response_from_reply(reply^, accept)
