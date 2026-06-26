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

ponytail: this adapter is *buffered* -- the handler returns the
full message list and the adapter encodes them all into one
:class:`Response` body, which the reactor flushes once at
END_STREAM. Ceiling: an unbounded / large stream holds every
message in memory before the first byte ships. Upgrade path: an
incremental variant that writes each LPM frame onto the live H2
DATA path via :mod:`flare.http.streaming_server` and only frames
the trailers at the end.
"""

from std.collections import List, Optional
from std.memory import Span
from std.time import perf_counter_ns

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response

from .metadata import GrpcMetadata
from .server import (
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcRequestHeaders,
    _grpc_headers_from_request,
    _negotiate_response_encoding,
    _response_from_outcome,
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


def run_server_streaming_call[
    H: GrpcServerStreaming
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcCallOutcome:
    """End-to-end driver for a server-streaming call.

    Same failure folding as :func:`flare.grpc.server.run_unary_call`:
    HEADERS validation and LPM-stitch failures map to
    ``INVALID_ARGUMENT``; a handler ``raises`` maps to ``INTERNAL``.
    The OK path encodes every yielded message into the response body.
    """
    var accept = String("")
    if Bool(headers.accept_encoding):
        accept = headers.accept_encoding.value()
    var req_encoding = String("")
    if Bool(headers.encoding):
        req_encoding = headers.encoding.value()
    var ctx: GrpcCallContext
    try:
        ctx = parse_request_headers(headers)
    except e:
        return _outcome_from_stream_reply(
            GrpcServerStreamReply.err(
                GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
            ),
            accept,
        )
    var request_bytes: List[UInt8]
    try:
        request_bytes = stitch_request_data(request_data, req_encoding)
    except e:
        return _outcome_from_stream_reply(
            GrpcServerStreamReply.err(
                GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
            ),
            accept,
        )
    var reply: GrpcServerStreamReply
    try:
        reply = handler.serve_server_streaming(
            ctx, Span[UInt8, _](request_bytes)
        )
    except e:
        return _outcome_from_stream_reply(
            GrpcServerStreamReply.err(
                GrpcStatus.err(GRPC_STATUS_INTERNAL, String(e))
            ),
            accept,
        )
    return _outcome_from_stream_reply(reply^, accept)


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
        var outcome = run_server_streaming_call[Self.H](
            h, headers, Span[UInt8, _](req.body)
        )
        if budget_us > UInt64(0):
            var elapsed_us = UInt64((perf_counter_ns() - start_ns) // 1_000)
            if elapsed_us > budget_us:
                outcome = _outcome_from_stream_reply(
                    GrpcServerStreamReply.err(
                        GrpcStatus.err(
                            GRPC_STATUS_DEADLINE_EXCEEDED,
                            String("deadline exceeded"),
                        )
                    )
                )
        return _response_from_outcome(outcome^)
