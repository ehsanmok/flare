"""``flare.grpc.client_stream`` -- server-side client-streaming + bidi.

A client-streaming call carries *many* request LPM frames and a
*single* response message; a bidi call carries many request frames and
*many* response frames. Both map onto one HTTP/2 stream:

* Request HEADERS + N request LPM frames, then the client half-closes.
* Response HEADERS + (client-streaming) one LPM frame / (bidi) N LPM
  frames + trailing HEADERS carrying ``grpc-status``.

The flare H2 reactor assembles the whole request body (all N frames)
before dispatch, so these adapters decode every request frame into a
list and hand it to the handler at once.

ponytail: request ingress is buffered (the reactor half-close boundary
is the whole assembled body), so a handler cannot react to request
frame k before frame k+1 arrives. True incremental request ingress
(surface each frame as it lands) needs a partial-body dispatch hook in
the reactor; the buffered decode here is the in-language ceiling and
covers the common request-aggregation shape. Bidi responses *are*
incremental (each reply ships as its own DATA frame via the K1
streaming path).
"""

from std.collections import List, Optional
from std.memory import Span
from std.time import perf_counter_ns

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response

from .framing import decode_grpc_message
from .server import (
    GrpcCallContext,
    GrpcRequestHeaders,
    GrpcUnaryReply,
    _decompress_payload,
    _grpc_headers_from_request,
    _outcome_from_reply,
    _parse_grpc_timeout,
    _response_from_outcome,
    parse_request_headers,
)
from .server_stream import (
    GrpcServerStreamReply,
    _streaming_response_from_reply,
)
from .status import (
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_INVALID_ARGUMENT,
    GrpcStatus,
)


def decode_request_messages(
    request_data: Span[UInt8, _],
    encoding: String = String(""),
) raises -> List[List[UInt8]]:
    """Decode every back-to-back LPM frame into its own payload list.

    Unlike :func:`flare.grpc.server.stitch_request_data` (which
    concatenates all payloads into one contiguous buffer for the unary
    shape), this preserves message boundaries so a client-streaming /
    bidi handler sees the ordered list of request messages. Compressed
    frames are decompressed per the call's ``grpc-encoding``.
    """
    var msgs = List[List[UInt8]]()
    var pos = 0
    var n = len(request_data)
    while pos < n:
        var dec = decode_grpc_message(request_data[pos:])
        if dec.needs_more:
            raise Error(
                "grpc adapter: truncated LPM frame at offset " + String(pos)
            )
        var payload = List[UInt8]()
        if dec.message.flag.is_compressed():
            var plain = _decompress_payload(
                Span[UInt8, _](dec.message.payload), encoding
            )
            for i in range(len(plain)):
                payload.append(plain[i])
        else:
            for i in range(len(dec.message.payload)):
                payload.append(dec.message.payload[i])
        msgs.append(payload^)
        pos += dec.consumed
    return msgs^


# ── Client-streaming (N requests -> 1 response) ────────────────────────────


trait GrpcClientStreaming(Movable):
    """Client-streaming gRPC handler.

    Receives the ordered list of decoded request messages (all frames
    the client sent before half-close) and returns a single
    :class:`GrpcUnaryReply` (one response message + status).
    """

    def serve_client_streaming(
        mut self,
        ctx: GrpcCallContext,
        messages: List[List[UInt8]],
    ) raises -> GrpcUnaryReply:
        ...


def _drive_client_stream_reply[
    H: GrpcClientStreaming
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcUnaryReply:
    """Validate + decode + dispatch a client-streaming call.

    Same failure folding as the unary driver: header / LPM decode
    failures map to ``INVALID_ARGUMENT``; a handler ``raises`` maps to
    ``INTERNAL``.
    """
    var ctx: GrpcCallContext
    try:
        ctx = parse_request_headers(headers)
    except e:
        return GrpcUnaryReply.err(
            GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
        )
    var req_encoding = String("")
    if Bool(headers.encoding):
        req_encoding = headers.encoding.value()
    var messages: List[List[UInt8]]
    try:
        messages = decode_request_messages(request_data, req_encoding)
    except e:
        return GrpcUnaryReply.err(
            GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
        )
    try:
        return handler.serve_client_streaming(ctx, messages^)
    except e:
        return GrpcUnaryReply.err(
            GrpcStatus.err(GRPC_STATUS_INTERNAL, String(e))
        )


@fieldwise_init
struct GrpcClientStreamingService[
    H: Copyable & GrpcClientStreaming & ImplicitlyDestructible
](Copyable, Handler, Movable):
    """Adapt a :class:`GrpcClientStreaming` handler into a
    :trait:`Handler` for the unified H2 reactor. One H2 stream = one
    client-streaming call; the reply is a single buffered LPM frame."""

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
        var reply = _drive_client_stream_reply[Self.H](
            h, headers, Span[UInt8, _](req.body)
        )
        if budget_us > UInt64(0):
            var elapsed_us = UInt64((perf_counter_ns() - start_ns) // 1_000)
            if elapsed_us > budget_us:
                reply = GrpcUnaryReply.err(
                    GrpcStatus.err(
                        GRPC_STATUS_DEADLINE_EXCEEDED,
                        String("deadline exceeded"),
                    )
                )
        return _response_from_outcome(_outcome_from_reply(reply^, accept))


# ── Bidirectional (N requests -> N responses) ──────────────────────────────


trait GrpcBidiStreaming(Movable):
    """Bidirectional-streaming gRPC handler.

    Receives the ordered list of decoded request messages and returns a
    :class:`GrpcServerStreamReply` (ordered response messages + status).
    Responses ship incrementally, one DATA frame per message.
    """

    def serve_bidi(
        mut self,
        ctx: GrpcCallContext,
        messages: List[List[UInt8]],
    ) raises -> GrpcServerStreamReply:
        ...


def _drive_bidi_reply[
    H: GrpcBidiStreaming
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcServerStreamReply:
    """Validate + decode + dispatch a bidi call (same folding shape)."""
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
    var messages: List[List[UInt8]]
    try:
        messages = decode_request_messages(request_data, req_encoding)
    except e:
        return GrpcServerStreamReply.err(
            GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
        )
    try:
        return handler.serve_bidi(ctx, messages^)
    except e:
        return GrpcServerStreamReply.err(
            GrpcStatus.err(GRPC_STATUS_INTERNAL, String(e))
        )


@fieldwise_init
struct GrpcBidiService[
    H: Copyable & GrpcBidiStreaming & ImplicitlyDestructible
](Copyable, Handler, Movable):
    """Adapt a :class:`GrpcBidiStreaming` handler into a
    :trait:`Handler`. Responses stream incrementally via the K1
    body-stream path (one DATA frame per reply message)."""

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
        var reply = _drive_bidi_reply[Self.H](
            h, headers, Span[UInt8, _](req.body)
        )
        if budget_us > UInt64(0):
            var elapsed_us = UInt64((perf_counter_ns() - start_ns) // 1_000)
            if elapsed_us > budget_us:
                reply = GrpcServerStreamReply.err(
                    GrpcStatus.err(
                        GRPC_STATUS_DEADLINE_EXCEEDED,
                        String("deadline exceeded"),
                    )
                )
        return _streaming_response_from_reply(reply^, accept)
