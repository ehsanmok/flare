"""``flare.grpc`` — gRPC primitives on top of the HTTP/2 reactor.

gRPC is a 4-layer protocol on top of HTTP/2:

1. **Length-Prefix-Message (LPM) framing** -- every gRPC message
   on the wire is a 1-byte compression flag + a 4-byte big-endian
   length + the payload bytes. This module ships that codec in
   :mod:`flare.grpc.framing`.
2. **Status + Metadata** -- the trailer ``grpc-status``,
   ``grpc-message``, and trailing-metadata header set. Carried in
   :mod:`flare.grpc.status`.
3. **Call shapes** -- unary, server-streaming, client-streaming,
   and bidirectional. Each maps onto a single HTTP/2 stream
   (request HEADERS + DATA frames carry length-prefixed messages,
   response HEADERS + DATA + trailing HEADERS carry the reply).
4. **Codegen** -- proto3 message + service codegen. Not in this
   commit; the framing + status layers are the prerequisite.

This module establishes the bottom two layers (framing + status).
The call shapes + codegen build on top of these in later commits;
the HTTP/2 reactor already provides the stream multiplexer they
need.

Public re-exports:

- :class:`GrpcCompressionFlag` -- the LPM frame's flag byte.
- :class:`GrpcMessage` -- decoded LPM frame (flag + payload).
- :func:`encode_grpc_message` / :func:`decode_grpc_message` --
  the byte-level codec.
- :class:`GrpcStatus` + the named status code constants --
  trailer carrier + RPC outcome.
"""

from .framing import (
    GRPC_COMPRESSION_NONE,
    GRPC_COMPRESSION_COMPRESSED,
    GrpcCompressionFlag,
    GrpcMessage,
    GrpcDecodeResult,
    decode_grpc_message,
    encode_grpc_message,
)
from .metadata import (
    GrpcMetadata,
    GrpcMetadataEntry,
)
from .server import (
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcUnary,
    encode_unary_response,
    parse_request_headers,
    run_unary_call,
    stitch_request_data,
)
from .status import (
    GRPC_STATUS_OK,
    GRPC_STATUS_CANCELLED,
    GRPC_STATUS_UNKNOWN,
    GRPC_STATUS_INVALID_ARGUMENT,
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_NOT_FOUND,
    GRPC_STATUS_ALREADY_EXISTS,
    GRPC_STATUS_PERMISSION_DENIED,
    GRPC_STATUS_RESOURCE_EXHAUSTED,
    GRPC_STATUS_FAILED_PRECONDITION,
    GRPC_STATUS_ABORTED,
    GRPC_STATUS_OUT_OF_RANGE,
    GRPC_STATUS_UNIMPLEMENTED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_UNAVAILABLE,
    GRPC_STATUS_DATA_LOSS,
    GRPC_STATUS_UNAUTHENTICATED,
    GrpcStatus,
)
