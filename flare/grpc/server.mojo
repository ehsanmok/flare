"""``flare.grpc.server`` -- gRPC server adapter on the HTTP/2 reactor.

A gRPC unary call maps onto a single HTTP/2 stream:

* Request HEADERS: ``:method=POST``, ``:scheme=http(s)``,
  ``:path=/<service>/<method>``, ``content-type=application/grpc``
  (or one of the ``+proto`` / ``+json`` flavours),
  ``te: trailers``, plus optional ``grpc-encoding`` /
  ``grpc-accept-encoding`` / ``grpc-timeout`` / application
  metadata.
* Request DATA: zero or more length-prefix-message (LPM) frames
  containing the serialized request bodies.
* Response HEADERS: ``:status=200``, ``content-type=application/
  grpc``, optional ``grpc-encoding``.
* Response DATA: zero or more LPM frames carrying the serialized
  reply bodies.
* Response trailing HEADERS: ``grpc-status`` (REQUIRED), optional
  ``grpc-message``, optional trailing metadata.

This module exposes the adapter that performs the validation +
LPM stitching + status-code mapping, so a unary handler reads
the decoded request bytes and writes either ``Ok(response_bytes)``
or a typed :class:`GrpcStatus` error and the adapter takes care
of the rest.

Public surface:

* :class:`GrpcCallContext` -- per-call view: full path, deadline
  (parsed from ``grpc-timeout``), initial metadata, accept-
  encoding hint.
* :class:`GrpcUnary` -- the user handler trait. ``serve_unary(ctx,
  request_bytes) -> (response_bytes, status, trailing_metadata)``.
* :class:`GrpcServerAdapter` -- bridges one HTTP/2 stream to one
  :class:`GrpcUnary` call. Steps:
  1. validate request HEADERS;
  2. accumulate request DATA bytes until END_STREAM;
  3. decode LPM frames -> request bytes;
  4. invoke the unary handler;
  5. encode response bytes as LPM frame;
  6. emit response HEADERS + DATA + trailing HEADERS.

The adapter is sans-I/O at the codec boundary: byte streams in,
HTTP/2 wire bytes (HEADERS frame field section + DATA payload +
trailing HEADERS field section) out. Networking + flow control
is the H2Connection's job.

References:
- gRPC PROTOCOL-HTTP2 spec.
- RFC 9113 (HTTP/2) §4 (frames) + §6.10 (TRAILERS marker).
"""

from std.collections import List, Optional
from std.memory import Span

from .framing import (
    GRPC_COMPRESSION_NONE,
    GrpcMessage,
    decode_grpc_message,
    encode_grpc_message,
)
from .metadata import GrpcMetadata
from .status import GRPC_STATUS_OK, GRPC_STATUS_INTERNAL, GrpcStatus


# ── Validation helpers ─────────────────────────────────────────────────────


comptime CONTENT_TYPE_GRPC: String = "application/grpc"
"""Canonical gRPC content-type. The adapter also accepts the
flavored variants ``application/grpc+proto`` / ``+json`` /
``+thrift`` -- any string starting with this prefix and an
optional ``+<flavor>`` segment."""


def _is_grpc_content_type(value: String) -> Bool:
    """Return ``True`` when ``value`` is ``application/grpc`` or
    ``application/grpc+<flavor>`` (RFC 8259-style suffix syntax).
    The check is case-sensitive on the prefix; HTTP normalises
    field values upstream of this adapter so case-folding here
    would be redundant work.
    """
    var prefix = CONTENT_TYPE_GRPC.as_bytes()
    var bytes = value.as_bytes()
    var n = len(bytes)
    var p = len(prefix)
    if n < p:
        return False
    for i in range(p):
        if bytes[i] != prefix[i]:
            return False
    if n == p:
        return True
    var c = bytes[p]
    return c == UInt8(ord("+")) or c == UInt8(ord(";"))


def _parse_grpc_timeout(value: String) raises -> UInt64:
    """Parse a ``grpc-timeout`` header value (TimeoutValue
    TimeoutUnit) into microseconds.

    The unit suffix is one of ``H``, ``M``, ``S``, ``m``
    (milliseconds), ``u`` (microseconds), ``n`` (nanoseconds);
    the value is an ASCII positive integer up to 8 digits per
    the spec. Out-of-range or malformed values raise so the
    adapter can surface ``INVALID_ARGUMENT`` upstream.
    """
    var bytes = value.as_bytes()
    var n = len(bytes)
    if n < 2 or n > 9:
        raise Error("grpc-timeout: malformed length")
    var unit = bytes[n - 1]
    var num = 0
    for i in range(n - 1):
        var c = bytes[i]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            raise Error("grpc-timeout: non-digit in numeric part")
        num = num * 10 + (Int(c) - ord("0"))
    if unit == UInt8(ord("H")):
        return UInt64(num) * UInt64(3600) * UInt64(1_000_000)
    if unit == UInt8(ord("M")):
        return UInt64(num) * UInt64(60) * UInt64(1_000_000)
    if unit == UInt8(ord("S")):
        return UInt64(num) * UInt64(1_000_000)
    if unit == UInt8(ord("m")):
        return UInt64(num) * UInt64(1_000)
    if unit == UInt8(ord("u")):
        return UInt64(num)
    if unit == UInt8(ord("n")):
        return UInt64(num) // UInt64(1_000)
    raise Error("grpc-timeout: unknown unit suffix")


# ── Request-headers carrier ───────────────────────────────────────────────


@fieldwise_init
struct GrpcRequestHeaders(Copyable, Movable):
    """Typed carrier for the H2 request-HEADERS field set the gRPC
    adapter consumes.

    The ``method`` / ``path`` / ``content_type`` / ``te`` fields are
    REQUIRED on every well-formed gRPC call; the optional fields
    (``timeout`` -- ``grpc-timeout``, ``accept_encoding`` --
    ``grpc-accept-encoding``) carry the empty :class:`Optional` when
    the client omits them. ``initial_metadata`` is the
    application-visible subset (``grpc-`` reserved keys stripped).

    The H2 driver builds this carrier from the parsed
    ``H2RequestHeaders`` field set and hands it to
    :func:`parse_request_headers` or :func:`run_unary_call`. The
    typed shape collapses the prior seven-positional-string
    signature into a single argument and lets the driver build
    each field with the right ``Optional[String]`` semantics.
    """

    var method: String
    var path: String
    var content_type: String
    var te: String
    var timeout: Optional[String]
    var accept_encoding: Optional[String]
    var initial_metadata: GrpcMetadata


# ── Per-call context ──────────────────────────────────────────────────────


@fieldwise_init
struct GrpcCallContext(Copyable, Movable):
    """View of the per-call HTTP/2 request state visible to the
    application handler.

    The path field is the gRPC method name (``/svc/method``); the
    deadline is the absolute microsecond timestamp at which the
    server should abandon the call (``0`` means "no deadline
    specified"). Initial metadata is the application-visible
    subset of the request HEADERS (``grpc-`` reserved keys are
    stripped before the handler sees them).
    """

    var path: String
    var deadline_us: UInt64
    var initial_metadata: GrpcMetadata
    var accept_encoding: String


# ── Unary handler trait ────────────────────────────────────────────────────


trait GrpcUnary(Movable):
    """Single-method gRPC handler.

    The handler receives the decoded request bytes (already
    LPM-stitched + decompressed) and returns a tuple of the
    response payload bytes, the call status, and trailing
    metadata. Returning a non-OK ``GrpcStatus`` causes the
    adapter to emit an empty response body + the trailers; the
    response bytes are ignored in that case.
    """

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> Tuple[List[UInt8], GrpcStatus, GrpcMetadata]:
        ...


# ── Adapter ────────────────────────────────────────────────────────────────


@fieldwise_init
struct GrpcCallOutcome(Copyable, Movable):
    """Output of one full unary call -- the bytes the H2 driver
    queues onto the response stream.

    * ``response_data`` is the encoded LPM frame for the response
      body (empty on non-OK status; the trailers carry the status).
    * ``status`` is the gRPC status code the trailer must carry.
    * ``trailing_metadata`` is the trailing HEADERS field set
      excluding ``grpc-status`` / ``grpc-message`` (those are
      framework-managed; see :func:`emit_trailing_headers`).
    """

    var response_data: List[UInt8]
    var status: GrpcStatus
    var trailing_metadata: GrpcMetadata


def parse_request_headers(
    headers: GrpcRequestHeaders,
) raises -> GrpcCallContext:
    """Validate the H2 request HEADERS for a gRPC call and build
    the :class:`GrpcCallContext`.

    Validation surface (all RFC + gRPC PROTOCOL-HTTP2 MUSTs):

    * ``:method`` MUST be ``POST``.
    * ``:path`` MUST start with ``/`` and contain at least one
      additional ``/`` segment (``/<service>/<method>``).
    * ``content-type`` MUST be ``application/grpc[+flavor]``.
    * ``te`` MUST contain the ``trailers`` token. Without it the
      client wouldn't read the trailing HEADERS, so the call has
      no way to learn the status; the spec promotes the missing
      ``te: trailers`` to a connection-level fail-closed.

    The optional ``grpc-timeout`` is parsed into a microsecond
    deadline; missing / unparseable timeouts surface as ``0``
    (no deadline) so partial deployments don't fail closed.
    """
    if headers.method != "POST":
        raise Error("grpc adapter: :method must be POST")
    var path_bytes = headers.path.as_bytes()
    if len(path_bytes) < 3 or path_bytes[0] != UInt8(ord("/")):
        raise Error("grpc adapter: :path must be /<service>/<method>")
    var seen_slash = False
    for i in range(1, len(path_bytes)):
        if path_bytes[i] == UInt8(ord("/")):
            seen_slash = True
            break
    if not seen_slash:
        raise Error("grpc adapter: :path missing method segment")
    if not _is_grpc_content_type(headers.content_type):
        raise Error("grpc adapter: content-type must be application/grpc")
    var has_trailers = False
    var te_bytes = headers.te.as_bytes()
    var n = len(te_bytes)
    var idx = 0
    while idx + 8 <= n:
        if (
            te_bytes[idx] == UInt8(ord("t"))
            and te_bytes[idx + 1] == UInt8(ord("r"))
            and te_bytes[idx + 2] == UInt8(ord("a"))
            and te_bytes[idx + 3] == UInt8(ord("i"))
            and te_bytes[idx + 4] == UInt8(ord("l"))
            and te_bytes[idx + 5] == UInt8(ord("e"))
            and te_bytes[idx + 6] == UInt8(ord("r"))
            and te_bytes[idx + 7] == UInt8(ord("s"))
        ):
            has_trailers = True
            break
        idx += 1
    if not has_trailers:
        raise Error("grpc adapter: te header must include 'trailers'")
    var deadline_us = UInt64(0)
    if Bool(headers.timeout):
        var timeout_str = headers.timeout.value()
        if timeout_str.byte_length() > 0:
            try:
                deadline_us = _parse_grpc_timeout(timeout_str)
            except:
                deadline_us = UInt64(0)
    var accept_encoding = String("")
    if Bool(headers.accept_encoding):
        accept_encoding = headers.accept_encoding.value()
    return GrpcCallContext(
        path=headers.path,
        deadline_us=deadline_us,
        initial_metadata=headers.initial_metadata.copy(),
        accept_encoding=accept_encoding^,
    )


def stitch_request_data(
    request_data: Span[UInt8, _],
) raises -> List[UInt8]:
    """Stitch one or more LPM frames out of the accumulated
    request DATA bytes into a single contiguous payload.

    Returns the concatenated payloads (in order). gRPC unary
    calls SHOULD only emit a single LPM frame, but the spec
    permits a server to receive multiple back-to-back frames
    inside one call (a streaming client packing requests through
    a unary stub is the example shape); the adapter handles both.

    Raises on:
    * truncated LPM frame (need-more-data at the end of the
      request body),
    * compressed flag set without a negotiated encoding (the
      decompression step is a v0.9 line item; for now we accept
      uncompressed only and surface a typed error).
    """
    var out = List[UInt8]()
    var pos = 0
    var n = len(request_data)
    while pos < n:
        var rest = request_data[pos:]
        var dec = decode_grpc_message(rest)
        if dec.needs_more:
            raise Error(
                "grpc adapter: truncated LPM frame at offset " + String(pos)
            )
        if dec.message.flag.is_compressed():
            raise Error(
                "grpc adapter: compressed LPM frame received but no "
                "encoding negotiated (server-side decompression is "
                "not implemented in this build)"
            )
        for i in range(len(dec.message.payload)):
            out.append(dec.message.payload[i])
        pos += dec.consumed
    return out^


def encode_unary_response(
    response_bytes: List[UInt8],
) raises -> List[UInt8]:
    """Wrap ``response_bytes`` in a single uncompressed LPM frame.

    The encoder always emits flag=0 (no message-level
    compression). Compression negotiation lives at the channel
    level (``grpc-encoding`` / ``grpc-accept-encoding``) and is
    a follow-up line item alongside the decompression path.
    """
    return encode_grpc_message(Span[UInt8, _](response_bytes), compressed=False)


def run_unary_call[
    H: GrpcUnary
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) raises -> GrpcCallOutcome:
    """End-to-end driver: validate headers, stitch LPM, invoke
    the user handler, encode the response.

    The HTTP/2 driver calls this once per stream; success
    produces a :class:`GrpcCallOutcome` whose bytes go on the
    DATA frame and whose status / trailing metadata go on the
    trailing HEADERS frame.
    """
    var ctx = parse_request_headers(headers)
    var request_bytes = stitch_request_data(request_data)
    var result = handler.serve_unary(ctx, Span[UInt8, _](request_bytes))
    var response_data = List[UInt8]()
    var status_copy = result[1].copy()
    if status_copy.is_ok():
        response_data = encode_unary_response(result[0])
    var trailing_metadata_copy = result[2].copy()
    return GrpcCallOutcome(
        response_data=response_data^,
        status=status_copy^,
        trailing_metadata=trailing_metadata_copy^,
    )
