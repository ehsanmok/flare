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
from std.time import perf_counter_ns

from flare.crypto.base64 import base64_encode
from flare.http.encoding import (
    compress_gzip,
    decompress_deflate,
    decompress_gzip,
)
from flare.http.handler import Handler
from flare.http.proto.ascii import ascii_lower
from flare.http.request import Request
from flare.http.response import Response
from flare.http.simd_parsers import simd_memmem

from .framing import (
    GRPC_COMPRESSION_NONE,
    GrpcMessage,
    decode_grpc_message,
    encode_grpc_message,
)
from .metadata import GrpcMetadata, GrpcMetadataEntry
from .status import (
    GRPC_STATUS_OK,
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_INVALID_ARGUMENT,
    GrpcStatus,
)


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
    var encoding: Optional[String]
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


# ── Unary handler reply ────────────────────────────────────────────────────


@fieldwise_init
struct GrpcUnaryReply(Copyable, Movable):
    """Typed return value for a unary gRPC handler.

    Replaces the prior ``Tuple[List[UInt8], GrpcStatus, GrpcMetadata]``
    so a handler's call site reads as ``return GrpcUnaryReply.ok(body)``
    or ``return GrpcUnaryReply.err(GrpcStatus.err(...))`` instead of a
    positional 3-tuple. The :func:`run_unary_call` driver always emits
    an empty response body for non-OK replies; ``body`` is ignored in
    that case (the spec carries the status on the trailers, not the
    payload).

    The two factory methods (:func:`ok` and :func:`err`) handle the
    metadata-default ergonomics so a handler that does not attach
    trailing metadata can omit the argument.
    """

    var body: List[UInt8]
    var status: GrpcStatus
    var trailing_metadata: GrpcMetadata

    @staticmethod
    def ok(
        var body: List[UInt8],
        var trailing_metadata: GrpcMetadata = GrpcMetadata(),
    ) -> Self:
        """Build an OK reply carrying ``body`` and the (optional)
        trailing metadata. ``GrpcStatus.ok()`` is filled in for the
        caller.
        """
        return Self(
            body=body^,
            status=GrpcStatus.ok(),
            trailing_metadata=trailing_metadata^,
        )

    @staticmethod
    def err(
        var status: GrpcStatus,
        var trailing_metadata: GrpcMetadata = GrpcMetadata(),
    ) -> Self:
        """Build a non-OK reply carrying ``status`` plus optional
        trailing metadata. The body is always empty; the trailers
        carry the status code + message.
        """
        return Self(
            body=List[UInt8](),
            status=status^,
            trailing_metadata=trailing_metadata^,
        )


# ── Unary handler trait ────────────────────────────────────────────────────


trait GrpcUnary(Movable):
    """Single-method gRPC handler.

    The handler receives the decoded request bytes (already
    LPM-stitched + decompressed) and returns a typed
    :class:`GrpcUnaryReply` carrying the response body + status +
    trailing metadata. Returning a non-OK reply causes the adapter
    to emit an empty response body + the trailers; the response
    bytes are ignored in that case.
    """

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
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
    var encoding: String


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
    # RFC 9110 §10.1.4: TE field values are tokens and tokens compare
    # case-insensitively. Canonicalise via the ASCII-lowercaser and use
    # ``simd_memmem`` for the contains-``trailers`` probe so values such
    # as ``Trailers``, ``TRAILERS``, and ``gzip, trailers`` all pass.
    var lowered = ascii_lower(headers.te)
    var needle = String("trailers")
    if simd_memmem(lowered.as_bytes(), needle.as_bytes()) < 0:
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


comptime GRPC_COMPRESS_MIN_BYTES: Int = 64
"""Response payloads at or above this size are eligible for
message-level compression when the client advertises a codec via
``grpc-accept-encoding``. Below it the gzip/deflate header overhead
outweighs the saving, so the frame ships uncompressed (flag 0).
ponytail: a fixed cutoff, not an adaptive ratio probe."""


def _negotiate_response_encoding(accept_encoding: String) -> String:
    """Pick the response message codec from a client
    ``grpc-accept-encoding`` list. Prefers ``gzip``, then
    ``deflate``; returns the empty string (identity) when the
    client offered neither (or sent nothing)."""
    if accept_encoding.byte_length() == 0:
        return String("")
    var lowered = ascii_lower(accept_encoding)
    if simd_memmem(lowered.as_bytes(), String("gzip").as_bytes()) >= 0:
        return String("gzip")
    if simd_memmem(lowered.as_bytes(), String("deflate").as_bytes()) >= 0:
        return String("deflate")
    return String("")


def _decompress_payload(
    payload: Span[UInt8, _], encoding: String
) raises -> List[UInt8]:
    """Decompress a compressed LPM payload per the request's
    ``grpc-encoding``. Supports ``gzip`` and ``deflate``; any other
    (or empty) encoding on a compressed frame is a protocol error."""
    var enc = ascii_lower(encoding)
    if enc == "gzip":
        return decompress_gzip(payload)
    if enc == "deflate":
        return decompress_deflate(payload)
    raise Error(
        "grpc adapter: compressed LPM frame with unsupported / missing "
        "grpc-encoding '"
        + encoding
        + "'"
    )


def stitch_request_data(
    request_data: Span[UInt8, _],
    encoding: String = String(""),
) raises -> List[UInt8]:
    """Stitch one or more LPM frames out of the accumulated
    request DATA bytes into a single contiguous payload.

    Returns the concatenated payloads (in order). gRPC unary
    calls SHOULD only emit a single LPM frame, but the spec
    permits a server to receive multiple back-to-back frames
    inside one call (a streaming client packing requests through
    a unary stub is the example shape); the adapter handles both.

    Compressed frames (flag bit 0 set) are decompressed using the
    call's ``grpc-encoding`` (``gzip`` / ``deflate``). A compressed
    frame with no / unsupported ``grpc-encoding`` raises.

    Raises on:
    * truncated LPM frame (need-more-data at the end of the
      request body),
    * compressed flag set with no negotiated / supported encoding.
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
            var plain = _decompress_payload(
                Span[UInt8, _](dec.message.payload), encoding
            )
            for i in range(len(plain)):
                out.append(plain[i])
        else:
            for i in range(len(dec.message.payload)):
                out.append(dec.message.payload[i])
        pos += dec.consumed
    return out^


def encode_unary_response(
    response_bytes: List[UInt8],
    mut out: List[UInt8],
    encoding: String = String(""),
) raises:
    """Append a single LPM frame wrapping ``response_bytes`` to
    ``out``.

    When ``encoding`` is ``gzip`` / ``deflate`` and the payload is at
    least :data:`GRPC_COMPRESS_MIN_BYTES`, the payload is compressed
    and the frame's flag byte is set (bit 0). Otherwise an
    uncompressed frame (flag 0) is emitted. The caller is responsible
    for advertising the chosen codec on the response ``grpc-encoding``
    header (see :func:`_response_from_outcome`).

    The caller owns the buffer and may reuse the same
    ``List[UInt8]`` across responses so the underlying
    allocation amortises across the stream. The encoder appends
    only; it never reads from or truncates the existing contents.
    """
    var enc = ascii_lower(encoding)
    if len(response_bytes) >= GRPC_COMPRESS_MIN_BYTES and (
        enc == "gzip" or enc == "deflate"
    ):
        var compressed: List[UInt8]
        if enc == "gzip":
            compressed = compress_gzip(Span[UInt8, _](response_bytes))
        else:
            # gRPC "deflate" is zlib-wrapped DEFLATE; compress_gzip
            # emits a gzip container, so for deflate we fall back to
            # an uncompressed frame rather than mislabel the bytes.
            # ponytail: deflate egress not wired (only gzip);
            # upgrade path: add a raw-zlib compressor to
            # flare.http.encoding and emit it here.
            encode_grpc_message(
                Span[UInt8, _](response_bytes), out, compressed=False
            )
            return
        encode_grpc_message(Span[UInt8, _](compressed), out, compressed=True)
    else:
        encode_grpc_message(
            Span[UInt8, _](response_bytes), out, compressed=False
        )


def emit_trailing_headers_status(
    status: GrpcStatus,
) -> List[Tuple[String, String]]:
    """Return the framework-controlled trailer entries for a
    completed gRPC call.

    Always emits ``grpc-status`` (the wire-level integer outcome).
    Emits ``grpc-message`` when ``status.message`` is non-empty
    (clients use it for diagnostics only). Emits
    ``grpc-status-details-bin`` when ``status.details`` carries a
    payload, RFC 4648 §4 base64-encoded per gRPC PROTOCOL-HTTP2.

    The caller (the H2 trailer encoder) appends the application
    trailing metadata after these framework-owned entries; this
    helper does not look at :class:`GrpcMetadata`.

    Returning ``List[Tuple[String, String]]`` keeps the trailer
    emitter sans-I/O: the H2 driver decides how to serialise the
    pairs onto a HEADERS frame (HPACK literal-without-indexing,
    QPACK, h3 SETTINGS-aware, etc.).
    """
    var trailers = List[Tuple[String, String]]()
    trailers.append(
        Tuple[String, String](String("grpc-status"), String(status.code))
    )
    if status.message.byte_length() > 0:
        trailers.append(
            Tuple[String, String](String("grpc-message"), status.message.copy())
        )
    if Bool(status.details):
        var details_bytes = status.details.value().copy()
        var encoded = base64_encode(Span[UInt8, _](details_bytes))
        trailers.append(
            Tuple[String, String](String("grpc-status-details-bin"), encoded^)
        )
    return trailers^


def _outcome_from_reply(
    var reply: GrpcUnaryReply,
    accept_encoding: String = String(""),
) -> GrpcCallOutcome:
    """Pack a :class:`GrpcUnaryReply` into the wire-shape
    :class:`GrpcCallOutcome` the H2 driver actually emits.

    A non-OK reply produces an empty response-body buffer per the
    spec (the trailer carries the status, not the body). The
    LPM-encoder only runs on the OK branch; if it itself raises
    (out-of-memory) the outcome falls back to an empty body +
    INTERNAL status so the driver still has something well-formed
    to put on the wire.

    When the client advertised ``grpc-accept-encoding: gzip`` and the
    OK body is large enough to be worth it, the response frame is
    gzip-compressed and ``outcome.encoding`` is set to ``gzip`` so the
    driver emits the matching ``grpc-encoding`` header.
    """
    var response_data = List[UInt8]()
    var status = reply.status.copy()
    var used_encoding = String("")
    if status.is_ok():
        var chosen = _negotiate_response_encoding(accept_encoding)
        if chosen == "gzip" and len(reply.body) >= GRPC_COMPRESS_MIN_BYTES:
            used_encoding = String("gzip")
        try:
            encode_unary_response(reply.body, response_data, used_encoding)
        except:
            response_data = List[UInt8]()
            used_encoding = String("")
            status = GrpcStatus.err(
                GRPC_STATUS_INTERNAL,
                String("grpc adapter: response LPM encode failed"),
            )
    var trailing_copy = reply.trailing_metadata.copy()
    return GrpcCallOutcome(
        response_data=response_data^,
        status=status^,
        trailing_metadata=trailing_copy^,
        encoding=used_encoding^,
    )


def run_unary_call[
    H: GrpcUnary
](
    mut handler: H,
    headers: GrpcRequestHeaders,
    request_data: Span[UInt8, _],
) -> GrpcCallOutcome:
    """End-to-end driver: validate headers, stitch LPM, invoke
    the user handler, encode the response.

    The HTTP/2 driver calls this once per stream; success
    produces a :class:`GrpcCallOutcome` whose bytes go on the
    DATA frame and whose status / trailing metadata go on the
    trailing HEADERS frame.

    The driver itself never raises -- every failure mode
    (HEADERS validation, truncated/compressed LPM, handler
    raising) is folded into a typed :class:`GrpcCallOutcome`
    with the right ``grpc-status``:

    * HEADERS validation failure ->
      ``GRPC_STATUS_INVALID_ARGUMENT`` (the gRPC spec maps client
      malformed input to this code).
    * LPM stitch failure (truncated frame, compressed without a
      negotiated encoding) -> ``GRPC_STATUS_INVALID_ARGUMENT``.
    * Handler ``raises`` -> ``GRPC_STATUS_INTERNAL`` with the
      raise message (clients see ``grpc-message`` for diagnostics
      only; the failure mode is "server side bug, not client
      input").
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
        return _outcome_from_reply(
            GrpcUnaryReply.err(
                GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
            ),
            accept,
        )
    var request_bytes: List[UInt8]
    try:
        request_bytes = stitch_request_data(request_data, req_encoding)
    except e:
        return _outcome_from_reply(
            GrpcUnaryReply.err(
                GrpcStatus.err(GRPC_STATUS_INVALID_ARGUMENT, String(e))
            ),
            accept,
        )
    var reply: GrpcUnaryReply
    try:
        reply = handler.serve_unary(ctx, Span[UInt8, _](request_bytes))
    except e:
        return _outcome_from_reply(
            GrpcUnaryReply.err(GrpcStatus.err(GRPC_STATUS_INTERNAL, String(e))),
            accept,
        )
    return _outcome_from_reply(reply^, accept)


# ── Reactor-mounted unary service (HttpServer H2) ─────────────────────────────


def _grpc_headers_from_request(req: Request) raises -> GrpcRequestHeaders:
    """Lift an HTTP/2 :class:`Request` into the typed
    :class:`GrpcRequestHeaders` the sans-I/O adapter consumes.

    ``:method`` / ``:path`` arrive on ``req.method`` / ``req.url`` (the
    H2 reactor already mapped the pseudo-headers); the gRPC framing
    fields come off the regular header map. Application metadata is the
    set of non-reserved, non-framing text headers; ``-bin`` keys are
    skipped here (their wire value is base64 and the unary v1 client
    omits them too).
    """
    var content_type = req.headers.get("content-type")
    var te = req.headers.get("te")
    var timeout = Optional[String]()
    var to = req.headers.get("grpc-timeout")
    if to.byte_length() > 0:
        timeout = Optional[String](to)
    var accept_encoding = Optional[String]()
    var ae = req.headers.get("grpc-accept-encoding")
    if ae.byte_length() > 0:
        accept_encoding = Optional[String](ae)
    var encoding = Optional[String]()
    var enc = req.headers.get("grpc-encoding")
    if enc.byte_length() > 0:
        encoding = Optional[String](enc)
    var meta = GrpcMetadata()
    for i in range(len(req.headers._keys)):
        var k = ascii_lower(req.headers._keys[i])
        # Skip pseudo-headers, framing fields, and reserved grpc-* keys
        # (those are framework-managed). ``-bin`` keys carry base64 on
        # the wire; decoding them is a future-phase concern.
        if (
            k == "content-type"
            or k == "te"
            or k == "host"
            or k.startswith("grpc-")
            or k.startswith(":")
        ):
            continue
        # ``append_text`` rejects reserved/``-bin`` keys by raising; we
        # swallow that so a stray binary header just isn't forwarded.
        try:
            meta.append_text(k, req.headers._values[i])
        except:
            pass
    return GrpcRequestHeaders(
        method=req.method,
        path=req.url,
        content_type=content_type^,
        te=te^,
        timeout=timeout^,
        accept_encoding=accept_encoding^,
        encoding=encoding^,
        initial_metadata=meta^,
    )


def _response_from_outcome(var outcome: GrpcCallOutcome) raises -> Response:
    """Pack a :class:`GrpcCallOutcome` into an HTTP/2 :class:`Response`.

    The reply rides as ``:status=200`` + ``content-type:
    application/grpc`` with the LPM frame in the body; ``grpc-status`` /
    ``grpc-message`` (+ any text trailing metadata) land in
    ``Response.trailers`` so the H2 reactor frames them as a trailing
    HEADERS block (END_STREAM). A real gRPC client reads the status off
    those trailers.
    """
    var resp = Response(200, "", outcome.response_data.copy())
    resp.headers.set("content-type", "application/grpc")
    if outcome.encoding != "":
        resp.headers.set("grpc-encoding", outcome.encoding)
    var status_trailers = emit_trailing_headers_status(outcome.status)
    for i in range(len(status_trailers)):
        resp.trailers.set(status_trailers[i][0], status_trailers[i][1])
    var entries = outcome.trailing_metadata.entries()
    for i in range(len(entries)):
        if entries[i].is_binary:
            continue
        resp.trailers.set(
            entries[i].key,
            String(unsafe_from_utf8=Span[UInt8, _](entries[i].value)),
        )
    return resp^


@fieldwise_init
struct GrpcService[H: Copyable & GrpcUnary & ImplicitlyDestructible](
    Copyable, Handler, Movable
):
    """Adapt a :class:`GrpcUnary` handler into a plain :trait:`Handler`
    so it serves over the unified :class:`flare.http.HttpServer` H2
    reactor path -- no bespoke per-RPC glue.

    Mount it like any other handler::

        var svc = GrpcService(EchoHandler())
        var server = HttpServer.bind(addr)
        server.serve(svc)   # over h2c / h2

    One H2 stream maps to one unary call: the reactor hands this
    adapter the assembled :class:`Request` (HEADERS + DATA), the adapter
    runs :func:`run_unary_call`, and returns a :class:`Response` whose
    trailers carry ``grpc-status``. The inner handler is copied per call
    (``H: Copyable``) so the immutable ``serve`` borrow holds while
    ``serve_unary`` mutates its own copy -- unary handlers are config-
    only in practice, so the copy is cheap.

    Deadlines: when the client sends ``grpc-timeout`` the adapter
    enforces it as a wall-clock ceiling on the handler invocation and
    returns ``DEADLINE_EXCEEDED`` if the handler overruns.

    ponytail: deadline enforcement is a post-hoc elapsed check, not a
    cooperative mid-call cancel (the handler runs to completion, then we
    compare elapsed vs budget). Ceiling: a runaway handler still burns
    its full time before the status flips. Upgrade path: thread a
    :class:`flare.http.Cancel` into a cancel-aware ``GrpcUnary`` variant
    and flip it from a deadline timer.
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
        var outcome = run_unary_call[Self.H](
            h, headers, Span[UInt8, _](req.body)
        )
        if budget_us > UInt64(0):
            var elapsed_us = UInt64((perf_counter_ns() - start_ns) // 1_000)
            if elapsed_us > budget_us:
                outcome = _outcome_from_reply(
                    GrpcUnaryReply.err(
                        GrpcStatus.err(
                            GRPC_STATUS_DEADLINE_EXCEEDED,
                            String("deadline exceeded"),
                        )
                    )
                )
        return _response_from_outcome(outcome^)
