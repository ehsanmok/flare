"""Unit tests for ``flare.grpc.server`` -- gRPC unary adapter.

Validates the request-headers validation surface (POST-only,
content-type, te: trailers, :path shape, grpc-timeout parsing),
LPM stitching across multi-frame request bodies, the unary
handler dispatch path, and the response encoding (LPM frame +
status bookkeeping).
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_false, assert_true

from flare.grpc import (
    GRPC_STATUS_INTERNAL,
    GRPC_STATUS_INVALID_ARGUMENT,
    GRPC_STATUS_NOT_FOUND,
    GRPC_STATUS_OK,
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcCompressionFlag,
    GrpcMessage,
    GrpcMetadata,
    GrpcRequestHeaders,
    GrpcStatus,
    GrpcUnary,
    GrpcUnaryReply,
    decode_grpc_message,
    emit_trailing_headers_status,
    encode_grpc_message,
    encode_unary_response,
    parse_request_headers,
    run_unary_call,
    stitch_request_data,
)


def _headers(
    var method: String,
    var path: String,
    var content_type: String,
    var te: String,
    timeout: Optional[String] = None,
    accept_encoding: Optional[String] = None,
) -> GrpcRequestHeaders:
    """Build a `GrpcRequestHeaders` carrier for the tests; the
    `Optional[String]` fields default to absent so call sites read
    as `_headers("POST", "/svc/m", ..., "trailers")` for the
    minimal-shape cases.
    """
    return GrpcRequestHeaders(
        method=method^,
        path=path^,
        content_type=content_type^,
        te=te^,
        timeout=timeout,
        accept_encoding=accept_encoding,
        initial_metadata=GrpcMetadata(),
    )


@fieldwise_init
struct EchoUnary(GrpcUnary, Movable):
    var seen_path: String

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        self.seen_path = String(ctx.path)
        var out = List[UInt8]()
        for i in range(len(request_bytes)):
            out.append(request_bytes[i])
        return GrpcUnaryReply.ok(out^)


@fieldwise_init
struct ErrorUnary(GrpcUnary, Movable):
    var hit: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        self.hit = True
        return GrpcUnaryReply.err(
            GrpcStatus.err(GRPC_STATUS_INTERNAL, String("oops"))
        )


def test_parse_request_headers_minimal() raises:
    var ctx = parse_request_headers(
        _headers(
            String("POST"),
            String("/echo.Echo/Hello"),
            String("application/grpc"),
            String("trailers"),
            accept_encoding=String("identity"),
        )
    )
    assert_equal(ctx.path, "/echo.Echo/Hello")
    assert_equal(ctx.deadline_us, UInt64(0))
    assert_equal(ctx.accept_encoding, "identity")


def test_parse_request_headers_proto_flavor() raises:
    var ctx = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc+proto"),
            String("trailers"),
        )
    )
    assert_equal(ctx.path, "/svc/m")


def test_parse_request_headers_rejects_get() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            _headers(
                String("GET"),
                String("/svc/m"),
                String("application/grpc"),
                String("trailers"),
            )
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_bad_content_type() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            _headers(
                String("POST"),
                String("/svc/m"),
                String("text/plain"),
                String("trailers"),
            )
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_missing_trailers() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            _headers(
                String("POST"),
                String("/svc/m"),
                String("application/grpc"),
                String(""),
            )
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_path_without_method() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            _headers(
                String("POST"),
                String("/svc"),
                String("application/grpc"),
                String("trailers"),
            )
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_parses_timeout() raises:
    var ctx = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
            timeout=String("100m"),  # 100 milliseconds = 100,000 us
        )
    )
    assert_equal(ctx.deadline_us, UInt64(100_000))


def test_parse_request_headers_timeout_units() raises:
    var ctx_h = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
            timeout=String("1H"),
        )
    )
    assert_equal(ctx_h.deadline_us, UInt64(3600) * UInt64(1_000_000))
    var ctx_s = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
            timeout=String("5S"),
        )
    )
    assert_equal(ctx_s.deadline_us, UInt64(5_000_000))


def test_parse_request_headers_te_case_insensitive() raises:
    """RFC 9110 §10.1.4: TE field tokens compare case-insensitively;
    the adapter must accept ``Trailers`` / ``TRAILERS`` / ``trailers``
    interchangeably and accept ``trailers`` anywhere in the list (so
    a client that emits ``gzip, trailers`` is well-formed).
    """
    var ctx_mixed = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("Trailers"),
        )
    )
    assert_equal(ctx_mixed.path, "/svc/m")
    var ctx_upper = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("TRAILERS"),
        )
    )
    assert_equal(ctx_upper.path, "/svc/m")
    var ctx_after = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("gzip, trailers"),
        )
    )
    assert_equal(ctx_after.path, "/svc/m")
    var ctx_before = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers, gzip"),
        )
    )
    assert_equal(ctx_before.path, "/svc/m")


def test_parse_request_headers_missing_optionals_default() raises:
    """A minimal headers shape with no ``grpc-timeout`` or
    ``grpc-accept-encoding`` MUST still produce a valid context
    with a zero deadline and an empty accept-encoding hint.
    """
    var ctx = parse_request_headers(
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
        )
    )
    assert_equal(ctx.deadline_us, UInt64(0))
    assert_equal(ctx.accept_encoding, "")


def test_stitch_single_lpm_frame() raises:
    var payload = List[UInt8]()
    payload.append(UInt8(0x41))
    payload.append(UInt8(0x42))
    payload.append(UInt8(0x43))
    var encoded = encode_grpc_message(Span[UInt8, _](payload))
    var stitched = stitch_request_data(Span[UInt8, _](encoded))
    assert_equal(len(stitched), 3)
    assert_equal(stitched[0], UInt8(0x41))
    assert_equal(stitched[1], UInt8(0x42))
    assert_equal(stitched[2], UInt8(0x43))


def test_stitch_multiple_lpm_frames() raises:
    var p1 = List[UInt8]()
    p1.append(UInt8(0x01))
    var p2 = List[UInt8]()
    p2.append(UInt8(0x02))
    p2.append(UInt8(0x03))
    var combined = List[UInt8]()
    var e1 = encode_grpc_message(Span[UInt8, _](p1))
    var e2 = encode_grpc_message(Span[UInt8, _](p2))
    for i in range(len(e1)):
        combined.append(e1[i])
    for i in range(len(e2)):
        combined.append(e2[i])
    var stitched = stitch_request_data(Span[UInt8, _](combined))
    assert_equal(len(stitched), 3)
    assert_equal(stitched[0], UInt8(0x01))
    assert_equal(stitched[1], UInt8(0x02))
    assert_equal(stitched[2], UInt8(0x03))


def test_stitch_rejects_truncated_frame() raises:
    # 5-byte header declares 10 bytes but only 3 follow.
    var buf = List[UInt8]()
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(10))
    buf.append(UInt8(0xAA))
    buf.append(UInt8(0xBB))
    buf.append(UInt8(0xCC))
    var raised = False
    try:
        var _ = stitch_request_data(Span[UInt8, _](buf))
    except:
        raised = True
    assert_true(raised)


def test_stitch_rejects_compressed_frame() raises:
    var payload = List[UInt8]()
    payload.append(UInt8(0xFF))
    var encoded = encode_grpc_message(Span[UInt8, _](payload), compressed=True)
    var raised = False
    try:
        var _ = stitch_request_data(Span[UInt8, _](encoded))
    except:
        raised = True
    assert_true(raised)


def test_run_unary_call_echo() raises:
    var payload = List[UInt8]()
    payload.append(UInt8(0xAA))
    payload.append(UInt8(0xBB))
    var encoded = encode_grpc_message(Span[UInt8, _](payload))
    var handler = EchoUnary(seen_path=String(""))
    var outcome = run_unary_call(
        handler,
        _headers(
            String("POST"),
            String("/echo.Echo/Hello"),
            String("application/grpc"),
            String("trailers"),
            accept_encoding=String("identity"),
        ),
        Span[UInt8, _](encoded),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_OK)
    var dec = decode_grpc_message(Span[UInt8, _](outcome.response_data))
    assert_false(dec.needs_more)
    assert_equal(len(dec.message.payload), 2)
    assert_equal(dec.message.payload[0], UInt8(0xAA))
    assert_equal(dec.message.payload[1], UInt8(0xBB))


@fieldwise_init
struct RaisingUnary(GrpcUnary, Movable):
    """Handler that raises out of ``serve_unary`` -- used to verify
    ``run_unary_call`` folds that into an INTERNAL outcome rather
    than propagating the exception.
    """

    var hit: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        self.hit = True
        raise Error("simulated handler failure")


def test_run_unary_call_invalid_method_emits_invalid_argument() raises:
    """Header-validation failure (`GET` instead of `POST`) must
    surface as `INVALID_ARGUMENT` rather than raising.
    """
    var encoded = encode_grpc_message(Span[UInt8, _](List[UInt8]()))
    var handler = EchoUnary(seen_path=String(""))
    var outcome = run_unary_call(
        handler,
        _headers(
            String("GET"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
        ),
        Span[UInt8, _](encoded),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_INVALID_ARGUMENT)
    assert_equal(len(outcome.response_data), 0)


def test_run_unary_call_truncated_lpm_emits_invalid_argument() raises:
    """Stitch failure (LPM header says 10 bytes, only 3 follow)
    must surface as `INVALID_ARGUMENT` and the body must be empty.
    """
    var buf = List[UInt8]()
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(0))
    buf.append(UInt8(10))
    buf.append(UInt8(0xAA))
    buf.append(UInt8(0xBB))
    buf.append(UInt8(0xCC))
    var handler = EchoUnary(seen_path=String(""))
    var outcome = run_unary_call(
        handler,
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
        ),
        Span[UInt8, _](buf),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_INVALID_ARGUMENT)
    assert_equal(len(outcome.response_data), 0)


def test_run_unary_call_handler_raise_emits_internal() raises:
    """A handler that raises out of `serve_unary` must produce a
    typed outcome with `INTERNAL` status and an empty body.
    """
    var payload = List[UInt8]()
    payload.append(UInt8(0xAA))
    var encoded = encode_grpc_message(Span[UInt8, _](payload))
    var handler = RaisingUnary(hit=False)
    var outcome = run_unary_call(
        handler,
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
        ),
        Span[UInt8, _](encoded),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_INTERNAL)
    assert_equal(len(outcome.response_data), 0)


def test_emit_trailing_headers_status_ok_minimal() raises:
    """An OK status with no message and no details emits just the
    framework-required ``grpc-status: 0`` entry; the H2 driver
    appends the application trailing metadata after that.
    """
    var trailers = emit_trailing_headers_status(GrpcStatus.ok())
    assert_equal(len(trailers), 1)
    assert_equal(trailers[0][0], String("grpc-status"))
    assert_equal(trailers[0][1], String("0"))


def test_emit_trailing_headers_status_err_with_message() raises:
    """A non-OK status with a message emits both ``grpc-status``
    and ``grpc-message`` (the spec says clients may surface
    ``grpc-message`` for diagnostics)."""
    var trailers = emit_trailing_headers_status(
        GrpcStatus.err(GRPC_STATUS_NOT_FOUND, String("missing"))
    )
    assert_equal(len(trailers), 2)
    assert_equal(trailers[0][0], String("grpc-status"))
    assert_equal(trailers[0][1], String("5"))
    assert_equal(trailers[1][0], String("grpc-message"))
    assert_equal(trailers[1][1], String("missing"))


def test_emit_trailing_headers_status_with_details_bin() raises:
    """``with_details`` attaches an opaque byte payload that the
    trailer emitter base64-encodes for ``grpc-status-details-bin``.
    A 4-byte ``0xDEADBEEF`` fixture encodes to ``3q2+7w==`` under
    the standard alphabet (RFC 4648 §4).
    """
    var payload = List[UInt8]()
    payload.append(UInt8(0xDE))
    payload.append(UInt8(0xAD))
    payload.append(UInt8(0xBE))
    payload.append(UInt8(0xEF))
    var status = GrpcStatus.err(
        GRPC_STATUS_INTERNAL, String("boom")
    ).with_details(payload^)
    var trailers = emit_trailing_headers_status(status)
    assert_equal(len(trailers), 3)
    assert_equal(trailers[2][0], String("grpc-status-details-bin"))
    assert_equal(trailers[2][1], String("3q2+7w=="))


def test_run_unary_call_error_status_emits_empty_body() raises:
    var payload = List[UInt8]()
    payload.append(UInt8(0xAA))
    var encoded = encode_grpc_message(Span[UInt8, _](payload))
    var handler = ErrorUnary(hit=False)
    var outcome = run_unary_call(
        handler,
        _headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
        ),
        Span[UInt8, _](encoded),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_INTERNAL)
    assert_equal(len(outcome.response_data), 0)


def main() raises:
    test_parse_request_headers_minimal()
    test_parse_request_headers_proto_flavor()
    test_parse_request_headers_rejects_get()
    test_parse_request_headers_rejects_bad_content_type()
    test_parse_request_headers_rejects_missing_trailers()
    test_parse_request_headers_rejects_path_without_method()
    test_parse_request_headers_parses_timeout()
    test_parse_request_headers_timeout_units()
    test_parse_request_headers_te_case_insensitive()
    test_parse_request_headers_missing_optionals_default()
    test_stitch_single_lpm_frame()
    test_stitch_multiple_lpm_frames()
    test_stitch_rejects_truncated_frame()
    test_stitch_rejects_compressed_frame()
    test_run_unary_call_echo()
    test_run_unary_call_error_status_emits_empty_body()
    test_run_unary_call_invalid_method_emits_invalid_argument()
    test_run_unary_call_truncated_lpm_emits_invalid_argument()
    test_run_unary_call_handler_raise_emits_internal()
    test_emit_trailing_headers_status_ok_minimal()
    test_emit_trailing_headers_status_err_with_message()
    test_emit_trailing_headers_status_with_details_bin()
    print("test_grpc_server: 22 passed")
