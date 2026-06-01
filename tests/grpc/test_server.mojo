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
    GRPC_STATUS_OK,
    GrpcCallContext,
    GrpcCallOutcome,
    GrpcCompressionFlag,
    GrpcMessage,
    GrpcMetadata,
    GrpcStatus,
    GrpcUnary,
    decode_grpc_message,
    encode_grpc_message,
    encode_unary_response,
    parse_request_headers,
    run_unary_call,
    stitch_request_data,
)


@fieldwise_init
struct EchoUnary(GrpcUnary, Movable):
    var seen_path: String

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> Tuple[List[UInt8], GrpcStatus, GrpcMetadata]:
        self.seen_path = String(ctx.path)
        var out = List[UInt8]()
        for i in range(len(request_bytes)):
            out.append(request_bytes[i])
        return Tuple[List[UInt8], GrpcStatus, GrpcMetadata](
            out^, GrpcStatus.ok(), GrpcMetadata()
        )


@fieldwise_init
struct ErrorUnary(GrpcUnary, Movable):
    var hit: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> Tuple[List[UInt8], GrpcStatus, GrpcMetadata]:
        self.hit = True
        return Tuple[List[UInt8], GrpcStatus, GrpcMetadata](
            List[UInt8](),
            GrpcStatus.err(GRPC_STATUS_INTERNAL, String("oops")),
            GrpcMetadata(),
        )


def test_parse_request_headers_minimal() raises:
    var ctx = parse_request_headers(
        String("POST"),
        String("/echo.Echo/Hello"),
        String("application/grpc"),
        String("trailers"),
        String(""),
        String("identity"),
        GrpcMetadata(),
    )
    assert_equal(ctx.path, "/echo.Echo/Hello")
    assert_equal(ctx.deadline_us, UInt64(0))
    assert_equal(ctx.accept_encoding, "identity")


def test_parse_request_headers_proto_flavor() raises:
    var ctx = parse_request_headers(
        String("POST"),
        String("/svc/m"),
        String("application/grpc+proto"),
        String("trailers"),
        String(""),
        String(""),
        GrpcMetadata(),
    )
    assert_equal(ctx.path, "/svc/m")


def test_parse_request_headers_rejects_get() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            String("GET"),
            String("/svc/m"),
            String("application/grpc"),
            String("trailers"),
            String(""),
            String(""),
            GrpcMetadata(),
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_bad_content_type() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            String("POST"),
            String("/svc/m"),
            String("text/plain"),
            String("trailers"),
            String(""),
            String(""),
            GrpcMetadata(),
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_missing_trailers() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            String("POST"),
            String("/svc/m"),
            String("application/grpc"),
            String(""),
            String(""),
            String(""),
            GrpcMetadata(),
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_rejects_path_without_method() raises:
    var raised = False
    try:
        var _ = parse_request_headers(
            String("POST"),
            String("/svc"),
            String("application/grpc"),
            String("trailers"),
            String(""),
            String(""),
            GrpcMetadata(),
        )
    except:
        raised = True
    assert_true(raised)


def test_parse_request_headers_parses_timeout() raises:
    var ctx = parse_request_headers(
        String("POST"),
        String("/svc/m"),
        String("application/grpc"),
        String("trailers"),
        String("100m"),  # 100 milliseconds = 100,000 us
        String(""),
        GrpcMetadata(),
    )
    assert_equal(ctx.deadline_us, UInt64(100_000))


def test_parse_request_headers_timeout_units() raises:
    var ctx_h = parse_request_headers(
        String("POST"),
        String("/svc/m"),
        String("application/grpc"),
        String("trailers"),
        String("1H"),
        String(""),
        GrpcMetadata(),
    )
    assert_equal(ctx_h.deadline_us, UInt64(3600) * UInt64(1_000_000))
    var ctx_s = parse_request_headers(
        String("POST"),
        String("/svc/m"),
        String("application/grpc"),
        String("trailers"),
        String("5S"),
        String(""),
        GrpcMetadata(),
    )
    assert_equal(ctx_s.deadline_us, UInt64(5_000_000))


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
        String("POST"),
        String("/echo.Echo/Hello"),
        String("application/grpc"),
        String("trailers"),
        String(""),
        String("identity"),
        GrpcMetadata(),
        Span[UInt8, _](encoded),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_OK)
    # Decode the response LPM frame and confirm payload echo.
    var dec = decode_grpc_message(Span[UInt8, _](outcome.response_data))
    assert_false(dec.needs_more)
    assert_equal(len(dec.message.payload), 2)
    assert_equal(dec.message.payload[0], UInt8(0xAA))
    assert_equal(dec.message.payload[1], UInt8(0xBB))


def test_run_unary_call_error_status_emits_empty_body() raises:
    var payload = List[UInt8]()
    payload.append(UInt8(0xAA))
    var encoded = encode_grpc_message(Span[UInt8, _](payload))
    var handler = ErrorUnary(hit=False)
    var outcome = run_unary_call(
        handler,
        String("POST"),
        String("/svc/m"),
        String("application/grpc"),
        String("trailers"),
        String(""),
        String(""),
        GrpcMetadata(),
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
    test_stitch_single_lpm_frame()
    test_stitch_multiple_lpm_frames()
    test_stitch_rejects_truncated_frame()
    test_stitch_rejects_compressed_frame()
    test_run_unary_call_echo()
    test_run_unary_call_error_status_emits_empty_body()
    print("test_grpc_server: 14 passed")
