"""Tests for gRPC message compression negotiation (gzip)."""

from std.collections import Optional
from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.framing import decode_grpc_message, encode_grpc_message
from flare.grpc.server import (
    GrpcCallContext,
    GrpcRequestHeaders,
    GrpcUnary,
    GrpcUnaryReply,
    encode_unary_response,
    run_unary_call,
    stitch_request_data,
)
from flare.grpc.metadata import GrpcMetadata
from flare.grpc.status import GRPC_STATUS_OK
from flare.http.encoding import compress_gzip, decompress_gzip


struct BigEchoHandler(Copyable, GrpcUnary, Movable):
    """Echoes the request bytes back -- used to drive the response
    compression path with a large, compressible body."""

    def __init__(out self):
        pass

    def serve_unary(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> GrpcUnaryReply:
        var body = List[UInt8]()
        for i in range(len(request_bytes)):
            body.append(request_bytes[i])
        return GrpcUnaryReply.ok(body^)


def _headers(
    accept_encoding: Optional[String], encoding: Optional[String]
) -> GrpcRequestHeaders:
    return GrpcRequestHeaders(
        method=String("POST"),
        path=String("/svc/M"),
        content_type=String("application/grpc"),
        te=String("trailers"),
        timeout=None,
        accept_encoding=accept_encoding,
        encoding=encoding,
        initial_metadata=GrpcMetadata(),
    )


def _compressible_body(n: Int) -> List[UInt8]:
    # Highly compressible: repeating pattern.
    var b = List[UInt8]()
    for i in range(n):
        b.append(UInt8((i % 4) + ord("A")))
    return b^


def test_response_compressed_when_accepted() raises:
    var handler = BigEchoHandler()
    var body = _compressible_body(2048)
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](body), lpm, compressed=False)

    var outcome = run_unary_call[BigEchoHandler](
        handler,
        _headers(Optional[String]("gzip"), None),
        Span[UInt8, _](lpm),
    )
    assert_equal(outcome.status.code, GRPC_STATUS_OK)
    assert_equal(outcome.encoding, "gzip")
    # The response frame must carry the compressed flag and decompress
    # back to the original body.
    var dec = decode_grpc_message(Span[UInt8, _](outcome.response_data))
    assert_true(dec.message.flag.is_compressed())
    var plain = decompress_gzip(Span[UInt8, _](dec.message.payload))
    assert_equal(len(plain), 2048)
    assert_equal(plain[0], body[0])


def test_response_uncompressed_when_not_accepted() raises:
    var handler = BigEchoHandler()
    var body = _compressible_body(2048)
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](body), lpm, compressed=False)

    var outcome = run_unary_call[BigEchoHandler](
        handler, _headers(None, None), Span[UInt8, _](lpm)
    )
    assert_equal(outcome.encoding, "")
    var dec = decode_grpc_message(Span[UInt8, _](outcome.response_data))
    assert_true(not dec.message.flag.is_compressed())


def test_small_response_not_compressed() raises:
    var handler = BigEchoHandler()
    var body = _compressible_body(8)  # below GRPC_COMPRESS_MIN_BYTES
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](body), lpm, compressed=False)

    var outcome = run_unary_call[BigEchoHandler](
        handler, _headers(Optional[String]("gzip"), None), Span[UInt8, _](lpm)
    )
    assert_equal(outcome.encoding, "")


def test_request_decompression_gzip() raises:
    # Client sends a gzip-compressed request frame + grpc-encoding: gzip.
    var body = _compressible_body(512)
    var compressed = compress_gzip(Span[UInt8, _](body))
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](compressed), lpm, compressed=True)

    var stitched = stitch_request_data(Span[UInt8, _](lpm), String("gzip"))
    assert_equal(len(stitched), 512)
    assert_equal(stitched[0], body[0])
    assert_equal(stitched[511], body[511])


def test_compressed_request_without_encoding_raises() raises:
    var body = _compressible_body(128)
    var compressed = compress_gzip(Span[UInt8, _](body))
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](compressed), lpm, compressed=True)
    var raised = False
    try:
        _ = stitch_request_data(Span[UInt8, _](lpm), String(""))
    except:
        raised = True
    assert_true(raised)


def main() raises:
    print("=" * 60)
    print("test_grpc_compression.mojo -- gzip negotiation")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
