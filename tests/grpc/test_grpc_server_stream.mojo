"""Tests for the server-streaming gRPC adapter."""

from std.collections import Optional
from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.framing import decode_grpc_message, encode_grpc_message
from flare.grpc.metadata import GrpcMetadata
from flare.grpc.server import GrpcCallContext, GrpcRequestHeaders
from flare.grpc.server_stream import (
    GrpcServerStreaming,
    GrpcServerStreamReply,
    run_server_streaming_call,
)
from flare.grpc.status import GRPC_STATUS_INTERNAL, GRPC_STATUS_OK


struct CountHandler(Copyable, GrpcServerStreaming, Movable):
    """Yields ``n`` messages where the request body's first byte is
    ``n`` -- the i-th message body is the single byte ``i``."""

    def __init__(out self):
        pass

    def serve_server_streaming(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> GrpcServerStreamReply:
        var n = 0
        if len(request_bytes) > 0:
            n = Int(request_bytes[0])
        var msgs = List[List[UInt8]]()
        for i in range(n):
            var m = List[UInt8]()
            m.append(UInt8(i))
            msgs.append(m^)
        return GrpcServerStreamReply.ok(msgs^)


struct BoomHandler(Copyable, GrpcServerStreaming, Movable):
    """Always raises -- exercises the INTERNAL fold."""

    def __init__(out self):
        pass

    def serve_server_streaming(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> GrpcServerStreamReply:
        raise Error("boom")


def _headers() -> GrpcRequestHeaders:
    return GrpcRequestHeaders(
        method=String("POST"),
        path=String("/svc/Stream"),
        content_type=String("application/grpc"),
        te=String("trailers"),
        timeout=None,
        accept_encoding=None,
        encoding=None,
        initial_metadata=GrpcMetadata(),
    )


def _request_lpm(n: Int) raises -> List[UInt8]:
    var body = List[UInt8]()
    body.append(UInt8(n))
    var lpm = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](body), lpm, compressed=False)
    return lpm^


def _decode_frames(data: List[UInt8]) raises -> List[List[UInt8]]:
    """Split a concatenated LPM byte stream into its message payloads."""
    var out = List[List[UInt8]]()
    var pos = 0
    while pos < len(data):
        var rest = Span[UInt8, _](data)[pos:]
        var dec = decode_grpc_message(rest)
        assert_true(not dec.needs_more)
        out.append(dec.message.payload.copy())
        pos += dec.consumed
    return out^


def test_stream_yields_n_frames() raises:
    var handler = CountHandler()
    var req = _request_lpm(5)
    var outcome = run_server_streaming_call[CountHandler](
        handler, _headers(), Span[UInt8, _](req)
    )
    assert_equal(outcome.status.code, GRPC_STATUS_OK)
    var frames = _decode_frames(outcome.response_data)
    assert_equal(len(frames), 5)
    for i in range(5):
        assert_equal(len(frames[i]), 1)
        assert_equal(frames[i][0], UInt8(i))


def test_stream_zero_messages() raises:
    var handler = CountHandler()
    var req = _request_lpm(0)
    var outcome = run_server_streaming_call[CountHandler](
        handler, _headers(), Span[UInt8, _](req)
    )
    assert_equal(outcome.status.code, GRPC_STATUS_OK)
    assert_equal(len(outcome.response_data), 0)


def test_stream_handler_raises_maps_internal() raises:
    var handler = BoomHandler()
    var req = _request_lpm(3)
    var outcome = run_server_streaming_call[BoomHandler](
        handler, _headers(), Span[UInt8, _](req)
    )
    assert_equal(outcome.status.code, GRPC_STATUS_INTERNAL)
    assert_equal(len(outcome.response_data), 0)


def main() raises:
    print("=" * 60)
    print("test_grpc_server_stream.mojo -- server-streaming adapter")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
