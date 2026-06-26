"""Tests for flare.grpc.interceptor (chainable) + flare.grpc.health."""

from std.collections import Optional
from std.memory import Span
from std.testing import assert_equal, assert_true, TestSuite

from flare.grpc.health import (
    HealthService,
    HEALTH_SERVING,
    HEALTH_NOT_SERVING,
    HEALTH_SERVICE_UNKNOWN,
    encode_health_response,
    decode_health_request,
)
from flare.grpc.interceptor import GrpcInterceptor, Intercepted
from flare.grpc.proto import ProtoReader, ProtoWriter
from flare.grpc.server import GrpcCallContext, GrpcUnary, GrpcUnaryReply
from flare.grpc.metadata import GrpcMetadata
from flare.grpc.status import (
    GrpcStatus,
    GRPC_STATUS_OK,
    GRPC_STATUS_UNAUTHENTICATED,
)


# ── Test handlers / interceptors ──────────────────────────────────────────────


struct EchoHandler(Copyable, GrpcUnary, Movable):
    def __init__(out self):
        pass

    def serve_unary(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> GrpcUnaryReply:
        var body = List[UInt8]()
        for i in range(len(request_bytes)):
            body.append(request_bytes[i])
        return GrpcUnaryReply.ok(body^)


struct AuthInterceptor(Copyable, GrpcInterceptor, Movable):
    var required: String

    def __init__(out self, required: String):
        self.required = required

    def before(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> Optional[GrpcUnaryReply]:
        var tok = ctx.initial_metadata.get_text("authorization")
        if Bool(tok) and tok.value() == self.required:
            return Optional[GrpcUnaryReply]()
        return Optional[GrpcUnaryReply](
            GrpcUnaryReply.err(
                GrpcStatus.err(GRPC_STATUS_UNAUTHENTICATED, String("no token"))
            )
        )

    def after(
        mut self, ctx: GrpcCallContext, var reply: GrpcUnaryReply
    ) raises -> GrpcUnaryReply:
        return reply^


struct TagInterceptor(Copyable, GrpcInterceptor, Movable):
    def __init__(out self):
        pass

    def before(
        mut self, ctx: GrpcCallContext, request_bytes: Span[UInt8, _]
    ) raises -> Optional[GrpcUnaryReply]:
        return Optional[GrpcUnaryReply]()

    def after(
        mut self, ctx: GrpcCallContext, var reply: GrpcUnaryReply
    ) raises -> GrpcUnaryReply:
        var r = reply^
        r.trailing_metadata.append_text("x-handled", "1")
        return r^


def _ctx(var meta: GrpcMetadata) -> GrpcCallContext:
    return GrpcCallContext(
        path=String("/svc/M"),
        deadline_us=UInt64(0),
        initial_metadata=meta^,
        accept_encoding=String(""),
    )


# ── Interceptor tests ─────────────────────────────────────────────────────────


def test_interceptor_passthrough_and_after() raises:
    var svc = Intercepted(TagInterceptor(), EchoHandler())
    var body = List[UInt8]()
    body.append(UInt8(7))
    var reply = svc.serve_unary(_ctx(GrpcMetadata()), Span[UInt8, _](body))
    assert_equal(reply.status.code, GRPC_STATUS_OK)
    assert_equal(len(reply.body), 1)
    assert_equal(reply.body[0], UInt8(7))
    var entries = reply.trailing_metadata.entries()
    assert_equal(len(entries), 1)
    assert_equal(entries[0].key, "x-handled")


def test_interceptor_short_circuit() raises:
    var svc = Intercepted(AuthInterceptor("Bearer ok"), EchoHandler())
    var body = List[UInt8]()
    var reply = svc.serve_unary(_ctx(GrpcMetadata()), Span[UInt8, _](body))
    assert_equal(reply.status.code, GRPC_STATUS_UNAUTHENTICATED)


def test_interceptor_chain_nested() raises:
    var meta = GrpcMetadata()
    meta.append_text("authorization", "Bearer ok")
    var svc = Intercepted(
        AuthInterceptor("Bearer ok"),
        Intercepted(TagInterceptor(), EchoHandler()),
    )
    var body = List[UInt8]()
    body.append(UInt8(42))
    var reply = svc.serve_unary(_ctx(meta^), Span[UInt8, _](body))
    assert_equal(reply.status.code, GRPC_STATUS_OK)
    assert_equal(reply.body[0], UInt8(42))
    var entries = reply.trailing_metadata.entries()
    assert_equal(len(entries), 1)
    assert_equal(entries[0].key, "x-handled")


# ── Health tests ──────────────────────────────────────────────────────────────


def _health_request(service: String) -> List[UInt8]:
    var w = ProtoWriter()
    if service.byte_length() > 0:
        w.write_string(1, service)
    return w.take()


def _decode_status(payload: List[UInt8]) raises -> Int:
    var r = ProtoReader(Span[UInt8, _](payload))
    var status = 0
    while r.has_more():
        var t = r.read_tag()
        if t[0] == 1:
            status = r.read_enum()
        else:
            r.skip(t[1])
    return status


def test_health_serving() raises:
    var h = HealthService()
    h.set_status("", HEALTH_SERVING)
    h.set_status("my.Svc", HEALTH_NOT_SERVING)
    var req = _health_request("")
    var reply = h.serve_unary(_ctx(GrpcMetadata()), Span[UInt8, _](req))
    assert_equal(_decode_status(reply.body), HEALTH_SERVING)


def test_health_not_serving() raises:
    var h = HealthService()
    h.set_status("my.Svc", HEALTH_NOT_SERVING)
    var req = _health_request("my.Svc")
    var reply = h.serve_unary(_ctx(GrpcMetadata()), Span[UInt8, _](req))
    assert_equal(_decode_status(reply.body), HEALTH_NOT_SERVING)


def test_health_unknown_service() raises:
    var h = HealthService()
    var req = _health_request("nope.Svc")
    var reply = h.serve_unary(_ctx(GrpcMetadata()), Span[UInt8, _](req))
    assert_equal(_decode_status(reply.body), HEALTH_SERVICE_UNKNOWN)


def test_health_request_roundtrip() raises:
    var req = _health_request("svc.A")
    assert_equal(decode_health_request(Span[UInt8, _](req)), "svc.A")


def main() raises:
    print("=" * 60)
    print("test_grpc_interceptor_health.mojo")
    print("=" * 60)
    print()
    TestSuite.discover_tests[__functions_in_module()]().run()
