"""End-to-end tests for the reactor-mounted gRPC unary service (T1.5).

These exercise :class:`flare.grpc.GrpcService` -- the adapter that lets a
``GrpcUnary`` handler serve over the unified :class:`HttpServer` H2
reactor with no bespoke per-RPC glue. Unlike
``tests/grpc/test_grpc_client.mojo`` (which hand-writes the gRPC
response in a plain ``Handler``), here the server side is the framework
adapter and the ``grpc-status`` rides in genuine HTTP/2 trailing
HEADERS, which the flare H2 client merges into ``Response.headers``.

Tests:
- ``test_mounted_unary_echo``: a unary echo RPC round-trips end to end
  through ``GrpcService`` over h2c.
- ``test_mounted_unary_error``: a handler returning a non-OK status
  surfaces that status (carried in the trailers).
- ``test_mounted_deadline_exceeded``: a slow handler with a tight
  ``grpc-timeout`` yields ``DEADLINE_EXCEEDED`` (status code 4).
"""

from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.grpc import (
    GRPC_STATUS_DEADLINE_EXCEEDED,
    GRPC_STATUS_RESOURCE_EXHAUSTED,
    GrpcCallContext,
    GrpcClient,
    GrpcService,
    GrpcStatus,
    GrpcUnary,
    GrpcUnaryReply,
)
from flare.http import HttpServer
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server
from flare.utils import usleep


@fieldwise_init
struct EchoUnary(Copyable, GrpcUnary, Movable):
    """Echoes the request payload back as the reply."""

    var fail: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        if self.fail:
            return GrpcUnaryReply.err(
                GrpcStatus.err(GRPC_STATUS_RESOURCE_EXHAUSTED, String("nope"))
            )
        var echoed = List[UInt8](capacity=len(request_bytes))
        for i in range(len(request_bytes)):
            echoed.append(request_bytes[i])
        return GrpcUnaryReply.ok(echoed^)


@fieldwise_init
struct SlowUnary(Copyable, GrpcUnary, Movable):
    """Sleeps past any tight deadline before replying."""

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        usleep(60_000)  # 60ms; tests send a 1ms grpc-timeout
        return GrpcUnaryReply.ok(List[UInt8]())


def _base(port: UInt16) -> String:
    return String("http://127.0.0.1:") + String(Int(port))


def test_mounted_unary_echo() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, GrpcService(EchoUnary(fail=False)))

    var ok = False
    var code = -1
    var reply = String("")
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var r = ch.call("/echo.Echo/Say", "hello-mount".as_bytes())
        ok = r.is_ok()
        code = r.status.code
        reply = String(unsafe_from_utf8=Span[UInt8, _](r.message))
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "mounted echo raised")
    assert_true(ok, "expected OK status")
    assert_equal(code, 0)
    assert_equal(reply, "hello-mount")


def test_mounted_unary_error() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, GrpcService(EchoUnary(fail=True)))

    var code = -1
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var r = ch.call("/echo.Echo/Say", "x".as_bytes())
        code = r.status.code
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "error call raised")
    assert_equal(code, GRPC_STATUS_RESOURCE_EXHAUSTED)


def test_mounted_deadline_exceeded() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, GrpcService(SlowUnary()))

    var code = -1
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var r = ch.call("/echo.Echo/Slow", "x".as_bytes(), timeout_ms=1)
        code = r.status.code
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "deadline call raised")
    assert_equal(code, GRPC_STATUS_DEADLINE_EXCEEDED)


def main() raises:
    test_mounted_unary_echo()
    test_mounted_unary_error()
    test_mounted_deadline_exceeded()
    print("test_grpc_unary_mount: 3 passed")
