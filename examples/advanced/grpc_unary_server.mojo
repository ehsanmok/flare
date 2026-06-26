"""Reactor-mounted gRPC unary server on the HttpServer H2 path (T1.5).

The companion to ``grpc_unary_demo.mojo`` (which is sans-I/O): this one
actually binds a socket. A ``GrpcUnary`` handler is wrapped in
:class:`flare.grpc.GrpcService` -- a plain :trait:`flare.http.Handler`
-- and served over the unified :class:`HttpServer` H2 reactor with no
bespoke per-RPC glue. ``grpc-status`` rides in genuine HTTP/2 trailing
HEADERS.

The example forks the server, drives one unary echo RPC plus one
deadline-exceeded RPC with :class:`flare.grpc.GrpcClient` over h2c, then
tears the child down.

Run:
    pixi run mojo -I . examples/advanced/grpc_unary_server.mojo
"""

from std.memory import Span

from flare.grpc import (
    GrpcCallContext,
    GrpcClient,
    GrpcService,
    GrpcUnary,
    GrpcUnaryReply,
)
from flare.http import HttpServer
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server
from flare.utils import usleep


@fieldwise_init
struct Greeter(Copyable, GrpcUnary, Movable):
    """Replies ``hello, <request>``; sleeps if asked (deadline demo)."""

    var slow: Bool

    def serve_unary(
        mut self,
        ctx: GrpcCallContext,
        request_bytes: Span[UInt8, _],
    ) raises -> GrpcUnaryReply:
        if self.slow:
            usleep(60_000)
        var name = String(unsafe_from_utf8=request_bytes)
        var greeting = String("hello, ") + name
        var out = List[UInt8](capacity=greeting.byte_length())
        for b in greeting.as_bytes():
            out.append(b)
        return GrpcUnaryReply.ok(out^)


def main() raises:
    print("== gRPC unary server (reactor-mounted) ==")
    print("")

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    # Fast greeter for the happy path.
    var pid = fork_server(srv^, GrpcService(Greeter(slow=False)))
    var base = String("http://127.0.0.1:") + String(Int(port))

    var ch = GrpcClient(base)
    var r = ch.call("/demo.Greeter/SayHello", "flare".as_bytes())
    print("SayHello -> ok =", r.is_ok(), " status =", r.status.code)
    print("  reply  :", String(unsafe_from_utf8=Span[UInt8, _](r.message)))
    kill_forked_server(pid)

    # Restart with a slow greeter to show grpc-timeout enforcement.
    var srv2 = HttpServer.bind(SocketAddr.localhost(0))
    var port2 = UInt16(srv2.local_addr().port)
    var pid2 = fork_server(srv2^, GrpcService(Greeter(slow=True)))
    var base2 = String("http://127.0.0.1:") + String(Int(port2))

    var ch2 = GrpcClient(base2)
    var r2 = ch2.call(
        "/demo.Greeter/SayHello", "flare".as_bytes(), timeout_ms=1
    )
    print(
        "SayHello (1ms deadline) -> status =",
        r2.status.code,
        "(4 = DEADLINE_EXCEEDED)",
    )
    kill_forked_server(pid2)
    print("")
    print("Both RPCs served by GrpcService over the H2 reactor.")
