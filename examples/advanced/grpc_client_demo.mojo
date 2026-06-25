"""Unary gRPC client example over HTTP/2 cleartext (W3).

Spawns a child running :class:`flare.http.HttpServer` whose handler
speaks just enough gRPC to round-trip a unary call (LPM-decode the
request frame, echo the payload back as an LPM reply, set
``grpc-status`` on the response), and a parent that drives the call via
:class:`flare.grpc.GrpcClient`.

``GrpcClient`` composes on the same ``HttpClient`` HTTP/2 path the rest
of the library uses -- a unary RPC is one POST whose body is the LPM
request frame; the reply frame and ``grpc-status`` come back on the same
H2 stream. No new transport, no ``UnsafePointer`` in user code, and the
``/package.Service/Method`` path is the only gRPC-specific thing the
caller types.

Run with::

    pixi run -e dev mojo -I . examples/advanced/grpc_client_demo.mojo
"""

from flare.grpc import GrpcClient, decode_grpc_message, encode_grpc_message
from flare.http import HttpServer, Request, Response
from flare.net import SocketAddr
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid


def _greeter(req: Request) raises -> Response:
    # Decode the LPM request frame, build a greeting, re-frame as LPM.
    var name = List[UInt8]()
    if len(req.body) >= 5:
        var dec = decode_grpc_message(Span[UInt8, _](req.body))
        if not dec.needs_more:
            name = dec.message.payload.copy()

    var greeting = List[UInt8]()
    var prefix = String("hello, ").as_bytes()
    for i in range(len(prefix)):
        greeting.append(prefix[i])
    for i in range(len(name)):
        greeting.append(name[i])

    var out = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](greeting), out)
    var resp = Response(200, "", out^)
    resp.headers.set("content-type", "application/grpc+proto")
    resp.headers.set("grpc-status", "0")
    return resp^


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("[grpc server] listening on 127.0.0.1:" + String(Int(port)))

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_greeter)
        except:
            pass
        exit()
    usleep(150000)

    var base = String("http://127.0.0.1:") + String(Int(port))
    print("[grpc client] dialing " + base)
    var ch = GrpcClient(base)
    var reply = ch.call("/greet.Greeter/SayHello", "flare".as_bytes())
    print(
        "[grpc] SayHello -> status="
        + String(reply.status.code)
        + " ("
        + reply.status.name()
        + ") body="
        + String(unsafe_from_utf8=Span[UInt8, _](reply.message))
    )

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("[done]")
