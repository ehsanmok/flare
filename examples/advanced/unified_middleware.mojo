"""Advanced - one middleware stack behind both a control plane and a
streaming endpoint.

The concrete case: an inference front wants a REST
control plane (``Handler`` + middleware) and a token-streaming endpoint
(``StreamHandler``) in ONE process behind ONE logging / request-id /
routing stack. Before v0.9 that was two serve paths with no shared
middleware; a streaming front had to hand-roll its status line.

This example shows the shared stack:

- ``stack = Logger(RequestId(Router))`` -- a single ``Handler`` stack.
- Control plane: ``HttpServer.serve_cancellable(WithCancel(stack))``
  runs the whole stack on the cancel-aware reactor (shown by driving a
  request directly here, so the example does not block the test runner).
- Streaming endpoint: the SAME stack runs inside a streaming front via
  ``stack.serve(req)`` + ``conn.send_response(resp)``, then the front
  streams the tail with ``conn.send`` -- demonstrated over a loopback
  socket pair.

Run:
    pixi run example-unified-middleware
"""

from flare.http import (
    Logger,
    Method,
    Request,
    RequestId,
    Response,
    Router,
    WithCancel,
    ok,
)
from flare.http.streaming_server import StreamConn
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream


def status_handler(req: Request) raises -> Response:
    return ok("control-plane ok")


def _stack() raises -> Logger[RequestId[Router]]:
    var r = Router()
    r.get("/status", status_handler)
    return Logger(RequestId(r^), prefix="[app]")


def main() raises:
    print("=" * 60)
    print("flare - unified middleware (control plane + streaming)")
    print("=" * 60)

    # Control plane: the stack is what serve_cancellable would run.
    # ``WithCancel(stack^)`` is the exact value you would pass to
    # ``HttpServer.serve_cancellable``; here we drive one request
    # directly so the example stays non-blocking.
    var cp = WithCancel(_stack())
    var req = Request(method=Method.GET, url="/status")
    req.headers.set("X-Request-Id", "req-1")
    var cancel_stack = _stack()
    var resp = cancel_stack.serve(req)
    print("control plane GET /status ->", resp.status, resp.text())
    print("  echoed request id:", resp.headers.get("x-request-id"))
    _ = cp^

    # Streaming endpoint: same stack, framed onto a real socket via
    # send_response, then a streamed tail.
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var conn = StreamConn(lis.accept(), 1)

    var stack = _stack()
    var sreq = Request(method=Method.GET, url="/status")
    sreq.headers.set("X-Request-Id", "stream-1")
    var shead = stack.serve(sreq)
    conn.send_response(shead^, keep_alive=True)
    conn.send("\n--- streamed tail follows ---\n")
    conn.flush_blocking()

    var buf = List[UInt8](capacity=512)
    buf.resize(512, 0)
    var n = client.read(buf.unsafe_ptr(), 512)
    var wire = String(unsafe_from_utf8=Span[UInt8, _](buf)[0:n])
    client.close()
    _ = conn^

    print("streaming endpoint wrote", n, "bytes:")
    print(wire)
    print("OK.")
