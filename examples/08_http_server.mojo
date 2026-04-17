"""Example 08: HTTP/1.1 server with flare.http.HttpServer.

Shows how to build a simple server with routing, JSON responses, cookies,
and the new response helpers.

Real-world usage blocks forever:

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(handler)

Here we drive the server one request at a time using the internal
_parse_http_request + _write_response so the example exits cleanly.

Run:
    pixi run example-http-server
"""

from flare.http import (
    HttpServer,
    Request,
    Response,
    Status,
    ok,
    ok_json,
    not_found,
    bad_request,
)
from flare.http.server import _parse_http_request, _write_response
from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener


def send_and_receive(
    listener: TcpListener, raw_request: String
) raises -> String:
    """Send a raw HTTP request on loopback and return the status line."""
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var req_bytes = raw_request.as_bytes()
    client.write_all(Span[UInt8, _](req_bytes))

    var srv_stream = listener.accept()
    var req = _parse_http_request(srv_stream, 8192, 1024 * 1024)
    var resp = router(req^)
    _write_response(srv_stream, resp)
    srv_stream.close()

    var buf = List[UInt8](unsafe_uninit_length=4096)
    var n = client.read(buf.unsafe_ptr(), 4096)
    client.close()
    if n <= 0:
        return "<no data>"
    var line = String(capacity=64)
    for i in range(n):
        var c = buf[i]
        if c == 13 or c == 10:
            break
        line += chr(Int(c))
    return line^


def router(req: Request) raises -> Response:
    """Route requests to handlers."""
    if req.url == "/hello" and req.method == "GET":
        return ok("Hello from flare!")

    if req.url == "/json" and req.method == "GET":
        return ok_json('{"greeting": "hello", "from": "flare"}')

    if req.url == "/echo" and req.method == "POST":
        return Response(status=Status.OK, reason="OK", body=req.body)

    if req.url == "/hello":
        return bad_request("Only GET is allowed on /hello")

    return not_found(req.url)


def main() raises:
    print("=== flare Example 08: HTTP server ===")
    print()

    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    print("Bound on 127.0.0.1:" + String(port))
    print()

    print("GET /hello")
    print("  " + send_and_receive(
        listener, "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ))

    print("GET /json")
    print("  " + send_and_receive(
        listener, "GET /json HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ))

    print("POST /echo")
    print("  " + send_and_receive(
        listener,
        "POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello",
    ))

    print("GET /missing")
    print("  " + send_and_receive(
        listener, "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ))

    print()
    print("HttpServer.bind() pattern:")
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    print("  Listening on " + String(srv.local_addr()))
    print("  In production: srv.serve(router)")
    print()

    listener.close()
    print("=== Example 08 complete ===")
