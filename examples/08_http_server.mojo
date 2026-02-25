"""Example 08 — HTTP/1.1 server with flare.http.HttpServer.

Demonstrates:
  - Binding an HttpServer on an OS-assigned port
  - Request handler: routing on method and path
  - Returning 200 OK, 404 Not Found, 405 Method Not Allowed
  - Setting custom response headers
  - Reading the response from the client side (loopback)

Real-world usage blocks forever:

    fn handler(req: Request) raises -> Response:
        return Response(Status.OK, body="hello".as_bytes())

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve(handler)   # ← blocks indefinitely

Here we drive the server one connection at a time using the internal
``_handle_connection`` helper so the example exits cleanly.

Run:
    pixi run example-http-server
"""

from flare.http import HttpServer, Request, Response, Status
from flare.http.server import _handle_connection
from flare.net import SocketAddr
from flare.tcp import TcpStream, TcpListener


# ── Helpers ───────────────────────────────────────────────────────────────────


fn to_body(s: String) -> List[UInt8]:
    """Convert a String to a body byte list (Response requires List[UInt8])."""
    var out = List[UInt8](capacity=len(s))
    for b in s.as_bytes():
        out.append(b)
    return out^


fn send_raw(s: StringLiteral) -> List[UInt8]:
    """Convert a StringLiteral to bytes for writing to a TcpStream."""
    var out = List[UInt8](capacity=len(s))
    for b in s.as_bytes():
        out.append(b)
    return out^


fn read_response(mut client: TcpStream) raises -> String:
    """Read the response from the server and return the first line."""
    var buf = List[UInt8](unsafe_uninit_length=4096)
    var n = client.read(buf.unsafe_ptr(), len(buf))
    if n <= 0:
        return "<no data>"
    # Return the status line (first CRLF-terminated line)
    var line = String(capacity=32)
    for i in range(n):
        var c = buf[i]
        if c == 13 or c == 10:
            break
        line += chr(Int(c))
    return line^


# ── Request handler ───────────────────────────────────────────────────────────


fn router(req: Request) raises -> Response:
    """Simple router used throughout this example.

    Routes:
        GET  /hello       → 200 "Hello from flare!"
        POST /echo        → 200 echoes request body
        GET  /headers     → 200 shows Accept header
        *    /hello       → 405 Method Not Allowed
        *    anything     → 404 Not Found
    """
    if req.url == "/hello":
        if req.method != "GET":
            var r = Response(
                status=Status.METHOD_NOT_ALLOWED,
                reason="Method Not Allowed",
                body=to_body("Only GET is allowed on /hello"),
            )
            r.headers.set("Allow", "GET")
            return r^
        var r = Response(
            status=Status.OK,
            reason="OK",
            body=to_body("Hello from flare!"),
        )
        r.headers.set("X-Powered-By", "flare")
        return r^

    if req.url == "/echo" and req.method == "POST":
        return Response(status=Status.OK, reason="OK", body=req.body)

    if req.url == "/headers" and req.method == "GET":
        var accept = req.headers.get("Accept")
        return Response(
            status=Status.OK,
            reason="OK",
            body=to_body("Accept: " + accept),
        )

    return Response(
        status=Status.NOT_FOUND,
        reason="Not Found",
        body=to_body("404 Not Found: " + req.url),
    )


# ── One loopback round-trip ───────────────────────────────────────────────────


fn roundtrip(listener: TcpListener, raw_request: String) raises -> String:
    """Send a raw HTTP request and return the server's status line.

    Args:
        listener:    Bound TcpListener the server side uses.
        raw_request: Full HTTP/1.1 request including terminal blank line.

    Returns:
        The first line of the HTTP response (e.g. ``HTTP/1.1 200 OK``).
    """
    var port = listener.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var req_bytes = raw_request.as_bytes()
    client.write_all(Span[UInt8](req_bytes))

    var srv_stream = listener.accept()
    _handle_connection(srv_stream^, router, 8192, 1024 * 1024)

    return read_response(client)


# ── Main ──────────────────────────────────────────────────────────────────────


fn main() raises:
    print("=== flare Example 08: HTTP Server ===")
    print()

    # ── 1. Bind the server ────────────────────────────────────────────────────
    print("── 1. Bind HttpServer ──")
    var listener = TcpListener.bind(SocketAddr.localhost(0))
    var port = listener.local_addr().port
    print("  Bound on 127.0.0.1:" + String(port))
    print()

    # ── 2. GET /hello → 200 OK ────────────────────────────────────────────────
    print("── 2. GET /hello → 200 OK ──")
    var r1 = roundtrip(
        listener, "GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    print("  " + r1)
    print()

    # ── 3. POST /echo → 200 echoes body ──────────────────────────────────────
    print("── 3. POST /echo → 200 (echo body) ──")
    var echo_body = "hello server!"
    var post_req = (
        "POST /echo HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Content-Length: "
        + String(len(echo_body))
        + "\r\n\r\n"
        + echo_body
    )
    var r2 = roundtrip(listener, post_req)
    print("  " + r2)
    print()

    # ── 4. GET /headers → 200 shows request header ───────────────────────────
    print("── 4. GET /headers → echoes Accept header ──")
    var r3 = roundtrip(
        listener,
        (
            "GET /headers HTTP/1.1\r\nHost: localhost\r\nAccept:"
            " application/json\r\n\r\n"
        ),
    )
    print("  " + r3)
    print()

    # ── 5. GET /missing → 404 Not Found ──────────────────────────────────────
    print("── 5. GET /missing → 404 ──")
    var r4 = roundtrip(
        listener, "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    print("  " + r4)
    print()

    # ── 6. POST /hello → 405 Method Not Allowed ───────────────────────────────
    print("── 6. POST /hello → 405 (only GET allowed) ──")
    var r5 = roundtrip(
        listener,
        "POST /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )
    print("  " + r5)
    print()

    # ── 7. Malformed request → 400 Bad Request ────────────────────────────────
    print("── 7. Malformed request → 400 ──")
    var r6 = roundtrip(listener, "NOT HTTP AT ALL\r\n\r\n")
    print("  " + r6)
    print()

    # ── 8. HttpServer.bind() high-level API ───────────────────────────────────
    print("── 8. HttpServer.bind() + serve() pattern ──")
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    print("  HttpServer.bind() → " + String(srv.local_addr()))
    print(
        "  In production: srv.serve(router)  ← blocks, handles all connections"
    )
    print()

    listener.close()
    print("=== Example 08 complete ===")
