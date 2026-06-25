"""End-to-end tests for the gRPC unary client (W3).

Drives :class:`flare.grpc.GrpcClient` over the HTTP/2 cleartext (h2c
prior-knowledge) path against a forked flare ``HttpServer`` whose
handler speaks just enough gRPC to round-trip a unary call: it
LPM-decodes the request frame, echoes the payload back as an LPM reply
frame, and sets ``grpc-status`` / ``grpc-message`` on the response
headers (the flare H2 client merges these into ``Response.headers`` so
the client reads the RPC status transparently).

The flare H2 server does not emit explicit HTTP/2 trailing HEADERS, so
this harness carries ``grpc-status`` in the response header set (the
"trailers-only" shape a real gRPC server uses for an immediate status).
The client read path is identical either way.

Tests:
- ``test_unary_echo_ok``: payload round-trips, status OK.
- ``test_unary_non_ok_status``: a non-zero ``grpc-status`` + message
  surfaces on the result.
- ``test_unary_metadata_forwarded``: custom text metadata reaches the
  server (echoed back in the reply payload).
"""

from std.testing import assert_equal, assert_true

from flare.grpc import GrpcClient, decode_grpc_message, encode_grpc_message
from flare.grpc.metadata import GrpcMetadata
from flare.http import HttpServer, Request, Response
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


def _grpc(req: Request) raises -> Response:
    var path = req.url
    if path.startswith("/echo.Echo/Fail"):
        var resp = Response(200, "", List[UInt8]())
        resp.headers.set("content-type", "application/grpc+proto")
        resp.headers.set("grpc-status", "5")
        resp.headers.set("grpc-message", "nope")
        return resp^

    # Echo: LPM-decode the request frame and re-frame the payload.
    var payload = List[UInt8]()
    if len(req.body) >= 5:
        var dec = decode_grpc_message(Span[UInt8, _](req.body))
        if not dec.needs_more:
            payload = dec.message.payload.copy()

    # For the metadata test, append a marker if the custom header is seen.
    var marker = req.headers.get("x-flare-test")
    if marker.byte_length() > 0:
        var p = marker.as_bytes()
        payload.append(UInt8(ord(":")))
        for i in range(len(p)):
            payload.append(p[i])

    var out = List[UInt8]()
    encode_grpc_message(Span[UInt8, _](payload), out)
    var resp = Response(200, "", out^)
    resp.headers.set("content-type", "application/grpc+proto")
    resp.headers.set("grpc-status", "0")
    return resp^


def _base(port: UInt16) -> String:
    return String("http://127.0.0.1:") + String(Int(port))


def test_unary_echo_ok() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _grpc)

    var ok = False
    var code = -1
    var reply = String("")
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var r = ch.call("/echo.Echo/Say", "hello-grpc".as_bytes())
        ok = r.is_ok()
        code = r.status.code
        reply = String(unsafe_from_utf8=Span[UInt8, _](r.message))
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "unary echo raised")
    assert_true(ok, "expected OK status")
    assert_equal(code, 0)
    assert_equal(reply, "hello-grpc")


def test_unary_non_ok_status() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _grpc)

    var code = -1
    var msg = String("")
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var r = ch.call("/echo.Echo/Fail", "x".as_bytes())
        code = r.status.code
        msg = r.status.message
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "non-ok call raised")
    assert_equal(code, 5)
    assert_equal(msg, "nope")


def test_unary_metadata_forwarded() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _grpc)

    var reply = String("")
    var raised = False
    try:
        var ch = GrpcClient(_base(port))
        var md = GrpcMetadata()
        md.append_text("x-flare-test", "meta")
        var r = ch.call("/echo.Echo/Say", "p".as_bytes(), md)
        reply = String(unsafe_from_utf8=Span[UInt8, _](r.message))
    except:
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "metadata call raised")
    assert_equal(reply, "p:meta")


def main() raises:
    test_unary_echo_ok()
    test_unary_non_ok_status()
    test_unary_metadata_forwarded()
    print("test_grpc_client: 3 passed")
