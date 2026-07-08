"""Shared middleware path between ``serve`` and ``serve_streaming``.

A streaming front used to hand-roll its status line + headers as a raw
string, bypassing the ``Handler`` middleware stack the request/response
path uses. ``StreamConn.send_response`` closes that gap: the SAME
``Logger[RequestId[Router]]`` stack that ``serve`` would run is invoked
inside the front, and its ``Response`` (status, middleware-injected
headers, body) is framed onto the wire -- after which the front keeps
streaming with ``conn.send``. These tests pin that bridge by driving a
real loopback socket pair.
"""

from std.testing import assert_equal, assert_true

from flare.http import (
    Logger,
    Method,
    Request,
    RequestId,
    Response,
    Router,
    ok,
)
from flare.http.streaming_server import StreamConn
from flare.net import SocketAddr
from flare.tcp import TcpListener, TcpStream


def h_status(req: Request) raises -> Response:
    return ok("control-plane ok")


def _stack() raises -> Logger[RequestId[Router]]:
    # One middleware stack, identical to what `serve` would run.
    var r = Router()
    r.get("/status", h_status)
    return Logger(RequestId(r^), prefix="[stream]")


def _read_some(mut client: TcpStream, n: Int) raises -> String:
    var buf = List[UInt8](capacity=n)
    buf.resize(n, 0)
    var got = client.read(buf.unsafe_ptr(), n)
    return String(unsafe_from_utf8=Span[UInt8, _](buf)[0:got])


def test_send_response_frames_handler_output() raises:
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var conn = StreamConn(lis.accept(), 1)

    var stack = _stack()
    var req = Request(method=Method.GET, url="/status")
    req.headers.set("X-Request-Id", "rid-77")
    var resp = stack.serve(req)
    conn.send_response(resp^)
    conn.flush_blocking()

    var wire = _read_some(client, 512)
    client.close()
    _ = conn^

    assert_true(wire.startswith("HTTP/1.1 200"))
    # RequestId middleware echoed the inbound id onto the response.
    assert_true("rid-77" in wire)
    # Auto Content-Length for the fixed body.
    assert_true("Content-Length: 16" in wire)
    assert_true(wire.endswith("control-plane ok"))


def test_send_response_then_stream_tail() raises:
    # The front emits a Handler-produced head, then streams more bytes
    # with the ordinary send() path -- proving head + tail coexist.
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var client = TcpStream.connect(SocketAddr.localhost(port))
    var conn = StreamConn(lis.accept(), 1)

    var resp = Response(status=200, reason="OK")
    resp.headers.set("Content-Type", "text/event-stream")
    resp.headers.set("Transfer-Encoding", "chunked")
    conn.send_response(resp^, keep_alive=True)
    conn.send("data: hi\n\n")
    conn.flush_blocking()

    var wire = _read_some(client, 512)
    client.close()
    _ = conn^

    # Transfer-Encoding present -> no auto Content-Length injected.
    assert_true("Transfer-Encoding: chunked" in wire)
    assert_true("Content-Length" not in wire)
    assert_true("Connection: keep-alive" in wire)
    assert_true(wire.endswith("data: hi\n\n"))


def main() raises:
    test_send_response_frames_handler_output()
    print("test_stream_middleware_bridge: handler-output framing passed")
    test_send_response_then_stream_tail()
    print("test_stream_middleware_bridge: head + streamed tail passed")
