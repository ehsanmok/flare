"""End-to-end tests for gRPC streaming RPCs.

Drives :class:`flare.grpc.GrpcClient`'s streaming calls over the HTTP/2
cleartext (h2c prior-knowledge) path against a forked flare
``HttpServer``. The handler speaks just enough gRPC for each shape:

- ``/echo.Echo/ServerStream``: the one request frame carries an ASCII
  count ``N``; the handler replies with ``N`` LPM frames ``msg-0`` ..
  ``msg-(N-1)`` plus ``grpc-status: 0``. The client pulls them one at a
  time via ``recv()`` (incremental read path).
- ``/echo.Echo/ClientStream``: the client sends several request frames
  then half-closes; the handler counts them and replies with a single
  frame carrying the decimal count.
- ``/echo.Echo/Bidi``: the handler echoes each request frame back as a
  reply frame (the flare server answers after the request half-closes,
  so this exercises the send-all-then-recv-all bidi flow).

The flare H2 server carries ``grpc-status`` in the response header set
(the trailers-only shape); the client reads it identically whether it
arrived as an initial header or a trailing HEADERS frame.
"""

from std.testing import assert_equal, assert_true

from flare.grpc import GrpcClient, decode_grpc_message, encode_grpc_message
from flare.http import HttpServer, Request, Response
from flare.net import SocketAddr
from flare.testing import fork_server, kill_forked_server


def _decode_all(body: List[UInt8]) raises -> List[List[UInt8]]:
    """Decode every back-to-back LPM frame in ``body``."""
    var out = List[List[UInt8]]()
    var pos = 0
    while pos + 5 <= len(body):
        var sub = Span[UInt8, _](
            ptr=body.unsafe_ptr() + pos, length=len(body) - pos
        )
        var dec = decode_grpc_message(sub)
        if dec.needs_more:
            break
        out.append(dec.message.payload.copy())
        pos += dec.consumed
    return out^


def _stream_handler(req: Request) raises -> Response:
    var path = req.url

    if path.startswith("/echo.Echo/ServerStream"):
        var n = 0
        if len(req.body) >= 5:
            var dec = decode_grpc_message(Span[UInt8, _](req.body))
            if not dec.needs_more:
                n = Int(
                    String(unsafe_from_utf8=Span[UInt8, _](dec.message.payload))
                )
        var out = List[UInt8]()
        for i in range(n):
            var p = (String("msg-") + String(i)).as_bytes()
            encode_grpc_message(Span[UInt8, _](p), out)
        var resp = Response(200, "", out^)
        resp.headers.set("content-type", "application/grpc+proto")
        resp.headers.set("grpc-status", "0")
        return resp^

    if path.startswith("/echo.Echo/ClientStream"):
        var frames = _decode_all(req.body)
        var count_str = String(len(frames)).as_bytes()
        var out = List[UInt8]()
        encode_grpc_message(Span[UInt8, _](count_str), out)
        var resp = Response(200, "", out^)
        resp.headers.set("content-type", "application/grpc+proto")
        resp.headers.set("grpc-status", "0")
        return resp^

    if path.startswith("/echo.Echo/Bidi"):
        var frames = _decode_all(req.body)
        var out = List[UInt8]()
        for i in range(len(frames)):
            encode_grpc_message(Span[UInt8, _](frames[i]), out)
        var resp = Response(200, "", out^)
        resp.headers.set("content-type", "application/grpc+proto")
        resp.headers.set("grpc-status", "0")
        return resp^

    return Response(404, "", List[UInt8]())


def _base(port: UInt16) -> String:
    return String("http://127.0.0.1:") + String(Int(port))


def test_server_streaming_yields_n_messages_in_order() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _stream_handler)

    var raised = False
    var msgs = List[String]()
    var code = -1
    try:
        var ch = GrpcClient(_base(port))
        var st = ch.call_server_streaming(
            "/echo.Echo/ServerStream", "3".as_bytes()
        )
        while True:
            var m = st.recv()
            if not m:
                break
            msgs.append(String(unsafe_from_utf8=Span[UInt8, _](m.value())))
        code = st.status().code
        st.close()
    except e:
        print("server-streaming raised:", e)
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "server-streaming raised")
    assert_equal(len(msgs), 3)
    assert_equal(msgs[0], "msg-0")
    assert_equal(msgs[1], "msg-1")
    assert_equal(msgs[2], "msg-2")
    assert_equal(code, 0)


def test_client_streaming_counts_messages() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _stream_handler)

    var raised = False
    var reply = String("")
    var code = -1
    try:
        var ch = GrpcClient(_base(port))
        var st = ch.call_client_streaming("/echo.Echo/ClientStream")
        st.send("a".as_bytes())
        st.send("bb".as_bytes())
        st.send("ccc".as_bytes())
        st.close_send()
        var m = st.recv()
        if m:
            reply = String(unsafe_from_utf8=Span[UInt8, _](m.value()))
        var tail = st.recv()
        assert_true(not tail, "expected single client-streaming reply")
        code = st.status().code
        st.close()
    except e:
        print("client-streaming raised:", e)
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "client-streaming raised")
    assert_equal(reply, "3")
    assert_equal(code, 0)


def test_bidi_echoes_each_message() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, _stream_handler)

    var raised = False
    var echoes = List[String]()
    var code = -1
    try:
        var ch = GrpcClient(_base(port))
        var st = ch.call_bidi("/echo.Echo/Bidi")
        st.send("ping".as_bytes())
        st.send("pong".as_bytes())
        st.close_send()
        while True:
            var m = st.recv()
            if not m:
                break
            echoes.append(String(unsafe_from_utf8=Span[UInt8, _](m.value())))
        code = st.status().code
        st.close()
    except e:
        print("bidi raised:", e)
        raised = True

    kill_forked_server(pid)
    assert_true(not raised, "bidi raised")
    assert_equal(len(echoes), 2)
    assert_equal(echoes[0], "ping")
    assert_equal(echoes[1], "pong")
    assert_equal(code, 0)


def main() raises:
    test_server_streaming_yields_n_messages_in_order()
    test_client_streaming_counts_messages()
    test_bidi_echoes_each_message()
    print("test_grpc_streaming: 3 passed")
