"""End-to-end HTTP/3 client <-> flare QUIC/H3 server.

Drives the real :class:`flare.http3.client.Http3ClientConnection` (over
:class:`flare.quic.client.QuicClientConnection`) against the real
:class:`flare.quic.server.QuicListener` over loopback UDP, pumped in
lockstep on one thread:

1. Complete the QUIC handshake (client.poll <-> server.tick).
2. Client opens its control/QPACK uni-streams + a request bidi
   stream and writes ``HEADERS [+ DATA]`` with FIN.
3. Between ticks the server pulls completed H3 streams, runs a
   :trait:`flare.http.Handler`, and emits the response, which the
   1-RTT egress flushes back.
4. The client assembles the response via
   :class:`flare.http3.response_reader.Http3ResponseReader`.

This proves the full client path end to end over real QUIC
encryption: request HEADERS/DATA QPACK-encoded, server dispatch,
response HEADERS/DATA decoded into status + body.

Reuses the 2-cert fixture chain from
``tests/tls/fixtures/rustls-quic-client/`` (CA + ``localhost``
leaf), exactly as ``test_quic_client.mojo``.
"""

from std.collections import Dict, List
from std.pathlib import Path
from std.testing import assert_equal, assert_true

from flare.http3 import (
    Http3BodyChunk,
    Http3ClientConnection,
    Http3Connection,
    Http3ResponseReader,
)
from flare.http3.request_writer import encode_request_headers
from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _read_file(path: String) raises -> String:
    return Path(path).read_text()


def _h3_alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _make_connector() raises -> RustlsQuicConnector:
    var ca = _read_file(_FIXDIR + "ca.pem")
    return RustlsQuicConnector(ca^, _h3_alpn())


def _bind_server() raises -> QuicListener:
    var cert = _read_file(_FIXDIR + "cert.pem")
    var key = _read_file(_FIXDIR + "key.pem")
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = cert^
    cfg.rustls_config.private_key_pem = key^
    cfg.rustls_config.alpn_protocols = _h3_alpn()
    return QuicListener.bind(cfg^)


@fieldwise_init
struct _EchoOrOk(Copyable, Handler):
    """200 handler: echoes a non-empty request body, else 'ok'."""

    def serve(self, req: Request) raises -> Response:
        if len(req.body) > 0:
            var resp = ok(String(""))
            resp.body = req.body.copy()
            return resp^
        return ok(String("ok"))


def _server_dispatch(mut server: QuicListener) raises:
    """Run the handler over every completed H3 stream on every
    slot and emit the response (the inner body of a real serve
    loop, run inline so the test stays single-threaded)."""
    var handler = _EchoOrOk()
    for slot in range(server.connection_count()):
        var ready = server.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var sid = ready[i]
            var req = server.take_http3_request(slot, sid)
            var resp = handler.serve(req^)
            server.emit_http3_response(slot, sid, resp^)


def _drive_handshake(mut server: QuicListener) raises -> QuicClientConnection:
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")
    return client^


def test_h3_get() raises:
    """GET /hello over real QUIC: 200 + body 'ok'."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var sid = h3.send_request(
        String("GET"),
        String("https"),
        String("example.com"),
        String("/hello"),
        List[QpackHeader](),
        List[UInt8](),
    )
    var reader = Http3ResponseReader.new()
    var done = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        if h3.read_response(sid, reader, timeout_ms=50):
            done = True
            break
    assert_true(done, "GET response must complete over loopback h3")
    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)), String("ok")
    )
    server.close()
    h3.close()


def test_h3_post_echo() raises:
    """POST /echo with a body over real QUIC: 200 + echoed body."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var body = List[UInt8]()
    for b in String("flare-h3-body").as_bytes():
        body.append(b)
    var hdrs = List[QpackHeader]()
    hdrs.append(QpackHeader("content-type", "text/plain"))
    var sid = h3.send_request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/echo"),
        hdrs,
        body,
    )
    var reader = Http3ResponseReader.new()
    var done = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        if h3.read_response(sid, reader, timeout_ms=50):
            done = True
            break
    assert_true(done, "POST response must complete over loopback h3")
    var resp = reader.take_response()
    assert_equal(resp.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
        String("flare-h3-body"),
    )
    server.close()
    h3.close()


def test_h3_stream_body() raises:
    """Streaming body read: POST a multi-chunk body and drain the
    echoed response incrementally via poll_body, asserting the head
    (status + headers) is visible mid-stream and the concatenated
    chunks reconstruct the full body -- never buffering it whole."""
    var server = _bind_server()
    var client = _drive_handshake(server)
    var h3 = Http3ClientConnection(client^)

    var sent = List[UInt8]()
    for _ in range(8192):
        sent.append(UInt8(0x41))
    var hdrs = List[QpackHeader]()
    hdrs.append(QpackHeader("content-type", "application/octet-stream"))
    var sid = h3.request(
        String("POST"),
        String("https"),
        String("example.com"),
        String("/echo"),
        hdrs,
        sent,
    )

    var got = List[UInt8]()
    var done = False
    var saw_head = False
    for _ in range(200):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        var chunk = h3.poll_body(sid, timeout_ms=50)
        if not saw_head and h3.head_ready(sid):
            saw_head = True
            assert_equal(h3.stream_status(sid), 200)
        for i in range(len(chunk.data)):
            got.append(chunk.data[i])
        if chunk.done:
            done = True
            break
    assert_true(done, "streaming body must finish over loopback h3")
    assert_true(saw_head, "head must be visible before stream end")
    assert_equal(len(got), 8192)
    assert_equal(Int(got[0]), 0x41)
    assert_equal(Int(got[8191]), 0x41)
    server.close()
    h3.close()


def test_server_opens_its_control_stream_with_settings() raises:
    """H3-07: the server never opened its control stream, so the client
    never received SETTINGS. Over a real handshake the first 1-RTT
    flight must carry stream 3 (the first server-initiated uni stream)
    with type 0x00 and a SETTINGS frame, exactly once, and a client
    driver must read it as the peer's control stream."""
    var server = _bind_server()
    var connector = _make_connector()
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    var by_stream = Dict[UInt64, List[UInt8]]()
    var starts_at_zero = Dict[UInt64, Bool]()
    var chunks_on_3 = 0

    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        var ev = client.poll(timeout_ms=50)
        for i in range(len(ev.stream_chunks)):
            var sid = ev.stream_chunks[i].stream_id
            if sid == UInt64(3):
                chunks_on_3 += 1
                if ev.stream_chunks[i].offset == UInt64(0):
                    starts_at_zero[sid] = True
                    by_stream[sid] = ev.stream_chunks[i].data.copy()
        if client.is_established():
            break
    assert_true(client.is_established(), "handshake must complete first")

    # Send a request so the server's first 1-RTT flight (ACK, HANDSHAKE_DONE
    # and the control stream) definitely leaves, then keep polling.
    var wire = List[UInt8]()
    encode_request_headers(
        String("GET"),
        String("https"),
        String("localhost"),
        String("/"),
        List[QpackHeader](),
        wire,
    )
    client.send_stream(UInt64(0), wire, True)
    var answered = False
    for _ in range(60):
        _ = server.tick(timeout_ms=50)
        _server_dispatch(server)
        _ = server.tick(timeout_ms=50)
        var ev = client.poll(timeout_ms=50)
        for i in range(len(ev.stream_chunks)):
            var sid = ev.stream_chunks[i].stream_id
            if sid == UInt64(3):
                chunks_on_3 += 1
                if ev.stream_chunks[i].offset == UInt64(0):
                    starts_at_zero[sid] = True
                    by_stream[sid] = ev.stream_chunks[i].data.copy()
            if sid == UInt64(0) and ev.stream_chunks[i].fin:
                answered = True
        if answered and chunks_on_3 > 0:
            break
    server.close()
    assert_true(answered, "request must be answered")
    assert_equal(chunks_on_3, 1, "control stream must be sent exactly once")
    assert_true(UInt64(3) in starts_at_zero, "stream 3 must start at offset 0")
    var data = by_stream[UInt64(3)].copy()
    assert_true(len(data) >= 2)
    assert_equal(Int(data[0]), 0x00, "control stream type")
    assert_equal(Int(data[1]), 0x04, "SETTINGS is the first frame")
    # A client-side driver reads it as the peer's control stream.
    var peer = Http3Connection()
    peer.feed_uni_stream_chunk(3, data^)
    assert_equal(peer.peer_control_stream_id, 3)
    assert_true(peer.peer_settings_received)
    assert_equal(
        peer.peer_settings_max_field_section_size,
        Http3Connection().config.max_field_section_size,
    )


def main() raises:
    test_h3_get()
    test_h3_post_echo()
    test_h3_stream_body()
    test_server_opens_its_control_stream_with_settings()
    print("test_h3_client_e2e: 4 passed")
