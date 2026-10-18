"""HTTP/3 transfers larger than the initial QUIC flow-control windows.

Both sides advertise 1 MiB stream and connection windows. A 3 MiB
upload only completes if the server grants MAX_STREAM_DATA / MAX_DATA
as it consumes the body, and a 3 MiB download only completes if the
server stops at the client's windows and resumes on the client's
grants (RFC 9000 sec 4.1). The server runs in a forked child; the
parent drives the real flare h3 client.
"""

from std.pathlib import Path
from std.testing import TestSuite, assert_equal, assert_true

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.http3 import Http3ClientConnection
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic._server_support import _monotonic_ms
from flare.tls import RustlsQuicConnector
from flare.utils import exit, fork
from flare.testing import kill_forked_server


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"
comptime _BIG: Int = 3 * 1024 * 1024


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


@fieldwise_init
struct _SizeHandler(Copyable, Handler):
    """POST: reply with the body length. GET: reply with _BIG bytes."""

    def serve(self, req: Request) raises -> Response:
        if len(req.body) > 0:
            var sum = 0
            for i in range(len(req.body)):
                sum += Int(req.body[i])
            return ok(String(len(req.body)) + ":" + String(sum))
        var resp = ok(String(""))
        var body = List[UInt8](capacity=_BIG)
        for i in range(_BIG):
            body.append(UInt8(i % 251))
        resp.body = body^
        return resp^


def _serve_forever(mut server: QuicListener):
    var handler = _SizeHandler()
    try:
        while True:
            _ = server.tick(timeout_ms=5)
            for slot in range(server.connection_count()):
                var ready = server.take_http3_completed_streams(slot)
                for i in range(len(ready)):
                    var req = server.take_http3_request(slot, ready[i])
                    server.emit_http3_response(
                        slot, ready[i], handler.serve(req^)
                    )
            _ = server.drain_all_egress()
            _ = server.advance_timers(_monotonic_ms())
    except:
        pass
    exit()


def _start(mut pid: Int) raises -> Http3ClientConnection:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var server = QuicListener.bind(cfg^)
    var addr = server.local_addr()
    pid = fork()
    if pid == 0:
        _serve_forever(server)
    server.close()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(addr, connector, String("localhost"))
    for _ in range(100):
        _ = quic.poll(timeout_ms=20)
        if quic.is_established():
            break
    assert_true(quic.is_established(), "handshake")
    return Http3ClientConnection(quic^)


def _await(mut h3: Http3ClientConnection, sid: UInt64) raises -> Response:
    var deadline = _monotonic_ms() + 20_000
    while _monotonic_ms() < deadline:
        _ = h3.poll_responses(20)
        var r = h3.take_if_complete(sid)
        if r:
            var resp = Response(status=r.value().status)
            resp.body = r.value().body.copy()
            return resp^
    raise Error("response did not complete")


def test_upload_past_initial_window() raises:
    var pid = 0
    var h3 = _start(pid)
    var body = List[UInt8](capacity=_BIG)
    var sum = 0
    for i in range(_BIG):
        body.append(UInt8(i % 7))
        sum += i % 7
    var sid = h3.request(
        "POST", "https", "localhost", "/up", List[QpackHeader](), body
    )
    var resp = _await(h3, sid)
    kill_forked_server(pid)
    assert_equal(resp.status, 200)
    assert_equal(
        String(unsafe_from_utf8=Span[UInt8, _](resp.body)),
        String(_BIG) + ":" + String(sum),
    )


def test_download_past_initial_window() raises:
    var pid = 0
    var h3 = _start(pid)
    var sid = h3.request(
        "GET", "https", "localhost", "/down", List[QpackHeader](), List[UInt8]()
    )
    var resp = _await(h3, sid)
    kill_forked_server(pid)
    assert_equal(resp.status, 200)
    assert_equal(len(resp.body), _BIG)
    var bad = 0
    for i in range(_BIG):
        if resp.body[i] != UInt8(i % 251):
            bad += 1
    assert_equal(bad, 0)


def test_server_stops_at_the_client_window() raises:
    """Lockstep, one process: with a full congestion window nothing is
    framed; with a 32 KiB client window the server queues the 3 MiB
    response but frames no byte past the window until the client grants
    more, then finishes once the client reads."""
    comptime WINDOW = 32 * 1024
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    var server = QuicListener.bind(cfg^)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var quic = QuicClientConnection.start(
        server.local_addr(),
        connector,
        String("localhost"),
        initial_max_data=UInt64(WINDOW),
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=20)
        _ = quic.poll(timeout_ms=20)
        if quic.is_established():
            break
    var h3 = Http3ClientConnection(quic^)
    var sid = h3.request(
        "GET", "https", "localhost", "/down", List[QpackHeader](), List[UInt8]()
    )
    var handler = _SizeHandler()
    var emitted = False
    for _ in range(40):
        _ = server.tick(timeout_ms=5)
        var ready = server.take_http3_completed_streams(0)
        for i in range(len(ready)):
            var req = server.take_http3_request(0, ready[i])
            server.emit_http3_response(0, ready[i], handler.serve(req^))
            emitted = True
        if emitted:
            break
    assert_true(emitted, "request reached the server")
    # A full congestion window holds every response byte back.
    var saved = server.loss[0].bytes_in_flight
    server.loss[0].bytes_in_flight = server.loss[0].window()
    _ = server.drain_all_egress()
    assert_equal(server.connections[0].h3_tx[Int(sid)].off, UInt64(0))
    server.loss[0].bytes_in_flight = saved
    for _ in range(20):
        _ = server.tick(timeout_ms=5)
        _ = server.drain_all_egress()
    ref tx = server.connections[0].h3_tx[Int(sid)]
    assert_true(tx.off <= UInt64(WINDOW), "framed past MAX_STREAM_DATA")
    assert_true(server.connections[0].fc_tx_sent <= UInt64(WINDOW))
    assert_true(tx.pending() > 0, "the rest stays queued")
    var deadline = _monotonic_ms() + 20_000
    var body_len = -1
    while _monotonic_ms() < deadline and body_len < 0:
        _ = server.tick(timeout_ms=1)
        _ = server.drain_all_egress()
        _ = server.advance_timers(_monotonic_ms())
        _ = h3.poll_responses(1)
        var r = h3.take_if_complete(sid)
        if r:
            body_len = len(r.value().body)
    assert_equal(body_len, _BIG)
    server.close()


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
