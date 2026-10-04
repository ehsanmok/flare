# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/)
"""QPACK-05: an undecodable (or blocked) field section is not a connection error.

Lean: Flare.Bugs.QPACK_05.impl_counterexample (impl),
      Flare.Bugs.QPACK_05.fixed_spec (fix).
flare/qpack/dynamic.mojo:473-498 @59bda50 raises for a Required Insert Count
it cannot decode or that exceeds the insert count;
flare/http3/request_reader.mojo:276-284 turns that into a stream-local
protocol error, which take_completed_streams skips and nothing reads.

RFC 9204 sec 2.1.2: "If a decoder encounters more blocked streams than it
promised to support, it MUST treat this as a connection error of type
QPACK_DECOMPRESSION_FAILED" (flare's server advertises the default of 0);
sec 4.5.1.1: a Required Insert Count the encoder could not have produced is
QPACK_DECOMPRESSION_FAILED (the server's table capacity is 0).

Setup: a real QuicListener and QuicClientConnection over loopback UDP. After
the handshake the client sends, on stream 0, a HEADERS frame whose field
section is 01 00 80 (encoded Required Insert Count 1, one indexed dynamic
line), then a valid GET on stream 4. The server runs a handler between
ticks.
Inconclusive if the handshake does not complete, or if the connection is
neither closed with 0x200 nor still serving stream 4.

Expected: the server closes the connection with QPACK_DECOMPRESSION_FAILED
(0x200). Actual: the connection stays open and answers stream 4; stream 0 is
never answered or reset.

Minimal fix: in QuicListener._route_http3_stream_chunks, after feeding the
H3 driver, close the connection with 0x200 when a request stream reports a
QPACK decode failure.
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path

from flare.http.handler import Handler
from flare.http.request import Request
from flare.http.response import Response
from flare.http.server import ok
from flare.http3.request_writer import encode_request_headers
from flare.qpack import QpackHeader
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


@fieldwise_init
struct _Ok(Copyable, Handler):
    def serve(self, req: Request) raises -> Response:
        return ok(String("ok"))


def _bind_server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _dispatch(mut server: QuicListener) raises:
    var handler = _Ok()
    for slot in range(server.connection_count()):
        if server.slot_free[slot] or not server.connections[slot].alive:
            continue
        var ready = server.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var req = server.take_http3_request(slot, ready[i])
            server.emit_http3_response(slot, ready[i], handler.serve(req^))


def _slot(server: QuicListener) -> Int:
    for i in range(len(server.connections)):
        if not server.slot_free[i]:
            return i
    return -1


def main() raises:
    var server = _bind_server()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    if not client.is_established():
        print("inconclusive: QUIC handshake did not complete")
        raise Error("QPACK-05 inconclusive")
    var slot = _slot(server)

    # HEADERS (type 0x01, length 3): RIC enc 1, Sign 0 / Delta Base 0,
    # indexed dynamic field line with relative index 0.
    var bad: List[UInt8] = [0x01, 0x03, 0x01, 0x00, 0x80]
    client.send_stream(UInt64(0), bad, True)
    var good = List[UInt8]()
    encode_request_headers(
        String("GET"),
        String("https"),
        String("localhost"),
        String("/"),
        List[QpackHeader](),
        good,
    )
    client.send_stream(UInt64(4), good, True)

    var s0 = False
    var s4 = False
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _dispatch(server)
        _ = server.tick(timeout_ms=50)
        var ev = client.poll(timeout_ms=50)
        for i in range(len(ev.stream_chunks)):
            if ev.stream_chunks[i].stream_id == UInt64(0):
                s0 = True
            if ev.stream_chunks[i].stream_id == UInt64(4) and ev.stream_chunks[i].fin:
                s4 = True
        if s4 and not server.connections[slot].alive:
            break
    var alive = server.connections[slot].alive
    var code = server.connections[slot].conn.close_error_code
    server.close()
    print(
        "stream 4 answered:", s4, "| stream 0 answered:", s0,
        "| connection alive:", alive, "| close code:", code,
    )
    if not alive and code == UInt64(0x200):
        print("OK: undecodable field section closed the connection with QPACK_DECOMPRESSION_FAILED (0x200)")
        return
    if alive and s4 and not s0:
        print(
            "BUG REPRODUCED: field section 01 00 80 (RIC 1, table capacity 0,"
            " 0 blocked streams) left the connection open (stream 4 answered);"
            " stream 0 was never answered or reset"
        )
        raise Error("QPACK-05")
    print("inconclusive: connection neither closed with 0x200 nor serving stream 4")
    raise Error("QPACK-05 inconclusive")
