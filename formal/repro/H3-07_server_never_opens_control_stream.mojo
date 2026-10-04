# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/)
"""H3-07: the HTTP/3 server never opens its control stream or sends SETTINGS.

Lean: Flare.Bugs.H3_07.impl_no_control (impl), Flare.Bugs.H3_07.fixed_spec
(fix). flare/quic/server.mojo @59bda50 never sends on a server-initiated
unidirectional stream: the 1-RTT egress (`_drain_1rtt_coalesced`,
2225-2420) writes only ACK / HANDSHAKE_DONE / MAX_DATA / MAX_STREAMS /
NEW_CONNECTION_ID and the response streams, and
`Http3Connection.emit_initial_settings` (flare/http3/server.mojo:1230) is
not called anywhere under flare/ (only tests/h3/test_h3_uni_streams.mojo
and examples/advanced/http3_server.mojo:167, which prints the length).
Its docstring ("The reactor opens a local control uni-stream via QUIC and
emits these bytes") does not hold.

RFC 9114 sec 6.2.1: "Each side MUST initiate a single control stream at the
beginning of the connection and send its SETTINGS frame as the first frame
on this stream."

Setup: a real QuicListener and QuicClientConnection over loopback UDP with
the rustls fixtures; after the handshake the client sends GET / on stream 0
(HEADERS + FIN), the server runs a handler and answers. Every STREAM chunk
the client receives is recorded.
Inconclusive if the handshake or the response (FIN on stream 0) does not
complete.

Expected: a chunk at offset 0 on a server-initiated uni stream
(sid % 4 == 3) starting 00 04 (control stream type, SETTINGS frame).
Actual: the only stream the server sends on is the request stream.

Minimal fix: in `_drain_1rtt_coalesced`, together with the first
HANDSHAKE_DONE (the first 1-RTT flight), append a STREAM frame on stream 3
carrying `self.http3_connections[slot].emit_initial_settings()`.
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
        var ready = server.take_http3_completed_streams(slot)
        for i in range(len(ready)):
            var req = server.take_http3_request(slot, ready[i])
            server.emit_http3_response(slot, ready[i], handler.serve(req^))


def main() raises:
    var server = _bind_server()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost")
    )
    var sids = List[UInt64]()
    var offs = List[UInt64]()
    var heads = List[List[UInt8]]()
    var response_fin = False

    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        var ev = client.poll(timeout_ms=50)
        for i in range(len(ev.stream_chunks)):
            sids.append(ev.stream_chunks[i].stream_id)
            offs.append(ev.stream_chunks[i].offset)
            heads.append(ev.stream_chunks[i].data.copy())
        if client.is_established():
            break
    if not client.is_established():
        print("inconclusive: QUIC handshake did not complete")
        raise Error("H3-07 inconclusive")

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
    var extra = 0
    for _ in range(60):
        _ = server.tick(timeout_ms=50)
        _dispatch(server)
        _ = server.tick(timeout_ms=50)
        var ev = client.poll(timeout_ms=50)
        for i in range(len(ev.stream_chunks)):
            sids.append(ev.stream_chunks[i].stream_id)
            offs.append(ev.stream_chunks[i].offset)
            heads.append(ev.stream_chunks[i].data.copy())
            if ev.stream_chunks[i].stream_id == UInt64(0) and ev.stream_chunks[i].fin:
                response_fin = True
        if response_fin:
            extra += 1
            if extra >= 4:
                break
    server.close()
    if not response_fin:
        print("inconclusive: no response FIN on stream 0")
        raise Error("H3-07 inconclusive")

    var seen = String("")
    var control = False
    for i in range(len(sids)):
        seen += " " + String(sids[i])
        if sids[i] % 4 == 3 and offs[i] == 0 and len(heads[i]) >= 2:
            if heads[i][0] == 0x00 and heads[i][1] == 0x04:
                control = True
    if not control:
        print(
            "BUG REPRODUCED: request answered, but no server-initiated uni"
            " stream carried 00 + SETTINGS; streams the server sent on:" + seen
        )
        raise Error("H3-07")
    print("OK: server control stream (type 0x00 + SETTINGS) received; streams:" + seen)
