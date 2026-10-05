# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# RESOLVED: QUIC-23 fixed on fix/formal-findings
# fixtures in tests/tls/fixtures/rustls-quic-client/)
"""QUIC-23: the server keeps sending after the peer's CONNECTION_CLOSE.

Lean: Flare.Bugs.QUIC_23.impl_sends_draining, Flare.Bugs.QUIC_23.impl_trace
(impl), Flare.Bugs.QUIC_23.fixed_spec (fix).
A peer CONNECTION_CLOSE moves the server's connection to DRAINING
(flare/quic/state.mojo:430-445 @59bda50), but alive stays True and no
egress path checks the state: _drain_and_send (flare/quic/server.mojo:1993,
gate at 2033-2038 tests alive only), _drain_1rtt_coalesced (2210-2433), the
PTO and ACK-delay timer paths (2925-2980) all build packets through
_build_1rtt_response (2673).

RFC 9000 sec 10.2.2: "An endpoint in the draining state MUST NOT send any
packets."

Setup: a real QuicListener and QuicClientConnection over loopback UDP. After
the handshake the client sends a 1-RTT CONNECTION_CLOSE (NO_ERROR); the
server's connection must then be DRAINING (control). The client's socket is
flushed, then a GET arrives on stream 0 and the server runs a handler
between ticks for about 2 s. Every datagram reaching the client socket is
counted.
Inconclusive if the handshake does not complete or the server's state is
not DRAINING after the CONNECTION_CLOSE.

Expected: no datagram from the server after it entered DRAINING.
Before the fix: it keeps acknowledging and answers the request.

Minimal fix: _build_1rtt_response returns no datagram while the connection
is DRAINING.
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
from flare.quic.frame import ConnectionCloseFrame, encode_connection_close
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import CONN_STATE_DRAINING
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


def _count_rx(mut client: QuicClientConnection, wait_ms: Int) raises -> Int:
    var buf = List[UInt8](length=2048, fill=UInt8(0))
    var n = 0
    client.sock.set_recv_timeout(wait_ms)
    while True:
        try:
            var got = client.sock.recv_from(Span[UInt8, _](buf))
            if got[0] <= 0:
                break
            n += 1
        except:
            break
    return n


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
        raise Error("QUIC-23 inconclusive")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    var slot = _slot(server)

    var cc = List[UInt8]()
    encode_connection_close(
        ConnectionCloseFrame(False, UInt64(0), UInt64(0), List[UInt8]()), cc
    )
    while len(cc) < 16:
        cc.append(UInt8(0))
    var dg = client._build_1rtt(cc^, ack_eliciting=False)
    _ = client.sock.send_to(Span[UInt8, _](dg), client.peer)
    for _ in range(4):
        _ = server.tick(timeout_ms=50)
    if server.connections[slot].conn.state != CONN_STATE_DRAINING:
        print(
            "inconclusive: server state", server.connections[slot].conn.state,
            "is not DRAINING after the peer's CONNECTION_CLOSE",
        )
        raise Error("QUIC-23 inconclusive")
    _ = _count_rx(client, 100)

    var req = List[UInt8]()
    encode_request_headers(
        String("GET"),
        String("https"),
        String("localhost"),
        String("/"),
        List[QpackHeader](),
        req,
    )
    client.send_stream(UInt64(0), req, True)
    var n = 0
    for _ in range(20):
        _ = server.tick(timeout_ms=50)
        _dispatch(server)
        _ = server.tick(timeout_ms=20)
        n += _count_rx(client, 30)
    var state = server.connections[slot].conn.state
    server.close()
    print("server state:", state, "| datagrams sent to the client while DRAINING:", n)
    if n > 0:
        print(
            "BUG REPRODUCED: server in DRAINING sent", n,
            "datagram(s) after the peer's CONNECTION_CLOSE",
        )
        raise Error("QUIC-23")
    print("OK: no datagram from the server while draining")
