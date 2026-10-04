# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/)
"""QUIC-22: the server closes connections without sending CONNECTION_CLOSE.

Lean: Flare.Bugs.QUIC_22.impl_no_cc, Flare.Bugs.QUIC_22.impl_short_period
(impl), Flare.Bugs.QUIC_22.fixed_spec (fix).
flare/quic/server.mojo:2177-2180 @59bda50 (_close_for) marks the connection
CLOSING (state.mojo:890-911) and sets alive = False; _drain_and_send
(1993, check at 2033-2038) skips non-alive slots, so nothing is ever sent.
The server never calls encode_connection_close. The slot is reclaimed at the
next timer event (advance_timers, 2900-2938), not after 3 x PTO.

RFC 9000 sec 11.1: "An endpoint that detects an error SHOULD signal the
existence of that error to its peer" and connection errors are signalled
with CONNECTION_CLOSE (sec 10.2: an endpoint enters the closing state "after
initiating an immediate close" by sending CONNECTION_CLOSE; sec 10.2.1: in
the closing state it answers incoming packets with CONNECTION_CLOSE).

Setup: a real QuicListener and QuicClientConnection over loopback UDP. After
the handshake the client sends STREAM data on stream 1, a server-initiated
bidirectional id the server never opened (RFC 9000 sec 19.8:
STREAM_STATE_ERROR). The server closes the connection with 0x05 (the
control: alive becomes False and close_error_code is 5). The client is
polled for 2 s.
Inconclusive if the handshake does not complete or the server does not
close the connection.

Expected: the client receives CONNECTION_CLOSE and enters DRAINING.
Actual: nothing reaches the client; it stays ESTABLISHED.

Minimal fix: _close_for builds a 1-RTT CONNECTION_CLOSE(code) and sends it
to the peer before marking the slot not alive.
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path

from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import CONN_STATE_DRAINING
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind_server() raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


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
        raise Error("QUIC-22 inconclusive")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    var slot = _slot(server)
    var data: List[UInt8] = [0x41, 0x42, 0x43]
    client.send_stream(UInt64(1), data, True)

    var server_closed = False
    var server_code = UInt64(0)
    var client_drained = False
    for _ in range(20):
        _ = server.tick(timeout_ms=50)
        if not server_closed and not server.connections[slot].alive:
            server_closed = True
            server_code = server.connections[slot].conn.close_error_code
        var ev = client.poll(timeout_ms=50)
        if ev.connection_closed or client.conn.state == CONN_STATE_DRAINING:
            client_drained = True
            break
    server.close()
    print(
        "server closed:", server_closed, "(code", server_code, ")",
        "| client received CONNECTION_CLOSE:", client_drained,
        "| client state:", client.conn.state,
    )
    if client_drained:
        print("OK: the server's close reached the client as CONNECTION_CLOSE")
        return
    if not server_closed:
        print("inconclusive: the server did not close the connection")
        raise Error("QUIC-22 inconclusive")
    print(
        "BUG REPRODUCED: server closed the connection (error", server_code,
        ") but sent no CONNECTION_CLOSE; client still not draining after 2 s",
    )
    raise Error("QUIC-22")
