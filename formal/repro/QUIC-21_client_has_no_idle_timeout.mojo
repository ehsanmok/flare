# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/; about 6 s)
"""QUIC-21: the client never applies an idle timeout.

Lean: Flare.Bugs.QUIC_21.impl_never_closes, impl_counterexample (impl),
Flare.Bugs.QUIC_21.fixed_spec (fix).
flare/quic/client.mojo:557-608 @59bda50 (poll) has no idle check;
_dispatch_frames (902-912) passes now_us = 0 to handle_frame_buf, so
last_activity_us never moves, and is_idle_timeout_expired
(flare/quic/state.mojo:876-887) has no caller.

RFC 9000 sec 10.1: "If a max_idle_timeout is specified by either endpoint
in its transport parameters (Section 18.2), the connection is silently
closed and its state is discarded when it remains idle for longer than the
minimum of the max_idle_timeout value advertised by both endpoints."

Setup: a real QuicListener (max_idle_timeout 30000 ms) and a
QuicClientConnection started with max_idle_timeout_ms = 1000 over loopback
UDP. After the handshake the server stops running, so nothing more arrives;
the client keeps calling poll for 5 s.
Inconclusive if the handshake does not complete.

Expected: within about 1 s (at most 3 x PTO more) the client closes (state
CLOSED, not established).
Actual: after 5 s it is still established.

Minimal fix: pass the monotonic clock to handle_frame_buf in
_dispatch_frames, and in poll close the connection when
is_idle_timeout_expired.
"""

from std.collections import List
from std.pathlib import Path

from flare.quic._server_support import _monotonic_ms
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.quic.state import CONN_STATE_CLOSED, CONN_STATE_DRAINING
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
    cfg.max_idle_timeout_ms = UInt64(30_000)
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def main() raises:
    var server = _bind_server()
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost"),
        max_idle_timeout_ms=UInt64(1_000),
    )
    for _ in range(40):
        _ = server.tick(timeout_ms=50)
        _ = client.poll(timeout_ms=50)
        if client.is_established():
            break
    if not client.is_established():
        print("inconclusive: QUIC handshake did not complete")
        raise Error("QUIC-21 inconclusive")
    for _ in range(4):
        _ = server.tick(timeout_ms=20)
        _ = client.poll(timeout_ms=20)
    var start = _monotonic_ms()
    var closed_after = UInt64(0)
    while _monotonic_ms() - start < UInt64(5_000):
        var ev = client.poll(timeout_ms=100)
        if (
            ev.connection_closed
            or not client.is_established()
            or client.conn.state == CONN_STATE_CLOSED
            or client.conn.state == CONN_STATE_DRAINING
        ):
            closed_after = _monotonic_ms() - start
            break
    server.close()
    print(
        "client state:", client.conn.state, "| established:",
        client.is_established(),
    )
    if closed_after > UInt64(0):
        print(
            "OK: client closed the idle connection after", closed_after,
            "ms (max_idle_timeout 1000 ms)",
        )
        return
    print(
        "BUG REPRODUCED: client advertised max_idle_timeout 1000 ms, peer"
        " silent for 5 s, connection still established (not closed)",
    )
    raise Error("QUIC-21")
