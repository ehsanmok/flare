# PLATFORM: any (loopback UDP; needs the rustls QUIC shim and the
# fixtures in tests/tls/fixtures/rustls-quic-client/; about 15 s)
"""QUIC-20: the server's idle timer does not follow RFC 9000 sec 10.1.

Lean: Flare.Bugs.QUIC_20.impl_ignores_peer, impl_unauth_restarts,
impl_zero_closes, impl_no_send_restart, impl_no_pto_floor (impl),
Flare.Bugs.QUIC_20.fixed_spec (fix).
flare/quic/server.mojo:724-782 @59bda50 (_handle_inbound) sets
processed_any for every packet, whether or not it decrypted, and re-arms
the idle timer; schedule_idle_timeout (2874-2898) arms
config.max_idle_timeout_ms only (the client's max_idle_timeout is never
read, and 0 is clamped to 1 ms by the timer wheel,
flare/runtime/timer_wheel.mojo:119-144); sends never re-arm it and there is
no 3 x PTO floor.

RFC 9000 sec 10.1: "Each endpoint advertises a max_idle_timeout, but the
effective value at an endpoint is computed as the minimum of the two
advertised values (or the sole advertised value, if only one endpoint
advertises a non-zero value)"; "An endpoint restarts its idle timer when a
packet from its peer is received and processed successfully"; sec 18.2:
"Idle timeout is disabled when both endpoints omit this transport parameter
or specify a value of 0."

Setup: three loopback connections (real QuicListener and
QuicClientConnection), each silent after the handshake while the server
runs tick + advance_timers:
  A. client max_idle_timeout 1000 ms, server 30000 ms; 5 s of silence.
  B. both 30000 ms on the client, 1000 ms on the server; the client socket
     sends an undecryptable short-header datagram carrying the server's CID
     every 300 ms for 5 s.
  C. both 0 (no idle timeout); 2 s of silence.
Inconclusive if a handshake stalls without the server closing the slot.

Expected: A closed (effective timeout 1 s), B closed (undecryptable packets
do not count), C open.
Actual: A and B open, C closed within milliseconds.

Minimal fix: only successfully processed packets re-arm the timer;
schedule_idle_timeout uses the minimum of the non-zero local and peer
values and arms nothing when both are 0.
"""

from std.collections import List
from std.collections.span import Span
from std.pathlib import Path

from flare.quic._server_support import _monotonic_ms
from flare.quic.client import QuicClientConnection
from flare.quic.server import QuicListener, QuicServerConfig
from flare.tls import RustlsQuicConnector


comptime _FIXDIR: String = "tests/tls/fixtures/rustls-quic-client/"


def _alpn() -> List[String]:
    var a = List[String]()
    a.append(String("h3"))
    return a^


def _bind_server(idle_ms: UInt64) raises -> QuicListener:
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(0)
    cfg.max_idle_timeout_ms = idle_ms
    cfg.rustls_config.cert_chain_pem = Path(_FIXDIR + "cert.pem").read_text()
    cfg.rustls_config.private_key_pem = Path(_FIXDIR + "key.pem").read_text()
    cfg.rustls_config.alpn_protocols = _alpn()
    return QuicListener.bind(cfg^)


def _slot(server: QuicListener) -> Int:
    for i in range(len(server.connections)):
        if not server.slot_free[i]:
            return i
    return -1


def _closed(server: QuicListener, slot: Int) -> Bool:
    return server.slot_free[slot] or not server.connections[slot].alive


def _tick(mut server: QuicListener) raises:
    _ = server.tick(timeout_ms=20)
    _ = server.advance_timers(_monotonic_ms())


def _scenario(
    server_idle: UInt64, client_idle: UInt64, garbage: Bool, silent_ms: UInt64
) raises -> Int:
    """0: no connection accepted or handshake stalled; 1: still open at
    the end; 2: closed (also when the slot died mid-handshake)."""
    var server = _bind_server(server_idle)
    var connector = RustlsQuicConnector(
        Path(_FIXDIR + "ca.pem").read_text(), _alpn()
    )
    var client = QuicClientConnection.start(
        server.local_addr(), connector, String("localhost"),
        max_idle_timeout_ms=client_idle,
    )
    for _ in range(60):
        _tick(server)
        _ = client.poll(timeout_ms=20)
        if client.is_established():
            break
    var slot = _slot(server)
    if not client.is_established() or slot < 0:
        var died = len(server.connections) > 0 and _slot(server) < 0
        server.close()
        if died:
            print("  closed: True before the handshake completed")
            return 2
        return 0
    for _ in range(4):
        _tick(server)
        _ = client.poll(timeout_ms=20)
    var junk = List[UInt8]()
    junk.append(UInt8(0x41))
    for i in range(len(client.dcid.bytes)):
        junk.append(client.dcid.bytes[i])
    for _ in range(30):
        junk.append(UInt8(0x5A))
    var start = _monotonic_ms()
    var last_junk = start
    var closed = _closed(server, slot)
    while not closed and _monotonic_ms() - start < silent_ms:
        if garbage and _monotonic_ms() - last_junk >= UInt64(300):
            _ = client.sock.send_to(Span[UInt8, _](junk), client.peer)
            last_junk = _monotonic_ms()
        _tick(server)
        closed = _closed(server, slot)
    var waited = _monotonic_ms() - start
    server.close()
    print("  closed:", closed, "after", waited, "ms")
    return 2 if closed else 1


def main() raises:
    print("A: client idle 1000 ms, server 30000 ms, silent")
    var a = _scenario(UInt64(30_000), UInt64(1_000), False, UInt64(5_000))
    print("B: server idle 1000 ms, undecryptable packets every 300 ms")
    var b = _scenario(UInt64(1_000), UInt64(30_000), True, UInt64(5_000))
    print("C: both idle 0 (disabled), silent")
    var c = _scenario(UInt64(0), UInt64(0), False, UInt64(2_000))
    if a == 0 or b == 0 or c == 0:
        print("inconclusive: a handshake stalled (A, B, C):", a, b, c)
        raise Error("QUIC-20 inconclusive")
    var bad = List[String]()
    if a == 1:
        bad.append(String("A: peer's 1000 ms ignored, open after 5 s"))
    if b == 1:
        bad.append(String("B: undecryptable packets kept it open past 5 s"))
    if c == 2:
        bad.append(String("C: idle timeout 0 on both sides, server closed the connection anyway"))
    if len(bad) > 0:
        var msg = String("")
        for i in range(len(bad)):
            if i > 0:
                msg += "; "
            msg += bad[i]
        print("BUG REPRODUCED:", msg)
        raise Error("QUIC-20")
    print("OK: A closed, B closed, C open (RFC 9000 sec 10.1 idle timeout)")
