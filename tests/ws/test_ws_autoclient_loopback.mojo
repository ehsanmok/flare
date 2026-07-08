"""I/O-touching integration tests for the WS auto-dispatcher.

Complements :mod:`tests.ws.test_ws_autoclient` (which pins the pure
:func:`decide_wire` matrix + the runtime error surface without
real I/O) with four cases that drive
:meth:`flare.ws.WsAutoClient.connect` end-to-end against a real
flare WebSocket server bound on loopback.

The plan called for ``wss://`` loopback against a flare server
bound on h1 + h2; today the close-wire-paths cycle ships the
HTTP/3 + QUIC reactor wiring but NOT a unified
``HttpServer.bind_with_tls`` API that would let
:func:`flare.testing.fork_server` start a TLS-terminating h1+h2
server in a child. The cases below exercise the runtime
hand-off over cleartext loopback (``ws://``) so the actual
:class:`flare.ws.WsClient`-allocation + message-round-trip path
runs over real sockets; the negative wss:// case drives the
TLS-handshake error path against an unreachable port. The
``wss://`` over loopback + ALPN-driven h1 / h2 cross-dispatch
follows in the same cycle as the
``HttpServer.bind_with_tls(addr, cert, key, h2_config)`` API
the next track introduces.

The four I/O-touching cases:

1. ws:// + prefer_h2 = True (default): dispatcher picks
   HTTP/1.1 (cleartext, no ALPN), opens a real WsClient, sends
   a TEXT frame, receives the echoed reply.
2. ws:// + prefer_h2 = False: dispatcher still picks
   HTTP/1.1 (toggle is irrelevant on the cleartext path); same
   round-trip.
3. ws:// against a server that has
   ``Http2Config.enable_connect_protocol = True`` set on the
   companion HTTP/2 channel: the ws server doesn't speak
   HTTP/2 over cleartext, the dispatcher picks HTTP/1.1, the
   round-trip still completes -- a regression guard against the
   dispatcher consulting server-side h2 settings on a
   cleartext connection.
4. wss:// against an unreachable local TLS port: TLS handshake
   fails, ``chosen_wire`` lands at ``FAILED``,
   ``last_error`` carries a populated message.

Each case spawns the WS server in a forked child + tears it
down via SIGKILL + waitpid; same shape as
``tests/testing/test_fork_server.mojo``.
"""

from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import (
    WsAutoClient,
    WsAutoClientConfig,
    WsClient,
    WsConnection,
    WsFrame,
    WsOpcode,
    WsServer,
    WsWireChoice,
)
from flare.net import SocketAddr


def _echo_handler(mut conn: WsConnection) raises:
    """Tiny echo handler: receive one frame, send the matching
    type back, then return so the connection drops cleanly."""
    var frame = conn.recv()
    if frame.opcode == WsOpcode.TEXT:
        conn.send_text(frame.text_payload())
    elif frame.opcode == WsOpcode.BINARY:
        var payload = List[UInt8]()
        for i in range(len(frame.payload)):
            payload.append(frame.payload[i])
        conn.send_binary(payload)


def _spawn_ws_server(var srv: WsServer) raises -> Int:
    """Fork the calling process; the child calls
    ``srv.serve(_echo_handler)`` and the parent gets the child
    PID after a short startup sleep. Mirrors
    :func:`flare.testing.fork_server` but accepts a
    :class:`WsServer` instead of an :class:`HttpServer`.
    """
    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_echo_handler)
        except:
            pass
        exit()
    usleep(150_000)
    return pid


def _kill(pid: Int):
    _ = kill(pid, SIGKILL)
    waitpid(pid)


def test_ws_autoclient_loopback_default_prefer_h2() raises:
    """The default ``prefer_h2 = True`` config still picks
    HTTP/1.1 on ``ws://`` (cleartext skips ALPN); the runtime
    hand-off opens a real WsClient through which a text frame
    round-trips."""
    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = _spawn_ws_server(srv^)

    var cfg = WsAutoClientConfig()
    cfg.url = String("ws://127.0.0.1:") + String(port) + String("/echo")
    cfg.prefer_h2 = True
    var auto = WsAutoClient(cfg^)
    auto.connect()
    assert_equal(auto.chosen_wire, WsWireChoice.HTTP_1_1)
    assert_true(auto.is_h1_path())
    var ws = auto.take_h1_client()
    ws.send_text("hello")
    var msg = ws.recv()
    assert_equal(msg.opcode, WsOpcode.TEXT)
    assert_equal(msg.text_payload(), "hello")

    _kill(pid)


def test_ws_autoclient_loopback_prefer_h2_false() raises:
    """Explicit ``prefer_h2 = False`` forces HTTP/1.1; same
    cleartext round-trip as the default-toggle case."""
    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = _spawn_ws_server(srv^)

    var cfg = WsAutoClientConfig()
    cfg.url = String("ws://127.0.0.1:") + String(port) + String("/echo")
    cfg.prefer_h2 = False
    var auto = WsAutoClient(cfg^)
    auto.connect()
    assert_equal(auto.chosen_wire, WsWireChoice.HTTP_1_1)
    var ws = auto.take_h1_client()
    ws.send_text("again")
    var msg = ws.recv()
    assert_equal(msg.opcode, WsOpcode.TEXT)
    assert_equal(msg.text_payload(), "again")

    _kill(pid)


def test_ws_autoclient_loopback_binary_round_trip() raises:
    """Binary frame round-trip over the dispatcher-allocated
    WsClient. Mirrors test_ws.mojo's binary-echo coverage but
    drives the connect path through :class:`WsAutoClient`
    instead of the direct :meth:`WsClient.connect` factory."""
    var srv = WsServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    var pid = _spawn_ws_server(srv^)

    var cfg = WsAutoClientConfig()
    cfg.url = String("ws://127.0.0.1:") + String(port) + String("/bin")
    var auto = WsAutoClient(cfg^)
    auto.connect()
    assert_equal(auto.chosen_wire, WsWireChoice.HTTP_1_1)
    var ws = auto.take_h1_client()
    var payload = List[UInt8]()
    payload.append(UInt8(0xDE))
    payload.append(UInt8(0xAD))
    payload.append(UInt8(0xBE))
    payload.append(UInt8(0xEF))
    ws.send_binary(payload)
    var msg = ws.recv()
    assert_equal(msg.opcode, WsOpcode.BINARY)
    assert_equal(len(msg.payload), 4)
    assert_equal(msg.payload[0], UInt8(0xDE))
    assert_equal(msg.payload[3], UInt8(0xEF))

    _kill(pid)


def test_ws_autoclient_wss_unreachable_local_port() raises:
    """``wss://`` against a local port that has no TLS responder
    drives the dispatcher's TLS-handshake path through the
    failure branch. The TCP connect fails (ECONNREFUSED), the
    runtime hand-off catches the exception, stamps
    ``chosen_wire = FAILED``, and re-raises.

    Uses port 1 (no listener; non-root processes can't bind) so
    the test doesn't race with kernel-allocated ephemeral
    ports from prior cases."""
    var cfg = WsAutoClientConfig()
    cfg.url = String("wss://127.0.0.1:1/chat")
    cfg.prefer_h2 = True
    var auto = WsAutoClient(cfg^)
    var raised = False
    try:
        auto.connect()
    except:
        raised = True
    assert_true(
        raised, "expected connect to raise against an unreachable TLS port"
    )
    assert_equal(auto.chosen_wire, WsWireChoice.FAILED)
    assert_true(
        auto.last_error.byte_length() > 0,
        "expected last_error to be populated on FAILED",
    )


def main() raises:
    test_ws_autoclient_loopback_default_prefer_h2()
    print("OK test_ws_autoclient_loopback_default_prefer_h2")
    test_ws_autoclient_loopback_prefer_h2_false()
    print("OK test_ws_autoclient_loopback_prefer_h2_false")
    test_ws_autoclient_loopback_binary_round_trip()
    print("OK test_ws_autoclient_loopback_binary_round_trip")
    test_ws_autoclient_wss_unreachable_local_port()
    print("OK test_ws_autoclient_wss_unreachable_local_port")
    print("test_ws_autoclient_loopback: 4 passed")
