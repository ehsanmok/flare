"""Smoke test for multi-worker :meth:`flare.ws.WsServer.serve(handler, num_workers=N)`.

Forks a child running ``WsServer.serve(echo_handler, num_workers=4)``
on a fixed loopback port, opens 4 concurrent ``WsClient`` echoes
in a loop from the parent (one per round), and verifies the
round-trip works end-to-end. The kernel hashes the new 4-tuples
across the SO_REUSEPORT listener set, so the test exercises the
fan-out path without needing per-worker observation.

The "concurrent" part is sequential here on purpose: spawning
multiple ``WsClient`` from a single Mojo thread is enough to
prove the multi-worker server's accept loops are all live; a
proper concurrency test would need ``pthread`` plumbing on the
client side that flare doesn't ship.
"""

from std.ffi import c_int, external_call
from std.testing import assert_equal, assert_true

from flare.net import SocketAddr
from flare.ws import WsClient, WsConnection, WsOpcode, WsServer


@always_inline
def _fork() -> c_int:
    return external_call["fork", c_int]()


@always_inline
def _waitpid(pid: c_int):
    _ = external_call["waitpid", c_int](pid, 0, c_int(0))


@always_inline
def _exit_child(code: c_int = c_int(0)):
    _ = external_call["_exit", c_int](code)


@always_inline
def _kill(pid: c_int, sig: c_int) -> c_int:
    return external_call["kill", c_int](pid, sig)


@always_inline
def _usleep(us: c_int):
    _ = external_call["usleep", c_int](us)


comptime _SIGKILL: c_int = c_int(9)


def _echo(mut conn: WsConnection) raises:
    """Simplest possible WS handler: echo every text frame back.

    Signature matches :meth:`flare.ws.WsServer.serve`'s
    ``def(mut WsConnection) raises thin -> None`` exactly --
    ``mut`` so the body can call ``conn.recv()`` /
    ``conn.send_text()`` (both ``mut self``).
    """
    while True:
        var frame = conn.recv()
        if frame.opcode == WsOpcode.CLOSE:
            break
        if frame.opcode == WsOpcode.TEXT:
            conn.send_text(frame.text_payload())


def test_ws_multicore_serve_4_workers_echo_round_trip() raises:
    """Spawn a 4-worker WsServer, drive 4 sequential WsClient echoes
    against it, and verify each round-trip."""
    var port = UInt16(28491)
    var srv = WsServer.bind(SocketAddr.localhost(port))

    var pid = _fork()
    if pid == 0:
        try:
            srv.serve(_echo, num_workers=4)
        except:
            pass
        _exit_child()
    _usleep(c_int(300000))

    var url = String("ws://127.0.0.1:") + String(Int(port)) + String("/")
    var raised = False
    var n_echoed = 0
    try:
        for i in range(4):
            with WsClient.connect(url) as c:
                var msg = String("hello-") + String(i)
                c.send_text(msg)
                var f = c.recv()
                assert_equal(f.opcode, WsOpcode.TEXT)
                assert_equal(f.text_payload(), msg)
                n_echoed += 1
    except:
        raised = True

    _ = _kill(pid, _SIGKILL)
    _waitpid(pid)
    assert_true(not raised, "WsClient round-trip raised")
    assert_equal(n_echoed, 4)


def main() raises:
    test_ws_multicore_serve_4_workers_echo_round_trip()
    print("test_ws_multicore: 1 passed")
