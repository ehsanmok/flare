"""``ServerConfig.ws_offload``: keep the reactor free during a WebSocket.

A WebSocket handler owns its connection for as long as that connection
lives. Run inline, it owns the reactor worker too -- so on a
single-worker server one slow WebSocket stalls every other connection
pinned to that worker, ordinary HTTP requests included.

These two tests are a differential: the same server, the same
deliberately slow WebSocket handler, and the same plain HTTP GET issued
while that handler is still running. Inline, the GET waits for the
WebSocket to finish. Offloaded, it comes back immediately.

The thresholds are far apart on purpose (the handler sleeps 2500 ms, the
split is at 1200 ms) so neither direction turns into a timing flake on a
loaded machine.
"""

from std.ffi import c_int, c_size_t
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpServer, Request, Response, ok
from flare.http.client_pool import _monotonic_ms
from flare.net import SocketAddr
from flare.net._libc import (
    AF_INET,
    MSG_NOSIGNAL,
    SOCK_STREAM,
    _close,
    _connect,
    _fill_sockaddr_in,
    _recv,
    _send,
    _socket,
    _strerror,
    get_errno,
)
from flare.ws import WsClient, WsConnection, WsOpcode


comptime _WS_HOLD_MS = 2500
"""How long the WebSocket handler occupies its connection."""

comptime _SPLIT_MS = 1200
"""Below this the HTTP GET overtook the WebSocket; above it, it waited."""


def _http_handler(req: Request) raises -> Response:
    return ok("hello http")


def _slow_ws_handler(mut conn: WsConnection) raises -> None:
    """Hold the connection long enough to be unmistakable, then echo."""
    var frame = conn.recv()
    usleep(_WS_HOLD_MS * 1000)
    if frame.opcode == WsOpcode.TEXT:
        conn.send_text("echo: " + frame.text_payload())


def _connect_loopback(port: UInt16) raises -> c_int:
    var c = _socket(AF_INET, SOCK_STREAM, c_int(0))
    if c < c_int(0):
        raise Error("socket() failed: " + _strerror(get_errno().value))
    var sa = stack_allocation[16, UInt8]()
    for i in range(16):
        (sa + i).init_pointee_copy(UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    (ip + 0).init_pointee_copy(UInt8(127))
    (ip + 1).init_pointee_copy(UInt8(0))
    (ip + 2).init_pointee_copy(UInt8(0))
    (ip + 3).init_pointee_copy(UInt8(1))
    _fill_sockaddr_in(sa, port, ip)
    if _connect(c, sa, c_int(16).cast[DType.uint32]()) < c_int(0):
        var msg = _strerror(get_errno().value)
        _ = _close(c)
        raise Error("connect 127.0.0.1 failed: " + msg)
    return c


def _timed_http_get(port: UInt16, mut body: String) raises -> Int:
    """Issue ``GET /`` and return how many ms the round-trip took."""
    var fd = _connect_loopback(port)
    var req = String(
        "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    var rb = req.as_bytes()
    var started = _monotonic_ms()
    _ = _send(
        fd, rb.unsafe_ptr(), c_size_t(req.byte_length()), c_int(MSG_NOSIGNAL)
    )
    var buf = stack_allocation[4096, UInt8]()
    var attempts = 0
    while attempts < 20 and "hello http" not in body:
        attempts += 1
        var n = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(n) <= 0:
            break
        for i in range(Int(n)):
            body += chr(Int(buf[i]))
    var elapsed = _monotonic_ms() - started
    _ = _close(fd)
    return elapsed


def _measure(
    ws_offload: Bool, mut body: String, mut ws_echo: String
) raises -> Int:
    """Start a one-worker server, open a slow WebSocket on it, and time a
    plain HTTP GET issued while that WebSocket is still being handled."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_ws_upgrade(
                _http_handler, _slow_ws_handler, ws_offload=ws_offload
            )
        except:
            pass
        exit()
    usleep(300000)

    var elapsed = -1
    try:
        var ws = WsClient.connect("ws://127.0.0.1:" + String(Int(port)) + "/ws")
        ws.send_text("hold")
        # The handler is now inside its sleep. Race an HTTP GET against it.
        usleep(200000)
        elapsed = _timed_http_get(port, body)
        var reply = ws.recv()
        if reply.opcode == WsOpcode.TEXT:
            ws_echo = reply.text_payload()
        ws.close()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return elapsed


def test_offloaded_websocket_does_not_block_http() raises:
    """With ``ws_offload``, the GET overtakes the busy WebSocket."""
    var body = String("")
    var ws_echo = String("")
    var elapsed = _measure(True, body, ws_echo)

    assert_true(
        "hello http" in body,
        "HTTP GET did not complete during the WebSocket; got: " + body,
    )
    assert_true(
        elapsed >= 0 and elapsed < _SPLIT_MS,
        String("offloaded GET should not wait for the WebSocket; took ")
        + String(elapsed)
        + "ms",
    )
    # The WebSocket still ran to completion on its own thread.
    assert_equal(ws_echo, "echo: hold")


def test_inline_websocket_blocks_http_on_one_worker() raises:
    """Without it, the same GET waits for the WebSocket -- the behaviour
    ``ws_offload`` exists to fix, pinned here so it cannot regress into
    looking like the fixed case."""
    var body = String("")
    var ws_echo = String("")
    var elapsed = _measure(False, body, ws_echo)

    assert_true(
        "hello http" in body,
        "HTTP GET never completed at all; got: " + body,
    )
    assert_true(
        elapsed >= _SPLIT_MS,
        String("inline GET was expected to wait for the WebSocket; took ")
        + String(elapsed)
        + "ms",
    )
    assert_equal(ws_echo, "echo: hold")


def main() raises:
    test_offloaded_websocket_does_not_block_http()
    test_inline_websocket_blocks_http_on_one_worker()
    print("test_server_ws_offload: 2 passed")
