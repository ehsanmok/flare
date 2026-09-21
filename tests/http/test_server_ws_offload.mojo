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

A third test covers the other half of what ``ws_offload`` changes: two
offloaded handlers run at the same time. The reactor staying free says
nothing about that, and concurrency is the part of the contract that
changes what handler authors have to do about shared state.
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

comptime _OVERLAP_SPLIT_MS = 4000
"""Two 2500 ms handlers: ~2500 ms overlapped, ~5000 ms serialised. The
split sits between them with 1500 ms of slack either way."""


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
        sa.unsafe_offset(i).unsafe_write(copy=UInt8(0))
    var ip = stack_allocation[4, UInt8]()
    ip.unsafe_offset(0).unsafe_write(copy=UInt8(127))
    ip.unsafe_offset(1).unsafe_write(copy=UInt8(0))
    ip.unsafe_offset(2).unsafe_write(copy=UInt8(0))
    ip.unsafe_offset(3).unsafe_write(copy=UInt8(1))
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
            body += chr(Int(buf[unsafe_offset=i]))
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


def test_two_offloaded_websockets_run_concurrently() raises:
    """Two offloaded handlers overlap rather than queue behind each
    other.

    The other two tests prove the reactor worker is free, which is not
    the same claim: a single shared handler thread would satisfy them
    both and still serialise every WebSocket. Each handler holds for
    2500 ms, so two of them finish in about 2500 ms concurrently and
    about 5000 ms one after the other.

    This is also the assertion behind the docstring's warning that
    handlers which used to be serialised per worker now run at the same
    time, and that shared state is theirs to protect.
    """
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_ws_upgrade(
                _http_handler, _slow_ws_handler, ws_offload=True
            )
        except:
            pass
        exit()
    usleep(300000)

    var url = String("ws://127.0.0.1:") + String(Int(port)) + String("/ws")
    var first = String("")
    var second = String("")
    var elapsed = -1
    try:
        var a = WsClient.connect(url)
        var b = WsClient.connect(url)
        # Both handlers are sitting in recv(); start their holds back to
        # back so the two sleeps overlap if anything lets them.
        var started = _monotonic_ms()
        a.send_text("hold")
        b.send_text("hold")
        var ra = a.recv()
        var rb = b.recv()
        elapsed = _monotonic_ms() - started
        if ra.opcode == WsOpcode.TEXT:
            first = ra.text_payload()
        if rb.opcode == WsOpcode.TEXT:
            second = rb.text_payload()
        a.close()
        b.close()
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_equal(first, "echo: hold")
    assert_equal(second, "echo: hold")
    assert_true(
        elapsed >= 0 and elapsed < _OVERLAP_SPLIT_MS,
        String("two offloaded handlers should overlap; took ")
        + String(elapsed)
        + "ms",
    )


def main() raises:
    test_offloaded_websocket_does_not_block_http()
    test_inline_websocket_blocks_http_on_one_worker()
    test_two_offloaded_websockets_run_concurrently()
    print("test_server_ws_offload: 3 passed")
