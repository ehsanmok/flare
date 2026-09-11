"""Single-port HTTP + WebSocket upgrade test.

Proves the additive WebSocket seam in :class:`flare.http.server.HttpServer`:
ONE server on ONE port answers an ordinary HTTP ``GET /`` with a unary
``Response`` AND upgrades ``GET /ws`` to a WebSocket, echoing a frame —
both on the same listener. This is the capability flare lacked before
(``HttpServer`` had no upgrade path; ``WsServer`` assumed EVERY conn was
a WS upgrade), so an app can now serve normal routes + a WS endpoint
without a second port.

Topology mirrors tests/http/test_unified_http_server.mojo: fork a child
running ``HttpServer.serve_ws_upgrade(http_handler, ws_handler)``, drive both an
HTTP/1.1 client and a ``flare.ws.WsClient`` from the parent over the
same port, SIGKILL on test-end.
"""

from std.ffi import c_int, c_size_t
from std.memory import stack_allocation
from std.testing import assert_equal, assert_true

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid

from flare.http import HttpServer, Request, Response, ok
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


# ── HTTP handler: ordinary unary route ───────────────────────────────────────


def _http_handler(req: Request) raises -> Response:
    if req.url == "/health":
        return ok("ok-health")
    return ok("hello http on " + req.url)


# ── WS handler: echo one frame, prefixed ─────────────────────────────────────


def _ws_handler(mut conn: WsConnection) raises -> None:
    while True:
        var frame = conn.recv()
        if frame.opcode == WsOpcode.CLOSE:
            break
        if frame.opcode == WsOpcode.TEXT:
            conn.send_text("echo: " + frame.text_payload())
        else:
            conn.send_binary(frame.payload)


# ── Raw loopback connect helper (same as unified-server test) ─────────────────


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


def test_http_and_ws_on_one_port() raises:
    """One HttpServer, one port: plain HTTP GET works AND a WebSocket
    upgrade on the SAME port echoes a frame."""
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve_ws_upgrade(_http_handler, _ws_handler)
        except:
            pass
        exit()
    usleep(300000)

    # ── 1. Plain HTTP/1.1 GET /health on the shared port. ─────────────────────
    var http_body = String("")
    var http_raised = False
    try:
        var fd = _connect_loopback(port)
        var req = String(
            "GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection:"
            " close\r\n\r\n"
        )
        var rb = req.as_bytes()
        _ = _send(
            fd,
            rb.unsafe_ptr(),
            c_size_t(req.byte_length()),
            c_int(MSG_NOSIGNAL),
        )
        var buf = stack_allocation[4096, UInt8]()
        var attempts = 0
        while attempts < 20 and "ok-health" not in http_body:
            attempts += 1
            var n = _recv(fd, buf, c_size_t(4096), c_int(0))
            if Int(n) <= 0:
                break
            for i in range(Int(n)):
                http_body += chr(Int(buf[i]))
        _ = _close(fd)
    except:
        http_raised = True

    # ── 2. WebSocket upgrade on the SAME port + echo round-trip. ──────────────
    var ws_echo = String("")
    var ws_raised = False
    try:
        var ws = WsClient.connect("ws://127.0.0.1:" + String(Int(port)) + "/ws")
        ws.send_text("from-client")
        var reply = ws.recv()
        if reply.opcode == WsOpcode.TEXT:
            ws_echo = reply.text_payload()
        ws.close()
    except:
        ws_raised = True

    # ── 3. After the WS session, the SAME port still answers HTTP. ────────────
    var http_body2 = String("")
    try:
        var fd2 = _connect_loopback(port)
        var req2 = String(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        var rb2 = req2.as_bytes()
        _ = _send(
            fd2,
            rb2.unsafe_ptr(),
            c_size_t(req2.byte_length()),
            c_int(MSG_NOSIGNAL),
        )
        var buf2 = stack_allocation[4096, UInt8]()
        var attempts2 = 0
        while attempts2 < 20 and "hello http" not in http_body2:
            attempts2 += 1
            var n2 = _recv(fd2, buf2, c_size_t(4096), c_int(0))
            if Int(n2) <= 0:
                break
            for i in range(Int(n2)):
                http_body2 += chr(Int(buf2[i]))
        _ = _close(fd2)
    except:
        pass

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(not http_raised, "plain HTTP round-trip raised")
    assert_true(
        "ok-health" in http_body,
        "HTTP /health response missing body; got: " + http_body,
    )
    assert_true(not ws_raised, "WebSocket round-trip raised")
    assert_equal(ws_echo, "echo: from-client")
    assert_true(
        "hello http" in http_body2,
        "HTTP still works after WS session; got: " + http_body2,
    )


def test_upgrade_request_is_ordinary_traffic_without_a_ws_handler() raises:
    """The seam is opt-in: a server started with plain ``serve`` must
    answer a WebSocket handshake as an ordinary request.

    Without this, adding the seam would silently change what an
    existing server does with an upgrade request it never asked to
    handle.
    """
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_http_handler)
        except:
            pass
        exit()
    usleep(300000)

    var body = String("")
    var raised = False
    try:
        var fd = _connect_loopback(port)
        var req = String(
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade:"
            " websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key:"
            " dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version:"
            " 13\r\nConnection: close\r\n\r\n"
        )
        var rb = req.as_bytes()
        _ = _send(
            fd,
            rb.unsafe_ptr(),
            c_size_t(req.byte_length()),
            c_int(MSG_NOSIGNAL),
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
        _ = _close(fd)
    except:
        raised = True

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    assert_true(not raised, "upgrade request round-trip raised")
    assert_true(
        "101" not in body,
        "server switched protocols without a ws_handler; got: " + body,
    )
    assert_true(
        "hello http" in body,
        "upgrade request did not reach the HTTP handler; got: " + body,
    )


def main() raises:
    test_http_and_ws_on_one_port()
    test_upgrade_request_is_ordinary_traffic_without_a_ws_handler()
    print("test_server_ws_upgrade: 2 passed")
