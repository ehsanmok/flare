"""Example — HTTP routes + a WebSocket endpoint on ONE port.

Before this seam, an app needed two flare servers (``HttpServer`` for
routes, ``WsServer`` for WebSocket) on two ports. Now a single
``HttpServer`` answers ordinary HTTP requests AND upgrades qualifying
RFC 6455 requests to WebSocket on the SAME listener:

    def http_handler(req: Request) raises -> Response:
        return ok("hello " + req.url)

    def ws_handler(mut conn: WsConnection) raises -> None:
        while True:
            var frame = conn.recv()
            if frame.opcode == WsOpcode.CLOSE:
                break
            conn.send_text("echo: " + frame.text_payload())

    var srv = HttpServer.bind(SocketAddr.localhost(8080))
    srv.serve_ws_upgrade(http_handler, ws_handler)  # one port, both protocols

This example forks a child running exactly that, then drives both a
plain HTTP GET and a WebSocket echo from the parent over the same port,
and exits cleanly.

Run:
    pixi run example-http-ws-one-port
"""

from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

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


def http_handler(req: Request) raises -> Response:
    return ok("hello from HTTP route " + req.url)


def ws_handler(mut conn: WsConnection) raises -> None:
    while True:
        var frame = conn.recv()
        if frame.opcode == WsOpcode.CLOSE:
            break
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


def main() raises:
    print("=== flare: HTTP + WebSocket on one port ===")
    print()

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    print("── Bound HttpServer on 127.0.0.1:" + String(Int(port)) + " ──")

    var pid = fork()
    if pid == 0:
        try:
            # ONE server, ONE port, BOTH the unary HTTP handler and the
            # opt-in WebSocket upgrade handler.
            srv.serve_ws_upgrade(http_handler, ws_handler)
        except:
            pass
        exit()
    usleep(300000)

    # ── Plain HTTP GET on the shared port. ────────────────────────────────────
    print()
    print("── HTTP GET /hello on the same port ──")
    var http_body = String("")
    var fd = _connect_loopback(port)
    var req = String(
        "GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    var rb = req.as_bytes()
    _ = _send(
        fd, rb.unsafe_ptr(), c_size_t(req.byte_length()), c_int(MSG_NOSIGNAL)
    )
    var buf = stack_allocation[4096, UInt8]()
    var attempts = 0
    while attempts < 20 and "hello from" not in http_body:
        attempts += 1
        var n = _recv(fd, buf, c_size_t(4096), c_int(0))
        if Int(n) <= 0:
            break
        for i in range(Int(n)):
            http_body += chr(Int(buf[i]))
    _ = _close(fd)
    if "hello from" in http_body:
        print("   HTTP response body contained: 'hello from HTTP route /hello'")
    else:
        print("   HTTP response missing expected body!")

    # ── WebSocket upgrade + echo on the SAME port. ────────────────────────────
    print()
    print("── WebSocket upgrade GET /ws on the same port ──")
    var ws = WsClient.connect("ws://127.0.0.1:" + String(Int(port)) + "/ws")
    print("   handshake OK (101 Switching Protocols)")
    ws.send_text("hi over websocket")
    var reply = ws.recv()
    if reply.opcode == WsOpcode.TEXT:
        print("   WS echo: " + reply.text_payload())
    ws.close()

    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print()
    print("=== done: one HttpServer served HTTP + WebSocket on one port ===")
