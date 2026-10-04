# PLATFORM: any
"""WS-07: HttpServer's WebSocket upgrade seam accepts a Sec-WebSocket-Key
that is not base64 of 16 bytes and a Connection field whose only token
merely contains "upgrade".

Lean: Flare.Bugs.WS_07.counterexample (reactorUpgrades holds, ServerOK
fails) and Flare.L3.Ws.Handshake.reactorFixed_ok (fix meets spec).
flare/http/_reactor/conn_handle.mojo:1514-1526 (`"upgrade" not in
conn_hdr`; `ws_key.byte_length() == 0` is the only key check) @59bda50.
Method, HTTP version and Sec-WebSocket-Version are checked (1515 and
143-152 -> 426), and are proved right in the Lean model. A WS upgrade on
TLS is APP-48 (not repeated here).

Expected (RFC 6455 §4.2.1 items 4 and 5): the Connection field must
include the token "upgrade" and the key must base64-decode to 16 bytes;
otherwise the request is not an opening handshake.
Actual: "Connection: noupgrade" with "Sec-WebSocket-Key: x" gets
"101 Switching Protocols" and the connection is handed to the ws handler.

Minimal fix: in _handle_ws_upgrade, compare comma-separated, stripped,
lowercased Connection tokens with "upgrade", and require the key to
decode (flare.crypto.base64) to exactly 16 bytes; return False otherwise.
"""

from flare.http import HttpServer, Request, Response, ok
from flare.net import SocketAddr
from flare.tcp import TcpStream
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws import WsConnection, WsOpcode


def _http_handler(req: Request) raises -> Response:
    return ok("plain http")


def _ws_handler(mut conn: WsConnection) raises -> None:
    while True:
        var frame = conn.recv()
        if frame.opcode == WsOpcode.CLOSE:
            break


def _status_line(port: UInt16, req: String) raises -> String:
    var s = TcpStream.connect(SocketAddr.localhost(port))
    s.write_all(req.as_bytes())
    var got = List[UInt8]()
    var tmp = List[UInt8](capacity=1024)
    tmp.resize(1024, 0)
    while True:
        var n = s.read(tmp.unsafe_ptr(), 1024)
        if n == 0:
            break
        for i in range(n):
            got.append(tmp[i])
        var nl = False
        for b in got:
            if b == 10:
                nl = True
        if nl:
            break
    s.close()
    var line = String("")
    for b in got:
        if b == 13 or b == 10:
            break
        line += chr(Int(b))
    return line


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork()
    if pid == 0:
        try:
            srv.serve_ws_upgrade(_http_handler, _ws_handler)
        except:
            pass
        exit()
    usleep(300_000)
    var good: String
    var bad: String
    try:
        good = _status_line(
            port,
            "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection:"
            " Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
        )
        bad = _status_line(
            port,
            "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection:"
            " noupgrade\r\nSec-WebSocket-Key: x\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n",
        )
    except e:
        _ = kill(pid, SIGKILL)
        waitpid(pid)
        print("inconclusive: setup failed: " + String(e))
        raise Error("inconclusive")
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    print("valid handshake:", good)
    print("Connection: noupgrade, key 'x':", bad)
    if not good.startswith("HTTP/1.1 101"):
        print("inconclusive: the valid handshake was not upgraded")
        raise Error("inconclusive")
    if bad.startswith("HTTP/1.1 101"):
        print(
            "BUG REPRODUCED: reactor upgraded a request with Connection:"
            " noupgrade and Sec-WebSocket-Key: x (" + bad + ")"
        )
        raise Error("WS-07")
    print("OK: invalid handshake not upgraded (" + bad + ")")
