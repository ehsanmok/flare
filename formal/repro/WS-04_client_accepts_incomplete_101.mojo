# PLATFORM: any
"""WS-04: WsClient accepts a 101 response that lacks Upgrade/Connection and
selects a subprotocol it never offered.

Lean: Flare.Bugs.WS_04.counterexample (clientAccepts holds, ClientOK
fails) and Flare.L3.Ws.Handshake.clientFixed_ok (fix meets spec);
Flare.L3.Ws.Handshake.handshake_complete shows flare's own server response
passes the fixed check.
flare/ws/client.mojo:557-604 and 609-645 (_connect_impl: only the
status-line prefix "HTTP/1.1 101" and Sec-WebSocket-Accept are checked)
@59bda50.

Expected (RFC 6455 §4.1, client requirements 1-6): the client MUST fail
the connection if the response lacks "Upgrade: websocket", lacks a
Connection field with the "upgrade" token, has a Sec-WebSocket-Accept
other than the expected one, or names an extension or subprotocol the
client did not request (flare requests none).
Actual: a 101 carrying only Sec-WebSocket-Accept plus
"Sec-WebSocket-Protocol: chat" is accepted and WsClient.connect returns.

Minimal fix: in both branches of _connect_impl, also record Upgrade,
Connection, Sec-WebSocket-Extensions and Sec-WebSocket-Protocol; raise
WsHandshakeError unless Upgrade is "websocket" (case-insensitive),
Connection holds the token "upgrade", and the other two are absent.
"""

from flare.net import SocketAddr
from flare.tcp import TcpListener
from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.ws.client import WsClient
from flare.ws.server import _compute_accept_srv


def _serve_101(var lis: TcpListener, full: Bool):
    """Child: read the upgrade request, answer 101 with the right accept;
    ``full`` adds the Upgrade and Connection fields and no subprotocol."""
    try:
        var s = lis.accept()
        var got = List[UInt8]()
        var tmp = List[UInt8](capacity=4096)
        tmp.resize(4096, 0)
        while True:
            var n = s.read(tmp.unsafe_ptr(), 4096)
            if n == 0:
                break
            for i in range(n):
                got.append(tmp[i])
            var done = False
            for i in range(3, len(got)):
                if got[i - 3] == 13 and got[i - 2] == 10 and got[i - 1] == 13 and got[i] == 10:
                    done = True
            if done:
                break
        var req = String(unsafe_from_utf8=Span[UInt8, _](got))
        var key = String("")
        for line in req.split("\r\n"):
            var l = String(line)
            if l.lower().startswith("sec-websocket-key:"):
                key = String(String(l[byte=18:]).strip())
        var accept = _compute_accept_srv(key)
        var resp = String("HTTP/1.1 101 Switching Protocols\r\n")
        if full:
            resp += "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        else:
            resp += "Sec-WebSocket-Protocol: chat\r\n"
        resp += "Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
        s.write_all(resp.as_bytes())
        usleep(2_000_000)
        _ = s^
    except:
        pass
    exit()


def _try(full: Bool) raises -> String:
    var lis = TcpListener.bind(SocketAddr.localhost(0))
    var port = lis.local_addr().port
    var pid = fork()
    if pid == 0:
        _serve_101(lis^, full)
    usleep(100_000)
    var out: String
    try:
        var c = WsClient.connect("ws://127.0.0.1:" + String(Int(port)) + "/")
        out = "connected"
        _ = c^
    except e:
        out = "raised: " + String(e)
    _ = kill(pid, SIGKILL)
    waitpid(pid)
    return out


def main() raises:
    var control = _try(True)
    print("complete 101:", control)
    if control != "connected":
        print("inconclusive: a complete 101 was refused: " + control)
        raise Error("inconclusive")
    var bad = _try(False)
    print("101 without Upgrade/Connection, unrequested subprotocol:", bad)
    if bad == "connected":
        print(
            "BUG REPRODUCED: WsClient accepted a 101 with no Upgrade or"
            " Connection field and an unrequested Sec-WebSocket-Protocol"
        )
        raise Error("WS-04")
    print("OK: incomplete 101 refused (" + bad + ")")
