# PLATFORM: any (needs the test certificates under tests/certs)
"""APP-48: a WebSocket handshake on a TLS-terminated HTTP/1.1 connection is
upgraded in cleartext: the 101 and every server frame go out unencrypted on
the TLS socket.

Lean: Flare.L4.ConnExt.Ws.upgradeTaken, Flare.Bugs.APP_48.violates_spec
(counterexample) and Flare.Bugs.APP_48.fixed_meets_spec (fix meets spec).
flare/http/_reactor/conn_handle.mojo:838-875 @59bda50: the
`config.ws.handler` branch of `on_readable` calls `_handle_ws_upgrade`
without checking `self.tls` (the h2c branch just below does check it,
:881). `_handle_ws_upgrade` (:1476-1574) detaches the raw fd, writes the
101 with a plain `TcpStream` and hands the raw fd to a `WsConnection`. A
TLS connection reaches this code because `_migrate_tls`
(flare/http/_unified_reactor_impl.mojo:545-552) promotes an http/1.1 TLS
session to a `ConnHandle` with `attach_tls`.

Documented contract (server.mojo:813-814, conn_handle.mojo:1506-1508):
"Cleartext only: a wss:// connection is terminated by the TLS connection
handler, which has no upgrade seam."

Scenario: `bind_tls` + `ServerConfig.ws = WsUpgrade(handler)`; the WS
handler sends "secret-token" as soon as it gets the connection. A TLS
client sends a valid WebSocket handshake inside its TLS session and peeks
at the raw TCP bytes that come back.

Expected: the handshake is not upgraded on TLS; whatever the server
answers is TLS records (first byte 0x17).
Actual: after the TLS session-ticket records, the raw bytes are the
cleartext "HTTP/1.1 101 Switching Protocols" followed by an unencrypted
WebSocket text frame carrying "secret-token".

Minimal fix: guard the branch like the h2c one,
`if config.ws.handler and not self.tls:` (conn_handle.mojo:857), so a
handshake on TLS falls through to the HTTP handler.
"""

from std.ffi import c_int, c_size_t
from std.memory import stack_allocation

from flare.utils import SIGKILL, exit, fork, kill, usleep, waitpid
from flare.net import IpAddr, SocketAddr
from flare.net._libc import _recv
from flare.tls import TlsConfig, TlsStream
from flare.http import HttpServer, Request, Response, WsUpgrade, ok
from flare.ws.server import WsConnection

comptime _SERVER_CRT: String = "tests/certs/server.crt"
comptime _SERVER_KEY: String = "tests/certs/server.key"
comptime _CA_CRT: String = "tests/certs/ca.crt"
comptime MSG_PEEK = 2


def _hello(req: Request) raises -> Response:
    return ok("hello https")


def _ws(mut ws: WsConnection) raises:
    ws.send_text("secret-token")


def _cleartext(raw: List[UInt8]) -> Int:
    """Offset of a cleartext "HTTP/1.1 101" or "secret-token" in `raw`, or -1.
    """
    var needles = List[String]()
    needles.append("HTTP/1.1 101")
    needles.append("secret-token")
    for ref nd in needles:
        var b = nd.as_bytes()
        var m = len(b)
        for i in range(len(raw) - m + 1):
            var hit = True
            for j in range(m):
                if raw[i + j] != b[j]:
                    hit = False
                    break
            if hit:
                return i
    return -1


def main() raises:
    var alpn = List[String]()
    alpn.append("http/1.1")
    var srv = HttpServer.bind_tls(
        SocketAddr(IpAddr.parse("127.0.0.1"), UInt16(0)),
        _SERVER_CRT,
        _SERVER_KEY,
        alpn=alpn^,
    )
    srv.config.ws = WsUpgrade(_ws, False)
    var port = UInt16(srv.local_addr().port)

    var pid = fork()
    if pid == 0:
        try:
            srv.serve(_hello)
        except:
            pass
        exit()
    usleep(300000)

    var raw = List[UInt8]()
    var plain = String("")
    var err = String("")
    try:
        var cfg = TlsConfig(ca_bundle=_CA_CRT)
        var s = TlsStream.connect("localhost", port, cfg)
        var hs = String(
            "GET /chat HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.write_all(hs.as_bytes())
        s.set_recv_timeout(200)
        # Session-ticket records can arrive before the answer, so keep
        # peeking at the raw socket for up to 2 s.
        var tmp = stack_allocation[4096, UInt8]()
        for _ in range(10):
            usleep(200000)
            var n = _recv(
                s._tcp._socket.fd, tmp, c_size_t(4096), c_int(MSG_PEEK)
            )
            if Int(n) > 0:
                raw.clear()
                for i in range(Int(n)):
                    raw.append(tmp[unsafe_offset=i])
                if _cleartext(raw) >= 0:
                    break
        if _cleartext(raw) < 0:
            # No cleartext: the answer must then decrypt as HTTP.
            var buf = List[UInt8](length=4096, fill=UInt8(0))
            for _ in range(10):
                var got = 0
                try:
                    got = s.read(buf.unsafe_ptr(), len(buf))
                except:
                    pass
                if got > 0:
                    plain = String(
                        unsafe_from_utf8=Span[UInt8, _](buf)[:got]
                    )
                    break
        s.close()
    except e:
        err = String(e)

    _ = kill(pid, SIGKILL)
    waitpid(pid)

    var at = _cleartext(raw)
    if at >= 0:
        var text = String(unsafe_from_utf8=Span[UInt8, _](raw)[at:])
        var shown = text.replace("\r\n", "\\r\\n")
        print(
            "BUG REPRODUCED: raw TCP bytes on the TLS connection contain"
            " cleartext at offset "
            + String(at)
            + " of "
            + String(len(raw))
            + ": "
            + shown
        )
        raise Error("APP-48")
    if plain.startswith("HTTP/1.1"):
        print(
            "OK: no cleartext on the wire ("
            + String(len(raw))
            + " raw bytes, first byte "
            + String(Int(raw[0]) if len(raw) > 0 else -1)
            + "); the answer decrypts to "
            + repr(String(plain[byte=0:15]))
        )
        return
    print(
        "inconclusive: no cleartext and no decrypted answer ("
        + String(len(raw))
        + " raw bytes; "
        + err
        + ")"
    )
    raise Error("APP-48 inconclusive")
