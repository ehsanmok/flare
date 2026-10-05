# PLATFORM: any
# RESOLVED: WS-05 fixed on fix/formal-findings
"""WS-05: the standalone WsServer accepts opening handshakes RFC 6455 says
it must refuse: any method and version, any Sec-WebSocket-Version (or
none), a key that is not base64 of 16 bytes, and "upgrade" as a substring
of another Connection token.

Lean: Flare.Bugs.WS_05.counterexample (srvAccepts holds, ServerOK fails)
and Flare.L3.Ws.Handshake.srvFixed_ok (fix meets spec);
Flare.L3.Ws.Handshake.handshake_complete shows flare's own client request
passes the fixed check.
flare/ws/server.mojo:188-261 (_parse_ws_upgrade_bytes) and 264-321
(_read_upgrade_request, the same logic, used by WsServer.serve at 794,
825 and _handle_ws_connection) @59bda50.

Expected (RFC 6455 §4.2.1, §4.2.2, §4.4): a GET over HTTP/1.1 or later,
Upgrade "websocket", a Connection token "upgrade", a Sec-WebSocket-Key
that base64-decodes to 16 bytes, and Sec-WebSocket-Version 13; otherwise
400 (426 with Sec-WebSocket-Version: 13 for a version mismatch).
Before the fix: Actual: "POST / HTTP/1.0" with "Connection: noupgrade",
"Sec-WebSocket-Key: x" and "Sec-WebSocket-Version: 8" is accepted.

Minimal fix: check the request line (GET, HTTP/1.1) instead of skipping
it; split Connection on commas and compare stripped lowercase tokens;
require the key to base64-decode to 16 bytes and the version to be "13".
"""

from flare.ws.server import _parse_ws_upgrade_bytes


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _verdict(req: String) -> String:
    try:
        var r = _parse_ws_upgrade_bytes(Span[UInt8, _](_bytes(req)))
        return "accepted key=" + r.key
    except e:
        return "raised: " + String(e)


def main() raises:
    var good = _verdict(
        "GET /chat HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection:"
        " Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    )
    print("RFC example request:", good)
    if not good.startswith("accepted"):
        print("inconclusive: the RFC 6455 example request was refused")
        raise Error("inconclusive")
    var bad = _verdict(
        "POST /chat HTTP/1.0\r\nHost: a\r\nUpgrade: websocket\r\nConnection:"
        " noupgrade\r\nSec-WebSocket-Key: x\r\nSec-WebSocket-Version: 8\r\n\r\n"
    )
    print("POST, HTTP/1.0, noupgrade, key x, version 8:", bad)
    if bad.startswith("accepted"):
        print(
            "BUG REPRODUCED: WsServer handshake accepted POST/HTTP/1.0 with"
            " Connection: noupgrade, key 'x' and version 8 (" + bad + ")"
        )
        raise Error("WS-05")
    print("OK: invalid opening handshake refused (" + bad + ")")
