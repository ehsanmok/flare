# PLATFORM: any (loopback TCP in-process; no external network)
"""DOC-02: `WsConnection` refuses an unmasked client frame by raising, but
never sends the CLOSE 1002 the threat model promises.

Lean: Flare.Bugs.DOC_02.counterexample (counterexample) and
Flare.Bugs.DOC_02.fixed (fix meets spec).
flare/ws/server.mojo:558-562 @59bda50: `_recv_one` raises
WsProtocolError("client sent unmasked frame") and writes nothing; the
only close frame `_recv_one` ever sends is 1009 (server.mojo:587-598).
`WsCloseCode.PROTOCOL_ERROR` (frame.mojo:56) is never sent.

Doc claim: docs/threat-model.md:60 "`WsConnection.recv` enforces the RFC
6455 sec 5.1 client-side mask requirement; unmasked frames are rejected
with 1002."
RFC 6455 sec 5.1: "The server MUST close the connection upon receiving a
frame that is not masked. In this case, a server MAY send a Close frame
with a status code of 1002 (protocol error)". The rejection itself is
proved (Flare.L3.Ws.server_safe); the 1002 is what is missing.

Setup: a loopback pair; the server side is a WsConnection whose prebuf
holds one unmasked TEXT frame "hi". Expected: recv raises and the client
receives CLOSE 1002 (wire 88 02 03 EA). Actual: recv raises and the client
receives nothing before the socket closes.

Minimal fix: before the raise at server.mojo:560, write
WsFrame.close(WsCloseCode.PROTOCOL_ERROR) unmasked (best effort, as the
1009 path does).
"""

from flare.ws import WsConnection, WsFrame
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr


def _serve(var s: TcpStream, var prebuf: List[UInt8]) -> Bool:
    """True when recv raised. The socket closes on return."""
    var conn = WsConnection(s^, SocketAddr.localhost(0), prebuf^)
    try:
        _ = conn.recv()
        return False
    except:
        return True


def main() raises:
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = ln.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(2000)
    var s = ln.accept()
    var wire = WsFrame.text("hi").encode(mask=False)
    var raised = _serve(s^, wire^)
    var got = List[UInt8]()
    var tmp = List[UInt8](length=256, fill=0)
    try:
        while True:
            var n = c.read(tmp.unsafe_ptr(), len(tmp))
            if n <= 0:
                break
            for i in range(n):
                got.append(tmp[i])
    except:
        pass
    c.close()
    ln.close()
    if not raised:
        print("inconclusive: the unmasked frame was not refused at all")
        raise Error("setup")
    if (
        len(got) >= 4
        and got[0] == 0x88
        and got[1] == 0x02
        and got[2] == 0x03
        and got[3] == 0xEA
    ):
        print("OK: unmasked client frame refused with CLOSE 1002")
        return
    print(
        "BUG REPRODUCED: unmasked client frame was refused (recv raised) but",
        "the client received",
        len(got),
        "bytes and no CLOSE 1002 (expected 88 02 03 EA)",
    )
    raise Error("DOC-02")
