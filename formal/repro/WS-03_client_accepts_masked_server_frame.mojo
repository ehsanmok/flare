# PLATFORM: any (loopback TCP in-process; no external network)
"""WS-03: WsClient accepts a masked frame from the server.

Lean: Flare.Bugs.WS_03.counterexample (counterexample) and
Flare.Bugs.WS_03.fixed_client_safe (fix meets spec).
flare/ws/client.mojo:717-763 @59bda50 (`_recv_one` has no masked check;
the server side has one at flare/ws/server.mojo:558-562).

Spec: RFC 6455 sec 5.1: "A server MUST NOT mask any frames that it sends to
the client. A client MUST close a connection if it detects a masked frame."

Expected: WsClient.recv() raises WsProtocolError on a masked server frame.
Actual: the frame is unmasked and returned as a normal TEXT frame.

Minimal fix: in WsClient._recv_one, after decode_one succeeds, raise
WsProtocolError if result.frame.masked.
"""

from flare.ws import WsFrame
from flare.ws.client import WsClient, _WsStream
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr


def main() raises:
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = ln.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(3000)
    var s = ln.accept()
    var key = SIMD[DType.uint8, 4](0x11, 0x22, 0x33, 0x44)
    var wire = WsFrame.text("hi").encode_with_key(True, key)
    s.write_all(Span[UInt8, _](wire))
    var ws = WsClient(_WsStream(c^), "k")
    var got = String("")
    var accepted = False
    try:
        var f = ws.recv()
        got = f.text_payload()
        accepted = True
    except:
        pass
    s.close()
    ln.close()
    if accepted:
        print(
            "BUG REPRODUCED: client accepted a masked server frame (payload '"
            + got + "')"
        )
        raise Error("WS-03")
    print("OK: client rejects a masked server frame")
