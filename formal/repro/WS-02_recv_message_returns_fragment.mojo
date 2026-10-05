# PLATFORM: any (loopback TCP in-process; no external network)
# RESOLVED: WS-02 fixed on fix/formal-findings
"""WS-02: WsClient.recv_message returns one fragment, not the message.

Lean: Flare.Bugs.WS_02.counterexample_fragment,
Flare.Bugs.WS_02.counterexample_pong (counterexamples about the pre-fix
recvMessageOld) and
Flare.Bugs.WS_02.fixed_meets_spec (fix meets spec).
flare/ws/client.mojo:765-794 @59bda50 ("TEXT or anything else: return as
text").

Spec: RFC 6455 sec 5.4: a message is a TEXT or BINARY frame with FIN clear
followed by CONTINUATION frames up to one with FIN set (control frames may
be interleaved), and its payload is the concatenation. Sec 5.5.3 allows an
unsolicited PONG, which is not a message. recv_message is documented as
"Receive the next complete message".

Expected: TEXT(fin=0,"hel") + CONTINUATION(fin=1,"lo") gives one message
"hello"; PONG("x") + TEXT("a") gives "a".
Before the fix: Actual: the first call returns "hel" and the second returns "lo", and a
PONG payload is returned as a text message.

Minimal fix: in recv_message, skip PONG, require TEXT/BINARY to start a
message, then append CONTINUATION payloads until FIN (raising on any other
data opcode), and validate UTF-8 over the whole text message.
"""

from flare.ws import WsFrame, WsOpcode
from flare.ws.client import WsClient, _WsStream
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def main() raises:
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = ln.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(3000)
    var s = ln.accept()
    var wire = WsFrame(
        opcode=WsOpcode.TEXT, payload=_bytes("hel"), fin=False
    ).encode(mask=False)
    wire.extend(
        Span[UInt8, _](
            WsFrame(opcode=WsOpcode.CONTINUATION, payload=_bytes("lo")).encode(
                mask=False
            )
        )
    )
    wire.extend(Span[UInt8, _](WsFrame.pong(_bytes("x")).encode(mask=False)))
    wire.extend(Span[UInt8, _](WsFrame.text("a").encode(mask=False)))
    s.write_all(Span[UInt8, _](wire))
    var ws = WsClient(_WsStream(c^), "k")
    var first = ws.recv_message().as_text()
    var second = ws.recv_message().as_text()
    if first != "hello" or second != "a":
        var third = ws.recv_message().as_text()
        s.close()
        ln.close()
        print(
            "BUG REPRODUCED: recv_message returned '" + first + "', '"
            + second + "', '" + third + "' (expected 'hello', 'a')"
        )
        raise Error("WS-02")
    s.close()
    ln.close()
    print("OK: recv_message reassembles fragments and skips PONG")
