# PLATFORM: any (loopback TCP in-process; no external network)
# RESOLVED: DOC-01 fixed on fix/formal-findings
"""DOC-01: `WsConnection.recv` hands a TEXT frame whose payload is not valid
UTF-8 to the handler; it never sends CLOSE 1007 and never fails the
connection.

Lean: Flare.Bugs.DOC_01.counterexample (counterexample) and
Flare.Bugs.DOC_01.fixed (fix meets spec).
flare/ws/server.mojo:514-536 @59bda50 (`recv` returns every TEXT frame
`_recv_one` decodes, with no UTF-8 check). The validator exists
(`_is_valid_utf8`, flare/ws/frame.mojo:553) but only `text_payload`
(frame.mojo:522-536) calls it, after the frame was delivered, and
`WsCloseCode.INVALID_PAYLOAD` (frame.mojo:68) is never sent anywhere.

Doc claims: docs/threat-model.md:61 "Frame-level UTF-8 validator runs on
every TEXT payload; invalid sequences trigger 1007"; docs/security.md:16
"UTF-8 validation on TEXT frames"; docs/features.md:552.
RFC 6455 sec 8.1: an endpoint that finds a byte stream it must interpret
as UTF-8 is not valid UTF-8 "MUST _Fail the WebSocket Connection_";
sec 7.4.1: 1007 is the status for data inconsistent with the message type.

Setup: a loopback pair. The server side is wrapped in a WsConnection whose
prebuf holds one masked, final TEXT frame with payload C3 28 (a lead byte
followed by a non-continuation byte). A valid TEXT frame is the control.

Expected: recv raises and the client receives CLOSE with status 1007
(wire 88 02 03 EF). Before the fix: recv returns the TEXT frame and the client
receives nothing before the socket closes.

Minimal fix (unfragmented frames; the server has no reassembly): in
`recv`, before returning a final TEXT frame whose payload fails
`_is_valid_utf8`, write CLOSE(1007) unmasked and raise WsProtocolError.
"""

from flare.ws import WsConnection, WsFrame, WsOpcode
from flare.tcp import TcpStream, TcpListener
from flare.net import SocketAddr


def _serve(var s: TcpStream, var prebuf: List[UInt8]) -> Int:
    """1: recv returned a TEXT frame; 2: recv raised; 0: anything else.
    The connection (and its socket) is destroyed on return."""
    var conn = WsConnection(s^, SocketAddr.localhost(0), prebuf^)
    try:
        var f = conn.recv()
        if f.opcode == WsOpcode.TEXT:
            return 1
        return 0
    except:
        return 2


def _drain(mut c: TcpStream) -> List[UInt8]:
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
    return got^


def _run(payload: List[UInt8]) raises -> Tuple[Int, List[UInt8]]:
    var ln = TcpListener.bind(SocketAddr.localhost(0))
    var port = ln.local_addr().port
    var c = TcpStream.connect(SocketAddr.localhost(port))
    c.set_recv_timeout(2000)
    var s = ln.accept()
    var key = SIMD[DType.uint8, 4](0x11, 0x22, 0x33, 0x44)
    var wire = WsFrame(WsOpcode.TEXT, payload, fin=True).encode_with_key(
        True, key
    )
    var status = _serve(s^, wire^)
    var got = _drain(c)
    c.close()
    ln.close()
    return (status, got^)


def _has_close(b: List[UInt8], code: Int) -> Bool:
    return (
        len(b) >= 4
        and b[0] == 0x88
        and b[1] == 0x02
        and Int(b[2]) == (code >> 8)
        and Int(b[3]) == (code & 0xFF)
    )


def main() raises:
    var good: List[UInt8] = [UInt8(0x68), UInt8(0x69)]
    var control = _run(good)
    if control[0] != 1:
        print("inconclusive: the valid TEXT control frame was not delivered")
        raise Error("setup")

    var bad: List[UInt8] = [UInt8(0xC3), UInt8(0x28)]
    var r = _run(bad)
    var status = r[0]
    var got = r[1].copy()
    if status == 2 and _has_close(got, 1007):
        print("OK: invalid UTF-8 TEXT frame refused with CLOSE 1007")
        return
    var what = String("delivered to the handler") if status == 1 else String(
        "refused"
    )
    print(
        "BUG REPRODUCED: TEXT frame with invalid UTF-8 payload C3 28 was",
        what,
        "and the client received",
        len(got),
        "bytes (no CLOSE 1007; expected 88 02 03 EF)",
    )
    raise Error("DOC-01")
