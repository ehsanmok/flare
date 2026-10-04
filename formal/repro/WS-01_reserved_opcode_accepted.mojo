# PLATFORM: any
"""WS-01: decode_one accepts frames with a reserved opcode.

Lean: Flare.Bugs.WS_01.counterexample (counterexample) and
Flare.Bugs.WS_01.fixed_known_opcode (fix meets spec).
flare/ws/frame.mojo:395-508 @59bda50 (opcode = byte0 & 0x0F, never checked).

Spec: RFC 6455 sec 5.2: opcodes 0x3-0x7 and 0xB-0xF are reserved, and "if
an unknown opcode is received, the receiving endpoint MUST _Fail the
WebSocket Connection_". decode_one already fails the connection on the
other reserved header bits (RSV1-3), and both WsConnection.recv and
WsClient.recv return whatever it decodes.

Expected: WsFrame.decode_one(b"\\x83\\x00") raises WsProtocolError.
Actual: it returns a frame with opcode 3, which recv() hands to the
application as a data frame.

Minimal fix: in decode_one, after the RSV checks, raise WsProtocolError
unless opcode is 0x0-0x2 or 0x8-0xA.
"""

from flare.ws import WsFrame


def main() raises:
    var reserved = List[UInt8]()
    reserved.append(0x83)  # FIN | opcode 0x3 (reserved non-control)
    reserved.append(0x00)  # unmasked, empty payload
    var accepted = -1
    try:
        var r = WsFrame.decode_one(Span[UInt8, _](reserved))
        accepted = Int(r.frame.opcode)
    except:
        pass
    var reserved_ctl = List[UInt8]()
    reserved_ctl.append(0x8B)  # FIN | opcode 0xB (reserved control)
    reserved_ctl.append(0x00)
    var accepted_ctl = -1
    try:
        var r = WsFrame.decode_one(Span[UInt8, _](reserved_ctl))
        accepted_ctl = Int(r.frame.opcode)
    except:
        pass
    if accepted >= 0 or accepted_ctl >= 0:
        print(
            "BUG REPRODUCED: decode_one accepted reserved opcodes (0x3 ->"
            " opcode " + String(accepted) + ", 0xB -> opcode "
            + String(accepted_ctl) + "; -1 = rejected)"
        )
        raise Error("WS-01")
    print("OK: reserved opcodes 0x3 and 0xB are rejected")
