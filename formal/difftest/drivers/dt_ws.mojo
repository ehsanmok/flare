"""Difftest driver: flare.ws.protocol.

Targets (input layout as in formal/Oracle/Ws.lean):
  ws_protocol.trace  byte 0 -> ``max_message = byte0 % 8 + 1`` and
                     ``max_outbox`` = [4, 16, 64, 2^20][(byte0 >> 3) % 4];
                     then one event per header byte ``e``: kind ``e % 8``
                     (0 TEXT, 1 BINARY, 2 CONTINUATION, 3 PING, 4 PONG,
                     5 CLOSE, 6 RSV2 set, 7 declares max_message + 1 bytes),
                     FIN = bit 3 (forced on control frames), payload = the
                     next ``min((e >> 4) % 8, max_message)`` bytes (kinds
                     0-5), unmasked iff ``e >> 4 == 15``.

Every event is encoded as a client frame and the whole trace is fed to one
``WsProtocol``; events are drained with ``next_event`` and the outbox is
decoded back into the frames queued for the peer.

Run: pixi run mojo -I . formal/difftest/drivers/dt_ws.mojo IN OUT
"""

from std.sys import argv

from flare.ws.frame import WsFrame, WsOpcode
from flare.ws.protocol import WS_EVENT_MESSAGE, WsProtocol

from _dtio import hex, read_cases, write_lines

comptime _KEY = SIMD[DType.uint8, 4](0x11, 0x22, 0x33, 0x44)


def _opcode(kind: Int) -> UInt8:
    if kind == 0:
        return WsOpcode.TEXT
    if kind == 1:
        return WsOpcode.BINARY
    if kind == 2:
        return WsOpcode.CONTINUATION
    if kind == 3:
        return WsOpcode.PING
    if kind == 4:
        return WsOpcode.PONG
    return WsOpcode.CLOSE


def _frame(
    mut out: List[UInt8], byte0: UInt8, masked: Bool, payload: List[UInt8]
):
    out.append(byte0)
    out.append(UInt8(len(payload)) | (UInt8(0x80) if masked else UInt8(0)))
    if masked:
        for i in range(4):
            out.append(_KEY[i])
    for i in range(len(payload)):
        out.append(payload[i] ^ _KEY[i % 4] if masked else payload[i])


def _trace(data: List[UInt8]) raises -> String:
    if len(data) == 0:
        return "ERR"
    var m = Int(data[0]) % 8 + 1
    var limits = [4, 16, 64, 1 << 20]
    var proto = WsProtocol(m, limits[(Int(data[0]) >> 3) % 4])
    var wire = List[UInt8]()
    var i = 1
    while i < len(data):
        var e = Int(data[i])
        i += 1
        var kind = e % 8
        if kind == 6:
            _frame(wire, UInt8(0xA1), True, List[UInt8]())
            continue
        if kind == 7:
            _frame(wire, UInt8(0x81), True, List[UInt8](length=m + 1, fill=0))
            continue
        var n = min((e >> 4) % 8, m, len(data) - i)
        var payload = List[UInt8](Span(data)[i : i + n])
        i += n
        var fin = (e >> 3) % 2 == 1 or kind >= 3
        _frame(
            wire,
            _opcode(kind) | (UInt8(0x80) if fin else UInt8(0)),
            (e >> 4) != 15,
            payload,
        )
    proto.inbox = wire^
    var events = String("")
    while True:
        var next = proto.next_event()
        if not next:
            break
        var ev = next.take()
        if ev.kind == WS_EVENT_MESSAGE:
            events += ("T" if ev.is_text else "B") + hex(Span(ev.payload)) + "."
        else:
            events += "E" + String(ev.code) + "."
    var sends = String("")
    var pos = 0
    while pos < len(proto.outbox):
        var r = WsFrame.decode_one(Span(proto.outbox)[pos:])
        pos += r.consumed
        var f = r^.take_frame()
        if f.opcode == WsOpcode.PONG:
            sends += "P" + hex(Span(f.payload)) + "."
        elif len(f.payload) == 0:
            sends += "C."
        else:
            sends += "C" + String(Int(f.payload[0]) * 256 + Int(f.payload[1])) + "."
    return "OK:" + events + "|" + sends + "|" + String(len(proto.outbox))


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "ws_protocol.trace":
            try:
                lines.append(_trace(c.data))
            except e:
                lines.append("BAD:" + String(e))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
