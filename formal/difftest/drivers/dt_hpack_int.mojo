"""Difftest driver: flare.http2.hpack integer codec.

Targets (input layout as in formal/Oracle/Registry.lean):
  hpack_int.decode  byte 0 -> prefix N = byte0 % 8 + 1, rest = buffer
  hpack_int.encode  byte 0 -> N, byte 1 -> flag byte, bytes 2..5 -> value

Run: pixi run mojo -I . formal/difftest/drivers/dt_hpack_int.mojo IN OUT
"""

from std.sys import argv

from flare.http2.hpack import decode_integer, encode_integer

from _dtio import be_take, ok_hex, read_cases, write_lines


def _decode(data: List[UInt8]) -> String:
    if len(data) == 0:
        return "ERR"
    var n = Int(data[0]) % 8 + 1
    var buf = List[UInt8]()
    for i in range(1, len(data)):
        buf.append(data[i])
    try:
        var r = decode_integer(Span[UInt8, _](buf), 0, n)
        return "OK:" + String(r.value) + "," + String(r.offset)
    except:
        return "ERR"


def _encode(data: List[UInt8]) -> String:
    if len(data) < 2:
        return "ERR"
    var n = Int(data[0]) % 8 + 1
    var rest = List[UInt8]()
    for i in range(2, len(data)):
        rest.append(data[i])
    var out = List[UInt8]()
    encode_integer(out, Int(be_take(4, rest)), n, data[1])
    return ok_hex(Span[UInt8, _](out))


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "hpack_int.decode":
            lines.append(_decode(c.data))
        elif c.target == "hpack_int.encode":
            lines.append(_encode(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
