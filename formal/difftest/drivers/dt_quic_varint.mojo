"""Difftest driver: flare.quic.varint.

Targets (input layout as in formal/Oracle/Registry.lean):
  quic_varint.decode  the buffer
  quic_varint.encode  bytes 0..7 -> value (big-endian)

Run: pixi run mojo -I . formal/difftest/drivers/dt_quic_varint.mojo IN OUT
"""

from std.sys import argv

from flare.quic.varint import decode_varint, encode_varint

from _dtio import be_take, ok_hex, read_cases, write_lines


def _decode(data: List[UInt8]) -> String:
    try:
        var r = decode_varint(Span[UInt8, _](data))
        return "OK:" + String(r.value) + "," + String(r.consumed)
    except:
        return "ERR"


def _encode(data: List[UInt8]) -> String:
    try:
        var out = encode_varint(be_take(8, data))
        return ok_hex(Span[UInt8, _](out))
    except:
        return "ERR"


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "quic_varint.decode":
            lines.append(_decode(c.data))
        elif c.target == "quic_varint.encode":
            lines.append(_encode(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
