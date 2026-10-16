"""Difftest driver: UTF-8 validation and lossy decoding.

Targets (input layout as in formal/Oracle/Registry.lean):
  utf8.valid  flare.io.byte_cursor._is_valid_utf8 on the buffer
  utf8.lossy  flare.http.proto.utf8.utf8_lossy_string on the buffer

Run: pixi run mojo -I . formal/difftest/drivers/dt_utf8.mojo IN OUT
"""

from std.sys import argv

from flare.http.proto.utf8 import utf8_lossy_string
from flare.io.byte_cursor import _is_valid_utf8

from _dtio import ok_hex, read_cases, write_lines


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "utf8.valid":
            var ok = _is_valid_utf8(Span[UInt8, _](c.data))
            lines.append("OK:1" if ok else "OK:0")
        elif c.target == "utf8.lossy":
            var s = utf8_lossy_string(Span[UInt8, _](c.data))
            lines.append(ok_hex(s.as_bytes()))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
