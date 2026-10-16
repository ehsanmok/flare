"""Difftest driver: HTTP/1.1 framing (flare.http.proto.chunked).

Targets (input layout as in formal/Oracle/Registry.lean):
  h1_chunked.resume  byte 0 -> max_body (table below), byte 1 -> start
                     cursor (byte1 % 8, at most the buffer length), rest ->
                     buffer; scan_chunked_resume with decoded_total = 0

Run: pixi run mojo -I . formal/difftest/drivers/dt_h1.mojo IN OUT
"""

from std.sys import argv

from flare.http.proto.chunked import scan_chunked_resume

from _dtio import read_cases, write_lines


def _max_body(sel: UInt8) -> Int:
    var t = [0, 1, 10, 255, 4096, 65536, 1 << 30, 1 << 40]
    return t[Int(sel) % 8]


def _chunked_resume(data: List[UInt8]) -> String:
    if len(data) < 2:
        return "ERR"
    var buf = List[UInt8](capacity=len(data) - 2)
    for i in range(2, len(data)):
        buf.append(data[i])
    var cursor = min(Int(data[1]) % 8, len(buf))
    var total = 0
    var v = scan_chunked_resume(
        Span[UInt8, _](buf), cursor, total, _max_body(data[0])
    )
    return "OK:" + String(v) + "," + String(cursor) + "," + String(total)


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "h1_chunked.resume":
            lines.append(_chunked_resume(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
