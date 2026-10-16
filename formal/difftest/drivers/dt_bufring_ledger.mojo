"""Difftest driver: flare.http._bufring_ledger.

Targets (input layout as in formal/Oracle/Registry.lean, ``ledgerTrace``):
  bufring_ledger.trace  byte 0 -> ring size ``byte0 % 8 + 1``; each later
                        byte is one event. Low two bits 0: kernel fill.
                        Otherwise a completion: bit 2 = connection live,
                        bits 3-4 = result (0, -105, 1, 8192), bit 5 =
                        carries a buffer (only while one is held).

Run: pixi run mojo -I . formal/difftest/drivers/dt_bufring_ledger.mojo IN OUT
"""

from std.sys import argv

from flare.http._bufring_ledger import (
    BufLedger,
    RECV_DROP,
    RECV_STAGE,
)

from _dtio import read_cases, write_lines


def _res(code: Int) -> Int:
    if code == 0:
        return 0
    if code == 1:
        return -105
    if code == 2:
        return 1
    return 8192


def _trace(data: List[UInt8]) -> String:
    if len(data) == 0:
        return "ERR"
    var led = BufLedger(Int(data[0]) % 8 + 1)
    var out = String("OK:")
    for i in range(1, len(data)):
        var b = Int(data[i])
        if b % 4 == 0:
            out += "F" if led.on_fill() else "N"
            continue
        var live = (b >> 2) & 1 == 1
        var has_buf = (b >> 5) & 1 == 1 and led.in_cq > 0
        var d = led.on_complete(live, _res((b >> 3) & 3), has_buf)
        if d.action == RECV_STAGE:
            out += "S"
        elif d.action == RECV_DROP:
            out += "D"
        else:
            out += "C"
        if d.return_buf:
            out += "r"
    out += ";" + String(led.in_ring) + "," + String(led.in_cq)
    out += "," + String(led.enobufs)
    return out


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "bufring_ledger.trace":
            lines.append(_trace(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
