"""Difftest driver: flare.net.cstr, checked against what C reads.

Targets (input layout as in formal/Oracle/Registry.lean, ``cstrCross``):
  cstr.cross  byte 0 bits 0-1 -> what an empty value means, ``% 3``
              (``EMPTY_REJECT``, ``EMPTY_NULL``, ``EMPTY_PASS``); bit 2 ->
              build the string as a slice of a longer one (not
              NUL-terminated, like ``Url.parse(...).host``) when the bytes
              are valid UTF-8; bit 3 with an empty string -> the default
              ``TlsConfig().ca_bundle`` (the string of issue #42). The rest
              is the string. The string goes through ``c_str_addr``; for a
              nonzero address, libc ``strlen`` and ``memcpy`` read back what
              C sees: ``PASS:<hex>``. Address 0 is ``NULL``, a raise
              ``REJECT``.

Run: pixi run mojo -I . formal/difftest/drivers/dt_cstr.mojo IN OUT
"""

from std.ffi import external_call
from std.sys import argv

from flare.io.byte_cursor import _is_valid_utf8
from flare.net.cstr import c_str_addr
from flare.tls import TlsConfig

from _dtio import hex, read_cases, write_lines


def _cross(data: List[UInt8]) -> String:
    if len(data) == 0:
        return "ERR"
    var mode = (Int(data[0]) & 3) % 3
    var raw = List[UInt8]()
    for i in range(1, len(data)):
        raw.append(data[i])
    var s: String
    if (Int(data[0]) & 8) == 8 and len(raw) == 0:
        s = TlsConfig().ca_bundle
    # Only a valid UTF-8 string can be sliced at a byte offset.
    elif (Int(data[0]) & 4) == 4 and _is_valid_utf8(Span(raw)):
        var wide = List[UInt8]()
        wide.append(0x5B)
        wide.extend(Span(raw))
        wide.append(0x5D)
        var w = String(unsafe_from_utf8=Span(wide))
        s = String(w[byte = 1 : 1 + len(raw)])
    else:
        s = String(unsafe_from_utf8=Span(raw))
    try:
        var addr = c_str_addr(s, mode, "difftest")
        if addr == 0:
            return "NULL"
        var n = external_call["strlen", Int](addr)
        var seen = List[UInt8](length=n, fill=0)
        _ = external_call["memcpy", Int](Int(seen.unsafe_ptr()), addr, n)
        _ = s^
        return "PASS:" + hex(Span(seen))
    except:
        return "REJECT"


def main() raises:
    var args = argv()
    var lines = List[String]()
    for c in read_cases(String(args[1])):
        if c.target == "cstr.cross":
            lines.append(_cross(c.data))
        else:
            lines.append("BAD:unknown target " + c.target)
    write_lines(String(args[2]), lines)
