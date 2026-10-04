# PLATFORM: any
"""NET-09: the "hostname too long" error splits a UTF-8 character.

Lean: Flare.Bugs.NET_09.message_not_utf8 (counterexample) and
Flare.Bugs.NET_09.fixed_wf (fix meets spec).
flare/dns/resolver.mojo:82-87 @59bda50.

Expected: the error text is well-formed UTF-8 (a Mojo String invariant).
Actual: the message quotes String(unsafe_from_utf8=host_bytes[:20]); for a
host with "é" (C3 A9) at bytes 19-20 the quote ends in a lone C3, followed
by the E2 80 A6 of the ellipsis.

Minimal fix: quote whole characters only, e.g. advance k by each lead
byte's sequence length while k + len <= 20, then slice [:k].
"""

from flare.dns import resolve


def _utf8_ok(b: Span[UInt8, _]) -> Bool:
    var i = 0
    var n = len(b)
    while i < n:
        var c = Int(b[i])
        var need: Int
        if c < 0x80:
            need = 0
        elif c >= 0xC2 and c <= 0xDF:
            need = 1
        elif c >= 0xE0 and c <= 0xEF:
            need = 2
        elif c >= 0xF0 and c <= 0xF4:
            need = 3
        else:
            return False
        if i + need >= n and need > 0:
            return False
        for k in range(1, need + 1):
            var d = Int(b[i + k])
            if d < 0x80 or d > 0xBF:
                return False
        i += need + 1
    return True


def main() raises:
    var host = String("")
    for _ in range(19):
        host += "a"
    host += "é"
    for _ in range(240):
        host += "a"
    var msg = String("")
    try:
        _ = resolve(host)
    except e:
        msg = String(e)
    if not ("too long" in msg):
        raise Error("test setup: expected the too-long error, got " + msg)
    if not _utf8_ok(msg.as_bytes()):
        var hex = String("")
        var bs = msg.as_bytes()
        for i in range(len(bs)):
            if Int(bs[i]) >= 0x80:
                hex += hex_byte(Int(bs[i])) + " "
        print(
            "BUG REPRODUCED: error text is not valid UTF-8; its non-ASCII"
            " bytes are",
            hex,
        )
        raise Error("NET-09")
    print("OK: error text is valid UTF-8")


def hex_byte(v: Int) -> String:
    comptime digits = "0123456789ABCDEF"
    return String(digits[byte = v >> 4]) + String(digits[byte = v & 15])
