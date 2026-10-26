"""Fuzz harness: ``flare.net.cstr``, the strings flare hands C as ``char*``.

The properties are the Lean theorems of ``formal/Flare/Kernels/CStr.lean``,
checked against real C on every input:

1. ``verdict_ok``: a pass is a nonempty string with no NUL, NULL is an
   empty string where the parameter allows it, everything else is refused.
2. ``pass_exact``: for a pass, libc ``strlen`` and ``memcmp`` on the address
   ``c_str_addr`` returns see exactly the Mojo string, whether the string
   was owned or a slice of a longer one (``Url.parse(...).host``).

Byte 0: bits 0-1 pick what an empty value means (``% 3``: reject, NULL,
``""``), bit 2 slicing, bit 3 (empty only) the default
``TlsConfig().ca_bundle``. The rest is the string. Issue #42 was an empty string C read as unrelated static data.

Run:
    pixi run --environment fuzz fuzz-cstr
"""

from std.ffi import external_call

from mozz import fuzz, FuzzConfig

from flare.io.byte_cursor import _is_valid_utf8
from flare.tls import TlsConfig
from flare.net.cstr import (
    EMPTY_NULL,
    EMPTY_PASS,
    CSTR_NULL,
    CSTR_PASS,
    CSTR_REJECT,
    c_str_addr,
    c_str_verdict,
)


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


def _assert(cond: Bool, msg: String) raises:
    # mozz counts a raise as a crash only when the message carries a crash
    # marker; any other raise is a valid rejection.
    if not cond:
        raise Error("assertion failed: " + msg)


def target(data: List[UInt8]) raises:
    if len(data) == 0:
        return
    var mode = (Int(data[0]) & 3) % 3
    var raw = List[UInt8]()
    var has_nul = False
    for i in range(1, len(data)):
        raw.append(data[i])
        has_nul = has_nul or data[i] == 0
    var n = len(raw)

    var v = c_str_verdict(Span(raw), mode)
    if v == CSTR_PASS:
        _assert(not has_nul, "cstr: passed a string holding a NUL")
        _assert(n > 0 or mode == EMPTY_PASS, "cstr: passed an empty string")
    elif v == CSTR_NULL:
        _assert(n == 0 and mode == EMPTY_NULL, "cstr: NULL where not allowed")
    else:
        _assert(v == CSTR_REJECT, "cstr: unknown verdict")
        _assert(
            has_nul or (n == 0 and mode != EMPTY_NULL and mode != EMPTY_PASS),
            "cstr: refused a valid string",
        )

    var s: String
    if (Int(data[0]) & 8) == 8 and n == 0:
        s = TlsConfig().ca_bundle
    elif (Int(data[0]) & 4) == 4 and _is_valid_utf8(Span(raw)):
        var wide = List[UInt8]()
        wide.append(0x5B)
        wide.extend(Span(raw))
        wide.append(0x5D)
        var w = String(unsafe_from_utf8=Span(wide))
        s = String(w[byte = 1 : 1 + n])
    else:
        s = String(unsafe_from_utf8=Span(raw))
    var addr: Int
    try:
        addr = c_str_addr(s, mode, "fuzz")
    except:
        _assert(v == CSTR_REJECT, "cstr: c_str_addr raised on a pass")
        return
    _assert(v != CSTR_REJECT, "cstr: c_str_addr passed a refused string")
    if addr == 0:
        _assert(v == CSTR_NULL, "cstr: NULL address for a pass")
        return
    var seen = external_call["strlen", Int](addr)
    _assert(seen == n, "cstr: C read " + String(seen) + " of " + String(n))
    var diff = external_call["memcmp", Int32](addr, Int(raw.unsafe_ptr()), n)
    _assert(diff == 0, "cstr: C read different bytes")
    # Both addresses escaped as raw Ints: keep the buffers alive past C.
    _ = s^
    _ = raw^


def main() raises:
    print("=" * 60)
    print("fuzz_cstr.mojo — strings crossing into C as char*")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("\x00"))  # empty, required
    seeds.append(_bytes("\x01"))  # empty, NULL allowed
    seeds.append(_bytes("\x02"))  # empty is ""
    seeds.append(_bytes("\x0a"))  # issue #42: TlsConfig().ca_bundle as ""
    seeds.append(_bytes("\x09"))  # issue #42: TlsConfig().ca_bundle as NULL
    seeds.append(_bytes("\x00localhost"))
    seeds.append(_bytes("\x04localhost"))  # slice-derived
    seeds.append(_bytes("\x00localhost\x00.evil"))
    seeds.append(_bytes("\x01\x00"))
    seeds.append(_bytes("\x00/etc/ssl/certs/ca-certificates.crt"))
    seeds.append(_bytes("\x04\xc3\xa9t\xc3\xa9"))  # multi-byte UTF-8

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/cstr",
            corpus_dir="fuzz/corpus/cstr",
            max_input_len=256,
        ),
        seeds,
    )
