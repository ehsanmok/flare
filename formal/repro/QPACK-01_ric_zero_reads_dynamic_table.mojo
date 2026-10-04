# PLATFORM: any
"""QPACK-01: a field section with Required Insert Count 0 resolves a
dynamic-table entry (Base wraps; no `abs < RIC` check).

Lean: Flare.Bugs.QPACK_01.counterexample / violates_safety (flare resolves
RIC=0, Sign=1, Delta=0, post-base index 1 to absolute index 0) and
Flare.Bugs.QPACK_01.fixed_meets_spec (the fixed resolver equals the RFC
9204 spec and never yields an index >= RIC).
flare/qpack/dynamic.mojo:489-555 @59bda50 (base at 493, post-base at 544).

RFC 9204 sec 4.5.1.2: with Sign=1, a Required Insert Count <= Delta Base
is invalid. Sec 4.5.1 / 4.5.3 / 4.5.5: a reference to an absolute index
>= Required Insert Count is QPACK_DECOMPRESSION_FAILED.

flare computes base = ric - delta - 1 = 0 - 0 - 1 = 2^64-1 (UInt64 wrap);
post-base index 1 gives abs = base + 1 = 0, and get_abs(0) succeeds.

Expected: decode raises. Actual: the section decodes to the dynamic entry.
Reachable only when the decoder's table capacity is non-zero
(Http3Config.qpack_max_table_capacity > 0; default is 0).

Minimal fix: raise when sign_set and delta >= ric; raise for a pre-base
relative index >= base; raise when any resolved abs_idx >= ric.
"""

from std.collections import List
from std.collections.span import Span

from flare.qpack import QpackHeader
from flare.qpack.dynamic import QpackDynamicTable, decode_field_section_dynamic


def main() raises:
    var t = QpackDynamicTable(4096)
    _ = t.insert(QpackHeader("x-secret", "dynamic-entry-0"))
    # RIC=0 (0x00), Sign=1 Delta=0 (0x80), post-base indexed line idx 1 (0x11).
    var sec = List[UInt8]()
    sec.append(0x00)
    sec.append(0x80)
    sec.append(0x11)
    var raised = False
    var got = String("")
    try:
        var hs = decode_field_section_dynamic(Span[UInt8, _](sec), t)
        if len(hs) > 0:
            got = hs[0].name + ": " + hs[0].value
    except e:
        raised = True
    if not raised:
        print(
            "BUG REPRODUCED: field section with Required Insert Count 0"
            " decoded dynamic entry abs 0 ->",
            got,
        )
        raise Error("QPACK-01")
    print("OK: RIC=0 section with a post-base reference was rejected")
