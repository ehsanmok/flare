# PLATFORM: any
# RESOLVED: QPACK-04 fixed on fix/formal-findings
"""QPACK-04: an encoder-stream instruction that references a missing
dynamic entry stalls the stream instead of raising
QPACK_ENCODER_STREAM_ERROR.

Lean: Flare.Bugs.QPACK_04.counterexample (pre-fix: empty table, dynamic name ref
index 0 -> stall) vs spec_errors (QPACK_ENCODER_STREAM_ERROR), and
Flare.Bugs.QPACK_04.fixed_meets_spec.
flare/qpack/dynamic.mojo:319-320 and 337-338 @59bda50, handled by
apply_encoder_instructions_partial at 281-297.

insert_count() - 1 - ip wraps in UInt64 for ip >= insert_count; get_abs
then raises "qpack: dynamic abs index ... evicted or not yet inserted",
which lacks the QPACK_ENCODER_STREAM_ERROR tag, so the partial replayer
treats it as a truncated instruction and returns (0, 0): the bytes are
carried and retried forever. RFC 9204 sec 4.3.2 / 4.3.4: a reference to
a missing or evicted entry is a QPACK_ENCODER_STREAM_ERROR.

Expected: raise QPACK_ENCODER_STREAM_ERROR. Before the fix: Actual: returns (0, 0).

Minimal fix: check ip < insert_count() - dropped before the subtraction
and raise "QPACK_ENCODER_STREAM_ERROR: ..." (lines 319 and 337).
"""

from std.collections import List
from std.collections.span import Span

from flare.qpack.dynamic import (
    QpackDynamicTable,
    apply_encoder_instructions_partial,
)


def main() raises:
    var t = QpackDynamicTable(4096)
    # Insert With Name Reference, T=0 (dynamic), relative index 0, value "".
    var instr = List[UInt8]()
    instr.append(0x80)
    instr.append(0x00)
    var raised = False
    var msg = String("")
    var res = Tuple[Int, Int](-1, -1)
    try:
        res = apply_encoder_instructions_partial(t, Span[UInt8, _](instr))
    except e:
        raised = True
        msg = String(e)
    if not raised:
        print(
            "BUG REPRODUCED: dynamic name ref into an empty table returned"
            " (inserts, consumed) = (",
            res[0],
            ",",
            res[1],
            ") -- treated as truncation, no QPACK_ENCODER_STREAM_ERROR",
        )
        raise Error("QPACK-04")
    print("OK: bad reference raised:", msg)
