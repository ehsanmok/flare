# PLATFORM: any
"""QPACK-02: decode_field_section_dynamic reads the Sign/Delta-Base byte
one past the end of the field section.

Lean: Flare.Bugs.QPACK_02.out_of_bounds (for [0xFF, 0x01] with MaxEntries
256 and an empty table the read index is 2 = len) and
Flare.Bugs.QPACK_02.fixed_inBounds.
flare/qpack/dynamic.mojo:482-490 @59bda50.

The only length check is len(buf) >= 2. The Required Insert Count prefix
integer 0xFF 0x01 (= 256) consumes both bytes; decode_required_insert_count
accepts it (MaxEntries 256 -> RIC 255), then line 489 evaluates
buf[ric_enc.offset] = buf[2]. In the H3 reader the field section is a
sub-span of the stream buffer, so this reads the next frame's byte.

Observation: with Mojo's default bounds assertions the read aborts the
process ("Assert Error: index 2 is out of bounds" at dynamic.mojo:489), a
peer-triggerable crash of the whole server. The repro runs the decode in a
forked child and reports whether the child died from a signal.

Expected: a truncation error before any read past the end.
Actual: out-of-bounds read at line 489 (process abort under assertions).
Needs a decoder table capacity >= 4096 (default H3 config uses 0).

Minimal fix: `if ric_enc.offset >= len(buf): raise Error(...)` before
line 489.
"""

from std.collections import List
from std.collections.span import Span
from std.ffi import external_call, c_int
from std.memory import Pointer

from flare.qpack.dynamic import QpackDynamicTable, decode_field_section_dynamic


def _child():
    var t = QpackDynamicTable(8192)  # MaxEntries = 256
    var backing = List[UInt8]()
    backing.append(0xFF)
    backing.append(0x01)
    backing.append(0x80)  # byte just past the 2-byte section
    var sec = Span[UInt8, _](backing)[0:2]
    try:
        _ = decode_field_section_dynamic(sec, t)
    except:
        pass
    _ = external_call["_exit", c_int](c_int(0))


def main() raises:
    var pid = Int(external_call["fork", c_int]())
    if pid == 0:
        _child()
        return
    if pid < 0:
        raise Error("fork failed")
    var status = Int32(0)
    var status_addr = Int(Pointer[Int32, _](to=status))
    _ = external_call["waitpid", c_int](c_int(pid), status_addr, c_int(0))
    var sig = Int(status & 0x7F)
    if sig != 0:
        print(
            "BUG REPRODUCED: decoding the 2-byte field section [0xFF, 0x01]"
            " killed the process with signal",
            sig,
            "(out-of-bounds read of buf[2] at dynamic.mojo:489)",
        )
        raise Error("QPACK-02")
    print("OK: truncated prefix rejected without reading past the end")
