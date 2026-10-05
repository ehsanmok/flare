# PLATFORM: any
# RESOLVED: ENC-04 fixed on fix/formal-findings
"""ENC-04: ByteReader._need overflows; skip(n) with a huge n succeeds and
moves the cursor negative.

Lean: Flare.Bugs.ENC_04.counterexample (after read_u8 on a 4-byte buffer,
skip(Int.MAX) succeeds and pos = -2^63) and
Flare.Bugs.ENC_04.fixed_preserves_inv (the fixed check keeps 0 <= pos <= len).
flare/io/byte_cursor.mojo:144-155 @59bda50.

Expected: "Every read is bounds-checked (a short buffer raises rather than
reading out of bounds)" (module docstring); skip(n) past the end raises.
Before the fix: `self.pos + n > len(self.buf)` wraps for n > 2^63 - 1 - pos, so the
check passes, pos becomes -2^63, remaining() is negative and the next read
indexes the span at a negative offset. In-tree callers pass n < 2^32 and are
not affected; any caller that forwards a 64-bit length is.

Minimal fix:
    if n < 0 or n > len(self.buf) - self.pos:
"""

from flare.io import ByteReader


def main() raises:
    var raw: List[UInt8] = [1, 2, 3, 4]
    var r = ByteReader(Span[UInt8, _](raw))
    _ = r.read_u8()
    var skipped = True
    try:
        r.skip(Int.MAX)
    except:
        skipped = False
    if skipped:
        print(
            "BUG REPRODUCED: skip(Int.MAX) on a 4-byte buffer succeeded; pos =",
            r.position(),
            "remaining() =",
            r.remaining(),
        )
        raise Error("ENC-04")
    print("OK: skip(Int.MAX) raises; pos stays", r.position())
