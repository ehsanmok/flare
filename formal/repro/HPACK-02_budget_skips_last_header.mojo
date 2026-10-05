# PLATFORM: any
# RESOLVED: HPACK-02 fixed on fix/formal-findings
"""HPACK-02: HpackDecoder.decode never charges the last header of a block
against its decode budget.

Lean: Flare.Bugs.HPACK_02.bug (counterexample) and
Flare.Bugs.HPACK_02.fixed (charging every header enforces the budget).
flare/http2/hpack.mojo:376-385 @59bda50.

Contract (docstring of decode): "budget: When positive, the most decoded
bytes (RFC 7541 entry size: name + value + 32, summed) the block may
expand to. Past it decoding stops with HPACK_BUDGET_ERROR."

The loop adds header i-1 to the running total at the top of iteration i,
so the header decoded in the last iteration is never added. A one-field
block whose field is 133 bytes passes a 50-byte budget.

Expected: HPACK_BUDGET_ERROR. Before the fix: the block decodes. The overrun is at
most one field (bounded by the block length or the table size), so the
connection-level ceiling (_header_block_ceiling) is exceeded by at most
that much.

Minimal fix: charge each header right after it is decoded (or once more
after the loop).
"""

from flare.http2.hpack import HpackDecoder


def main() raises:
    # Literal without indexing, new name: 0x00, "x", then 100 x 'a'.
    var block = List[UInt8]()
    block.append(0x00)
    block.append(0x01)
    block.append(UInt8(ord("x")))
    block.append(100)
    for _ in range(100):
        block.append(UInt8(ord("a")))
    var budget = 50
    var dec = HpackDecoder()
    var raised = False
    var n = 0
    try:
        var hs = dec.decode(Span[UInt8, _](block), budget)
        n = len(hs)
    except e:
        raised = True
    if not raised:
        print(
            "BUG REPRODUCED: a block expanding to",
            1 + 100 + 32,
            "bytes decoded",
            n,
            "header(s) under a budget of",
            budget,
            "with no HPACK_BUDGET_ERROR",
        )
        raise Error("HPACK-02")
    print("OK: the 133-byte block was refused under a 50-byte budget")
