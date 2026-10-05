# PLATFORM: any (pure Mojo, no I/O)
# RESOLVED: QPACK-06 fixed on fix/formal-findings
"""QPACK-06: the dynamic-table encoder tracks no acknowledgments.

Lean: Flare.Bugs.QPACK_06.implOld_references_unacked,
      Flare.Bugs.QPACK_06.implOld_evicts_unacked (pre-fix),
      Flare.Bugs.QPACK_06.fixed_spec (fix).
flare/qpack/dynamic.mojo:405-470 @59bda50 (encode_field_section_dynamic, via
QpackEncoder.encode 617-619) references any entry find / find_name return;
QpackEncoder.insert (606-615) evicts through QpackDynamicTable.insert
(138-148). The encoder has no Known Received Count and is never told the
peer's SETTINGS_QPACK_BLOCKED_STREAMS.

RFC 9204 sec 2.1.2: "An encoder MUST limit the number of streams that could
become blocked to the value of SETTINGS_QPACK_BLOCKED_STREAMS at all times"
(default 0). Sec 2.1.1: "A dynamic table entry cannot be evicted immediately
after insertion ... the encoder MUST NOT insert that entry" when it would
have to evict entries that are not evictable.

Setup: QpackEncoder with capacity 40 (room for one 34-byte entry). Insert
("a", "b"), encode a section with a: b, then insert ("c", "d"). A
QpackDecoder with the same capacity applies the encoder stream, then decodes
the section.
Inconclusive if the first insert is refused.

Expected: with nothing acknowledged the section references no dynamic entry
(Required Insert Count 0) and the second insert is refused, so the decoder
decodes the section. Before the fix: Actual: the section has Required Insert Count 1 (an
unacknowledged entry) and the second insert evicts that entry, so the
decoder cannot decode the section.

Minimal fix: in QpackEncoder, encode against no dynamic entries and refuse
an insert that would evict, until acknowledgments are tracked.
"""

from std.collections import List
from std.collections.span import Span

from flare.qpack import QpackHeader
from flare.qpack.dynamic import QpackDecoder, QpackEncoder


def main() raises:
    var enc = QpackEncoder(UInt64(40))
    var stream = List[UInt8]()
    if not enc.insert(String("a"), String("b"), stream):
        print("inconclusive: the first insert was refused")
        raise Error("QPACK-06 inconclusive")
    var hs = List[QpackHeader]()
    hs.append(QpackHeader(String("a"), String("b")))
    var section = List[UInt8]()
    enc.encode(hs, section)
    var ric_enc = Int(section[0])
    var second = enc.insert(String("c"), String("d"), stream)
    var dec = QpackDecoder(UInt64(40))
    _ = dec.feed_encoder_stream(Span[UInt8, _](stream))
    var decoded = True
    var err = String("")
    try:
        var out = dec.decode(Span[UInt8, _](section))
        if len(out) != 1 or out[0].name != "a" or out[0].value != "b":
            decoded = False
            err = String("wrong headers")
    except e:
        decoded = False
        err = String(e)
    print(
        "encoded RIC byte:",
        ric_enc,
        "| second insert accepted:",
        second,
        "| decoder:",
        "ok" if decoded else "failed (" + err + ")",
    )
    if ric_enc != 0 or second or not decoded:
        print(
            (
                "BUG REPRODUCED: encoder referenced an unacknowledged entry"
                " (encoded Required Insert Count field"
            ),
            ric_enc,
            (
                ", non-zero) and then evicted it; the decoder"
                " cannot decode the section:"
            ),
            err,
        )
        raise Error("QPACK-06")
    print("OK: nothing unacknowledged referenced or evicted; section decodes")
