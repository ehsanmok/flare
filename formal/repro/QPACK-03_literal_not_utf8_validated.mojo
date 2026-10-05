# PLATFORM: any
# RESOLVED: QPACK-03 fixed on fix/formal-findings
"""QPACK-03: QPACK string literals become Strings without UTF-8 validation.

Lean: Flare.Bugs.QPACK_03.counterexample / not_string_ok (pre-fix) (literal [0x01,
0xFF] yields payload [0xFF], which is not valid UTF-8) and
Flare.Bugs.QPACK_03.fixed_ok.
flare/qpack/codec.mojo:215-234 @59bda50 (ascii_unchecked_string at 231/233).

ascii_unchecked_string's contract (flare/http/proto/ascii.mojo:63-70):
"the bytes MUST already be valid ASCII (each byte < 0x80)". The QPACK
decoder passes arbitrary peer bytes (raw or Huffman-decoded), so a
header value can be a Mojo String that is not valid UTF-8.

Expected: the decoder rejects (or validates) non-UTF-8 literal bytes.
Before the fix: Actual: the header value String holds byte 0xFF.

Minimal fix: build the String with a validating constructor
(String(from_utf8=...)) and raise on failure.
"""

from std.collections import List
from std.collections.span import Span

from flare.qpack.codec import decode_field_section


def main() raises:
    # RIC=0, Base=0, literal with static name ref idx 0 (:authority),
    # value literal: length 1, byte 0xFF.
    var sec = List[UInt8]()
    sec.append(0x00)
    sec.append(0x00)
    sec.append(0x50)
    sec.append(0x01)
    sec.append(0xFF)
    var raised = False
    var bad = False
    try:
        var out = decode_field_section(Span[UInt8, _](sec))
        var b = out[0].value.as_bytes()
        if len(b) == 1 and b[0] == 0xFF:
            bad = True
    except e:
        raised = True
    if bad:
        var valid = True
        try:
            var b2 = List[UInt8]()
            b2.append(0xFF)
            _ = String(from_utf8=Span[UInt8, _](b2))
        except:
            valid = False
        print(
            "BUG REPRODUCED: decoded header value is a String holding byte"
            " 0xFF (validating String constructor accepts it:",
            valid,
            ")",
        )
        raise Error("QPACK-03")
    print("OK: non-UTF-8 literal rejected (raised =", raised, ")")
