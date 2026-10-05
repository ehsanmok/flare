# PLATFORM: any
# RESOLVED: ENC-03 fixed on fix/formal-findings
"""ENC-03: ProtoReader accepts a length-delimited field of length 2^63-1;
the cursor wraps negative and the next read is out of bounds.

Lean: Flare.Bugs.ENC_03.counterexample (skip on this message succeeds and
leaves pos = -9223372036854775799 with has_more() true) and
Flare.Bugs.ENC_03.fixed_preserves_inv (the fixed check keeps 0 <= pos <= len
for every input).
flare/grpc/proto.mojo:282-283 and :299-300 @59bda50.

Expected: skip()/read_bytes() raise "truncated" when the declared length
exceeds the remaining bytes (protobuf length-delimited records must fit).
Before the fix: the check `self.pos + n > len(self.data)` is evaluated in wrapping
Int arithmetic; with n = 2^63 - 1 the sum is negative, the check passes and
pos becomes negative. decode_health_request (grpc/health.mojo:47-55) runs
exactly this loop on the request body, so the 11-byte health-check request
below makes the next read_tag index data[-9223372036854775799] (bounds
assertion abort, or a wild read in an unchecked build).

Minimal fix (both sites):
    if n < 0 or n > len(self.data) - self.pos:
"""

from flare.grpc.proto import ProtoReader


def main() raises:
    # field 2, wire type LEN (0x12), length varint 0x7FFFFFFFFFFFFFFF
    var msg: List[UInt8] = [
        0x12,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0xFF,
        0x7F,
        0x00,
    ]
    var r = ProtoReader(Span[UInt8, _](msg))
    var t = r.read_tag()
    if t[0] != 2 or t[1] != 2:
        raise Error("sanity: expected field 2, wire type 2")
    var skipped = True
    try:
        r.skip(t[1])
    except:
        skipped = False
    if skipped:
        print(
            (
                "BUG REPRODUCED: skip() accepted a length of 2^63-1 in an"
                " 11-byte message; pos ="
            ),
            r.pos,
            "has_more() =",
            r.has_more(),
        )
        raise Error("ENC-03")
    print("OK: skip() rejects a length-delimited field longer than the message")
