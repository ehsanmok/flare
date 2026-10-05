# PLATFORM: any
# RESOLVED: QUIC-13 fixed on fix/formal-findings
"""QUIC-13: preferred_address (0x0d) is never validated.

Lean: Flare.Bugs.QUIC_13.impl_accepts (impl),
      Flare.Bugs.QUIC_13.decodeFixed_spec (fix).
flare/quic/transport_params.mojo:410-525 @59bda50
(`decode_transport_parameters`): id 0x0d has no branch and is dropped like
an unknown id, whatever its contents.

RFC 9000 §18.2 (preferred_address): the value is IPv4 address (4), IPv4
port (2), IPv6 address (16), IPv6 port (2), CID length (1), CID, stateless
reset token (16); "a server MUST NOT include a zero-length connection ID in
this transport parameter. A client MUST treat a violation of these
requirements as a connection error of type TRANSPORT_PARAMETER_ERROR."
§7.4: a parameter with an invalid value is TRANSPORT_PARAMETER_ERROR.
Expected: decoding a preferred_address whose CID length is 0, one that is
5 bytes long, and one whose CID length is 21 raises. Before the fix: all decode.

Minimal fix: a 0x0d branch requiring `value_len >= 25`,
`1 <= cid_len <= 20` (byte 24) and `value_len == 41 + cid_len`.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic.transport_params import decode_transport_parameters


def _pa(cid_len: Int, total: Int) -> List[UInt8]:
    var v = List[UInt8]()
    for _ in range(24):
        v.append(0)
    v.append(UInt8(cid_len))
    while len(v) < total:
        v.append(0x55)
    while len(v) > total:
        _ = v.pop()
    var b = List[UInt8]()
    b.append(0x0D)
    b.append(UInt8(len(v)))
    for i in range(len(v)):
        b.append(v[i])
    return b^


def main() raises:
    var names = List[String]()
    names.append("zero-length CID")
    names.append("5-byte value")
    names.append("CID length 21")
    var blobs = List[List[UInt8]]()
    blobs.append(_pa(0, 41))
    blobs.append(_pa(0, 5))
    blobs.append(_pa(21, 62))
    var accepted = 0
    for i in range(len(blobs)):
        try:
            _ = decode_transport_parameters(Span[UInt8, _](blobs[i]))
            print(names[i], "-> accepted")
            accepted += 1
        except e:
            print(names[i], "-> rejected:", e)
    if accepted > 0:
        print(
            "BUG REPRODUCED: invalid preferred_address accepted in",
            accepted,
            "of 3 cases",
        )
        raise Error("QUIC-13")
    print("OK: invalid preferred_address rejected")
