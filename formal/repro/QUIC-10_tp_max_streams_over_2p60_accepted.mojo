# PLATFORM: any
"""QUIC-10: initial_max_streams_bidi / _uni above 2^60 are accepted.

Lean: Flare.Bugs.QUIC_10.impl_accepts (impl),
      Flare.Bugs.QUIC_10.decodeFixed_spec (fix).
flare/quic/transport_params.mojo:482-489 @59bda50
(`decode_transport_parameters`, ids 0x08 / 0x09): the value is stored with
no range check.

RFC 9000 §18.2 (initial_max_streams_bidi, initial_max_streams_uni): "This
value cannot exceed 2^60 ... Receipt of a parameter that exceeds this limit
MUST be treated as a connection error of type TRANSPORT_PARAMETER_ERROR."
Expected: decoding `08 08 d0 00 00 00 00 00 00 01` (bidi = 2^60 + 1) and the
same with id 09 raises. Actual: both decode.

Minimal fix: in the 0x08 and 0x09 branches raise when the value exceeds
2^60.
"""

from std.collections import List
from std.collections.span import Span

from flare.quic.transport_params import decode_transport_parameters


def _blob(id: UInt8) -> List[UInt8]:
    var b = List[UInt8]()
    b.append(id)
    b.append(0x08)
    b.append(0xD0)  # 8-byte varint, top bits 0x10 -> 2^60
    for _ in range(6):
        b.append(0x00)
    b.append(0x01)  # + 1
    return b^


def main() raises:
    var accepted = String("")
    for id in [UInt8(0x08), UInt8(0x09)]:
        var b = _blob(id)
        try:
            var tp = decode_transport_parameters(Span[UInt8, _](b))
            var v = (
                tp.initial_max_streams_bidi.value() if id
                == 0x08 else tp.initial_max_streams_uni.value()
            )
            accepted += hex(Int(id)) + "=" + String(v) + " "
        except:
            pass
    if accepted != "":
        print(
            "BUG REPRODUCED: transport parameter max_streams > 2^60 accepted:",
            accepted,
        )
        raise Error("QUIC-10")
    print("OK: max_streams > 2^60 rejected")
