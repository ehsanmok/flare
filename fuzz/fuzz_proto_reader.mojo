"""Fuzz harness: ``flare.grpc.proto.ProtoReader`` field walk.

``ProtoReader`` decodes proto3 wire bytes (varints, length-delimited,
fixed32/64) from an untrusted gRPC message body. It must never panic /
SIGSEGV on arbitrary bytes -- truncation, varint overflow, and bogus
lengths must surface as a raised ``Error``, and ``pos`` must only ever
advance (no infinite loop, no out-of-bounds read).

Properties:

1. **No crash.** Walking arbitrary bytes with the canonical
   read_tag / read_* / skip loop never panics; raises are fine.
2. **Progress / bounds.** ``pos`` is monotonic and never exceeds the
   buffer length.

Run:
    pixi run --environment fuzz fuzz-proto-reader
"""

from mozz import fuzz, FuzzConfig

from flare.grpc.proto import (
    ProtoReader,
    WIRE_I32,
    WIRE_I64,
    WIRE_LEN,
    WIRE_VARINT,
)


def _bytes(*vals: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(vals)):
        out.append(UInt8(vals[i] & 0xFF))
    return out^


def target(data: List[UInt8]) raises:
    var r = ProtoReader(Span[UInt8, _](data))
    var last = -1
    var guard = 0
    while r.has_more():
        guard += 1
        if guard > 100_000:
            raise Error("proto reader made no progress (possible loop)")
        # pos must be monotonic and in-bounds.
        if r.pos <= last:
            raise Error("proto reader pos did not advance")
        if r.pos > len(data):
            raise Error("proto reader pos past end")
        last = r.pos
        try:
            var tw = r.read_tag()
            var wire = tw[1]
            if wire == WIRE_VARINT:
                _ = r.read_uint64()
            elif wire == WIRE_I64:
                r.skip(WIRE_I64)
            elif wire == WIRE_I32:
                r.skip(WIRE_I32)
            elif wire == WIRE_LEN:
                _ = r.read_bytes()
            else:
                # Unknown/invalid wire type: skip must reject or advance.
                r.skip(wire)
        except:
            # Malformed field (truncation / overflow / bad wire type) is
            # a valid rejection; stop walking.
            return


def main() raises:
    print("=" * 60)
    print("fuzz_proto_reader.mojo — proto3 ProtoReader field walk")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(0x08, 0x96, 0x01))  # field 1 varint = 150
    seeds.append(_bytes(0x12, 0x03, 0x61, 0x62, 0x63))  # field 2 len "abc"
    seeds.append(_bytes(0x0D, 0x00, 0x00, 0x80, 0x3F))  # field 1 i32
    seeds.append(_bytes(0x09, 0, 0, 0, 0, 0, 0, 0, 0))  # field 1 i64
    seeds.append(_bytes(0xFF, 0xFF, 0xFF))  # garbage
    seeds.append(_bytes(0x12, 0x7F))  # len field claiming 127 bytes, truncated

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/proto_reader",
            corpus_dir="fuzz/corpus/proto_reader",
            max_input_len=512,
        ),
        seeds,
    )
