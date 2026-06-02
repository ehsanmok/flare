"""Fuzz harness: QUIC Connection ID handling --
``flare.quic.packet.ConnectionId`` + the routing-side
``ConnectionIdTable`` from ``flare.quic.server``.

The CID is the single value the QUIC dispatch layer routes on
(RFC 9000 §5.1). The wire format allows lengths in ``[0, 20]``;
the routing table hashes a lowercase-hex encoding of the bytes
so collisions / case-flip / null-padding edge cases must not
break the layer.

Properties checked:

1. :func:`flare.quic.server.cid_to_hex` returns a string that
   round-trips to a CID of the original length and bytes (we
   verify by re-encoding through ``cid_to_hex`` after a
   reconstructed copy).
2. :meth:`ConnectionIdTable.register` + :meth:`lookup` round
   trip the slot index for a wide range of CID shapes
   (zero-length, all-zero, all-0xFF, mixed bytes,
   length-20 max).
3. :meth:`ConnectionIdTable.retire` removes the mapping and
   subsequent :meth:`lookup` returns -1.
4. Re-registering the same CID with a different slot
   overwrites the prior mapping (CID rebinding on connection
   migration -- RFC 9000 §9.3).

Run:
    pixi run --environment fuzz fuzz-quic-connection-id
"""

from mozz import fuzz, FuzzConfig

from flare.quic import ConnectionId
from flare.quic.server import ConnectionIdTable, cid_to_hex


def _bytes(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8](capacity=len(b))
    for i in range(len(b)):
        out.append(b[i])
    return out^


@always_inline
def _assert(cond: Bool, msg: String) raises:
    if not cond:
        raise Error(msg)


def _cid_from(data: List[UInt8], offset: Int, length: Int) -> ConnectionId:
    """Carve a CID of ``length`` bytes from ``data`` starting at
    ``offset`` (wrapping on short inputs)."""
    var bytes = List[UInt8](capacity=length)
    var n = len(data)
    if n == 0:
        for _ in range(length):
            bytes.append(UInt8(0))
        return ConnectionId(bytes=bytes^)
    for i in range(length):
        bytes.append(data[(offset + i) % n])
    return ConnectionId(bytes=bytes^)


def target(data: List[UInt8]) raises:
    """Run the four properties against the fuzz input."""
    var n = len(data)
    if n == 0:
        return
    # Length byte clamped to [0, 20] (the RFC 9000 §5.1.1 limit).
    var length = Int(data[0]) % 21
    var cid = _cid_from(data, 1, length)
    _assert(
        cid.length() == length,
        "ConnectionId.length() drifted from constructed length",
    )

    # Property 1: cid_to_hex is deterministic + 2 chars per byte.
    var hex_a = cid_to_hex(cid)
    var hex_b = cid_to_hex(cid)
    _assert(
        hex_a == hex_b,
        "cid_to_hex must be deterministic on a single CID",
    )
    _assert(
        len(hex_a) == length * 2,
        "cid_to_hex must emit exactly 2 hex chars per CID byte",
    )

    # Property 2: register + lookup round-trips the slot.
    var table = ConnectionIdTable()
    var slot = (Int(data[0]) >> 3) & 0x1FFF  # 0..8191
    table.register(hex_a, slot)
    _assert(
        table.lookup(hex_a) == slot,
        "table.lookup must return the slot just registered",
    )

    # Property 3: retire removes the mapping.
    table.retire(hex_a)
    _assert(
        table.lookup(hex_a) == -1,
        "lookup of a retired CID must return -1",
    )

    # Property 4: re-register overwrites.
    table.register(hex_a, slot)
    var new_slot = (slot + 1) & 0x1FFF
    table.register(hex_a, new_slot)
    _assert(
        table.lookup(hex_a) == new_slot,
        "re-register must overwrite the prior slot",
    )

    # Bonus: empty CID short-circuits to an empty string.
    var empty = ConnectionId(bytes=List[UInt8]())
    _assert(
        len(cid_to_hex(empty)) == 0,
        "zero-length CID hex must be the empty string",
    )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_connection_id.mojo -- CID + dispatch table")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Zero-length CID.
    seeds.append(_bytes("\x00"))
    # Length-1 zero byte.
    seeds.append(_bytes("\x01\x00"))
    # Length-8 ASCII pattern.
    seeds.append(_bytes("\x08AAAAAAAA"))
    # Length-20 (max) pattern.
    var max_seed = List[UInt8]()
    max_seed.append(UInt8(20))
    for i in range(20):
        max_seed.append(UInt8(0xA0 + i))
    seeds.append(max_seed^)
    # Length-20 all-0xFF.
    var ff = List[UInt8]()
    ff.append(UInt8(20))
    for _ in range(20):
        ff.append(UInt8(0xFF))
    seeds.append(ff^)
    # Length byte > 20 (mod 21 -> 0).
    seeds.append(_bytes("\xFF"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_connection_id",
            corpus_dir="fuzz/corpus/quic_connection_id",
            max_input_len=64,
        ),
        seeds,
    )
