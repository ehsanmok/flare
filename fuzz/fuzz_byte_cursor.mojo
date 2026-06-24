"""Fuzz harness: ``flare.io.byte_cursor`` (ByteReader / ByteWriter).

Three property contracts over arbitrary input bytes:

1. **Bounds safety.** A sequence of reads driven by the fuzz bytes
   either succeeds within bounds or raises a regular ``Error`` -- it
   must never read out of bounds or panic. After every operation the
   cursor invariants hold: ``0 <= position <= len`` and
   ``remaining == len - position``.

2. **UTF-8 honesty.** ``read_utf8(n)`` on arbitrary bytes either
   returns a ``String`` of exactly ``n`` bytes (the bytes were valid
   UTF-8) or raises. It never panics and never advances the cursor on
   failure.

3. **Encode/decode round trip.** Values written through ``ByteWriter``
   at every integer width read back identical through ``ByteReader``
   (be<->be, le<->le).

Run:
    pixi run --environment fuzz fuzz-byte-cursor
"""

from mozz import fuzz, FuzzConfig

from flare.io import ByteReader, ByteWriter


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


def target(data: List[UInt8]) raises:
    var n = len(data)
    var span = Span[UInt8, _](data)

    # ── 1. Bounds-safe read walk ────────────────────────────────
    # Use each byte as an opcode selecting a read width; every read is
    # guarded. The cursor invariants must hold no matter what.
    var r = ByteReader(span)
    var guard = 0
    while r.remaining() > 0 and guard < 4096:
        guard += 1
        var op = Int(data[r.position() % n]) % 6
        var before = r.position()
        try:
            if op == 0:
                _ = r.read_u8()
            elif op == 1:
                _ = r.read_u16_be()
            elif op == 2:
                _ = r.read_u32_le()
            elif op == 3:
                _ = r.read_u64_be()
            elif op == 4:
                _ = r.skip(3)
            else:
                _ = r.read_bytes(2)
        except:
            # A short read must leave the cursor untouched.
            _assert(
                r.position() == before,
                "byte_cursor: cursor moved on a failed read",
            )
            # Stop walking once we hit the first short read.
            break
        # Invariants after every successful op.
        _assert(
            r.position() >= before,
            "byte_cursor: position went backwards",
        )
        _assert(
            r.position() <= n,
            "byte_cursor: position past end of buffer",
        )
        _assert(
            r.remaining() == n - r.position(),
            "byte_cursor: remaining() inconsistent with position()",
        )

    # ── 2. read_utf8 honesty on arbitrary bytes ─────────────────
    var r2 = ByteReader(span)
    try:
        var s = r2.read_utf8(n)
        # Succeeded => bytes were valid UTF-8; the String holds exactly
        # n bytes and the cursor consumed all of them.
        _assert(
            s.byte_length() == n,
            "byte_cursor: read_utf8 length drift",
        )
        _assert(
            r2.position() == n,
            "byte_cursor: read_utf8 did not consume n bytes",
        )
    except:
        # Rejected (invalid UTF-8 or short) => cursor untouched.
        _assert(
            r2.position() == 0,
            "byte_cursor: read_utf8 advanced on failure",
        )

    # ── 3. Encode/decode round trip ─────────────────────────────
    if n >= 8:
        var v8: UInt64 = 0
        for i in range(8):
            v8 |= UInt64(data[i]) << (UInt64(i) * 8)
        var v4 = UInt32(v8 & 0xFFFFFFFF)
        var v2 = UInt16(v8 & 0xFFFF)
        var v1 = UInt8(v8 & 0xFF)

        var w = ByteWriter()
        w.write_u8(v1)
        w.write_u16_be(v2)
        w.write_u16_le(v2)
        w.write_u32_be(v4)
        w.write_u32_le(v4)
        w.write_u64_be(v8)
        w.write_u64_le(v8)
        var encoded = w.take()

        var rr = ByteReader(Span[UInt8, _](encoded))
        _assert(rr.read_u8() == v1, "byte_cursor: u8 round-trip drift")
        _assert(rr.read_u16_be() == v2, "byte_cursor: u16_be round-trip drift")
        _assert(rr.read_u16_le() == v2, "byte_cursor: u16_le round-trip drift")
        _assert(rr.read_u32_be() == v4, "byte_cursor: u32_be round-trip drift")
        _assert(rr.read_u32_le() == v4, "byte_cursor: u32_le round-trip drift")
        _assert(rr.read_u64_be() == v8, "byte_cursor: u64_be round-trip drift")
        _assert(rr.read_u64_le() == v8, "byte_cursor: u64_le round-trip drift")
        _assert(
            rr.remaining() == 0,
            "byte_cursor: round-trip left trailing bytes",
        )


def main() raises:
    print("=" * 60)
    print("fuzz_byte_cursor.mojo — ByteReader / ByteWriter")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x00"))
    seeds.append(_bytes("hello"))
    seeds.append(_bytes("\x00\x00\x00\x05hello"))
    seeds.append(_bytes("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"))
    seeds.append(_bytes("\xC3\xA9"))  # valid 2-byte UTF-8 (é)
    seeds.append(_bytes("\xFF"))  # invalid UTF-8 lead byte
    seeds.append(_bytes("\xE2\x82\xAC"))  # valid 3-byte UTF-8 (€)
    seeds.append(_bytes("\xC3"))  # truncated 2-byte sequence

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/byte_cursor",
            corpus_dir="fuzz/corpus/byte_cursor",
            max_input_len=256,
        ),
        seeds,
    )
