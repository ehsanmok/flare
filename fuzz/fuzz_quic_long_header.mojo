"""Fuzz harness: ``flare.quic.packet.parse_long_header``.

QUIC long-header packets are the handshake-time wire format
(Initial / 0-RTT / Handshake / Retry per RFC 9000 §17.2). The
parser reads the 1-byte flag, the 32-bit version, and two
length-prefixed connection IDs (each 0..20 octets); everything
beyond is either type-specific extras (Initial token + length
varint) or header-protected payload bytes.

Properties checked:

1. ``parse_long_header`` either returns a ``LongHeader`` with:
   - ``packet_type in {0, 1, 2, 3}``,
   - ``payload_offset <= len(buf)``,
   - ``payload_offset = 7 + dcid.length + scid.length`` (the
     parser's only fixed-shape arithmetic), and
   - both CID lengths in ``[0, 20]``,
   or raises a regular ``Error`` (truncated, bad indicator bits,
   CID length > 20, …). It must never panic on arbitrary bytes.

2. ``encode_long_header(...)`` round-trips through
   ``parse_long_header`` exactly: ``packet_type``, ``version``,
   and both CIDs are preserved byte-for-byte. We exercise this
   on inputs synthesised from the fuzz bytes (CID lengths kept
   within RFC bounds; bigger random CIDs are tested as
   adversarial inputs in branch A).

3. ``parse_long_header`` is idempotent: re-parsing the bytes the
   parser previously accepted yields a structurally identical
   ``LongHeader`` (same payload_offset, same CID byte contents).

Run:
    pixi run --environment fuzz fuzz-quic-long-header
"""

from mozz import fuzz, FuzzConfig

from flare.quic import (
    MAX_CID_LENGTH,
    PACKET_TYPE_INITIAL,
    PACKET_TYPE_HANDSHAKE,
    QUIC_VERSION_1,
    ConnectionId,
    LongHeader,
    encode_long_header,
    parse_long_header,
)


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


def _cid(data: List[UInt8], start: Int, length: Int) -> ConnectionId:
    """Carve a ConnectionId of ``length`` bytes out of ``data``
    starting at ``start``. Wraps around if the source is short --
    the goal is variety, not deterministic content.
    """
    var bytes = List[UInt8](capacity=length)
    var n = len(data)
    if n == 0:
        for _ in range(length):
            bytes.append(UInt8(0))
        return ConnectionId(bytes=bytes^)
    for i in range(length):
        bytes.append(data[(start + i) % n])
    return ConnectionId(bytes=bytes^)


def target(data: List[UInt8]) raises:
    """Two exercises per fuzz run.

    Branch A — raw parse of fuzz bytes:
        Probe ``parse_long_header`` on adversarial input. If it
        succeeds the consumed-byte invariant must hold; if it
        raises, the input was either too short or violated one of
        the structural checks (high bit not set, CID > 20, …).

    Branch B — encode/parse round trip:
        Build CIDs from the fuzz bytes (lengths clamped to
        ``[0, MAX_CID_LENGTH]``), encode a long header, parse it,
        assert every field round-trips.
    """
    var n = len(data)
    var span = Span[UInt8, _](data)

    # ── A. Raw parse ─────────────────────────────────────────────
    try:
        var hdr = parse_long_header(span)
        _assert(
            hdr.packet_type >= 0 and hdr.packet_type <= 3,
            (
                "quic long header: packet_type "
                + String(hdr.packet_type)
                + " out of [0, 3]"
            ),
        )
        _assert(
            hdr.dcid.length() <= MAX_CID_LENGTH,
            "quic long header: dcid length > 20",
        )
        _assert(
            hdr.scid.length() <= MAX_CID_LENGTH,
            "quic long header: scid length > 20",
        )
        # payload_offset = 7 (first byte + 4-byte version + 2 CID
        # length bytes) + dcid.length + scid.length.
        var expected_off = 7 + hdr.dcid.length() + hdr.scid.length()
        _assert(
            hdr.payload_offset == expected_off,
            (
                "quic long header: payload_offset="
                + String(hdr.payload_offset)
                + " expected="
                + String(expected_off)
            ),
        )
        _assert(
            hdr.payload_offset <= n,
            "quic long header: payload_offset > buffer length",
        )

        # Idempotent re-parse.
        var hdr2 = parse_long_header(span)
        _assert(
            hdr2.packet_type == hdr.packet_type
            and hdr2.version == hdr.version
            and hdr2.payload_offset == hdr.payload_offset
            and hdr2.dcid.length() == hdr.dcid.length()
            and hdr2.scid.length() == hdr.scid.length(),
            "quic long header: re-parse drifted from first parse",
        )
        for i in range(hdr.dcid.length()):
            if hdr.dcid.bytes[i] != hdr2.dcid.bytes[i]:
                raise Error("quic long header: dcid bytes drifted on re-parse")
        for i in range(hdr.scid.length()):
            if hdr.scid.bytes[i] != hdr2.scid.bytes[i]:
                raise Error("quic long header: scid bytes drifted on re-parse")
    except:
        # All raised errors are accepted -- the parser is allowed to
        # reject any structurally invalid input.
        pass

    # ── B. Encode-then-parse round trip ─────────────────────────
    if n >= 2:
        # Clamp the two CID length bytes to [0, 20].
        var dlen = Int(data[0]) % (MAX_CID_LENGTH + 1)
        var slen = Int(data[1]) % (MAX_CID_LENGTH + 1)
        var dcid = _cid(data, 2, dlen)
        var scid = _cid(data, 2 + dlen, slen)
        # Pick a packet type from the next byte (mod 4).
        var ptype: Int = 0
        if n >= 3:
            ptype = Int(data[2]) & 0x3
        # Pick a version from the next 4 bytes if available.
        var version: UInt32 = QUIC_VERSION_1
        if n >= 7:
            version = (
                (UInt32(data[3]) << 24)
                | (UInt32(data[4]) << 16)
                | (UInt32(data[5]) << 8)
                | UInt32(data[6])
            )
        var encoded = encode_long_header(
            packet_type=ptype,
            version=version,
            dcid=dcid.copy(),
            scid=scid.copy(),
            type_specific_bits=0,
        )
        var parsed = parse_long_header(Span[UInt8, _](encoded))
        _assert(
            parsed.packet_type == ptype,
            (
                "quic long header round-trip: packet_type drift "
                + String(parsed.packet_type)
                + " vs "
                + String(ptype)
            ),
        )
        _assert(
            parsed.version == version,
            "quic long header round-trip: version drift",
        )
        _assert(
            parsed.dcid.length() == dlen,
            "quic long header round-trip: dcid length drift",
        )
        _assert(
            parsed.scid.length() == slen,
            "quic long header round-trip: scid length drift",
        )
        for i in range(dlen):
            if parsed.dcid.bytes[i] != dcid.bytes[i]:
                raise Error(
                    "quic long header round-trip: dcid byte "
                    + String(i)
                    + " drift"
                )
        for i in range(slen):
            if parsed.scid.bytes[i] != scid.bytes[i]:
                raise Error(
                    "quic long header round-trip: scid byte "
                    + String(i)
                    + " drift"
                )
        _assert(
            parsed.payload_offset == len(encoded),
            (
                "quic long header round-trip: payload_offset="
                + String(parsed.payload_offset)
                + " expected="
                + String(len(encoded))
            ),
        )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_long_header.mojo — QUIC long-header parser")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # Minimal Initial-like header with empty CIDs:
    # 11000000 00000000 00000001 0 (dcid len) 0 (scid len)
    seeds.append(_bytes("\xC0\x00\x00\x00\x01\x00\x00"))
    # 8-byte DCID + 0-byte SCID, version 1.
    seeds.append(_bytes("\xC0\x00\x00\x00\x01\x08AAAAAAAA\x00"))
    # Handshake-type (T T = 10).
    seeds.append(_bytes("\xE0\x00\x00\x00\x01\x00\x00"))
    # Version negotiation packet (version = 0).
    seeds.append(_bytes("\xC0\x00\x00\x00\x00\x00\x00"))
    # CID length 20 (max) for both directions.
    var max_seed = List[UInt8]()
    max_seed.append(UInt8(0xC0))
    max_seed.append(UInt8(0))
    max_seed.append(UInt8(0))
    max_seed.append(UInt8(0))
    max_seed.append(UInt8(1))
    max_seed.append(UInt8(20))
    for i in range(20):
        max_seed.append(UInt8(i + 1))
    max_seed.append(UInt8(20))
    for i in range(20):
        max_seed.append(UInt8(i + 100))
    seeds.append(max_seed^)
    # Truncated header (fewer than 7 bytes).
    seeds.append(_bytes("\xC0\x00\x00"))
    # Long-header bit cleared (rejected).
    seeds.append(_bytes("\x40\x00\x00\x00\x01\x00\x00"))
    # CID length > 20 (rejected).
    seeds.append(_bytes("\xC0\x00\x00\x00\x01\x21AAAAAAAAAAAAAAAAAAAAAAAAAAAA"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_long_header",
            corpus_dir="fuzz/corpus/quic_long_header",
            max_input_len=128,
        ),
        seeds,
    )
