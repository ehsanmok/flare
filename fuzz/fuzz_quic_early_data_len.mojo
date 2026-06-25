"""Fuzz harness: ``flare.quic._server_0rtt.early_data_packet_len``.

The server's datagram-coalescing walk calls
:func:`early_data_packet_len` on attacker-controlled bytes to learn how
far a 0-RTT (EarlyData) long-header packet extends before the next
coalesced packet. A wrong or crashing length read would let a malformed
0-RTT packet desync the scan, so this target hammers the parser with
arbitrary input.

Properties checked:

1. ``early_data_packet_len`` never panics on arbitrary bytes -- it
   either returns a strictly positive length or raises a regular
   ``Error`` (truncated header, non-positive length).
2. On a synthesised well-formed 0-RTT packet (long header + 1-byte
   Length varint + payload) the returned length equals the exact
   packet size, matching the listener's step distance.

Run:
    pixi run --environment fuzz fuzz-quic-early-data-len
"""

from mozz import fuzz, FuzzConfig

from flare.quic._server_0rtt import early_data_packet_len
from flare.quic.packet import QUIC_VERSION_1, ConnectionId, encode_long_header


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


def _cid(n: Int) -> ConnectionId:
    var b = List[UInt8](capacity=n)
    for i in range(n):
        b.append(UInt8(i + 1))
    return ConnectionId(bytes=b^)


def target(data: List[UInt8]) raises:
    # ── A. Raw parse of fuzz bytes: must return positive or raise. ──
    try:
        var got = early_data_packet_len(Span[UInt8, _](data))
        _assert(got > 0, "early_data_packet_len returned non-positive")
    except:
        pass  # malformed input is allowed to raise

    # ── B. Synthesised well-formed 0-RTT packet round-trip. ─────────
    var dlen = 0
    var slen = 0
    if len(data) >= 2:
        dlen = Int(data[0]) % 21
        slen = Int(data[1]) % 21
    var hdr = encode_long_header(1, QUIC_VERSION_1, _cid(dlen), _cid(slen))
    var pkt = hdr.copy()
    var payload_len = 0
    if len(data) >= 3:
        payload_len = Int(data[2]) % 63  # single-byte varint range
    pkt.append(UInt8(payload_len))
    for i in range(payload_len):
        pkt.append(UInt8(i))
    var n = early_data_packet_len(Span[UInt8, _](pkt))
    _assert(
        n == len(pkt),
        "early_data_packet_len("
        + String(len(pkt))
        + "-byte packet) returned "
        + String(n),
    )


def main() raises:
    print("=" * 60)
    print("fuzz_quic_early_data_len.mojo — 0-RTT packet length parser")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    # 0-RTT type (0b01 in bits 4-5: 0xC0 | 0x10 = 0xD0), v1, empty CIDs,
    # length=4, 4 payload bytes.
    seeds.append(_bytes("\xD0\x00\x00\x00\x01\x00\x00\x04ABCD"))
    seeds.append(_bytes("\x00\x00\x00"))  # drives branch B with zero CIDs
    seeds.append(_bytes("\x08\x04\x14"))  # 8/4 CIDs, 20-byte payload
    seeds.append(_bytes("\xD0\x00\x00"))  # truncated header

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_early_data_len",
            corpus_dir="fuzz/corpus/quic_early_data_len",
            max_input_len=128,
        ),
        seeds,
    )
