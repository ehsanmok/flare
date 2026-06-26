"""Fuzz harness: ``flare.quic.retry`` token + Retry parse paths.

The server validates an attacker-influenced Retry token on every
address-validated Initial, so the parse path must never panic on
arbitrary bytes -- a forged / truncated / oversized token is simply
rejected (``validate_retry_token`` returns ``None``).

Properties checked:

1. ``validate_retry_token`` never panics on arbitrary token bytes; it
   returns either ``None`` or a recovered DCID of length <= 20.
2. ``verify_retry_integrity`` never panics on arbitrary packet bytes.

Run:
    pixi run --environment fuzz fuzz-quic-retry
"""

from mozz import FuzzConfig, fuzz

from flare.quic.packet import ConnectionId
from flare.quic.retry import validate_retry_token, verify_retry_integrity


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
    var key = List[UInt8]()
    for v in [1, 2, 3, 4, 5, 6, 7, 8]:
        key.append(UInt8(v))
    var addr = List[UInt8]()
    for v in [127, 0, 0, 1, 0x1F, 0x90]:
        addr.append(UInt8(v))

    var recovered = validate_retry_token(
        key, data, addr, UInt64(1000), UInt64(10000)
    )
    if Bool(recovered):
        _assert(
            recovered.value().length() <= 20,
            "recovered odcid exceeds 20 bytes",
        )

    # Retry integrity verification over arbitrary "packet" bytes must
    # also never panic (it returns False on a mismatch).
    var odcid_bytes = List[UInt8]()
    odcid_bytes.append(UInt8(0xAA))
    odcid_bytes.append(UInt8(0xBB))
    var odcid = ConnectionId(bytes=odcid_bytes^)
    var _ok = verify_retry_integrity(data, odcid)


def main() raises:
    print("=" * 60)
    print("fuzz_quic_retry.mojo -- RFC 9000 Retry token + integrity")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("\x01\x00\x00\x00\x00\x00\x00\x03\xe8\x00"))
    seeds.append(_bytes(""))
    seeds.append(_bytes("\x01"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=100_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/quic_retry",
            corpus_dir="fuzz/corpus/quic_retry",
            max_input_len=256,
        ),
        seeds,
    )
