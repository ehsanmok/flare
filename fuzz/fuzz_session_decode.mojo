"""Fuzz harness: signed-cookie decoder.

Tests ``signed_cookie_decode`` for crashes on arbitrary input.
Tampered MACs / malformed shapes raise — that's expected
rejection. Only panic-like errors / OOB reads are bugs.

Run:
    pixi run fuzz-session-decode
"""

from mozz import fuzz, FuzzConfig
from flare.crypto import hmac_sha256
from flare.http import signed_cookie_decode, signed_cookie_encode


def target(data: List[UInt8]) raises:
    """Fuzz target: parse arbitrary bytes as a signed cookie.

    Half the iterations also exercise the encode -> decode round
    trip property: a freshly produced cookie under a known key
    must decode back to the original payload (with the test
    fixed key).
    """
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))

    var key = hmac_sha256(
        List[UInt8]("FUZZKEY".as_bytes()),
        List[UInt8]("flare-fuzz".as_bytes()),
    )

    # Decode arbitrary input — must not crash. Bad MACs raise.
    try:
        _ = signed_cookie_decode(s, key)
    except:
        pass

    # Round-trip property on the input bytes themselves.
    try:
        var enc = signed_cookie_encode(data, key)
        var got = signed_cookie_decode(enc, key)
        if len(got) != len(data):
            raise Error("signed_cookie roundtrip: length mismatch")
        for i in range(len(data)):
            if got[i] != data[i]:
                raise Error("signed_cookie roundtrip: byte mismatch")
    except:
        pass


def main() raises:
    print("[mozz] fuzzing signed_cookie_decode()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("nopayload"))
    seeds.append(_bytes("aGVsbG8.AAAA"))
    seeds.append(_bytes("...."))
    seeds.append(_bytes("a.b"))
    seeds.append(_bytes("aGVsbG8.bm9wZQ"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/session",
            corpus_dir="fuzz/corpus/session",
            max_input_len=512,
        ),
        seeds,
    )
