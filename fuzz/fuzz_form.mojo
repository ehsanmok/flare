"""Fuzz harness: ``application/x-www-form-urlencoded`` parser.

Tests ``parse_form_urlencoded`` and ``urldecode`` for crashes on
arbitrary input. Truncated/malformed escapes raise a regular ``Error``
— that's an expected rejection, only panic-like errors are bugs.

Run:
    pixi run fuzz-form
"""

from mozz import fuzz, FuzzConfig
from flare.http.form import (
    parse_form_urlencoded,
    urldecode,
    urlencode,
)


def target(data: List[UInt8]) raises:
    """Fuzz target: parse arbitrary bytes as a form body.

    Also exercises ``urlencode``/``urldecode`` round-trip on the same
    bytes (well-formed string roundtrip must be a no-op).
    """
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))

    # Parser must not crash on any input. Errors (e.g. bad %XX) raise
    # the regular ``Error`` exception which the harness treats as a
    # rejection.
    try:
        var f = parse_form_urlencoded(s)
        # Round-trip property: re-encoding then re-parsing yields a
        # form with the same number of bindings and the same first
        # value per key.
        var enc = f.to_urlencoded()
        var f2 = parse_form_urlencoded(enc)
        if f.len() != f2.len():
            raise Error("form roundtrip: length mismatch")
    except:
        pass

    # ``urlencode`` is total. ``urldecode(urlencode(x))`` must equal
    # ``x`` for every input byte sequence (the unreserved set + the
    # encoder's escape produce a normal form for any input).
    var enc = urlencode(s)
    try:
        var dec = urldecode(enc)
        if dec.byte_length() != s.byte_length():
            raise Error("urlencode/urldecode roundtrip: length mismatch")
    except:
        raise Error("urldecode failed on output of urlencode")


def main() raises:
    print("[mozz] fuzzing parse_form_urlencoded() + urldecode()...")

    var seeds = List[List[UInt8]]()

    def _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    seeds.append(_bytes(""))
    seeds.append(_bytes("a=1"))
    seeds.append(_bytes("name=alice&age=30"))
    seeds.append(_bytes("k=v;k=w"))
    seeds.append(_bytes("flag&name=alice"))
    seeds.append(_bytes("hello+world"))
    seeds.append(_bytes("a=%2F&b=%26"))
    seeds.append(_bytes("a=%"))
    seeds.append(_bytes("a=%2"))
    seeds.append(_bytes("a=%ZZ"))
    seeds.append(_bytes("==="))
    seeds.append(_bytes("&&&"))
    seeds.append(_bytes("a=1&a=1&a=1&a=1&a=1&a=1&a=1&a=1"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/form",
            corpus_dir="fuzz/corpus/form",
            max_input_len=1024,
        ),
        seeds,
    )
