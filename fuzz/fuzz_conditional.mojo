"""Fuzz harness: conditional-request header parsers (ETag / HTTP-date).

The ``If-None-Match`` / ``If-Match`` / ``If-Modified-Since`` request
headers are untrusted client input consumed by the RFC 9110 §13
``Conditional`` cache middleware. The ETag CSV matcher and the
HTTP-date parser must never panic on arbitrary bytes and must be
stable (idempotent) across calls.

Run:
    pixi run --environment fuzz fuzz-conditional
"""

from mozz import fuzz, FuzzConfig

from flare.http.conditional import (
    _any_etag_matches,
    _httpdate_to_unix,
    _split_csv,
    fnv1a_etag,
)


def _printable(data: List[UInt8], start: Int, n: Int) -> String:
    var out = String()
    var end = start + n
    if end > len(data):
        end = len(data)
    for i in range(start, end):
        var c = Int(data[i])
        # Keep it in a header-ish printable band incl. comma / quote / colon.
        if c < 0x20 or c > 0x7E:
            out += "x"
        else:
            out += chr(c)
    return out^


def target(data: List[UInt8]) raises:
    if len(data) < 2:
        return
    var split = Int(data[0]) % (len(data))
    var a = _printable(data, 1, split)
    var b = _printable(data, 1 + split, len(data))

    # ETag matcher over an arbitrary If-None-Match CSV against an
    # arbitrary server etag: no panic + idempotent.
    var m1 = _any_etag_matches(a, b, False)
    var m2 = _any_etag_matches(a, b, False)
    if m1 != m2:
        raise Error("_any_etag_matches not idempotent")
    _ = _any_etag_matches(a, b, True)  # strong compare path

    # CSV splitter + HTTP-date parser on arbitrary bytes: no panic.
    _ = _split_csv(a)
    var d1 = _httpdate_to_unix(b)
    var d2 = _httpdate_to_unix(b)
    if d1 != d2:
        raise Error("_httpdate_to_unix not idempotent")

    # fnv1a_etag over the raw bytes: stable strong etag.
    var e1 = fnv1a_etag(Span[UInt8, _](data))
    var e2 = fnv1a_etag(Span[UInt8, _](data))
    if e1 != e2:
        raise Error("fnv1a_etag not deterministic")


def _seed(s: StringLiteral) -> List[UInt8]:
    var b = s.as_bytes()
    var out = List[UInt8]()
    out.append(UInt8(4))  # split byte
    for i in range(len(b)):
        out.append(b[i])
    return out^


def main() raises:
    print("=" * 60)
    print("fuzz_conditional.mojo — RFC 9110 conditional-request parsers")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_seed('"abc", "def"'))
    seeds.append(_seed('W/"weak", *'))
    seeds.append(_seed("Sun, 06 Nov 1994 08:49:37 GMT"))
    seeds.append(_seed("*"))
    seeds.append(_seed(", , ,,"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/conditional",
            corpus_dir="fuzz/corpus/conditional",
            max_input_len=256,
        ),
        seeds,
    )
