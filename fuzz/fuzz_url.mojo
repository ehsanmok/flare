"""Fuzz harness: URL parser.

Tests ``Url.parse()`` for crashes on arbitrary string inputs.
``UrlParseError`` is an expected rejection; only panic-like errors are bugs.

Run:
    pixi run fuzz-url
"""

from mozz import fuzz, FuzzConfig
from flare.http.url import Url


fn target(data: List[UInt8]) raises:
    """Fuzz target: parse a URL from arbitrary bytes.

    Args:
        data: Arbitrary bytes interpreted as a UTF-8 (or invalid) string.
    """
    # Convert bytes to String — invalid UTF-8 will produce replacement chars,
    # which is fine: we want to see how the parser handles them.
    var s = String(capacity=len(data) + 1)
    for i in range(len(data)):
        s += chr(Int(data[i]))
    _ = Url.parse(s)


fn main() raises:
    print("[mozz] fuzzing Url.parse()...")

    var seeds = List[List[UInt8]]()

    fn _bytes(s: StringLiteral) -> List[UInt8]:
        var b = s.as_bytes()
        var out = List[UInt8](capacity=len(b))
        for i in range(len(b)):
            out.append(b[i])
        return out^

    # Valid URLs
    seeds.append(_bytes("http://example.com"))
    seeds.append(_bytes("https://api.example.com:8443/v1/items?filter=active"))
    seeds.append(_bytes("http://user:pass@host/path#fragment"))
    seeds.append(_bytes("https://[::1]:8080/"))

    # Edge cases
    seeds.append(_bytes("http://"))
    seeds.append(_bytes("://no-scheme"))
    seeds.append(_bytes("ftp://wrong-scheme"))
    seeds.append(_bytes(""))
    seeds.append(_bytes("http://host:99999/overflow-port"))
    seeds.append(_bytes("https://[unterminated-ipv6"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/url",
            corpus_dir="fuzz/corpus/url",
            max_input_len=512,
        ),
        seeds,
    )
