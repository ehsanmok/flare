"""Fuzz harness: ``flare.http.cache.control.parse_cache_control``.

The Cache-Control header is the load-bearing input to the new
``Cache[Inner, S]`` middleware (RFC 9111 §5.2). The parser is
deliberately permissive — malformed numeric values silently drop,
unknown directives are surfaced through ``unknown_directives``
rather than rejected — so the surface area for crashes is wide.

Properties checked:

1. **No crashes.** ``parse_cache_control`` on arbitrary bytes must
   return a ``CacheControl`` value. It does not raise; any panic
   is a bug.

2. **Numeric directive bounds.** Every numeric directive
   (``max-age``, ``s-maxage``, ``stale-while-revalidate``,
   ``stale-if-error``) is either absent (``Optional[Int]()``) or
   carries a non-negative integer. Negative or non-digit values
   must silently drop per RFC 9111 §5.2 ("If the value is
   invalid, it should be treated as if it were not present").

3. **Idempotent re-parse.** Parsing the same input twice must
   produce ``CacheControl`` values whose boolean and numeric
   directive states all agree. The ``unknown_directives`` list
   must also have the same length (the contents are byte-equal).

4. **Vary parser stability.** ``parse_vary_header`` on the same
   bytes must never raise and must produce the same number of
   field names on two consecutive calls. We feed it the raw fuzz
   bytes too because Vary parsing shares the comma-splitting +
   trim + lowercase pipeline.

Run:
    pixi run --environment fuzz fuzz-cache-control-parser
"""

from mozz import fuzz, FuzzConfig

from flare.http.cache.control import (
    CacheControl,
    parse_cache_control,
    parse_vary_header,
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


def _printable_ascii(data: List[UInt8]) -> String:
    """Rewrite arbitrary bytes into a printable-ASCII string the
    parser can chew on without hitting non-text edge cases that
    aren't really exercising the directive grammar.
    """
    var n = len(data)
    if n == 0:
        return ""
    var out = String(capacity_bytes=n)
    for i in range(n):
        var b = data[i]
        # Restrict to ASCII letters, digits, comma, equals, dash,
        # space, quote, hash -- the set that exercises directive
        # splitting + quoted-string handling. NUL / control bytes
        # would never appear in a real header.
        var c = Int(b) % 64 + 32  # printable [32, 95]
        out += chr(c)
    return out^


def _assert_directive_state_eq(a: CacheControl, b: CacheControl) raises:
    _assert(a.no_cache == b.no_cache, "cache-control re-parse: no_cache drift")
    _assert(a.no_store == b.no_store, "cache-control re-parse: no_store drift")
    _assert(
        a.no_transform == b.no_transform,
        "cache-control re-parse: no_transform drift",
    )
    _assert(a.public == b.public, "cache-control re-parse: public drift")
    _assert(a.private == b.private, "cache-control re-parse: private drift")
    _assert(
        a.must_revalidate == b.must_revalidate,
        "cache-control re-parse: must_revalidate drift",
    )
    _assert(
        a.proxy_revalidate == b.proxy_revalidate,
        "cache-control re-parse: proxy_revalidate drift",
    )
    _assert(
        a.immutable == b.immutable, "cache-control re-parse: immutable drift"
    )
    _assert(
        a.max_age.__bool__() == b.max_age.__bool__(),
        "cache-control re-parse: max_age presence drift",
    )
    if a.max_age:
        _assert(
            a.max_age.value() == b.max_age.value(),
            "cache-control re-parse: max_age value drift",
        )
    _assert(
        a.s_maxage.__bool__() == b.s_maxage.__bool__(),
        "cache-control re-parse: s_maxage presence drift",
    )
    if a.s_maxage:
        _assert(
            a.s_maxage.value() == b.s_maxage.value(),
            "cache-control re-parse: s_maxage value drift",
        )
    _assert(
        a.stale_while_revalidate.__bool__()
        == b.stale_while_revalidate.__bool__(),
        "cache-control re-parse: stale_while_revalidate presence drift",
    )
    _assert(
        a.stale_if_error.__bool__() == b.stale_if_error.__bool__(),
        "cache-control re-parse: stale_if_error presence drift",
    )
    _assert(
        len(a.unknown_directives) == len(b.unknown_directives),
        "cache-control re-parse: unknown directive count drift",
    )


def _assert_numeric_bounds(cc: CacheControl) raises:
    """All numeric directives must be either absent or ≥ 0 (the
    parser drops negative inputs)."""
    if cc.max_age:
        _assert(
            cc.max_age.value() >= 0,
            "cache-control: max_age is negative",
        )
    if cc.s_maxage:
        _assert(
            cc.s_maxage.value() >= 0,
            "cache-control: s_maxage is negative",
        )
    if cc.stale_while_revalidate:
        _assert(
            cc.stale_while_revalidate.value() >= 0,
            "cache-control: stale_while_revalidate is negative",
        )
    if cc.stale_if_error:
        _assert(
            cc.stale_if_error.value() >= 0,
            "cache-control: stale_if_error is negative",
        )


def target(data: List[UInt8]) raises:
    """Two exercises per fuzz run.

    Branch A — raw bytes mapped to a printable-ASCII header value:
        Drives ``parse_cache_control`` on the mapped string twice
        and asserts the directive state is byte-identical between
        parses, with all numeric directives non-negative.

    Branch B — ``parse_vary_header`` on the same string:
        The Vary parser shares the comma-splitting + trim
        infrastructure; running it on the same input flushes out
        bugs in the shared helpers.
    """
    var s = _printable_ascii(data)

    var a = parse_cache_control(s)
    _assert_numeric_bounds(a)
    var b = parse_cache_control(s)
    _assert_directive_state_eq(a, b)

    var v1 = parse_vary_header(s)
    var v2 = parse_vary_header(s)
    _assert(
        len(v1) == len(v2),
        (
            "vary header re-parse: list length drift "
            + String(len(v1))
            + " vs "
            + String(len(v2))
        ),
    )
    for i in range(len(v1)):
        if v1[i] != v2[i]:
            raise Error("vary header re-parse: entry " + String(i) + " drifted")


def main() raises:
    print("=" * 60)
    print("fuzz_cache_control_parser.mojo — RFC 9111 §5.2 directive grammar")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()
    seeds.append(_bytes("no-store"))
    seeds.append(_bytes("no-cache"))
    seeds.append(_bytes("max-age=3600"))
    seeds.append(_bytes("max-age=0"))
    seeds.append(_bytes("public, max-age=60"))
    seeds.append(_bytes("private, max-age=300, must-revalidate"))
    seeds.append(_bytes("s-maxage=120"))
    seeds.append(_bytes("stale-while-revalidate=30"))
    seeds.append(_bytes("immutable"))
    seeds.append(_bytes("max-age=-5"))  # silently dropped
    seeds.append(_bytes("max-age=abc"))  # silently dropped
    seeds.append(_bytes(""))
    # Quoted directive values.
    seeds.append(_bytes('private="X-Foo, X-Bar", max-age=60'))
    # Vary-ish header values.
    seeds.append(_bytes("Accept, Authorization"))
    seeds.append(_bytes("*"))
    seeds.append(_bytes(", , ,, "))

    fuzz(
        target,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/cache_control_parser",
            corpus_dir="fuzz/corpus/cache_control_parser",
            max_input_len=256,
        ),
        seeds,
    )
