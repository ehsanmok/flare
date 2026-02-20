"""Benchmark: HTTP header / URL processing throughput.

Measures the core HTTP parsing utilities in isolation (no network I/O):
  - HeaderMap: setting and looking up headers
  - URL parsing: simple and complex URLs

Results on Apple M-series (indicative):
  - HeaderMap (10 set + 3 get):  ~1–2 µs/op  → ~500K–1M ops/s
  - Url.parse (simple):           ~0.5–1 µs/op → ~1–2M ops/s

Usage:
    pixi run bench-http
"""

from benchmark import (
    Bench,
    BenchConfig,
    Bencher,
    BenchId,
    keep,
)
from flare.http import Response, HeaderMap, Url


# ── Benchmark functions ───────────────────────────────────────────────────────


fn _bench_header_set_get(mut b: Bencher) raises capturing:
    """Set 10 headers and perform 3 case-insensitive lookups."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var hm = HeaderMap()
        hm.set("Content-Type", "application/json")
        hm.set("Cache-Control", "no-cache")
        hm.set("X-Request-Id", "abc-123")
        hm.set("Authorization", "Bearer tok")
        hm.set("Accept", "text/html,application/xhtml+xml")
        hm.set("Accept-Encoding", "gzip, deflate, br")
        hm.set("Accept-Language", "en-US,en;q=0.9")
        hm.set("Connection", "keep-alive")
        hm.set("Host", "example.com")
        hm.set("User-Agent", "flare/0.1.0")
        _ = hm.get("content-type")
        _ = hm.get("x-request-id")
        _ = hm.get("user-agent")
        keep(hm)

    b.iter[call_fn]()


fn _bench_response_construction(mut b: Bencher) raises capturing:
    """Build a Response with status and 2 headers."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var r = Response(status=200)
        r.headers.set("Content-Type", "application/json")
        r.headers.set("Content-Length", "42")
        keep(r)

    b.iter[call_fn]()


fn _bench_url_parse_simple(mut b: Bencher) raises capturing:
    """Parse a simple HTTP URL with a query string."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var u = Url.parse("http://example.com/path/to/resource?foo=bar&baz=1")
        keep(u)

    b.iter[call_fn]()


fn _bench_url_parse_https(mut b: Bencher) raises capturing:
    """Parse an HTTPS URL with a non-default port and query."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var u = Url.parse(
            "https://api.example.com:8443/v2/users?page=1&limit=50"
        )
        keep(u)

    b.iter[call_fn]()


# ── Main ──────────────────────────────────────────────────────────────────────


fn main() raises:
    print(
        "════════════════════════════════════════════════════════════════════════"
    )
    print("flare HTTP Benchmark — HeaderMap / Response / URL")
    print(
        "════════════════════════════════════════════════════════════════════════"
    )
    print()

    var cfg = BenchConfig()
    cfg.verbose_metric_names = False

    var m = Bench(cfg^)
    m.bench_function[_bench_header_set_get](BenchId("HeaderMap 10set+3get"))
    m.bench_function[_bench_response_construction](
        BenchId("Response construction")
    )
    m.bench_function[_bench_url_parse_simple](BenchId("Url.parse simple"))
    m.bench_function[_bench_url_parse_https](BenchId("Url.parse https+port"))
    m.dump_report()
    print()
    print("Done.")
