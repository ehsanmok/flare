"""Benchmark: IP address parsing and DNS resolution throughput.

Measures:
- ``IpAddr.parse`` throughput for IPv4 and IPv6 strings (Mops/s).
- ``SocketAddr.parse`` throughput for host:port strings.
- ``resolve("localhost")`` round-trip latency (µs/call).

Usage:
    pixi run bench-parse

These benchmarks establish the baseline for Phase 1–2.  SIMD does NOT help
here because:
- ``IpAddr.parse`` delegates to ``inet_pton`` (libc), a 7–39 byte input.
- DNS resolution involves a system call + resolver I/O; no inner loop.

The parse benchmarks confirm the overhead is in the FFI boundary + string
construction, not in CPU-bound scanning.
"""

from benchmark import (
    Bench,
    BenchConfig,
    Bencher,
    BenchId,
    ThroughputMeasure,
    BenchMetric,
)
from flare.net import IpAddr, SocketAddr
from flare.dns import resolve, resolve_v4


# ── IpAddr.parse throughput ───────────────────────────────────────────────────


fn bench_ip_parse_v4(mut b: Bencher) raises capturing:
    """Measure IpAddr.parse() throughput for an IPv4 string."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = IpAddr.parse("192.168.100.200")
        # Prevent the compiler from optimising away the result.
        _ = addr.is_v4()

    b.iter[call_fn]()


fn bench_ip_parse_v6(mut b: Bencher) raises capturing:
    """Measure IpAddr.parse() throughput for an IPv6 string."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = IpAddr.parse("2001:db8::1")
        _ = addr.is_v6()

    b.iter[call_fn]()


fn bench_ip_parse_v4_broadcast(mut b: Bencher) raises capturing:
    """Measure IpAddr.parse() for the broadcast address (worst-case dotted-decimal).
    """

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = IpAddr.parse("255.255.255.255")
        _ = addr.is_v4()

    b.iter[call_fn]()


# ── SocketAddr.parse throughput ───────────────────────────────────────────────


fn bench_socket_addr_parse(mut b: Bencher) raises capturing:
    """Measure SocketAddr.parse() throughput for '1.2.3.4:8080'."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = SocketAddr.parse("192.168.1.100:8080")
        _ = addr.port

    b.iter[call_fn]()


fn bench_socket_addr_parse_ipv6(mut b: Bencher) raises capturing:
    """Measure SocketAddr.parse() throughput for '[::1]:443'."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = SocketAddr.parse("[::1]:443")
        _ = addr.port

    b.iter[call_fn]()


# ── IpAddr construction (no parsing) ─────────────────────────────────────────


fn bench_ip_localhost(mut b: Bencher) raises capturing:
    """Measure IpAddr.localhost() construction — pure struct init, no FFI."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addr = IpAddr.localhost()
        _ = addr.is_v4()

    b.iter[call_fn]()


# ── DNS resolution latency ────────────────────────────────────────────────────


fn bench_dns_resolve_localhost(mut b: Bencher) raises capturing:
    """Measure resolve('localhost') round-trip latency including getaddrinfo(3).
    """

    @parameter
    @always_inline
    fn call_fn() raises:
        var addrs = resolve("localhost")
        _ = len(addrs)

    b.iter[call_fn]()


fn bench_dns_resolve_v4_localhost(mut b: Bencher) raises capturing:
    """Measure resolve_v4('localhost') latency (IPv4-only filter)."""

    @parameter
    @always_inline
    fn call_fn() raises:
        var addrs = resolve_v4("localhost")
        _ = len(addrs)

    b.iter[call_fn]()


# ── main ──────────────────────────────────────────────────────────────────────


fn main() raises:
    print("=" * 70)
    print("flare Phase 1–2 Benchmark: IP parsing + DNS resolution")
    print("=" * 70)
    print()
    print("Note: SIMD does NOT help here.  See development.md §SIMD Analysis.")
    print("  - IpAddr.parse delegates to libc inet_pton (7–39 byte inputs).")
    print("  - DNS involves syscall + resolver I/O; no CPU-bound loop.")
    print()

    var bench = Bench(BenchConfig(max_iters=1000, max_batch_size=64))

    bench.bench_function[bench_ip_parse_v4](BenchId("IpAddr.parse IPv4"))
    bench.bench_function[bench_ip_parse_v4_broadcast](
        BenchId("IpAddr.parse IPv4 broadcast")
    )
    bench.bench_function[bench_ip_parse_v6](BenchId("IpAddr.parse IPv6"))
    bench.bench_function[bench_socket_addr_parse](
        BenchId("SocketAddr.parse IPv4:port")
    )
    bench.bench_function[bench_socket_addr_parse_ipv6](
        BenchId("SocketAddr.parse [IPv6]:port")
    )
    bench.bench_function[bench_ip_localhost](
        BenchId("IpAddr.localhost() struct init")
    )

    print()
    print("── DNS resolution (system call + resolver I/O) ──")
    print("   Using fewer iterations: getaddrinfo is not a tight loop.")
    print()

    # DNS calls are slow (system call + resolver cache), so use fewer iterations.
    var dns_bench = Bench(BenchConfig(max_iters=50))
    dns_bench.bench_function[bench_dns_resolve_localhost](
        BenchId("resolve('localhost')")
    )
    dns_bench.bench_function[bench_dns_resolve_v4_localhost](
        BenchId("resolve_v4('localhost')")
    )

    bench.dump_report()
    dns_bench.dump_report()
