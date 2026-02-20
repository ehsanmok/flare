"""Benchmark: WebSocket payload XOR masking — scalar vs SIMD.

RFC 6455 §5.3 requires every client→server frame payload byte to be XOR'd
with a rotating 4-byte masking key.  For large messages this is the dominant
CPU cost of WebSocket encoding on the client side.

This benchmark directly measures the throughput advantage of SIMD over scalar
for the masking hot-path, across several payload sizes.

Usage:
    pixi run bench-ws-mask

Expected results on Apple M-series (ARM NEON, 16-byte SIMD vectors):
  - Scalar:   ~2–4 GB/s
  - SIMD-32:  ~8–20 GB/s  (4–10× speedup on sustained payloads)

Expected results on x86-64 with AVX2 (32-byte SIMD vectors):
  - Scalar:   ~2–4 GB/s
  - SIMD-32:  ~16–24 GB/s (8–12× speedup on sustained payloads)

The speedup is significant for payloads ≥ 128 B (amortises SIMD setup cost).
For tiny frames (< 32 B) the scalar loop is comparable or faster.
"""

from benchmark import (
    Bench,
    BenchConfig,
    Bencher,
    BenchId,
    ThroughputMeasure,
    BenchMetric,
    keep,
)
from memory import UnsafePointer

# ── SIMD width ────────────────────────────────────────────────────────────────

# 32-byte chunks = 256-bit (AVX2 on x86-64, emulated 2×NEON on ARM).
comptime SIMD_WIDTH: Int = 32


# ── Payload allocation helper ─────────────────────────────────────────────────


fn _alloc_payload(n: Int) -> List[UInt8]:
    """Allocate n bytes filled with a deterministic pattern.

    Args:
        n: Number of bytes to allocate and fill.

    Returns:
        A List populated with ``i & 0xFF`` for i in 0..n.
    """
    var buf = List[UInt8](capacity=n)
    for i in range(n):
        buf.append(UInt8(i & 0xFF))
    return buf^


fn _alloc_zeroed(n: Int) -> List[UInt8]:
    """Allocate n zero-bytes as output buffer.

    Args:
        n: Number of bytes to allocate.

    Returns:
        A List of n zero bytes.
    """
    var buf = List[UInt8](capacity=n)
    for _ in range(n):
        buf.append(UInt8(0))
    return buf^


# ── Benchmark functions ───────────────────────────────────────────────────────
# Each function allocates payload + output outside the timed loop and captures
# the raw pointers. Masking logic is inlined so Mojo's origin tracker can see
# that the output pointer comes from a `var` List (mutable).


fn _bench_scalar_32(mut b: Bencher) raises capturing:
    """Scalar mask, 32-byte payload — below one SIMD chunk."""
    var payload = _alloc_payload(32)
    var output = _alloc_zeroed(32)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    @parameter
    @always_inline
    fn call_fn():
        for i in range(32):
            (dst + i).store(src[i] ^ key[i & 3])
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_simd_32(mut b: Bencher) raises capturing:
    """SIMD mask, 32-byte payload — exactly one SIMD chunk."""
    var payload = _alloc_payload(32)
    var output = _alloc_zeroed(32)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    # Pre-compute tiled key outside the timed loop.
    var tiled = SIMD[DType.uint8, SIMD_WIDTH]()

    @parameter
    for i in range(SIMD_WIDTH):
        tiled[i] = key[i & 3]

    @parameter
    @always_inline
    fn call_fn():
        var chunk = src.load[width=SIMD_WIDTH]()
        dst.store[width=SIMD_WIDTH](chunk ^ tiled)
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_scalar_128(mut b: Bencher) raises capturing:
    """Scalar mask, 128-byte payload — 4 SIMD chunks."""
    var payload = _alloc_payload(128)
    var output = _alloc_zeroed(128)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    @parameter
    @always_inline
    fn call_fn():
        for i in range(128):
            (dst + i).store(src[i] ^ key[i & 3])
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_simd_128(mut b: Bencher) raises capturing:
    """SIMD mask, 128-byte payload — 4 SIMD chunks."""
    var payload = _alloc_payload(128)
    var output = _alloc_zeroed(128)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()
    var tiled = SIMD[DType.uint8, SIMD_WIDTH]()

    @parameter
    for i in range(SIMD_WIDTH):
        tiled[i] = key[i & 3]

    @parameter
    @always_inline
    fn call_fn():
        var i = 0
        while i + SIMD_WIDTH <= 128:
            var chunk = (src + i).load[width=SIMD_WIDTH]()
            (dst + i).store[width=SIMD_WIDTH](chunk ^ tiled)
            i += SIMD_WIDTH
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_scalar_1k(mut b: Bencher) raises capturing:
    """Scalar mask, 1 KB payload."""
    var payload = _alloc_payload(1024)
    var output = _alloc_zeroed(1024)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    @parameter
    @always_inline
    fn call_fn():
        for i in range(1024):
            (dst + i).store(src[i] ^ key[i & 3])
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_simd_1k(mut b: Bencher) raises capturing:
    """SIMD mask, 1 KB payload."""
    var payload = _alloc_payload(1024)
    var output = _alloc_zeroed(1024)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()
    var tiled = SIMD[DType.uint8, SIMD_WIDTH]()

    @parameter
    for i in range(SIMD_WIDTH):
        tiled[i] = key[i & 3]

    @parameter
    @always_inline
    fn call_fn():
        var i = 0
        while i + SIMD_WIDTH <= 1024:
            var chunk = (src + i).load[width=SIMD_WIDTH]()
            (dst + i).store[width=SIMD_WIDTH](chunk ^ tiled)
            i += SIMD_WIDTH
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_scalar_64k(mut b: Bencher) raises capturing:
    """Scalar mask, 64 KB payload."""
    var payload = _alloc_payload(65536)
    var output = _alloc_zeroed(65536)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    @parameter
    @always_inline
    fn call_fn():
        for i in range(65536):
            (dst + i).store(src[i] ^ key[i & 3])
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_simd_64k(mut b: Bencher) raises capturing:
    """SIMD mask, 64 KB payload."""
    var payload = _alloc_payload(65536)
    var output = _alloc_zeroed(65536)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()
    var tiled = SIMD[DType.uint8, SIMD_WIDTH]()

    @parameter
    for i in range(SIMD_WIDTH):
        tiled[i] = key[i & 3]

    @parameter
    @always_inline
    fn call_fn():
        var i = 0
        while i + SIMD_WIDTH <= 65536:
            var chunk = (src + i).load[width=SIMD_WIDTH]()
            (dst + i).store[width=SIMD_WIDTH](chunk ^ tiled)
            i += SIMD_WIDTH
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_scalar_1m(mut b: Bencher) raises capturing:
    """Scalar mask, 1 MB payload."""
    var payload = _alloc_payload(1048576)
    var output = _alloc_zeroed(1048576)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()

    @parameter
    @always_inline
    fn call_fn():
        for i in range(1048576):
            (dst + i).store(src[i] ^ key[i & 3])
        keep(dst[0])

    b.iter[call_fn]()


fn _bench_simd_1m(mut b: Bencher) raises capturing:
    """SIMD mask, 1 MB payload."""
    var payload = _alloc_payload(1048576)
    var output = _alloc_zeroed(1048576)
    var key = SIMD[DType.uint8, 4](0xDE, 0xAD, 0xBE, 0xEF)
    var src = payload.unsafe_ptr()
    var dst = output.unsafe_ptr()
    var tiled = SIMD[DType.uint8, SIMD_WIDTH]()

    @parameter
    for i in range(SIMD_WIDTH):
        tiled[i] = key[i & 3]

    @parameter
    @always_inline
    fn call_fn():
        var i = 0
        while i + SIMD_WIDTH <= 1048576:
            var chunk = (src + i).load[width=SIMD_WIDTH]()
            (dst + i).store[width=SIMD_WIDTH](chunk ^ tiled)
            i += SIMD_WIDTH
        keep(dst[0])

    b.iter[call_fn]()


# ── main ──────────────────────────────────────────────────────────────────────


fn main() raises:
    print("=" * 70)
    print("flare WebSocket XOR Masking Benchmark: Scalar vs SIMD")
    print("=" * 70)
    print()
    print("SIMD width:", SIMD_WIDTH, "bytes (compile-time constant)")
    print()
    print("Payload sizes: 32 B, 128 B, 1 KB, 64 KB, 1 MB")
    print("Throughput reported in GB/s (higher = faster).")
    print()

    var m32 = List[ThroughputMeasure]()
    m32.append(ThroughputMeasure(BenchMetric.bytes, 32))

    var m128 = List[ThroughputMeasure]()
    m128.append(ThroughputMeasure(BenchMetric.bytes, 128))

    var m1k = List[ThroughputMeasure]()
    m1k.append(ThroughputMeasure(BenchMetric.bytes, 1024))

    var m64k = List[ThroughputMeasure]()
    m64k.append(ThroughputMeasure(BenchMetric.bytes, 65536))

    var m1m = List[ThroughputMeasure]()
    m1m.append(ThroughputMeasure(BenchMetric.bytes, 1048576))

    var bench = Bench(BenchConfig(max_iters=500))

    bench.bench_function[_bench_scalar_32](BenchId("mask scalar", " 32 B"), m32)
    bench.bench_function[_bench_simd_32](BenchId("mask SIMD-32", " 32 B"), m32)
    bench.bench_function[_bench_scalar_128](
        BenchId("mask scalar", "128 B"), m128
    )
    bench.bench_function[_bench_simd_128](
        BenchId("mask SIMD-32", "128 B"), m128
    )
    bench.bench_function[_bench_scalar_1k](BenchId("mask scalar", " 1 KB"), m1k)
    bench.bench_function[_bench_simd_1k](BenchId("mask SIMD-32", " 1 KB"), m1k)
    bench.bench_function[_bench_scalar_64k](
        BenchId("mask scalar", "64 KB"), m64k
    )
    bench.bench_function[_bench_simd_64k](
        BenchId("mask SIMD-32", "64 KB"), m64k
    )
    bench.bench_function[_bench_scalar_1m](BenchId("mask scalar", " 1 MB"), m1m)
    bench.bench_function[_bench_simd_1m](BenchId("mask SIMD-32", " 1 MB"), m1m)

    print(bench)

    print()
    print("Interpretation guide:")
    print("  32 B:   SIMD setup cost ≈ work done — expect scalar ≈ SIMD")
    print(" 128 B:   expect SIMD 2–4×  faster")
    print("   1 KB:  expect SIMD 4–8×  faster")
    print("  64 KB:  expect SIMD 8–16× faster (memory-bandwidth limited)")
    print("   1 MB:  both limited by L2/L3 cache bandwidth")
    print()
    print("Production plan: WsFrame.encode() in flare/ws/frame.mojo should use")
    print("SIMD masking for payloads >= 128 B and scalar for smaller frames.")
