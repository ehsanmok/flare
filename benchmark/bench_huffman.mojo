"""Benchmark: HPACK Huffman decode -- scalar vs SIMD shim (Track c08).

RFC 7541 Appendix B canonical Huffman is the wire compression
format for HPACK string literals (h2 + h3 header fields). The
scalar decoder runs 5..30 bits per output byte through a linear
table scan; a true SIMD kernel (PSHUFB / VPCOMPRESSB on x86,
TBL on ARM NEON) can amortise the bit-walking by decoding 4-bit
nibbles in parallel.

This bench measures the two paths side by side at four
representative input sizes:

* 16  B -- below the SIMD setup-cost threshold; scalar should
  match or beat SIMD.
* 256 B -- typical h2 header value; SIMD starts paying off.
* 4 KB -- large header bag (concatenated cookie / set-cookie);
  SIMD should be >= 10% faster.
* 64 KB -- pathological header (long opaque token); SIMD's
  best case.

v0.7 ships the SIMD shim as a *parity fallback* that delegates
to the scalar decoder, so the two columns will read identically.
The bench scaffold lands now so the v0.8 SIMD kernel has a
concrete target.

Usage:
    pixi run bench-huffman
"""

from std.benchmark import (
    Bench,
    BenchConfig,
    BenchId,
    Bencher,
    BenchMetric,
    ThroughputMeasure,
    keep,
)

from flare.http.hpack_huffman import huffman_decode, huffman_encode
from flare.http.hpack_huffman_simd import huffman_decode_simd


def _alloc_pattern(n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8(0x20 + (i % 0x5E)))
    return out^


def _encode(input: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    huffman_encode(Span[UInt8, _](input), out)
    return out^


def _bench_scalar_16(mut b: Bencher) capturing:
    var raw = _alloc_pattern(16)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_simd_16(mut b: Bencher) capturing:
    var raw = _alloc_pattern(16)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode_simd(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_scalar_256(mut b: Bencher) capturing:
    var raw = _alloc_pattern(256)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_simd_256(mut b: Bencher) capturing:
    var raw = _alloc_pattern(256)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode_simd(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_scalar_4k(mut b: Bencher) capturing:
    var raw = _alloc_pattern(4096)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_simd_4k(mut b: Bencher) capturing:
    var raw = _alloc_pattern(4096)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode_simd(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_scalar_64k(mut b: Bencher) capturing:
    var raw = _alloc_pattern(65536)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def _bench_simd_64k(mut b: Bencher) capturing:
    var raw = _alloc_pattern(65536)
    var enc = _encode(raw)

    @parameter
    def call_fn():
        var out = List[UInt8]()
        try:
            huffman_decode_simd(Span[UInt8, _](enc), out)
        except:
            pass
        keep(len(out))

    b.iter[call_fn]()


def main() raises:
    var m16 = List[ThroughputMeasure]()
    m16.append(ThroughputMeasure(BenchMetric.bytes, 16))
    var m256 = List[ThroughputMeasure]()
    m256.append(ThroughputMeasure(BenchMetric.bytes, 256))
    var m4k = List[ThroughputMeasure]()
    m4k.append(ThroughputMeasure(BenchMetric.bytes, 4096))
    var m64k = List[ThroughputMeasure]()
    m64k.append(ThroughputMeasure(BenchMetric.bytes, 65536))

    var bench = Bench(BenchConfig(max_iters=500))
    bench.bench_function[_bench_scalar_16](
        BenchId("huffman scalar", "  16 B"), m16
    )
    bench.bench_function[_bench_simd_16](
        BenchId("huffman simd  ", "  16 B"), m16
    )
    bench.bench_function[_bench_scalar_256](
        BenchId("huffman scalar", " 256 B"), m256
    )
    bench.bench_function[_bench_simd_256](
        BenchId("huffman simd  ", " 256 B"), m256
    )
    bench.bench_function[_bench_scalar_4k](
        BenchId("huffman scalar", "  4 KB"), m4k
    )
    bench.bench_function[_bench_simd_4k](
        BenchId("huffman simd  ", "  4 KB"), m4k
    )
    bench.bench_function[_bench_scalar_64k](
        BenchId("huffman scalar", " 64 KB"), m64k
    )
    bench.bench_function[_bench_simd_64k](
        BenchId("huffman simd  ", " 64 KB"), m64k
    )
    print(bench)
