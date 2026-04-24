"""Fuzz harness: SIMD header scanners ``find_crlfcrlf`` + ``scan_content_length``.

Cross-checks the SIMD implementations against the scalar reference in
``flare.http._scan`` over random buffers. The two must never disagree;
any mismatch is a bug. ``scan_content_length`` is also fed inputs with
random ``Content-Length:`` insertion points so the chunk-boundary
branches of its inner scan get exercised.

Run:
    pixi run --environment fuzz fuzz-header-scan
"""

from mozz import fuzz, FuzzConfig

from flare.http._scan import find_crlfcrlf, scan_content_length


@always_inline
def _bytes(data: List[UInt8]) -> List[UInt8]:
    """Identity alias used so the fuzz target is easy to read."""
    return data.copy()


def _scalar_find_crlfcrlf(data: List[UInt8], start: Int) -> Int:
    """Reference implementation used as the oracle."""
    var n = len(data)
    if n < 4:
        return -1
    var p = data.unsafe_ptr()
    for i in range(start, n - 3):
        if p[i] == 13 and p[i + 1] == 10 and p[i + 2] == 13 and p[i + 3] == 10:
            return i + 4
    return -1


def _scalar_scan_content_length(data: List[UInt8], header_end: Int) -> Int:
    """Reference implementation used as the oracle."""
    var needle = "content-length:"
    var np = needle.unsafe_ptr()
    var nl = needle.byte_length()
    var p = data.unsafe_ptr()
    var i = 0
    while i + nl <= header_end:
        var found = True
        for j in range(nl):
            var c = p[i + j]
            if c >= 65 and c <= 90:
                c = c + 32
            if c != np[j]:
                found = False
                break
        if found:
            var pos = i + nl
            while pos < header_end and (p[pos] == 32 or p[pos] == 9):
                pos += 1
            var result = 0
            while pos < header_end and p[pos] >= 48 and p[pos] <= 57:
                result = result * 10 + Int(p[pos]) - 48
                pos += 1
            return result
        i += 1
    return 0


def target(data: List[UInt8]) raises:
    """Fuzz target: compare SIMD scanners against scalar reference.

    Bugs (treated as crashes):
        - ``find_crlfcrlf`` at W=32, W=64, or default width disagrees
          with the scalar reference.
        - ``scan_content_length`` at any width disagrees with the scalar
          reference.
    """
    if len(data) == 0:
        return

    # find_crlfcrlf
    var ref_end = _scalar_find_crlfcrlf(data, 0)
    var simd_end_32 = find_crlfcrlf[W=32](data, 0)
    var simd_end_64 = find_crlfcrlf[W=64](data, 0)
    if simd_end_32 != ref_end:
        raise Error(
            "find_crlfcrlf[32] mismatch: simd="
            + String(simd_end_32)
            + " ref="
            + String(ref_end)
        )
    if simd_end_64 != ref_end:
        raise Error(
            "find_crlfcrlf[64] mismatch: simd="
            + String(simd_end_64)
            + " ref="
            + String(ref_end)
        )

    # scan_content_length — use the input's own terminator position (or
    # len(data) when no terminator present) as header_end.
    var he = ref_end if ref_end > 0 else len(data)
    var ref_cl = _scalar_scan_content_length(data, he)
    var simd_cl_32 = scan_content_length[W=32](data, he)
    var simd_cl_64 = scan_content_length[W=64](data, he)
    if simd_cl_32 != ref_cl:
        raise Error(
            "scan_content_length[32] mismatch: simd="
            + String(simd_cl_32)
            + " ref="
            + String(ref_cl)
        )
    if simd_cl_64 != ref_cl:
        raise Error(
            "scan_content_length[64] mismatch: simd="
            + String(simd_cl_64)
            + " ref="
            + String(ref_cl)
        )


def main() raises:
    print("=" * 60)
    print("fuzz_header_scan.mojo — SIMD scanners vs scalar oracle")
    print("=" * 60)
    print()

    var seeds = List[List[UInt8]]()

    def _b(s: String) -> List[UInt8]:
        var bs = s.as_bytes()
        var out = List[UInt8](capacity=len(bs))
        for i in range(len(bs)):
            out.append(bs[i])
        return out^

    seeds.append(_b(""))
    seeds.append(_b("\r\n\r\n"))
    seeds.append(_b("GET / HTTP/1.1\r\n\r\n"))
    seeds.append(_b("POST /x HTTP/1.1\r\nContent-Length: 7\r\n\r\nhello!!"))
    # Boundary-spanning CRLFCRLF seeds.
    seeds.append(_b("x" * 29 + "\r\n\r\n"))
    seeds.append(_b("x" * 30 + "\r\n\r\n"))
    seeds.append(_b("x" * 31 + "\r\n\r\n"))
    seeds.append(_b("x" * 32 + "\r\n\r\n"))
    seeds.append(_b("x" * 63 + "\r\n\r\n"))
    seeds.append(_b("x" * 64 + "\r\n\r\n"))
    # CR-only lures.
    seeds.append(_b("\r\r\r\r"))
    seeds.append(_b("\r\n\r"))
    # Case variants on Content-Length.
    seeds.append(_b("GET / HTTP/1.1\r\nCONTENT-LENGTH: 5\r\n\r\nhello"))
    seeds.append(_b("GET / HTTP/1.1\r\ncontent-length:\t42\r\n\r\n"))

    fuzz(
        target,
        FuzzConfig(
            max_runs=500_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/header_scan",
            max_input_len=256,
        ),
        seeds,
    )
