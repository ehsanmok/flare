"""Fuzz harness for flare.http.encoding — gzip/deflate compression.

Two targets:

1. ``target_decompress`` — arbitrary bytes into ``decompress_gzip``.
   Valid gzip data must decompress cleanly; invalid data must raise a
   structured error, never crash.

2. ``target_roundtrip`` — ``compress_gzip`` followed by ``decompress_gzip``
   must reproduce the original bytes exactly (identity property).

Run:
    pixi run fuzz-encoding
"""

from mozz import fuzz, FuzzConfig
from flare.http.encoding import compress_gzip, decompress_gzip


fn target_decompress(data: List[UInt8]) raises:
    """Feed arbitrary bytes to decompress_gzip.

    Structured errors (zlib failures) are expected for random input.
    Crashes (abort, SIGSEGV) are always bugs.

    Args:
        data: Arbitrary fuzz input bytes.
    """
    try:
        _ = decompress_gzip(Span[UInt8](data))
    except:
        pass  # structured errors are fine for garbage input


fn target_roundtrip(data: List[UInt8]) raises:
    """compress_gzip → decompress_gzip must reproduce original bytes.

    Reports a bug message if the roundtrip produces incorrect output.

    Args:
        data: Arbitrary bytes to compress and decompress.
    """
    if len(data) == 0:
        return
    var compressed = compress_gzip(Span[UInt8](data))
    var decompressed = decompress_gzip(Span[UInt8](compressed))
    if len(decompressed) != len(data):
        print(
            "[BUG] gzip roundtrip length mismatch: input="
            + String(len(data))
            + " output="
            + String(len(decompressed))
        )
        return
    for i in range(len(data)):
        if decompressed[i] != data[i]:
            print("[BUG] gzip roundtrip byte mismatch at index " + String(i))
            return


fn main() raises:
    print("[mozz] fuzzing flare.http.encoding (gzip round-trip)...")

    # Seed corpus: real gzip byte sequences
    var seeds = List[List[UInt8]]()

    # Empty input
    seeds.append(List[UInt8]())

    # Single byte
    var s1 = List[UInt8]()
    s1.append(UInt8(65))  # 'A'
    seeds.append(s1^)

    # Short ASCII string
    var s2 = List[UInt8]()
    for b in "hello, world!".as_bytes():
        s2.append(b)
    seeds.append(s2^)

    # Gzip magic bytes (truncated — will fail gracefully)
    var s3: List[UInt8] = [0x1F, 0x8B, 0x08, 0x00]
    seeds.append(s3^)

    print("  target: decompress_gzip (arbitrary bytes)")
    fuzz(
        target_decompress,
        FuzzConfig(
            max_runs=200_000,
            seed=0,
            verbose=True,
            crash_dir=".mozz_crashes/encoding",
            corpus_dir="fuzz/corpus/encoding",
            max_input_len=4096,
        ),
        seeds,
    )

    print("  target: compress→decompress round-trip")
    fuzz(
        target_roundtrip,
        FuzzConfig(
            max_runs=100_000,
            seed=42,
            verbose=True,
            crash_dir=".mozz_crashes/encoding_roundtrip",
            corpus_dir="fuzz/corpus/encoding_roundtrip",
            max_input_len=2048,
        ),
        seeds,
    )

    print("[mozz] done.")
