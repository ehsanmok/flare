"""Example 10 — HTTP content encoding: gzip and deflate with flare.http.

Demonstrates:
  - compress_gzip(data, level) — compress bytes to gzip format
  - decompress_gzip(data)      — decompress gzip bytes
  - decompress_deflate(data)   — decompress zlib-wrapped deflate bytes
  - decode_content(body, encoding) — dispatch by Content-Encoding header
  - Round-trip identity: decompress(compress(data)) == data
  - Compressing a JSON payload (simulating a gzip-encoded HTTP response)
  - Encoding constants: Encoding.GZIP / DEFLATE / IDENTITY / BR

No network required — all operations are performed in-process.

Run:
    pixi run example-encoding
"""

from flare.http import (
    Encoding,
    compress_gzip,
    decompress_gzip,
    decompress_deflate,
    decode_content,
)


fn main() raises:
    print("=== flare Example 10: HTTP Content Encoding ===")
    print()

    # ── 1. Encoding constants ────────────────────────────────────────────────
    print("── 1. Encoding constants ──")
    print("  Encoding.GZIP     :", Encoding.GZIP)
    print("  Encoding.DEFLATE  :", Encoding.DEFLATE)
    print("  Encoding.IDENTITY :", Encoding.IDENTITY)
    print("  Encoding.BR       :", Encoding.BR)
    print()

    # ── 2. Gzip round-trip ───────────────────────────────────────────────────
    print("── 2. Gzip round-trip ──")
    var original = String("Hello, flare! This is a test of gzip compression.")
    var original_bytes = original.as_bytes()

    var compressed = compress_gzip(Span[UInt8](original_bytes))
    print("  original  :", len(original_bytes), "bytes")
    print("  compressed:", len(compressed), "bytes (gzip)")

    var decompressed = decompress_gzip(Span[UInt8](compressed))
    var restored = String(unsafe_from_utf8=decompressed)
    print("  restored  :", len(decompressed), "bytes")
    print("  match     :", restored == original)
    print()

    # ── 3. Compression levels ────────────────────────────────────────────────
    print("── 3. Compression levels (0=none … 9=max) ──")
    var lorem = String(
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
        + "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
        + "Ut enim ad minim veniam, quis nostrud exercitation ullamco."
    )
    var lorem_bytes = lorem.as_bytes()
    for level in range(0, 10):
        var c = compress_gzip(Span[UInt8](lorem_bytes), level)
        print("  level", level, "→", len(c), "bytes")
    print()

    # ── 4. Repeated content compresses well ──────────────────────────────────
    print("── 4. Highly compressible content ──")
    var rep = String(capacity=1024)
    for _ in range(100):
        rep += "AAAA"
    var rep_bytes = rep.as_bytes()
    var rep_compressed = compress_gzip(Span[UInt8](rep_bytes))
    print("  input :", len(rep_bytes), "bytes (400 × 'AAAA')")
    print("  output:", len(rep_compressed), "bytes (gzip)")
    var ratio = Float64(len(rep_bytes)) / Float64(len(rep_compressed))
    print("  ratio :", ratio, "× compression")
    print()

    # ── 5. JSON payload round-trip ────────────────────────────────────────────
    print("── 5. JSON payload round-trip ──")
    var json = String(
        '{"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}'
    )
    var json_bytes = json.as_bytes()
    var json_gz = compress_gzip(Span[UInt8](json_bytes))
    print("  JSON original :", len(json_bytes), "bytes")
    print("  JSON gzip     :", len(json_gz), "bytes")

    var json_back = decompress_gzip(Span[UInt8](json_gz))
    print("  JSON restored :", String(unsafe_from_utf8=json_back) == json)
    print()

    # ── 6. decode_content() dispatch ─────────────────────────────────────────
    print("── 6. decode_content() — Content-Encoding dispatch ──")
    var payload = String("the actual HTTP response body")
    var body_bytes = payload.as_bytes()

    # identity (no decompression)
    var body_list_id = List[UInt8](capacity=len(body_bytes))
    for b in body_bytes:
        body_list_id.append(b)
    var decoded_id = decode_content(body_list_id, Encoding.IDENTITY)
    print(
        "  identity →",
        String(unsafe_from_utf8=decoded_id),
        "(unchanged)",
    )

    # gzip: compress first, then decode
    var gz_bytes = compress_gzip(Span[UInt8](body_bytes))
    var gz_list = List[UInt8](capacity=len(gz_bytes))
    for b in gz_bytes:
        gz_list.append(b)
    var decoded_gz = decode_content(gz_list, Encoding.GZIP)
    print("  gzip    →", String(unsafe_from_utf8=decoded_gz))
    print()

    # ── 7. Empty input ────────────────────────────────────────────────────────
    print("── 7. Edge cases ──")
    var empty: List[UInt8] = []
    var empty_gz = compress_gzip(Span[UInt8](empty))
    var empty_back = decompress_gzip(Span[UInt8](empty_gz))
    print(
        "  empty → compressed:",
        len(empty_gz),
        "bytes → decompressed:",
        len(empty_back),
        "bytes",
    )

    # Single byte
    var one: List[UInt8] = [42]
    var one_gz = compress_gzip(Span[UInt8](one))
    var one_back = decompress_gzip(Span[UInt8](one_gz))
    print(
        "  [42]  → compressed:",
        len(one_gz),
        "bytes → decompressed:",
        Int(one_back[0]),
    )
    print()

    # ── 8. Error handling: invalid gzip input ────────────────────────────────
    print("── 8. Error handling ──")
    var garbage: List[UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
    try:
        _ = decompress_gzip(Span[UInt8](garbage))
        print("  ERROR: expected an error for invalid gzip data")
    except e:
        print("  ✓ decompress_gzip raised on garbage input:", String(e)[:40])
    print()

    print("=== Example 10 complete ===")
