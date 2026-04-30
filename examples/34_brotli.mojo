"""Example 34: Brotli ``Content-Encoding: br``.

Round-trips a body through ``compress_brotli`` /
``decompress_brotli`` and shows ``Compress`` middleware picking
``br`` over ``gzip`` when the client advertises a higher q-value
for it (per RFC 9110 paragraph 12.5.3).

Pure construction — no live network. Run:
    pixi run example-brotli
"""

from flare.http import (
    Compress,
    Encoding,
    Handler,
    Method,
    Request,
    Response,
    compress_brotli,
    decompress_brotli,
    decode_content,
    negotiate_encoding,
)


@fieldwise_init
struct LargeText(Copyable, Defaultable, Handler, Movable):
    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        var body = String("")
        for _ in range(2048):
            body += "Hello, brotli! "
        resp.body = List[UInt8](body.as_bytes())
        resp.headers.set("Content-Type", "text/plain")
        return resp^


def main() raises:
    print("=== flare Example 34: Brotli content-encoding ===")
    print()

    print("── 1. Direct compress / decompress round-trip ──")
    var data = String(
        "the quick brown fox jumps over the lazy dog. "
        "the quick brown fox jumps over the lazy dog. "
    )
    for _ in range(8):
        var dup = data.copy()
        data += dup
    var bytes = List[UInt8](data.as_bytes())
    var compressed = compress_brotli(Span[UInt8, _](bytes))
    print("  raw bytes        :", len(bytes))
    print("  compressed bytes :", len(compressed))
    var roundtrip = decompress_brotli(Span[UInt8, _](compressed))
    print("  roundtrip bytes  :", len(roundtrip))
    print()

    print("── 2. negotiate_encoding picks br when offered ──")
    var p = negotiate_encoding("gzip;q=0.7, br;q=0.9", True)
    print("  'gzip;q=0.7, br;q=0.9' ->", p.encoding)
    var p2 = negotiate_encoding("gzip", True)
    print("  'gzip' ->", p2.encoding)
    print()

    print("── 3. Compress middleware emits br ──")
    var stack = Compress(LargeText(), min_size_bytes=512)
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip;q=0.5, br;q=0.95")
    var resp = stack.serve(req)
    print("  status           :", resp.status)
    print("  Content-Encoding :", resp.headers.get("content-encoding"))
    print("  body length      :", len(resp.body))
    var dec = decode_content(
        Span[UInt8, _](resp.body),
        resp.headers.get("content-encoding"),
    )
    print("  decoded length   :", len(dec))
    print()

    print("=== Example 34 complete ===")
