"""Example 31: Middleware stack — Logger + RequestId + Compress + CatchPanic.

Shows the v0.6 generic middleware library in action:

- ``Logger`` logs ``method url status latency``.
- ``RequestId`` echoes ``X-Request-Id`` (or generates one).
- ``Compress`` negotiates ``Content-Encoding`` per RFC 9110
  paragraph 12.5.3 (gzip / br / identity), with a configurable
  minimum body size.
- ``CatchPanic`` turns any inner ``raise`` into a sanitised 500.

Pure construction — no live network. Run:
    pixi run example-middleware-stack
"""

from flare.http import (
    CatchPanic,
    Compress,
    Handler,
    HeaderMap,
    Logger,
    Method,
    Request,
    RequestId,
    Response,
    decompress_gzip,
    negotiate_encoding,
)


@fieldwise_init
struct LargePage(Copyable, Defaultable, Handler, Movable):
    """Returns a 4 KiB HTML body so ``Compress`` will engage."""

    var _placeholder: UInt8

    def __init__(out self):
        self._placeholder = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        var body = String("<!doctype html><h1>flare middleware demo</h1>")
        for _ in range(60):
            body += "<p>"
            for _ in range(60):
                body += "x"
            body += "</p>"
        resp.body = List[UInt8](body.as_bytes())
        resp.headers.set("Content-Type", "text/html; charset=utf-8")
        resp.headers.set("Content-Length", String(len(resp.body)))
        return resp^


def main() raises:
    print("=== flare Example 31: Middleware stack ===")
    print()

    var stack = CatchPanic(
        Logger(
            RequestId(Compress(LargePage(), min_size_bytes=512)),
            prefix="[demo]",
        )
    )

    # ── 1. negotiate_encoding directly ────────────────────────────────────
    print("── 1. negotiate_encoding ──")
    var p1 = negotiate_encoding("gzip, br;q=0.5", True)
    print("  'gzip, br;q=0.5' ->", p1.encoding)
    var p2 = negotiate_encoding("br;q=1.0, gzip;q=0.5", True)
    print("  'br;q=1.0, gzip;q=0.5' ->", p2.encoding)
    var p3 = negotiate_encoding("gzip;q=0", False)
    print(
        "  'gzip;q=0' (gzip explicitly rejected) ->",
        p3.encoding,
        " quality=",
        p3.quality,
    )
    print()

    # ── 2. Inbound request with Accept-Encoding: gzip ────────────────────
    print("── 2. Stack response (gzip) ──")
    var req = Request(method=Method.GET, url="/")
    req.headers.set("Accept-Encoding", "gzip, br;q=0.0")
    req.headers.set("X-Request-Id", "demo-req-42")
    var resp = stack.serve(req)
    print("  status         :", resp.status)
    print("  X-Request-Id   :", resp.headers.get("x-request-id"))
    print("  Content-Encoding:", resp.headers.get("content-encoding"))
    print("  Vary           :", resp.headers.get("vary"))
    print("  body length    :", len(resp.body))
    var roundtripped = decompress_gzip(Span[UInt8, _](resp.body))
    print("  decompressed   :", len(roundtripped), "bytes")
    print()

    # ── 3. Identity request (no Accept-Encoding) ──────────────────────────
    print("── 3. Stack response (identity) ──")
    var req2 = Request(method=Method.GET, url="/")
    var resp2 = stack.serve(req2)
    print("  status         :", resp2.status)
    print("  Content-Encoding:", resp2.headers.get("content-encoding"))
    print("  body length    :", len(resp2.body))
    print()

    print("=== Example 31 complete ===")
