# PLATFORM: any
# RESOLVED: APP-26 fixed on fix/formal-findings
"""APP-26: Compress gzips a 206 Partial Content body and keeps its Content-Range.

Lean: Flare.Bugs.APP_26.violates_spec (counterexample) and
Flare.Bugs.APP_26.fixed_meets_spec (fix meets spec).
flare/http/middleware.mojo:345-376 @59bda50.

Expected (RFC 9110 §14.4 and §8.4): the byte offsets in Content-Range refer
to the selected representation, which includes its content coding, and the
content length must equal the range length. A middleware that adds a
content coding after the range was cut cannot keep the old Content-Range.
Before the fix: an inner handler (for example FileServer with `Range:`) answers
206 with `Content-Range: bytes 0-2047/10000` and 2048 body bytes; Compress
gzips the 2048 bytes, keeps the status and Content-Range, and rewrites
Content-Length to the compressed size, so the range header no longer
matches the body.

Minimal fix: in Compress.serve, return the inner response unchanged when
its status is 206 (or it carries Content-Range).
"""

from flare.http import Compress, Handler, Method, Request, Response


@fieldwise_init
struct _Partial(Copyable, Defaultable, Handler):
    var _p: UInt8

    def __init__(out self):
        self._p = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=206)
        resp.body = List[UInt8](length=2048, fill=UInt8(65))
        resp.headers.set("Content-Range", "bytes 0-2047/10000")
        resp.headers.set("Content-Length", "2048")
        resp.headers.set("Accept-Ranges", "bytes")
        return resp^


def main() raises:
    var mw = Compress(_Partial())
    var req = Request(method=Method.GET, url="/big.bin")
    req.headers.set("Range", "bytes=0-2047")
    req.headers.set("Accept-Encoding", "gzip")
    var resp = mw.serve(req)
    var ce = resp.headers.get("content-encoding")
    var cr = resp.headers.get("content-range")
    if resp.status == 206 and ce.byte_length() > 0 and len(resp.body) != 2048:
        print(
            "BUG REPRODUCED: 206 with Content-Range '"
            + cr
            + "' was re-encoded as "
            + ce
            + "; body is "
            + String(len(resp.body))
            + " bytes, Content-Length "
            + resp.headers.get("content-length")
        )
        raise Error("APP-26")
    print(
        "OK: partial response passed through unencoded (status "
        + String(resp.status)
        + ", "
        + String(len(resp.body))
        + " bytes)"
    )
