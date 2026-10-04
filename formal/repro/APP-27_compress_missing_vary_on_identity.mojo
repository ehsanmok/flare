# PLATFORM: any
"""APP-27: Compress omits `Vary: Accept-Encoding` on the responses it leaves
uncompressed.

Lean: Flare.Bugs.APP_27.violates_spec (counterexample) and
Flare.Bugs.APP_27.fixed_meets_spec (fix meets spec).
flare/http/middleware.mojo:345-376 @59bda50.

Expected (RFC 9110 §12.5.5): an origin server SHOULD send Vary when the
representation it selects depends on request fields other than the method
and target URI. For a body at or above min_size_bytes, Compress picks gzip,
br or identity from Accept-Encoding, so every such response depends on that
field.
Actual: the gzip response carries `Vary: Accept-Encoding`, but the identity
response sent to a client without Accept-Encoding (same URL, same 2048-byte
body) carries no Vary, so a shared cache may store it as the only variant.

Minimal fix: in Compress.serve, append `Vary: Accept-Encoding` whenever the
body is at least min_size_bytes and not already encoded, including the
identity branches.
"""

from flare.http import Compress, Handler, Method, Request, Response


@fieldwise_init
struct _Big(Copyable, Defaultable, Handler):
    var _p: UInt8

    def __init__(out self):
        self._p = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8](length=2048, fill=UInt8(65))
        return resp^


def _has_vary_ae(resp: Response) -> Bool:
    var all = resp.headers.get_all("vary")
    for i in range(len(all)):
        if all[i].lower().find("accept-encoding") >= 0:
            return True
    return False


def main() raises:
    var mw = Compress(_Big())
    var gz = Request(method=Method.GET, url="/page")
    gz.headers.set("Accept-Encoding", "gzip")
    var r1 = mw.serve(gz)
    var plain = Request(method=Method.GET, url="/page")
    var r2 = mw.serve(plain)
    if _has_vary_ae(r1) and not _has_vary_ae(r2):
        print(
            "BUG REPRODUCED: gzip response has Vary: Accept-Encoding ("
            + r1.headers.get("content-encoding")
            + ") but the identity response for the same URL has none"
        )
        raise Error("APP-27")
    print("OK: Vary: Accept-Encoding on both variants")
