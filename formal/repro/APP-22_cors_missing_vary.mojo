# PLATFORM: any
"""APP-22: Cors omits `Vary: Origin` on responses it does not stamp.

Lean: Flare.Bugs.APP_22.violates_spec, Flare.Bugs.APP_22.missing_vary
(counterexample) and Flare.Bugs.APP_22.fixed_meets_spec (fix meets spec).
flare/http/cors.mojo:160-171 @59bda50.

Expected (WHATWG Fetch 3.2.5, "CORS protocol and HTTP caches"): when the
Access-Control-Allow-Origin value depends on the request's Origin, every
response for the resource carries `Vary: Origin`, including the response to
a request without Origin, so a shared cache does not hand an ACAO-less
response to a CORS request (or one origin's ACAO to another).
Actual: with allowed_origins = [a, b], a request from a gets ACAO a plus
Vary: Origin, but a request with no Origin (and one from a rejected
origin) gets the inner response with no Vary at all.

Minimal fix: in Cors.serve, append `Vary: Origin` to the pass-through
responses too (no Origin, rejected origin, rejected preflight).
"""

from flare.http import Cors, CorsConfig, Handler, Method, Request, Response


@fieldwise_init
struct _Echo(Copyable, Defaultable, Handler):
    var _p: UInt8

    def __init__(out self):
        self._p = UInt8(0)

    def serve(self, req: Request) raises -> Response:
        var resp = Response(status=200)
        resp.body = List[UInt8]("ok".as_bytes())
        return resp^


def _has_vary_origin(resp: Response) -> Bool:
    var all = resp.headers.get_all("vary")
    for i in range(len(all)):
        if all[i].lower().find("origin") >= 0:
            return True
    return False


def main() raises:
    var cfg = CorsConfig()
    cfg.allowed_origins.append("https://a.example")
    cfg.allowed_origins.append("https://b.example")
    var mw = Cors(_Echo(), cfg)

    var with_origin = Request(method=Method.GET, url="/api")
    with_origin.headers.set("Origin", "https://a.example")
    var r1 = mw.serve(with_origin)

    var no_origin = Request(method=Method.GET, url="/api")
    var r2 = mw.serve(no_origin)

    var other = Request(method=Method.GET, url="/api")
    other.headers.set("Origin", "https://evil.example")
    var r3 = mw.serve(other)

    var acao1 = r1.headers.get("access-control-allow-origin")
    if not _has_vary_origin(r2) or not _has_vary_origin(r3):
        print(
            "BUG REPRODUCED: ACAO varies with Origin ('"
            + acao1
            + "' for https://a.example, absent otherwise) but Vary: Origin is"
            + " missing on the no-Origin response ("
            + String(_has_vary_origin(r2))
            + ") / rejected-origin response ("
            + String(_has_vary_origin(r3))
            + ")"
        )
        raise Error("APP-22")
    print("OK: Vary: Origin present on all responses")
